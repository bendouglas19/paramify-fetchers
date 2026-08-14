#!/usr/bin/env python3
"""
Microsoft Entra ID multi-factor authentication coverage

Lists every user in the tenant with the facts a reviewer needs to judge MFA
coverage: whether the account is enabled, when it last signed in, and whether it
is MFA-capable — that is, whether it has at least one MFA method registered and
usable, which is the fact the Entra admin center's own "MFA capable" column
reports.

Two Graph reads are joined. `users` gives identity and account state;
`reports/authenticationMethods/userRegistrationDetails` gives the registration
posture. They must be joined rather than read separately because neither alone
answers the question: the users list has no MFA field, and the registration report
says nothing about whether the account is still enabled — and MFA coverage over
ALL users (including the disabled ones nobody can sign in as) understates the real
posture, sometimes badly in a tenant with a long tail of deprovisioned accounts.

Field projections and the join are ported from Prowler's
prowler/providers/azure/services/entra/entra_service.py (Apache-2.0), `_get_users`
and `_get_user_registration_details`, which read the same msgraph-sdk. Prowler's
`$select` projection and manual `odata_next_link` pagination are kept.

Tenant-scoped per invocation, NOT subscription-scoped: Graph data is tenant-wide.
Fanout across tenants happens at the runner layer (see fetcher.yaml).
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    write_evidence,
    write_status,
)
from entra_graph import (  # noqa: E402
    graph_attr,
    graph_list,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_mfa_status")

# Graph's $select projection for the users call, exactly Prowler's list plus
# userPrincipalName and userType. Projecting explicitly is not just a size
# optimization: signInActivity is only returned when it is ASKED for by name, so
# omitting the $select would silently produce a null last_sign_in for every user.
USER_SELECT = (
    "id",
    "displayName",
    "userPrincipalName",
    "accountEnabled",
    "userType",
    "signInActivity",
)

# Graph's userType for an invited external identity. Guests are counted separately
# in the summary because an unenforced guest is a different finding from an
# unenforced employee, and guest MFA is often owned by the inviting tenant.
GUEST_USER_TYPE = "guest"


# --- projections: the only code here that touches a Graph model ---

def project_user(user) -> dict:
    """Read a `User` model's attributes into a flat snake_case dict.

    `sign_in_activity` is the one nested model, and it is absent for any account
    that has never signed in as well as on a tenant without the
    AuditLog.Read.All permission — `graph_attr`'s None-tolerance covers both, so an
    absent block reads as a null timestamp rather than raising.

    `last_successful_sign_in` is kept alongside `last_sign_in` because they differ
    in a way that matters: `lastSignInDateTime` records the last interactive sign-in
    ATTEMPT, so a stale account whose password keeps being sprayed at it looks
    recently active by that field alone.
    """
    sign_in_activity = graph_attr(user, "sign_in_activity")
    return {
        "id": graph_attr(user, "id"),
        "display_name": graph_attr(user, "display_name"),
        "user_principal_name": graph_attr(user, "user_principal_name"),
        "account_enabled": graph_attr(user, "account_enabled"),
        "user_type": graph_attr(user, "user_type"),
        "last_sign_in": graph_attr(sign_in_activity, "last_sign_in_date_time"),
        "last_successful_sign_in": graph_attr(
            sign_in_activity, "last_successful_sign_in_date_time"
        ),
        "last_non_interactive_sign_in": graph_attr(
            sign_in_activity, "last_non_interactive_sign_in_date_time"
        ),
    }


def project_registration_details(detail) -> dict:
    """Read a `UserRegistrationDetails` model's attributes into a flat dict.

    Prowler takes only `is_mfa_capable` from this response. The rest of the fields
    below arrive in the SAME response body at no extra cost and answer the follow-up
    questions a reviewer always asks next — is MFA merely registered or actually
    usable, is the method phishing-resistant (passwordless), and is this a
    privileged account — so they are projected rather than discarded.
    """
    return {
        "id": graph_attr(detail, "id"),
        "is_mfa_capable": graph_attr(detail, "is_mfa_capable"),
        "is_mfa_registered": graph_attr(detail, "is_mfa_registered"),
        "is_passwordless_capable": graph_attr(detail, "is_passwordless_capable"),
        "is_sspr_capable": graph_attr(detail, "is_sspr_capable"),
        "is_sspr_registered": graph_attr(detail, "is_sspr_registered"),
        "is_admin": graph_attr(detail, "is_admin"),
        "methods_registered": graph_list(detail, "methods_registered"),
        "last_updated": graph_attr(detail, "last_updated_date_time"),
        "user_preferred_method_for_secondary_authentication": graph_attr(
            detail, "user_preferred_method_for_secondary_authentication"
        ),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def user_record(user: dict, registration: dict | None) -> dict:
    """Join one projected user with its projected registration details.

    Every boolean is coerced with `bool(x or False)` rather than passed through.
    Two different absences collapse to the same answer here and both must read as
    `false`, not `null`: Graph omits a false-y field rather than sending `false`,
    and a user with NO registration-details row at all (a freshly created account
    the report has not picked up yet) has registered nothing. A validator regex
    asserting `"is_mfa_capable": false` would not match `null`.

    `account_enabled` is the exception that defaults the other way: Prowler reads an
    absent `accountEnabled` as `True`, because the field is only omitted when it was
    not selected, and an account assumed disabled would be quietly dropped from the
    coverage denominator — understating exposure. Absent therefore reads as enabled.

    `has_registration_details` keeps the two absences distinguishable, so
    "registered nothing" can still be told apart from "not in the report".
    """
    details = registration if isinstance(registration, dict) else {}
    enabled = user.get("account_enabled")
    return {
        "id": user.get("id"),
        "display_name": user.get("display_name"),
        "user_principal_name": user.get("user_principal_name"),
        "account_enabled": True if enabled is None else bool(enabled),
        "user_type": user.get("user_type"),
        "is_guest": str(user.get("user_type") or "").lower() == GUEST_USER_TYPE,
        "last_sign_in": user.get("last_sign_in"),
        "last_successful_sign_in": user.get("last_successful_sign_in"),
        "last_non_interactive_sign_in": user.get("last_non_interactive_sign_in"),
        "has_registration_details": bool(details),
        "is_mfa_capable": bool(details.get("is_mfa_capable") or False),
        "is_mfa_registered": bool(details.get("is_mfa_registered") or False),
        "is_passwordless_capable": bool(details.get("is_passwordless_capable") or False),
        "is_sspr_capable": bool(details.get("is_sspr_capable") or False),
        "is_sspr_registered": bool(details.get("is_sspr_registered") or False),
        "is_admin": bool(details.get("is_admin") or False),
        "methods_registered": sorted(details.get("methods_registered") or []),
        "preferred_secondary_method": details.get(
            "user_preferred_method_for_secondary_authentication"
        ),
        "registration_last_updated": details.get("last_updated"),
    }


def join_users(users: list[dict], registrations: list[dict]) -> list[dict]:
    """Join the users list against the registration report on the user's object id.

    `userRegistrationDetails.id` IS the user's object id, which is what makes the
    join a plain dict lookup — Prowler relies on the same identity.

    Sorted by user principal name (falling back to id) so a re-run against an
    unchanged directory is byte-stable: Graph does not promise a stable order across
    pages, and an unsorted list would make every run look like a change.
    """
    by_id = {r.get("id"): r for r in registrations if r.get("id")}
    records = [user_record(u, by_id.get(u.get("id"))) for u in users]
    return sorted(records, key=lambda r: (r.get("user_principal_name") or "", r.get("id") or ""))


def summarize(users: list[dict]) -> dict:
    """MFA coverage over ENABLED users is the headline.

    Coverage over all users is also reported, but the enabled-user figure is the one
    that describes the tenant's actual exposure: a disabled account cannot sign in,
    so counting it as an uncovered user makes a well-run tenant with years of
    deprovisioned accounts look worse than a small neglected one. Both are present
    so neither reading can be accused of being cherry-picked.
    """
    enabled = [u for u in users if u["account_enabled"]]
    enabled_members = [u for u in enabled if not u["is_guest"]]
    admins = [u for u in users if u["is_admin"]]
    return {
        "total_users": len(users),
        "enabled_users": len(enabled),
        "disabled_users": len(users) - len(enabled),
        "guest_users": sum(1 for u in users if u["is_guest"]),
        "mfa_capable_users": sum(1 for u in users if u["is_mfa_capable"]),
        "mfa_capable_enabled_users": sum(1 for u in enabled if u["is_mfa_capable"]),
        # The headline: of the accounts that can actually sign in, how many can MFA.
        "mfa_coverage_percentage": coverage_percentage(
            sum(1 for u in enabled if u["is_mfa_capable"]), len(enabled)
        ),
        "mfa_coverage_percentage_all_users": coverage_percentage(
            sum(1 for u in users if u["is_mfa_capable"]), len(users)
        ),
        "enabled_users_without_mfa": sum(1 for u in enabled if not u["is_mfa_capable"]),
        "mfa_registered_enabled_users": sum(1 for u in enabled if u["is_mfa_registered"]),
        "passwordless_capable_enabled_users": sum(
            1 for u in enabled if u["is_passwordless_capable"]
        ),
        "passwordless_coverage_percentage": coverage_percentage(
            sum(1 for u in enabled if u["is_passwordless_capable"]), len(enabled)
        ),
        "sspr_registered_enabled_users": sum(1 for u in enabled if u["is_sspr_registered"]),
        # Guests split out: an unenforced guest is a different finding from an
        # unenforced employee, and is often the inviting tenant's to fix.
        "enabled_member_users": len(enabled_members),
        "mfa_capable_enabled_member_users": sum(
            1 for u in enabled_members if u["is_mfa_capable"]
        ),
        "member_mfa_coverage_percentage": coverage_percentage(
            sum(1 for u in enabled_members if u["is_mfa_capable"]), len(enabled_members)
        ),
        # Admins carry the most risk per account, so they get their own coverage.
        "admin_users": len(admins),
        "mfa_capable_admin_users": sum(1 for u in admins if u["is_mfa_capable"]),
        "admin_mfa_coverage_percentage": coverage_percentage(
            sum(1 for u in admins if u["is_mfa_capable"]), len(admins)
        ),
        # A user missing from the registration report is counted as uncovered above;
        # this says how much of the denominator that assumption is carrying.
        "users_without_registration_details": sum(
            1 for u in users if not u["has_registration_details"]
        ),
        "users_never_signed_in": sum(1 for u in users if not u["last_sign_in"]),
    }


# --- collection (lazy msgraph imports; not exercised by the fixture tests) ---

async def _collect(collector: Collector, cred) -> tuple[list[dict], dict]:
    """Resolve the tenant, then read users and registration details and join them."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.users.users_request_builder import UsersRequestBuilder

        request_configuration = RequestConfiguration(
            query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=list(USER_SELECT)
            )
        )
        users = [
            project_user(u)
            for u in await paginate(
                collector, "graph.users.get", client.users, request_configuration
            )
        ]
        registrations = [
            project_registration_details(d)
            for d in await paginate(
                collector,
                "graph.reports.authenticationMethods.userRegistrationDetails.get",
                client.reports.authentication_methods.user_registration_details,
            )
        ]
        logger.info(
            "Collected %d users and %d registration-detail rows",
            len(users),
            len(registrations),
        )
        return join_users(users, registrations), tenant

    # `with_graph_client` records a construction/transport failure itself and
    # returns the default, so there is nothing left here to raise.
    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], {"tenant_source": "unresolved"})


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* and msgraph/kiota/httpx stacks log every HTTP request at INFO,
    # which buries this fetcher's own lines and would dominate the runner's stderr
    # tail. Their warnings and errors still come through.
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        users: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
    else:
        users, tenant = asyncio.run(_collect(collector, cred))

    # NOTE: no `provider_registration_status()` call here, deliberately. Graph is
    # not an ARM resource provider, so there is no namespace whose registration
    # state could distinguish "not in use" from "empty" — and an Entra tenant always
    # exists, so the ambiguity that call exists to resolve cannot arise.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={"users": users},
        summary=summarize(users),
    )

    filename = f"azure_entra_mfa_status_{tenant_filename_key(tenant)}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        logger.error(
            "Encountered %d Microsoft Graph API failure(s) during collection",
            len(collector.failures),
        )
        write_status(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
