#!/usr/bin/env python3
"""
Microsoft Entra ID privileged directory roles and their members

Lists every ACTIVATED directory role in the tenant with the principals holding it,
flags the roles that carry tenant-wide administrative power, and counts the Global
Administrators — the single number most access-review controls turn on.

"Activated" is load-bearing and is why the evidence can be trusted as a complete
picture of who holds directory power: `GET /directoryRoles` returns only the roles
that have been instantiated in the tenant, which happens the first time a role is
assigned. A built-in role absent from the response therefore has no members at all,
so an empty response is genuine evidence of no directory-role assignments and not a
truncated read. (`GET /directoryRoleTemplates` would list all ~100 definitions, but
memberless, which is the opposite of what a reviewer needs.)

Ported from Prowler's
prowler/providers/azure/services/entra/entra_service.py (Apache-2.0)
`_get_directory_roles`, which makes the same two calls, and from their
entra_global_admin_in_less_than_five_users check, which likewise keys the Global
Administrator role by its display name.

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
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_privileged_roles")

# The role every access-review control names explicitly, and the one Prowler's
# entra_global_admin_in_less_than_five_users check counts.
GLOBAL_ADMINISTRATOR = "Global Administrator"

# The well-known role template id for Global Administrator. Used only as a SECOND
# way to recognize that role, never as the only one: `is_privileged_role` matches on
# the display name first, so if this constant were ever wrong the role would still
# be classified correctly rather than silently dropping out of the counts.
#
# NOTE on provenance: Prowler's prowler/providers/azure/config.py holds GUIDs for
# the ARM *RBAC* roles (Owner, Contributor, User Access Administrator, Role Based
# Access Control Administrator) — see the rbac_role_assignments fetcher, which
# reuses those verbatim. It carries no Entra *directory* role template ids, and the
# two are different id spaces. Prowler's own directory-role code matches on the
# display name, which is what this fetcher does too.
GLOBAL_ADMINISTRATOR_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Entra built-in directory roles that grant tenant-wide administrative power, by
# the display name Graph returns for them. These are the roles Microsoft documents
# as privileged: each one can either take over identities, grant itself more access,
# or read/alter the controls that protect the tenant.
#
# Matched on the display name because that is the stable, documented identifier the
# API returns for a built-in role (Graph v1.0 does not localize these), and it is
# what Prowler matches on. Each record also carries the role's `role_template_id`
# verbatim, so a reviewer or validator can pin the GUID without this list having to
# assert one.
PRIVILEGED_ROLE_NAMES = frozenset(
    {
        # --- full tenant control ---
        GLOBAL_ADMINISTRATOR,
        "Privileged Role Administrator",       # can grant any role, including GA
        "Privileged Authentication Administrator",  # can reset a GA's credentials
        # --- identity takeover ---
        "Authentication Administrator",
        "User Administrator",
        "Helpdesk Administrator",
        "Password Administrator",
        "Directory Writers",
        # --- can grant itself access via an app or a federated identity ---
        "Application Administrator",
        "Cloud Application Administrator",
        "Hybrid Identity Administrator",
        "Domain Name Administrator",
        "External Identity Provider Administrator",
        # --- controls the controls ---
        "Conditional Access Administrator",
        "Security Administrator",
        "Compliance Administrator",
        "Intune Administrator",
        # --- workload-wide data access ---
        "Exchange Administrator",
        "SharePoint Administrator",
        "Teams Administrator",
        # --- reads everything (no write, but full-tenant disclosure) ---
        "Global Reader",
        "Security Reader",
        # --- commercial control of the tenant ---
        "Billing Administrator",
        "Partner Tier2 Support",
    }
)

# Graph's @odata.type on a directory-role member, mapped to a plain principal kind.
# The members collection is typed as directoryObject, and the concrete kind only
# shows up in @odata.type — which matters because a GROUP or SERVICE PRINCIPAL
# holding a privileged role is a materially different finding from a user holding
# it: a role-assignable group moves the real access decision somewhere else, and a
# service principal has no interactive sign-in for MFA or Conditional Access to
# gate.
_MEMBER_TYPES = {
    "#microsoft.graph.user": "User",
    "#microsoft.graph.group": "Group",
    "#microsoft.graph.servicePrincipal": "ServicePrincipal",
    "#microsoft.graph.device": "Device",
    "#microsoft.graph.orgContact": "OrgContact",
}


# --- projections: the only code here that touches a Graph model ---

def project_directory_role(role) -> dict:
    """Read a `DirectoryRole` model's attributes into a flat snake_case dict.

    `members` is NOT read here: Graph does not expand it on the collection response,
    so it arrives only from the separate per-role members call and is filled in by
    `directory_role_record`.
    """
    return {
        "id": graph_attr(role, "id"),
        "role_template_id": graph_attr(role, "role_template_id"),
        "display_name": graph_attr(role, "display_name"),
        "description": graph_attr(role, "description"),
    }


def project_member(member) -> dict:
    """Read one directory-role member (a `directoryObject`) into a flat dict.

    The collection is typed as `directoryObject`, whose declared attributes are only
    `id` and `@odata.type` — but kiota deserializes each entry into its concrete
    subclass (User, Group, ServicePrincipal) based on that `@odata.type`, so
    `display_name` and `user_principal_name` are present on the object when the
    member is of a kind that has them. `graph_attr`'s None-tolerance is what lets
    one projection read all the kinds: a Group has no `user_principal_name`, and
    reading it yields None rather than raising.
    """
    return {
        "id": graph_attr(member, "id"),
        "odata_type": graph_attr(member, "odata_type"),
        "display_name": graph_attr(member, "display_name"),
        "user_principal_name": graph_attr(member, "user_principal_name"),
        "account_enabled": graph_attr(member, "account_enabled"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def member_type(odata_type: str | None) -> str:
    """Map a member's `@odata.type` to a plain principal kind.

    Falls back to the last dotted segment with its first letter upper-cased, so a
    principal kind Microsoft adds later is reported as itself rather than as
    "Unknown" — the point of this field is to say what holds the role, and losing
    that to an unmapped constant would be worse than an imperfect label.
    """
    if not odata_type:
        return "Unknown"
    mapped = _MEMBER_TYPES.get(str(odata_type))
    if mapped:
        return mapped
    tail = str(odata_type).rsplit(".", 1)[-1]
    return (tail[:1].upper() + tail[1:]) if tail else "Unknown"


def is_privileged_role(role: dict) -> bool:
    """Whether this directory role grants tenant-wide administrative power.

    Name first, template id second. The redundancy is deliberate: the display name
    is the identifier Graph documents and Prowler matches on, and the template-id
    check means the single most consequential role (Global Administrator) is still
    recognized if it ever came back under a different display name.
    """
    if (role.get("display_name") or "") in PRIVILEGED_ROLE_NAMES:
        return True
    return str(role.get("role_template_id") or "").lower() == GLOBAL_ADMINISTRATOR_TEMPLATE_ID


def member_record(member: dict) -> dict:
    """Normalize one projected member into an evidence record."""
    enabled = member.get("account_enabled")
    return {
        "id": member.get("id"),
        "principal_type": member_type(member.get("odata_type")),
        "display_name": member.get("display_name"),
        "user_principal_name": member.get("user_principal_name"),
        # Only user principals carry accountEnabled; None on a group or service
        # principal means "not applicable", not "disabled", so it is left as None
        # rather than coerced to False the way a genuinely optional bool would be.
        "account_enabled": None if enabled is None else bool(enabled),
    }


def directory_role_record(role: dict, members: list[dict]) -> dict:
    """Normalize one projected role plus its projected members into a record.

    Members are sorted by principal name so a re-run against an unchanged directory
    is byte-stable — Graph does not promise a stable member order. The key is
    lower-cased first: a user sorts by its UPN and a group or service principal by its
    display name, so a case-sensitive sort would interleave them by ASCII case (every
    capitalized group name ahead of every lower-case UPN) rather than alphabetically.
    The object id breaks ties, so the order is total.
    """
    records = sorted(
        (member_record(m) for m in members),
        key=lambda r: (
            (r.get("user_principal_name") or r.get("display_name") or "").lower(),
            r.get("id") or "",
        ),
    )
    return {
        "id": role.get("id"),
        "role_template_id": role.get("role_template_id"),
        "display_name": role.get("display_name"),
        "description": role.get("description"),
        "is_privileged": is_privileged_role(role),
        "is_global_administrator": (role.get("display_name") or "") == GLOBAL_ADMINISTRATOR
        or str(role.get("role_template_id") or "").lower() == GLOBAL_ADMINISTRATOR_TEMPLATE_ID,
        "member_count": len(records),
        "members": records,
        "user_member_count": sum(1 for r in records if r["principal_type"] == "User"),
        "group_member_count": sum(1 for r in records if r["principal_type"] == "Group"),
        "service_principal_member_count": sum(
            1 for r in records if r["principal_type"] == "ServicePrincipal"
        ),
    }


def summarize(roles: list[dict]) -> dict:
    """The Global Administrator count is the headline.

    It is the number the access-review controls (and CIS Azure 1.1.3, and Prowler's
    entra_global_admin_in_less_than_five_users) are written against, and the one
    figure that is meaningful without any further context.

    `distinct_privileged_principals` is reported alongside the raw assignment count
    because one person holding six privileged roles is one human to review, not six
    — and the two numbers diverging is itself the interesting signal.
    """
    privileged = [r for r in roles if r["is_privileged"]]
    global_admin_roles = [r for r in roles if r["is_global_administrator"]]
    privileged_principals = {
        m["id"] for r in privileged for m in r["members"] if m.get("id")
    }
    all_principals = {m["id"] for r in roles for m in r["members"] if m.get("id")}
    return {
        # Activated roles only — see the module docstring on why that is complete.
        "total_directory_roles_activated": len(roles),
        "total_role_assignments": sum(r["member_count"] for r in roles),
        "distinct_principals_with_a_directory_role": len(all_principals),
        # --- the headline ---
        "global_administrator_count": sum(r["member_count"] for r in global_admin_roles),
        "global_administrator_role_activated": bool(global_admin_roles),
        # --- privileged breadth ---
        "privileged_roles_activated": len(privileged),
        "privileged_roles_with_members": sum(1 for r in privileged if r["member_count"]),
        "privileged_role_names_assigned": sorted(
            r["display_name"] or "" for r in privileged if r["member_count"]
        ),
        "privileged_role_assignments": sum(r["member_count"] for r in privileged),
        "distinct_privileged_principals": len(privileged_principals),
        # --- what kind of principal holds the power ---
        "users_in_privileged_roles": sum(r["user_member_count"] for r in privileged),
        "groups_in_privileged_roles": sum(r["group_member_count"] for r in privileged),
        "service_principals_in_privileged_roles": sum(
            r["service_principal_member_count"] for r in privileged
        ),
        "privileged_assignment_percentage": coverage_percentage(
            sum(r["member_count"] for r in privileged), sum(r["member_count"] for r in roles)
        ),
        # An activated role with no members is a role that was assigned once and
        # revoked — worth seeing, and it keeps the denominators honest.
        "roles_with_no_members": sum(1 for r in roles if not r["member_count"]),
    }


# --- collection (lazy msgraph imports; not exercised by the fixture tests) ---

async def _collect(collector: Collector, cred) -> tuple[list[dict], dict]:
    """One directory_roles.get(), then one members.get() per role.

    The members call cannot be avoided or batched away: Graph does not return
    members on the collection response, and `$expand=members` is not supported on
    /directoryRoles. The call count is bounded by the number of ACTIVATED roles
    (single digits to low tens in practice), not by the ~100 role templates.
    """

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        projected = [
            project_directory_role(r)
            for r in await paginate(
                collector, "graph.directoryRoles.get", client.directory_roles
            )
        ]

        records = []
        for role in projected:
            role_id = role.get("id")
            if not role_id:
                collector.record(
                    "graph.directoryRoles.members.get",
                    RuntimeError(f"directory role {role.get('display_name')!r} has no id"),
                )
                continue
            members = await paginate(
                collector,
                f"graph.directoryRoles({role.get('display_name')}).members.get",
                client.directory_roles.by_directory_role_id(role_id).members,
            )
            records.append(
                directory_role_record(role, [project_member(m) for m in members])
            )

        logger.info(
            "Collected %d activated directory role(s) with %d member assignment(s)",
            len(records),
            sum(r["member_count"] for r in records),
        )
        # Sorted by display name so a re-run against an unchanged directory is
        # byte-stable; Graph does not promise a stable role order.
        return sorted(records, key=lambda r: (r.get("display_name") or "", r.get("id") or "")), tenant

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
        roles: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
    else:
        roles, tenant = asyncio.run(_collect(collector, cred))

    # NOTE: no `provider_registration_status()` call here, deliberately. Graph is
    # not an ARM resource provider, so there is no namespace whose registration
    # state could distinguish "not in use" from "empty" — and for directory roles
    # the ambiguity is already resolved: /directoryRoles returns only ACTIVATED
    # roles, so an empty response means no directory-role assignments exist.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={
            "directory_roles": roles,
            "privileged_role_names_checked": sorted(PRIVILEGED_ROLE_NAMES),
        },
        summary=summarize(roles),
    )

    filename = f"azure_entra_privileged_roles_{tenant_filename_key(tenant)}.json"
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
