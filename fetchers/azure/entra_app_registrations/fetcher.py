#!/usr/bin/env python3
"""
Microsoft Entra ID app registration credentials and their expiry

Every app registration in the tenant with each of its client secrets and certificate
credentials, and when each one expires — so credential rotation is evidenceable per
credential rather than asserted per tenant.

The evidence that varies is `end_date_time`. Three states are distinguished, because
they are three different findings and collapsing them loses the one that matters
most:

- **expired** — a credential past its end date. Usually harmless (it no longer
  authenticates) but it is the residue of an app nobody owns.
- **expiring soon** — inside the rotation window, the only state a reviewer can still
  act on.
- **no expiry at all** — a credential with a null `endDateTime`. The worst case and
  the easiest to miss, because it never appears in an "expiring soon" report by
  construction. It is counted separately and never folded into either bucket above.

Ported from Prowler's
prowler/providers/azure/services/entra/entra_service.py (Apache-2.0)
`_get_app_registrations`, which reads the same `passwordCredentials` and
`keyCredentials` collections, and from their
entra_app_registration_credential_not_expired check, whose 30-day rotation threshold
and three-way expiry classification this reproduces.

Tenant-scoped per invocation, NOT subscription-scoped: Graph data is tenant-wide.
Fanout across tenants happens at the runner layer (see fetcher.yaml).
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
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

logger = logging.getLogger("azure_entra_app_registrations")

# Prowler's EXPIRY_WARNING_DAYS, from their
# entra_app_registration_credential_not_expired check: a credential valid for fewer
# than this many more days is inside the rotation window.
EXPIRY_WARNING_DAYS = 30

# Graph's $select projection. Projected explicitly to keep the response small — an
# app registration's full representation is large and most of it (required resource
# access, redirect URIs, optional claims) is irrelevant to credential rotation.
APP_SELECT = (
    "id",
    "appId",
    "displayName",
    "createdDateTime",
    "signInAudience",
    "passwordCredentials",
    "keyCredentials",
)

CREDENTIAL_PASSWORD = "password"
CREDENTIAL_CERTIFICATE = "certificate"


# --- projections: the only code here that touches a Graph model ---

def project_credential(cred_model, credential_type: str) -> dict:
    """Read a `PasswordCredential` or `KeyCredential` into a flat snake_case dict.

    One projection covers both because the fields that matter to rotation —
    `displayName`, `keyId`, `startDateTime`, `endDateTime` — are spelled identically
    on the two models. `usage` and `type` exist only on KeyCredential (a certificate
    can be for Sign or Verify) and read as None on a password credential.

    `secret_text` is deliberately NOT projected. Graph only ever returns it in the
    response that CREATES a secret, never on a read, but naming it here would put a
    field called `secret_text` into the evidence schema — and a reader has no way to
    know it will always be null.
    """
    return {
        "display_name": graph_attr(cred_model, "display_name"),
        "credential_type": credential_type,
        # graph_attr renders a UUID as its string form and a datetime as ISO-8601
        # with a Z, matching what Graph put on the wire.
        "key_id": graph_attr(cred_model, "key_id"),
        "start_date_time": graph_attr(cred_model, "start_date_time"),
        "end_date_time": graph_attr(cred_model, "end_date_time"),
        "usage": graph_attr(cred_model, "usage"),
        "certificate_type": graph_attr(cred_model, "type"),
    }


def project_application(app) -> dict:
    """Read an `Application` model's attributes into a flat snake_case dict.

    Both credential collections are omitted by Graph when empty rather than sent as
    `[]`, so each is read through `or []` — an app with no credentials is the common
    case (it authenticates with a federated identity credential or not at all) and
    must not raise.

    `app_id` and `id` are different identifiers and both are kept: `id` is the
    directory object id the Graph URL uses, `appId` is the client id that appears in
    sign-in logs and in whatever config file holds the secret. A reviewer chasing a
    credential needs the latter.
    """
    return {
        "id": graph_attr(app, "id"),
        "app_id": graph_attr(app, "app_id"),
        "display_name": graph_attr(app, "display_name"),
        "created_date_time": graph_attr(app, "created_date_time"),
        "sign_in_audience": graph_attr(app, "sign_in_audience"),
        "credentials": [
            project_credential(c, CREDENTIAL_PASSWORD)
            for c in (getattr(app, "password_credentials", None) or [])
        ]
        + [
            project_credential(c, CREDENTIAL_CERTIFICATE)
            for c in (getattr(app, "key_credentials", None) or [])
        ],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _parse_timestamp(value) -> datetime | None:
    """Parse an ISO-8601 timestamp back to an aware datetime, or None.

    The projection has already rendered Graph's datetimes to strings (so the evidence
    carries the wire format rather than a Python repr), and the expiry arithmetic
    needs them back as datetimes. Naive values are assumed UTC — Graph always sends
    UTC, and Prowler makes the same assumption explicitly.

    Returns None for anything unparseable rather than raising: one malformed
    timestamp must not abort collection of every other credential, and a None here
    lands in `credentials_without_expiry`, which is the conservative bucket.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def credential_record(cred: dict, now: datetime) -> dict:
    """Classify one projected credential against `now`.

    `now` is passed in rather than read here so every credential in a run is judged
    against ONE instant — otherwise two credentials with the same end date could land
    in different buckets, and the transform would not be testable.

    The three states are mutually exclusive and `has_expiry` keeps the null case
    distinguishable from a date: `expired` and `expiring_soon` are both False for a
    never-expiring credential, so a reader who checks only those two flags would see
    a clean record. That is exactly why `has_expiry` is not omitted as redundant.
    """
    end = _parse_timestamp(cred.get("end_date_time"))
    if end is None:
        days_until_expiry = None
        expired = False
        expiring_soon = False
    else:
        # Truncating toward zero matches Prowler's `(end - now).days`.
        days_until_expiry = (end - now).days
        expired = end <= now
        expiring_soon = not expired and days_until_expiry <= EXPIRY_WARNING_DAYS

    return {
        "display_name": cred.get("display_name") or None,
        "credential_type": cred.get("credential_type"),
        "key_id": cred.get("key_id"),
        "start_date_time": cred.get("start_date_time"),
        "end_date_time": cred.get("end_date_time"),
        "usage": cred.get("usage"),
        "certificate_type": cred.get("certificate_type"),
        "has_expiry": end is not None,
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "rotation_threshold_days": EXPIRY_WARNING_DAYS,
        # The single field a validator can assert on: True only when the credential
        # has an expiry date that is further out than the rotation threshold.
        "healthy": end is not None and not expired and not expiring_soon,
    }


def application_record(app: dict, now: datetime) -> dict:
    """Normalize one projected application and classify all of its credentials.

    Credentials are sorted by end date (nulls last, then by key id) so a re-run
    against an unchanged tenant is byte-stable and the soonest expiry reads first.
    """
    credentials = [credential_record(c, now) for c in (app.get("credentials") or [])]
    credentials.sort(
        key=lambda c: (
            c["end_date_time"] is None,
            c["end_date_time"] or "",
            c["key_id"] or "",
        )
    )
    return {
        "id": app.get("id"),
        "app_id": app.get("app_id"),
        "display_name": app.get("display_name"),
        "created_date_time": app.get("created_date_time"),
        "sign_in_audience": app.get("sign_in_audience"),
        # Multi-tenant and personal-account audiences widen who can authenticate to
        # the app, so a leaked credential on one of those reaches further.
        "is_single_tenant": str(app.get("sign_in_audience") or "") == "AzureADMyOrg",
        "credential_count": len(credentials),
        "password_credential_count": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_PASSWORD
        ),
        "certificate_credential_count": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_CERTIFICATE
        ),
        "credentials": credentials,
        "has_expired_credential": any(c["expired"] for c in credentials),
        "has_credential_expiring_soon": any(c["expiring_soon"] for c in credentials),
        "has_credential_without_expiry": any(not c["has_expiry"] for c in credentials),
        # An app with no credentials at all is compliant by construction, not by
        # rotation — see the summary, which excludes it from the percentage.
        "has_credentials": bool(credentials),
        "all_credentials_healthy": bool(credentials) and all(c["healthy"] for c in credentials),
    }


def summarize(apps: list[dict]) -> dict:
    """Rotation compliance is measured over CREDENTIALS, not over apps.

    An app with one healthy secret and one that expired two years ago is not half
    compliant — it has one credential to clean up. Counting credentials is also what
    makes the percentage stable when an app is deleted along with its five stale
    secrets.

    The denominator excludes apps with no credentials entirely (Prowler skips them
    too): an app that authenticates with a federated identity credential has nothing
    to rotate, and counting it as compliant would let a tenant improve its score by
    registering unused apps.
    """
    credentials = [c for a in apps for c in a["credentials"]]
    healthy = sum(1 for c in credentials if c["healthy"])
    return {
        "total_app_registrations": len(apps),
        "apps_with_credentials": sum(1 for a in apps if a["has_credentials"]),
        "apps_without_credentials": sum(1 for a in apps if not a["has_credentials"]),
        "multi_tenant_apps": sum(1 for a in apps if not a["is_single_tenant"]),
        # --- credential inventory ---
        "total_credentials": len(credentials),
        "password_credentials": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_PASSWORD
        ),
        "certificate_credentials": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_CERTIFICATE
        ),
        # --- the three expiry states, kept separate ---
        "expired_credentials": sum(1 for c in credentials if c["expired"]),
        "credentials_expiring_soon": sum(1 for c in credentials if c["expiring_soon"]),
        "credentials_without_expiry": sum(1 for c in credentials if not c["has_expiry"]),
        "healthy_credentials": healthy,
        "rotation_threshold_days": EXPIRY_WARNING_DAYS,
        "credential_rotation_compliance_percentage": coverage_percentage(
            healthy, len(credentials)
        ),
        # --- rolled up per app, for chasing owners ---
        "apps_with_expired_credentials": sum(1 for a in apps if a["has_expired_credential"]),
        "apps_with_credentials_expiring_soon": sum(
            1 for a in apps if a["has_credential_expiring_soon"]
        ),
        "apps_with_credentials_without_expiry": sum(
            1 for a in apps if a["has_credential_without_expiry"]
        ),
        "apps_with_all_credentials_healthy": sum(1 for a in apps if a["all_credentials_healthy"]),
    }


# --- collection (lazy msgraph imports; not exercised by the fixture tests) ---

async def _collect(collector: Collector, cred, now: datetime) -> tuple[list[dict], dict]:
    """One applications.get() with a $select projection, paged to the end."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.applications.applications_request_builder import (
            ApplicationsRequestBuilder,
        )

        request_configuration = RequestConfiguration(
            query_parameters=ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                select=list(APP_SELECT)
            )
        )
        apps = [
            application_record(project_application(a), now)
            for a in await paginate(
                collector,
                "graph.applications.get",
                client.applications,
                request_configuration,
            )
        ]
        logger.info(
            "Collected %d app registration(s) with %d credential(s)",
            len(apps),
            sum(a["credential_count"] for a in apps),
        )
        # Sorted by display name so a re-run against an unchanged tenant is
        # byte-stable; Graph does not promise a stable application order.
        return (
            sorted(apps, key=lambda a: (a.get("display_name") or "", a.get("id") or "")),
            tenant,
        )

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

    # One instant for the whole run, so every credential is judged against the same
    # "now" and two credentials sharing an end date cannot land in different buckets.
    now = datetime.now(timezone.utc)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        apps: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
    else:
        apps, tenant = asyncio.run(_collect(collector, cred, now))

    # NOTE: no `provider_registration_status()` call here, deliberately. Graph is
    # not an ARM resource provider, so there is no namespace whose registration
    # state could distinguish "not in use" from "empty" — and a tenant with no app
    # registrations genuinely has none, which is unambiguous.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={"app_registrations": apps, "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
        summary=summarize(apps),
    )

    filename = f"azure_entra_app_registrations_{tenant_filename_key(tenant)}.json"
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
