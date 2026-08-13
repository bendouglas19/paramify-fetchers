#!/usr/bin/env python3
"""
KSI-MLA-03 / KSI-MLA-04 / KSI-CNA-07: Microsoft Defender for Cloud plan coverage

For one subscription, reports every Defender for Cloud pricing plan (Servers,
Storage Accounts, Containers, SQL, Key Vault, …): whether it is on the Standard
(paid, protecting) tier or Free, how much free trial is left, and which per-plan
extensions (agentless VM scanning, vulnerability assessment, file integrity
monitoring, …) are enabled. This is the evidence that vulnerability detection and
host/container hardening are actually switched on, not merely available.

Field projections are ported verbatim from Prowler's
prowler/providers/azure/services/defender/defender_service.py (Apache-2.0), which
reads the same azure-mgmt-security SDK.

"Subscription Not Registered" is VALID EVIDENCE, not a failure: it means the
Microsoft.Security resource provider was never registered on the subscription, so
Defender for Cloud is simply not in use. Reported as
`provider_registration_status: not_registered` with an exit 0 — the same
convention the AWS fetchers apply to SubscriptionRequiredException in
fetchers/aws/_shared/aws.sh ("not enabled" is a finding, not a broken run).

Single-subscription per invocation; fanout across subscriptions happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

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
    first,
    resolve_subscription,
    sanitize_for_filename,
    to_dict,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_defender_plans")

# The message Azure returns when Microsoft.Security was never registered on the
# subscription. Prowler matches this exact phrase on ResourceNotFoundError; we
# match the phrase on any exception so a differently-typed wrapper from another
# SDK version still reads as "not in use" rather than "collection failed".
PROVIDER_NOT_REGISTERED_MARKER = "subscription not registered"

# The tier that means the plan is actually protecting resources. "Free" is the
# no-op tier that every subscription has by default.
PROTECTED_TIER = "standard"

REGISTERED = "registered"
NOT_REGISTERED = "not_registered"
UNKNOWN = "unknown"


# --- pure transforms (operate on as_dict()-shaped dicts; unit-tested from fixtures) ---

def _prop(obj: dict, *names: str):
    """Read a field azure-mgmt flattens out of the wire `properties` bag."""
    val = first(obj, *names)
    if val is not None:
        return val
    nested = obj.get("properties") if isinstance(obj, dict) else None
    return first(nested, *names)


def _as_bool(value) -> bool:
    """Coerce azure-mgmt-security's STRING boolean enums to a real bool.

    `Extension.is_enabled` is typed `str` and carries the `IsEnabled` enum whose
    members are the literal strings "True" and "False" — so a plain `bool(value)`
    reports a DISABLED extension as enabled, because `bool("False") is True`. This
    is the one field in these three fetchers where Azure models a boolean as a
    string; storage/network return real JSON booleans.
    """
    if isinstance(value, bool) or value is None:
        return bool(value)
    return str(value).strip().lower() in ("true", "1", "yes", "on", "enabled")


def pricing_record(pricing: dict) -> dict:
    """Normalize one Defender plan — Prowler's exact five-field projection.

    `extensions` collapses the SDK's list of {name, is_enabled, ...} objects into a
    flat {name: bool} map, which is how Prowler's checks read it and how a reviewer
    wants to see it. `free_trial_remaining_time` is an ISO-8601 duration string
    from the SDK's serializer (a timedelta before serialization).
    """
    extensions = _prop(pricing, "extensions") or []
    return {
        "resource_id": first(pricing, "id"),
        "resource_name": first(pricing, "name"),
        "pricing_tier": _prop(pricing, "pricing_tier", "pricingTier"),
        "free_trial_remaining_time": _prop(
            pricing, "free_trial_remaining_time", "freeTrialRemainingTime"
        ),
        "extensions": {
            first(ext, "name"): _as_bool(first(ext, "is_enabled", "isEnabled"))
            for ext in extensions
            if first(ext, "name")
        },
    }


def summarize(plans: list[dict], registration_status: str) -> dict:
    """Standard-tier coverage is the headline: how many plans actually protect."""
    total = len(plans)
    standard = sum(1 for p in plans if str(p["pricing_tier"] or "").lower() == PROTECTED_TIER)
    return {
        "provider_registration_status": registration_status,
        "total_plans": total,
        "standard_tier_plans": standard,
        "free_tier_plans": total - standard,
        "standard_tier_percentage": coverage_percentage(standard, total),
        "plans_with_enabled_extensions": sum(
            1 for p in plans if any(p["extensions"].values())
        ),
        "total_enabled_extensions": sum(
            1 for p in plans for enabled in p["extensions"].values() if enabled
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def is_provider_not_registered(exc: BaseException) -> bool:
    """Is this the benign "Microsoft.Security was never registered" answer?"""
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return PROVIDER_NOT_REGISTERED_MARKER in message


def collect_pricings(subscription_id, cred, collector: Collector) -> tuple[list[dict], str]:
    """One pricings.list(scope_id=...) call; returns (plans, registration_status).

    The scope is the subscription itself. The response is a single PricingList with
    a `.value` array — not an ItemPaged — so there is nothing to paginate.
    """
    from azure.mgmt.security import SecurityCenter

    def _client():
        return SecurityCenter(credential=cred, subscription_id=subscription_id)

    client = collector.guard("security.SecurityCenter (init)", _client)
    if client is None:
        return [], UNKNOWN

    try:
        response = client.pricings.list(scope_id=f"subscriptions/{subscription_id}")
        plans = [
            pricing_record(to_dict(pricing)) for pricing in (getattr(response, "value", None) or [])
        ]
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_provider_not_registered(exc):
            # Deliberately NOT collector.record(): Defender for Cloud not being in
            # use is the finding, so this must stay exit 0 with empty plans.
            logger.warning(
                "Microsoft.Security is not registered on subscription %s — "
                "Defender for Cloud is not in use; reporting status %s",
                subscription_id,
                NOT_REGISTERED,
            )
            return [], NOT_REGISTERED
        collector.record("security.pricings.list", exc)
        return [], UNKNOWN

    return sorted(plans, key=lambda r: r.get("resource_name") or ""), REGISTERED


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which
    # buries this fetcher's own lines and would dominate the runner's stderr tail.
    # Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    plans: list[dict] = []
    registration_status = UNKNOWN
    if subscription_id and cred is not None:
        plans, registration_status = collect_pricings(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "defender_plans": plans,
            # Surfaced in results as well as summary so a validator can assert on
            # the payload's own account of whether the service is even in use.
            "provider_registration_status": registration_status,
        },
        summary=summarize(plans, registration_status),
    )

    filename = f"azure_defender_plans_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        logger.error(
            "Encountered %d Azure API failure(s) during collection", len(collector.failures)
        )
        write_status(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
