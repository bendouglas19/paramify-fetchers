"""Shared helpers for the Azure evidence fetchers.

Every Azure fetcher follows the same shape (mirroring the GCP category's
`_shared/gcp_common.py` and the AWS category's `_shared/aws.sh`): resolve the
target subscription from the ambient credential, collect one evidence set, wrap
it in a deterministic payload with a small metadata block, and exit non-zero if
any API call failed so a partial failure never looks like success.

Nothing here imports an Azure SDK at module scope — the heavy `azure.*` imports
are kept lazy inside `credential()` / `resolve_subscription()` and inside each
fetcher's `collect_*()`, so the pure transform functions (and their tests) import
with only the standard library present.

Design notes:
- **SDK models are read by attribute, never via `as_dict()`.** Each fetcher has one
  projection function per resource type that turns an azure-mgmt model into a flat
  snake_case dict; every transform downstream is pure dict-in/dict-out. See
  `model_attr()` below for why attribute access is the portable choice.
- **Auth is the ambient credential chain only.** `DefaultAzureCredential()`
  resolves the token; no secret is declared or read. See
  fetchers/_categories/azure.yaml for the resolution order and which env vars the
  runner lets through for each path.
- **`environment`** is read from AZURE_ENVIRONMENT (set per target in the
  manifest) and written into the payload's metadata block. The runner-built
  envelope does not carry an `environment` field, so it lives in the payload.
- **Determinism.** Resource lists are sorted by a stable identifier and the file
  is written with sort_keys=True, so a re-run with unchanged infra is byte-stable
  and regex validators stay quiet.
- **`write_status()`** is the failure-reason channel. When a fetcher exits
  non-zero the runner reads `$FETCHER_STATUS_FILE` for the reason; without it
  `metadata.error` falls back to the tail of stderr, which turns a final
  "Evidence saved to ..." INFO line into the reported failure reason.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# The contract's closed set of failure categories for $FETCHER_STATUS_FILE's
# optional `code`. Exit codes stay binary (0 / non-zero); the category goes here.
STATUS_CODES = frozenset(
    {
        "auth_failed",
        "not_authorized",
        "target_unreachable",
        "rate_limited",
        "bad_config",
        "partial_failure",
        "internal_error",
    }
)

_STATUS_LOGGER = logging.getLogger("azure_common")


def current_timestamp() -> str:
    """UTC, second-resolution, Z-suffixed — matches the AWS/GCP fetchers' format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a per-target output filename."""
    sanitized = (value or "").replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized) or "unknown"


def basename(resource_id: Optional[str]) -> Optional[str]:
    """Last segment of an ARM resource ID.

    ARM IDs are long ("/subscriptions/<sub>/resourceGroups/rg/providers/
    Microsoft.Network/networkSecurityGroups/nsg1"); the human-meaningful part is
    the tail. Full IDs are still kept alongside the short name wherever the
    evidence needs to be joined back to a resource.
    """
    if not resource_id:
        return resource_id
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def resource_group_from_id(resource_id: Optional[str]) -> Optional[str]:
    """Pull the resource group out of an ARM resource ID.

    `.../resourceGroups/<rg>/providers/...` -> `<rg>`. Returns None when the ID
    has no resource-group segment (subscription-scoped resources) or is absent.
    Centralized because nearly every Azure evidence record needs it: the SDK's
    per-resource-group getters (blob_services.get_service_properties, ...) take
    the group name but `list()` only hands back the composite ID.

    The segment is matched case-insensitively — ARM is inconsistent about
    `resourceGroups` vs `resourcegroups` across services and API versions.
    """
    if not resource_id:
        return None
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1] or None
    return None


def dig(obj: Any, *path: str) -> Any:
    """Walk a nested dict by keys, tolerating a missing link at any level."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


# --------------------------------------------------------------------------- #
# The SDK boundary: reading azure-mgmt model objects
# --------------------------------------------------------------------------- #
#
# Each fetcher has ONE projection function per resource type that reads the SDK
# model's attributes into a flat snake_case dict; everything downstream is a pure
# dict-in/dict-out transform. `model_attr` is the single primitive those
# projections are built from.
#
# Why attributes and not `as_dict()`: the azure-mgmt packages are not all on the
# same code generator, and `as_dict()` is where that shows.
#   - azure-mgmt-storage 25.x / azure-mgmt-network 31.x use the newer
#     `_model_base` runtime, whose `as_dict()` emits the WIRE shape — camelCase
#     keys nested under "properties" (NSG rules nested twice).
#   - azure-mgmt-security 7.0.0 is still on the msrest generator, whose
#     `as_dict()` emits FLAT snake_case.
# Attribute access is snake_case and flat on BOTH: the msrest generator flattens
# `properties.*` onto the model, and the `_model_base` generator emits a
# `__getattr__` that forwards the same flattened names to `self.properties`
# (returning None when `properties` is absent). So `account.encryption.key_source`
# reads identically on either generator — which is why Prowler reads models this
# way — and no camelCase/nesting tolerance is needed anywhere.

def model_attr(model: Any, name: str) -> Any:
    """Read ONE attribute off an azure-mgmt model, normalized to a plain value.

    Deliberately takes a single name: there are no alternate spellings to try and
    no `properties` bag to fall back into. Two normalizations happen here because
    this is the boundary where the SDK's own types stop:

    - **Absent reads as None.** Returns None when `model` is None or has no such
      attribute, so a nested model the API omitted (`encryption`, `key_policy`,
      `protocol_settings`) doesn't raise partway down a projection.
    - **Enum members unwrap to their wire string.** azure-mgmt types many fields
      as `str` enums (`KeySource`, `SecurityRuleProtocol`, `MinimumTlsVersion`).
      They compare equal to their value, but `str()` renders them as
      "KeySource.MICROSOFT_KEYVAULT", not "Microsoft.Keyvault" — which would
      silently break a downstream `str(...).lower()` comparison and put an enum
      repr in the evidence. `as_dict()` used to do this unwrapping for us.
    """
    value = getattr(model, name, None)
    return value.value if isinstance(value, Enum) else value


class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One subscription of five being inaccessible must not exit 0 with quietly-empty
    data (the worst failure mode for a compliance tool). Call `guard()` around each
    API interaction; failures accumulate and drive the exit code, a
    `partial_failure` flag in the payload, and the `$FETCHER_STATUS_FILE` reason.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.failures: List[Dict[str, str]] = []

    def record(self, operation: str, exc: BaseException) -> None:
        self.failures.append(
            {"operation": operation, "type": type(exc).__name__, "message": str(exc)}
        )
        self.logger.error("API call failed: %s (%s: %s)", operation, type(exc).__name__, exc)

    def guard(self, operation: str, fn: Callable[[], Any], default: Any = None) -> Any:
        """Run `fn()`, recording (not raising) any exception; returns `default`."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
            self.record(operation, exc)
            return default

    @property
    def ok(self) -> bool:
        return not self.failures


# --------------------------------------------------------------------------- #
# Failure classification for $FETCHER_STATUS_FILE's `code`
# --------------------------------------------------------------------------- #

# Matched against the recorded exception type name, then its message. Ordered
# most-specific-first; the first matching category wins across ALL failures so a
# run whose real problem is "the credential never resolved" doesn't get reported
# as a generic partial_failure.
_CODE_RULES = (
    (
        "auth_failed",
        ("clientauthenticationerror", "credentialunavailableerror", "chainedtokencredential"),
        ("authenticationfailed", "aadsts", "defaultazurecredential failed", "invalid_client",
         "no credential", "unable to get authority", "token request failed"),
    ),
    (
        "not_authorized",
        ("permissionerror",),
        ("authorizationfailed", "does not have authorization", "forbidden", "(403)",
         "insufficient privileges", "not authorized"),
    ),
    (
        "rate_limited",
        (),
        ("toomanyrequests", "(429)", "rate limit", "throttl"),
    ),
    (
        "target_unreachable",
        ("servicerequesterror", "servicerequesttimeouterror", "connectionerror",
         "timeouterror", "sslerror"),
        ("failed to establish a new connection", "name or service not known",
         "temporary failure in name resolution", "connection aborted", "timed out",
         "getaddrinfo", "max retries exceeded", "(503)", "(504)"),
    ),
    (
        "bad_config",
        (),
        ("subscriptionnotfound", "invalidsubscriptionid", "invalid subscription",
         "is not a valid subscription", "no subscription"),
    ),
    (
        # A missing azure-mgmt-* dependency is our fault, not the customer's
        # config — it must not masquerade as bad_config.
        "internal_error",
        ("modulenotfounderror", "importerror"),
        (),
    ),
)


def classify_failure_code(failures: List[Dict[str, str]]) -> str:
    """Map recorded failures onto the contract's `code` enum.

    Exit codes stay binary per the contract, so this is the only place the
    category is decided. Falls back to `partial_failure` — the honest answer when
    some calls worked and something else didn't in a way we can't name.
    """
    if not failures:
        return "partial_failure"
    types = {(f.get("type") or "").lower() for f in failures}
    messages = " ".join((f.get("message") or "").lower() for f in failures)
    for code, type_markers, message_markers in _CODE_RULES:
        if any(marker in t for t in types for marker in type_markers):
            return code
        if any(marker in messages for marker in message_markers):
            return code
    return "partial_failure"


def failure_reason(failures: List[Dict[str, str]], limit: int = 300) -> str:
    """One-line human-readable reason for `write_status`, from recorded failures.

    Names the first failure's operation and exception, which is what an operator
    needs to know where to look; the full set stays in the payload's
    `metadata.api_failures`. Truncation is marked so a clipped Azure error (they run
    to many lines) can't be mistaken for the whole message.
    """
    if not failures:
        return "collection failed"
    worst = failures[0]
    detail = " ".join((worst.get("message") or "").split())
    if len(detail) > limit:
        detail = detail[:limit].rstrip() + " ..."
    return (
        f"{len(failures)} Azure API failure(s); first: "
        f"{worst.get('operation')}: {worst.get('type')}: {detail}"
    )


def write_status(error: str, code: Optional[str] = None) -> None:
    """Write the failure reason to `$FETCHER_STATUS_FILE`, if the runner set one.

    The runner reads this file to fill `metadata.error` on a failed invocation.
    Without it the error falls back to the tail of stderr, which reports the last
    log line (often a harmless INFO) as the cause. Silently a no-op when the env
    var is unset, so a direct `python fetcher.py` invocation is unaffected.

    `error` is collapsed to one line. `code` must be one of STATUS_CODES; an
    unrecognized value is dropped rather than written, keeping the channel
    well-formed for the runner.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    one_line = " ".join(str(error).split()) or "collection failed"
    status: Dict[str, str] = {"error": one_line}
    if code is not None:
        if code in STATUS_CODES:
            status["code"] = code
        else:
            _STATUS_LOGGER.warning("dropping unrecognized status code %r", code)
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(status, f, sort_keys=True)
    except OSError as exc:
        # Never let the status channel be the thing that fails the run — the
        # non-zero exit code is still the authoritative signal.
        _STATUS_LOGGER.warning("could not write FETCHER_STATUS_FILE %s: %s", path, exc)


# --------------------------------------------------------------------------- #
# Auth / subscription resolution
# --------------------------------------------------------------------------- #

def credential():
    """DefaultAzureCredential. Lazy import so tests don't need the Azure SDK."""
    from azure.identity import DefaultAzureCredential  # lazy

    return DefaultAzureCredential()


def resolve_subscription(collector: Collector) -> Dict[str, Optional[str]]:
    """Resolve the subscription to collect from.

    Explicit AZURE_SUBSCRIPTION_ID (set by the runner from a target) wins; else
    discover the first *enabled* subscription the ambient credential can see
    ("collect where deployed"). Returns the subscription id and where it came
    from, for the metadata block.
    """
    explicit = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if explicit:
        return {"subscription_id": explicit, "subscription_source": "target"}

    def _discover() -> Optional[str]:
        from azure.mgmt.subscription import SubscriptionClient  # lazy

        client = SubscriptionClient(credential())
        for sub in client.subscriptions.list():
            # SubscriptionState serializes as "Enabled"; the enum's repr is
            # "SubscriptionState.ENABLED". Both contain "enabled"; "Disabled",
            # "Warned", "PastDue" and "Deleted" do not.
            if "enabled" in str(getattr(sub, "state", "")).lower():
                return getattr(sub, "subscription_id", None)
        return None

    subscription_id = collector.guard("subscription.subscriptions.list", _discover)
    return {
        "subscription_id": subscription_id,
        "subscription_source": "ambient_default" if subscription_id else "unresolved",
    }


# --------------------------------------------------------------------------- #
# Payload assembly / output
# --------------------------------------------------------------------------- #

def build_payload(
    *,
    subscription_id: Optional[str],
    subscription_source: str,
    collector: Collector,
    results: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble the raw evidence dict the runner will wrap in an envelope.

    `environment` comes from AZURE_ENVIRONMENT (manifest target/config). The
    envelope adds fetcher_name/version/status/target; this metadata block adds the
    Azure-specific context the AWS fetchers keep too (their profile/region/
    account_id).
    """
    return {
        "metadata": {
            "subscription_id": subscription_id,
            "subscription_source": subscription_source,
            "environment": os.environ.get("AZURE_ENVIRONMENT"),
            "datetime": current_timestamp(),
            # Explicit so a validator can assert on it, and so a partially-failed
            # run is legible from the payload alone, not only the envelope status.
            "partial_failure": not collector.ok,
            "api_failures": collector.failures,
        },
        "results": results,
        "summary": summary,
    }


def write_evidence(output_dir: Path, filename: str, evidence: Dict[str, Any]) -> Path:
    """Write the evidence dict deterministically (sorted keys, stable ordering)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True, default=str)
    return path


def coverage_percentage(covered: int, total: int) -> int:
    """Integer percentage, matching the AWS/GCP fetchers' summary math (0 when empty)."""
    return (covered * 100) // total if total > 0 else 0
