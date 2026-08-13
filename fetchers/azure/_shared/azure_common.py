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


def first(obj: Optional[Dict[str, Any]], *keys: str) -> Any:
    """Return the first present, non-None value among `keys` in `obj`.

    Defensive against the snake_case spellings `Model.as_dict()` produces and the
    camelCase wire names `Model.serialize()` / raw REST responses use for the same
    field (`enable_https_traffic_only` vs `supportsHttpsTrafficOnly`), so the pure
    transforms work on whichever shape the collector hands in.
    """
    if not isinstance(obj, dict):
        return None
    for key in keys:
        val = obj.get(key)
        if val is not None:
            return val
    return None


def dig(obj: Any, *path: str) -> Any:
    """Walk a nested dict by keys, tolerating a missing link at any level."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def to_dict(model: Any) -> Dict[str, Any]:
    """Best-effort plain dict from an azure-mgmt model.

    msrest/azure-core models expose `as_dict()` (snake_case attribute keys, nested
    models recursed). Fall back to `serialize()` (camelCase wire names) and then to
    `__dict__` so a model from a differently-generated SDK still yields something
    the transforms can read via `first()`/`dig()`.
    """
    for attr in ("as_dict", "serialize"):
        fn = getattr(model, attr, None)
        if callable(fn):
            try:
                result = fn()
            except Exception:  # noqa: BLE001 — fall through to the next strategy
                continue
            if isinstance(result, dict):
                return result
    if isinstance(model, dict):
        return model
    return dict(getattr(model, "__dict__", {}) or {})


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
