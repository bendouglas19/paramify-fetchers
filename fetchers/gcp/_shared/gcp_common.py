"""Shared helpers for the GCP evidence fetchers.

Every GCP fetcher follows the same shape (mirroring the AWS category's
`_shared/aws.sh`): resolve the target project from ADC, collect one evidence
set, wrap it in a deterministic payload with a small metadata block, and exit
non-zero if any API call failed so a partial failure never looks like success.

Nothing here imports a Google client library — the heavy `google.*` imports are
kept lazy inside each fetcher's `collect_*()` so the pure transform functions
(and their tests) import with only the standard library present.

Design notes:
- **Auth is ADC only.** `google.auth.default()` resolves the credential and the
  default project. No secret is declared or read; see fetchers/_categories/gcp.yaml
  for the resolution order and why GOOGLE_APPLICATION_CREDENTIALS is deliberately
  not wired.
- **`environment`** is read from GCP_ENVIRONMENT (set per target in the manifest)
  and written into the payload's metadata block. The runner-built envelope does
  not carry an `environment` field, so it lives in the payload — see the module
  README / SETUP notes for the rationale.
- **Determinism.** Resource lists are sorted by a stable identifier and the file
  is written with sort_keys=True, so a re-run with unchanged infra is byte-stable
  and regex validators stay quiet.
- **Failure reporting.** A non-zero exit says *that* collection failed;
  `write_status()` says *why* (see docs/fetcher_contract.md § Output). Without it
  the runner falls back to the tail of stderr — which, on the way out, is the
  "Evidence saved to ..." INFO line.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Read-only scope for every GCP fetcher — least privilege at the token level, on
# top of the read-only IAM role the setup notes define.
READ_ONLY_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]

# The failure categories the runner accepts in the `code` field of the status
# file. Exit codes stay binary (0 / non-zero), so the category lives here rather
# than carving up an exit-code space shared with the shell and signals.
STATUS_CODES = (
    "auth_failed",
    "not_authorized",
    "target_unreachable",
    "rate_limited",
    "bad_config",
    "partial_failure",
    "internal_error",
)


def current_timestamp() -> str:
    """UTC, second-resolution, Z-suffixed — matches the AWS fetchers' format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a per-target output filename."""
    sanitized = (value or "").replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized) or "unknown"


def basename(resource_url: Optional[str]) -> Optional[str]:
    """Last path segment of a GCP self-link / partial URL.

    Compute returns fully-qualified URLs for `zone`, `type`, `sourceDisk`, etc.
    (e.g. ".../zones/us-central1-a"); the human-meaningful part is the tail. KMS
    key `name` values are already relative resource paths and are left whole by
    callers that want the full path.
    """
    if not resource_url:
        return resource_url
    return resource_url.rstrip("/").rsplit("/", 1)[-1]


def first(obj: Optional[Dict[str, Any]], *keys: str) -> Any:
    """Return the first present, non-None value among `keys` in `obj`.

    Defensive against camelCase (REST / Compute / KMS `to_dict`) vs snake_case
    (gcloud-reformatted samples, some client serializers) spellings of the same
    field, so the pure transforms work on whichever shape the collector hands in.
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


def _spellings(key: str) -> Tuple[str, ...]:
    """`key` plus its camelCase and snake_case counterparts, deduplicated."""
    parts = key.split("_")
    camel = parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()
    return tuple(dict.fromkeys((key, camel, snake)))


def dig_any(obj: Any, *path: str) -> Any:
    """`dig()` that tolerates camelCase or snake_case at every level.

    GAPIC `to_dict()` emits snake_case; the REST/discovery APIs (and captured
    gcloud samples) emit camelCase. The encryption fetchers spell both variants
    by hand because their resources are one or two levels deep; the GKE and
    logging resources are deep enough (`private_cluster_config.
    enable_private_nodes`, `cmek_settings.kms_key_name`) that doing so stops
    being readable.
    """
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        for variant in _spellings(key):
            if variant in cur:
                cur = cur[variant]
                break
        else:
            return None
    return cur


def _one_line(text: Any, limit: int = 800) -> str:
    """Collapse to a single bounded line.

    Google API errors are routinely multi-line (a gRPC status block, a "go enable
    this API" URL on its own line). The status file's `error` is a one-line
    reason, so the collapse happens here rather than at each call site.
    """
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def write_status(error: str, code: Optional[str] = None) -> None:
    """Tell the runner WHY this invocation failed, via $FETCHER_STATUS_FILE.

    The runner masks any injected secret out of what we write and puts it in the
    envelope's `metadata.error` — the field Paramify shows whoever is triaging a
    failed collection. Skip it and the runner falls back to the *tail* of stderr,
    so the last thing logged becomes the reported reason: for these fetchers that
    is the "Evidence saved to ..." INFO line, i.e. a failed run reporting a
    success message as its cause.

    `error` is the required one-line reason; `code` is an optional category from
    STATUS_CODES. Writing is a silent no-op when the env var is unset (running a
    fetcher by hand), which is also why nothing here depends on the runner.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    body: Dict[str, Any] = {"error": _one_line(error)}
    if code:
        body["code"] = code
    Path(path).write_text(json.dumps(body))


# Substrings that map a recorded failure onto a STATUS_CODES category, matched
# against "<exception type> <message>" lowercased. First hit wins, so the order
# is deliberate: a 403 raised while refreshing a token is an auth problem, not a
# missing IAM permission.
_FAILURE_SIGNATURES = (
    ("auth_failed", (
        "defaultcredentialserror", "refresherror", "invalid_grant", "invalid_client",
        "unauthorized_client", "reauthentication", "unauthenticated",
        "could not automatically determine credentials",
        "invalid authentication credentials",
        # gRPC wraps a credential refresh failure as an UNAVAILABLE from the auth
        # plugin, so the 503 has to be read past to reach the real cause.
        "getting metadata from plugin failed",
        "401",
    )),
    ("not_authorized", (
        "permissiondenied", "forbidden", "403", "does not have permission",
        "caller does not have", "iam_permission_denied",
    )),
    ("rate_limited", (
        "resourceexhausted", "toomanyrequests", "429", "quota exceeded", "ratelimitexceeded",
    )),
    ("target_unreachable", (
        "serviceunavailable", "deadlineexceeded", "connectionerror", "timeout", "timed out",
        "name resolution", "getaddrinfo", "503", "504",
    )),
    ("bad_config", ("invalidargument", "badrequest", "notfound", "no project id", "400")),
)

# How much accumulated detail goes into the one-line reason. The runner truncates
# at 4000 chars; this keeps the line legible in a UI cell. Only the first few
# failures are spelled out — the leading count says how many there were, and the
# full ledger is in the payload's api_failures.
_MAX_REPORTED_FAILURES = 3
_MAX_REPORTED_MESSAGE_CHARS = 200


def _failure_code(failure: Dict[str, str]) -> str:
    blob = f"{failure.get('type', '')} {failure.get('message', '')}".lower()
    for code, signatures in _FAILURE_SIGNATURES:
        if any(sig in blob for sig in signatures):
            return code
    return "internal_error"


def service_disabled(exc: BaseException) -> bool:
    """True when the API itself was never enabled on this project.

    GCP does not answer "no such resources" for a service a project has never
    used — it 403s with SERVICE_DISABLED. A project with no GKE clusters usually
    has container.googleapis.com off, and that is evidence ("this project runs no
    GKE"), not a collection failure; the AWS fetchers reached the same conclusion
    about SubscriptionRequiredException. Pass as `guard(tolerate=...)`.
    """
    text = f"{type(exc).__name__} {exc}".lower()
    return any(
        marker in text
        for marker in (
            "service_disabled",
            "accessnotconfigured",
            "has not been used in project",
            "api is not enabled",
        )
    )


def access_denied(exc: BaseException) -> bool:
    """True for a 403 / permission error.

    Tolerable only for reads *above* the project — an organization- or
    folder-level sink lookup that a project-scoped read-only role is not expected
    to be granted. Never tolerate it for a project-scoped call: there, a 403 is a
    missing permission the operator has to fix, which is exactly what exiting
    non-zero is for.
    """
    text = f"{type(exc).__name__} {exc}".lower()
    return any(marker in text for marker in ("permissiondenied", "forbidden", "403"))


class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One project of five being inaccessible must not exit 0 with quietly-empty
    data (the worst failure mode for a compliance tool). Call `guard()` around
    each API interaction; failures accumulate and drive the exit code, a
    `partial_failure` flag in the payload, and the reason reported to the runner
    via `failure_report()` + `write_status()`.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.failures: List[Dict[str, str]] = []
        self.skipped: List[Dict[str, str]] = []

    def record(self, operation: str, exc: BaseException) -> None:
        self.failures.append(
            {"operation": operation, "type": type(exc).__name__, "message": str(exc)}
        )
        self.logger.error("API call failed: %s (%s: %s)", operation, type(exc).__name__, exc)

    def skip(self, operation: str, exc: BaseException) -> None:
        """Record a call that failed for a reason that is itself evidence.

        Kept out of `failures` so it doesn't set partial_failure or the exit
        code, but still written into the payload (metadata.skipped_calls) — a
        silently absent result is the failure mode this whole module avoids.
        """
        self.skipped.append(
            {"operation": operation, "type": type(exc).__name__, "message": _one_line(exc)}
        )
        self.logger.warning(
            "Skipping %s — not a collection failure (%s: %s)",
            operation, type(exc).__name__, _one_line(exc, 200),
        )

    def guard(
        self,
        operation: str,
        fn: Callable[[], Any],
        default: Any = None,
        tolerate: Optional[Callable[[BaseException], bool]] = None,
    ) -> Any:
        """Run `fn()`, recording (not raising) any exception; returns `default`.

        `tolerate` is an optional predicate over the exception — when it matches,
        the call is `skip()`ped instead of failed (see `service_disabled` /
        `access_denied`).
        """
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
            if tolerate is not None and tolerate(exc):
                self.skip(operation, exc)
            else:
                self.record(operation, exc)
            return default

    @property
    def ok(self) -> bool:
        return not self.failures

    def failure_report(self) -> Tuple[str, str]:
        """The one-line reason + STATUS_CODES category for `write_status()`.

        Summarizing here keeps every GCP fetcher's failure path identical.
        Failures that all classify the same way report that cause — expired ADC
        takes down every call in the run, and telling the operator `auth_failed`
        beats telling them `partial_failure`. A run with disagreeing causes has no
        single answer, so it reports `partial_failure` and leaves the detail to
        the reason line and the payload's api_failures ledger.
        """
        codes = {_failure_code(f) for f in self.failures}
        code = codes.pop() if len(codes) == 1 else "partial_failure"

        detail = "; ".join(
            f"{f['operation']} ({f['type']}: {f['message'][:_MAX_REPORTED_MESSAGE_CHARS]})"
            for f in self.failures[:_MAX_REPORTED_FAILURES]
        )
        noun = "call" if len(self.failures) == 1 else "calls"
        return _one_line(f"{len(self.failures)} GCP API {noun} failed: {detail}"), code


def resolve_project(collector: Collector) -> Dict[str, Optional[str]]:
    """Resolve the project to collect from.

    Explicit GOOGLE_CLOUD_PROJECT (set by the runner from a target) wins; else
    fall back to the ADC default project ("collect where deployed"). Returns the
    project id and where it came from, for the metadata block.
    """
    explicit = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT")
    if explicit:
        return {"project": explicit, "project_source": "target"}

    def _adc_project() -> Optional[str]:
        import google.auth  # lazy

        _creds, project = google.auth.default(scopes=READ_ONLY_SCOPES)
        return project

    project = collector.guard("google.auth.default (resolve project)", _adc_project)
    return {"project": project, "project_source": "adc_default" if project else "unresolved"}


def credentials():
    """ADC credentials scoped read-only. Lazy import so tests don't need google."""
    import google.auth  # lazy

    creds, _project = google.auth.default(scopes=READ_ONLY_SCOPES)
    return creds


def build_payload(
    *,
    project: Optional[str],
    project_source: str,
    collector: Collector,
    results: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble the raw evidence dict the runner will wrap in an envelope.

    `environment` comes from GCP_ENVIRONMENT (manifest target/config). The
    envelope adds fetcher_name/version/status/target; this metadata block adds
    the GCP-specific context the AWS fetchers keep too (their profile/region/
    account_id).
    """
    metadata: Dict[str, Any] = {
        "project": project,
        "project_source": project_source,
        "environment": os.environ.get("GCP_ENVIRONMENT"),
        "datetime": current_timestamp(),
        # Explicit so a validator can assert on it, and so a partially-failed
        # run is legible from the payload alone, not only the envelope status.
        "partial_failure": not collector.ok,
        "api_failures": collector.failures,
    }
    # Only present when something was actually tolerated (an API not enabled on
    # the project, an org-level read outside a project-scoped role), so a fetcher
    # that never calls guard(tolerate=...) keeps its payload byte-for-byte.
    if collector.skipped:
        metadata["skipped_calls"] = collector.skipped
    return {"metadata": metadata, "results": results, "summary": summary}


def write_evidence(output_dir: Path, filename: str, evidence: Dict[str, Any]) -> Path:
    """Write the evidence dict deterministically (sorted keys, stable ordering)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True, default=str)
    return path


def coverage_percentage(covered: int, total: int) -> int:
    """Integer percentage, matching the AWS fetchers' summary math (0 when empty)."""
    return (covered * 100) // total if total > 0 else 0
