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
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Read-only scope for every GCP fetcher — least privilege at the token level, on
# top of the read-only IAM role the setup notes define.
READ_ONLY_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


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


class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One project of five being inaccessible must not exit 0 with quietly-empty
    data (the worst failure mode for a compliance tool). Call `guard()` around
    each API interaction; failures accumulate and drive the exit code and a
    `partial_failure` flag in the payload.
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
    return {
        "metadata": {
            "project": project,
            "project_source": project_source,
            "environment": os.environ.get("GCP_ENVIRONMENT"),
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
    """Integer percentage, matching the AWS fetchers' summary math (0 when empty)."""
    return (covered * 100) // total if total > 0 else 0
