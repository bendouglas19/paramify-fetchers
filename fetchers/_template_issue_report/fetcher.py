#!/usr/bin/env python3
"""
<short title>: pull the <tool> <report kind> report.

<One paragraph: which report this pulls, over what scope, and how often the tool
regenerates it.>

THE ONE RULE: write the tool's bytes to disk exactly as received. No parsing, no
re-serializing, no added fields. Paramify's assessment intake parses the vendor's
own format, so a "helpful" normalization here is a broken import there. If you
find yourself calling json.dump or csv.writer, this should probably be an
evidence fetcher instead — see ../_template/.
"""

import json
import logging
import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

logger = logging.getLogger("<category>_<short_name>")

# Big enough for a real export: a full vulnerability scan is routinely hundreds
# of megabytes, and many tools generate the report on demand when you ask.
_TIMEOUT = 300


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the sidecar's error field.

    Call this on every path that returns non-zero. Without it the runner falls
    back to the tail of stderr, which is whatever you logged last. `code` is a
    machine-readable category (auth_failed, not_authorized, not_enabled,
    target_unreachable, rate_limited, bad_config, partial_failure).
    See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def target_suffix() -> str:
    """This invocation's fanout target as a filename-safe suffix ("" if single-run).

    ONE FILENAME PER INVOCATION. Every target of a fanout run writes into the same
    issue-reports/ directory, and the runner works out what a fetcher produced by
    diffing that directory before and after. A fixed filename therefore fails
    twice over: target 2 overwrites target 1's report, and because the name
    already existed the runner sees no new file and records nothing for target 2 —
    leaving one sidecar entry that carries target 1's identity and target 2's
    bytes. Nothing raises, and Paramify parses the missing target as "those
    findings are resolved".

    This mirrors the evidence-side convention — see
    fetchers/aws/acm_certificate_status/, which writes
    aws_acm_certificate_status_<profile>_<region>.json. Join every target_schema
    field that distinguishes one invocation from another, not just the first.
    Delete this only if the fetcher will never declare supports_targets.
    """
    value = os.environ.get("<TARGET_ENV_VAR>", "").strip()
    if not value:
        return ""
    # A target value comes from the manifest, not from us: sanitize it so a slash
    # or a space cannot write outside the directory the runner chose.
    return "_" + re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    token = os.environ.get("<UPPER_SNAKE_ENV_VAR>")
    if not token:
        report_failure("<UPPER_SNAKE_ENV_VAR> is not set", "bad_config")
        return 1

    # EVIDENCE_DIR already points at <run>/issue-reports/ for an issue-report
    # fetcher. Write a bare filename into it and never build the subdirectory
    # yourself — the runner owns that layout.
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"<category>_<short_name>{target_suffix()}.csv"

    # Replace with the real export call. Two shapes are common:
    #
    #   1. One request returns the report (below).
    #   2. Request an export, poll for readiness, then download. Put the polling
    #      here; a fetcher that returns before the report is ready writes a
    #      truncated file, and a truncated scan report reads as "these findings
    #      are resolved" once Paramify parses it.
    try:
        resp = requests.get(
            "https://<tool-host>/api/<report-export-path>",
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT,
            stream=True,
        )
    except requests.RequestException as e:
        report_failure(f"could not reach <tool>: {e}", "target_unreachable")
        return 1

    if resp.status_code in (401, 403):
        report_failure(f"<tool> rejected the credential (HTTP {resp.status_code})", "auth_failed")
        return 1
    if resp.status_code != 200:
        report_failure(
            f"<tool> export failed (HTTP {resp.status_code}): {resp.text[:300]}",
            "partial_failure",
        )
        return 1

    # Streamed to disk unmodified. Streaming matters at scan-report sizes, and it
    # also makes the no-transformation rule structural: there is no intermediate
    # object to be tempted into editing.
    try:
        with output_path.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    fh.write(chunk)
    except OSError as e:
        report_failure(f"could not write the report: {e}")
        return 1

    size = output_path.stat().st_size
    # An empty file is a failure, not an empty result: intake would parse it as
    # "no findings", silently resolving every open issue on the assessment.
    if size == 0:
        report_failure("<tool> returned an empty report", "partial_failure")
        return 1

    logger.info("Report saved to %s (%d bytes)", output_path, size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
