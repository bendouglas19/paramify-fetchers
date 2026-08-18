#!/usr/bin/env python3
"""
<KSI or control reference>: <short title>

<One paragraph: what this fetcher collects and why.>
"""

import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# If this fetcher relies on a category-shared module, uncomment:
# SCRIPT_DIR = Path(__file__).resolve().parent
# sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
# from <shared_module> import <EntryClass>

logger = logging.getLogger("<category>_<short_name>")


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the envelope's metadata.error.

    Call this on every path that returns non-zero. Without it the runner falls back
    to the tail of stderr, which is whatever you logged last — and for most fetchers
    that is the "Evidence saved" line, i.e. a success message reported as the reason
    for a failure. `code` is a machine-readable category (auth_failed,
    not_authorized, not_enabled, target_unreachable, rate_limited, bad_config,
    partial_failure). See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself and reads env directly.
    # Runner + secret resolver will replace this when the framework lands.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # Replace with the actual data-collection call.
    evidence: dict = {}

    output_path = output_dir / "<category>_<short_name>.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s", output_path)

    # Exit code is the ONLY failure signal the runner reads — it never looks inside
    # the payload. Non-zero for any failed call or precondition, and say why:
    #
    #     if api_failures:
    #         report_failure(f"{len(api_failures)} API calls failed", "partial_failure")
    #         return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
