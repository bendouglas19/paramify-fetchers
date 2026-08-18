#!/usr/bin/env python3
"""
Demo fetcher: synthetic audit-logging configuration, fanned out per account.

Deliberately fails on one of the three accounts the shipped demo manifest lists,
because a demo where everything is green teaches nothing about what a failure
looks like here. Three things it demonstrates, all of them real behaviour:

  - a fanout failure is ISOLATED: demo-sandbox exits non-zero, the other two
    accounts collect normally, and the fetcher's status ends up `partial`;
  - a PARTIAL collection still writes what it got. demo-sandbox reads two of its
    three regions, records the third as an API failure inside the payload, and
    exits non-zero so nobody reads the incomplete result as a clean one;
  - the reason is REPORTED, not guessed. Writing $FETCHER_STATUS_FILE puts a
    triage-ready `metadata.error` / `metadata.error_code` in that file's envelope
    instead of whatever happened to be the last line on stderr.

Not real evidence. See manifests/demo.yaml.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("demo_audit_logging")

# Hand-written per-account, per-region state, so the demo behaves the same on
# every run and every machine. "unreadable" is the synthetic API failure that
# makes demo-sandbox the failing target; `enabled: False` is a genuine FINDING on
# a region that answered, which is a different thing and must not be conflated —
# one is "we could not look", the other is "we looked, and it is off".
_ACCOUNTS = {
    "demo-prod-1": {
        "demo-east-1": {"enabled": True, "retention_days": 400},
        "demo-west-2": {"enabled": True, "retention_days": 400},
        "demo-central-1": {"enabled": True, "retention_days": 400},
    },
    "demo-prod-2": {
        "demo-east-1": {"enabled": True, "retention_days": 400},
        "demo-west-2": {"enabled": True, "retention_days": 400},
        "demo-central-1": {"enabled": True, "retention_days": 365},
    },
    "demo-sandbox": {
        "demo-east-1": {"enabled": True, "retention_days": 90},
        "demo-west-2": {"unreadable": "403 Forbidden — the demo role is not trusted in this region"},
        "demo-central-1": {"enabled": False, "retention_days": None},
    },
}

_DEFAULT_REGIONS = {
    "demo-east-1": {"enabled": True, "retention_days": 365},
    "demo-west-2": {"enabled": True, "retention_days": 365},
}


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the envelope's metadata.error.

    Without it the runner falls back to the tail of stderr — which on the way out
    is the "Evidence saved" line. See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def collect(account: str) -> tuple[list, list]:
    """Read every region for `account`. Returns (regions, api_failures)."""
    regions, api_failures = [], []
    for region, state in _ACCOUNTS.get(account, _DEFAULT_REGIONS).items():
        if "unreadable" in state:
            logger.warning("%s/%s: %s", account, region, state["unreadable"])
            api_failures.append({"region": region, "error": state["unreadable"]})
            continue
        regions.append({
            "region": region,
            "trail": f"{account}-trail" if state["enabled"] else None,
            "enabled": state["enabled"],
            "destination": f"{account}-audit-logs" if state["enabled"] else None,
            "log_file_validation": state["enabled"],
            "retention_days": state["retention_days"],
        })
    return regions, api_failures


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    account = os.environ.get("DEMO_ACCOUNT", "demo-unnamed")
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Reading synthetic audit-trail configuration for %s", account)
    regions, api_failures = collect(account)

    evidence = {
        "metadata": {
            "source": "demo",
            "note": "Synthetic evidence — not collected from any real system.",
            "account": account,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "results": {
            "account": account,
            "regions": regions,
            "summary": {
                "regions_read": len(regions),
                "audit_logging_enabled": sum(1 for r in regions if r["enabled"]),
                "audit_logging_disabled": sum(1 for r in regions if not r["enabled"]),
            },
            # Whether the collection was complete belongs IN the payload: without
            # it, a report missing a region is indistinguishable from an account
            # that only has the regions listed.
            "collection": {
                "status": "partial" if api_failures else "complete",
                "api_failures": api_failures,
            },
        },
    }

    output_path = output_dir / f"demo_audit_logging_{account}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s (%d region(s) read)", output_path, len(regions))

    # Exit non-zero when anything could not be read. The file above is still
    # written and still useful; what must not happen is an incomplete report
    # being counted as a clean one.
    if api_failures:
        detail = ", ".join(f"{f['region']}: {f['error']}" for f in api_failures)
        reason = f"{len(api_failures)} of {len(regions) + len(api_failures)} regions unreadable for {account} — {detail}"
        logger.error("collection incomplete: %s", reason)
        report_failure(reason, "not_authorized")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
