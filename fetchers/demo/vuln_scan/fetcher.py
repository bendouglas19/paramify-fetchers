#!/usr/bin/env python3
"""
Demo fetcher: synthetic vulnerability-scan summary, deliberately not instant.

Every other demo fetcher finishes in well under a tenth of a second, which makes
a demo run a single flash — nothing to see, and no way to tell that the runner
streams per-fetcher progress at all. This one walks four synthetic stages with a
configurable pause (DEMO_STAGE_DELAY_MS, default 450ms) and logs each, so a run
has something to watch. Set the delay to 0 and it behaves like the others.

Not real evidence. See manifests/demo.yaml.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("demo_vuln_scan")

# Fixed findings, so the summary is the same on every run.
_FINDINGS = [
    {"id": "DEMO-2026-0001", "severity": "high", "package": "demo-tls", "installed": "1.4.2",
     "fixed_in": "1.4.6", "asset": "demo-prod-web-1", "age_days": 11, "status": "open"},
    {"id": "DEMO-2026-0002", "severity": "medium", "package": "demo-json", "installed": "2.0.1",
     "fixed_in": "2.0.3", "asset": "demo-prod-web-1", "age_days": 4, "status": "open"},
    {"id": "DEMO-2026-0003", "severity": "medium", "package": "demo-http", "installed": "0.9.0",
     "fixed_in": "0.9.1", "asset": "demo-prod-api-2", "age_days": 22, "status": "open"},
    {"id": "DEMO-2026-0004", "severity": "low", "package": "demo-yaml", "installed": "5.1.0",
     "fixed_in": "5.1.1", "asset": "demo-sandbox-1", "age_days": 61, "status": "risk_accepted"},
]

_STAGES = [
    "enumerating synthetic assets",
    "matching installed packages against the demo advisory feed",
    "scoring findings",
    "assembling the summary",
]


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        delay = int(os.environ.get("DEMO_STAGE_DELAY_MS", "450")) / 1000
    except ValueError:
        delay = 0.45

    for i, stage in enumerate(_STAGES, start=1):
        logger.info("[%d/%d] %s", i, len(_STAGES), stage)
        time.sleep(max(delay, 0))

    by_severity = {}
    for f in _FINDINGS:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    evidence = {
        "metadata": {
            "source": "demo",
            "note": "Synthetic evidence — not collected from any real system.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "results": {
            "assets_scanned": 3,
            "findings": _FINDINGS,
            "summary": {
                "total": len(_FINDINGS),
                "by_severity": {
                    "critical": by_severity.get("critical", 0),
                    "high": by_severity.get("high", 0),
                    "medium": by_severity.get("medium", 0),
                    "low": by_severity.get("low", 0),
                },
                "open": sum(1 for f in _FINDINGS if f["status"] == "open"),
                "risk_accepted": sum(1 for f in _FINDINGS if f["status"] == "risk_accepted"),
                "oldest_open_days": max(f["age_days"] for f in _FINDINGS if f["status"] == "open"),
            },
        },
    }

    output_path = output_dir / "demo_vuln_scan.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s (%d findings)", output_path, len(_FINDINGS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
