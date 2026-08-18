#!/usr/bin/env python3
"""
Demo fetcher: synthetic quarterly access review, with a credential.

The other demo fetchers take no secrets, which leaves half the framework
undemonstrated — a manifest that wires a secret, `paramify doctor` reporting one
that is not set, and the difference between a required credential and an optional
one. This fetcher takes both: DEMO_API_TOKEN is required, DEMO_SERVICE_ACCOUNT_KEY
is optional and stands in for the ambient-identity path.

No value is sent anywhere and neither is written into the evidence — only *which*
path authenticated. Any non-empty token works. Not real evidence.
See manifests/demo.yaml.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("demo_access_review")

# Fixed roster, so the review reads the same on every run.
_ACCOUNTS = [
    {"user": "avery.diaz@demo.example", "role": "administrator", "mfa": True,
     "last_login_days": 1, "reviewed": True, "decision": "retain"},
    {"user": "blake.osei@demo.example", "role": "engineer", "mfa": True,
     "last_login_days": 3, "reviewed": True, "decision": "retain"},
    {"user": "casey.lindqvist@demo.example", "role": "auditor", "mfa": True,
     "last_login_days": 12, "reviewed": True, "decision": "retain"},
    {"user": "svc-demo-backup", "role": "service-account", "mfa": False,
     "last_login_days": 0, "reviewed": True, "decision": "retain",
     "note": "non-interactive; key rotated 2026-07-01"},
    {"user": "dana.whitfield@demo.example", "role": "engineer", "mfa": True,
     "last_login_days": 97, "reviewed": True, "decision": "revoke",
     "note": "dormant past the 90-day threshold"},
]


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the envelope's metadata.error.

    Without it the runner falls back to the tail of stderr — which on the way out
    is the "Evidence saved" line. See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # Required credential. A real fetcher would authenticate here; this one only
    # checks that it was given something, because the failure mode worth
    # demonstrating is the missing-credential one.
    token = os.environ.get("DEMO_API_TOKEN", "").strip()
    if not token:
        reason = "DEMO_API_TOKEN is not set (any non-empty value will do — this is a demo)"
        logger.error("collection failed: %s", reason)
        report_failure(reason, "bad_config")
        return 1

    # Optional credential: supplied means the static-key path, absent means the
    # ambient one. Which path authenticated is worth recording; the value is not.
    auth_method = (
        "static service-account key"
        if os.environ.get("DEMO_SERVICE_ACCOUNT_KEY", "").strip()
        else "ambient identity (no key supplied)"
    )
    logger.info("Authenticated via %s", auth_method)

    revoked = [a for a in _ACCOUNTS if a["decision"] == "revoke"]
    evidence = {
        "metadata": {
            "source": "demo",
            "note": "Synthetic evidence — not collected from any real system.",
            "auth_method": auth_method,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "results": {
            "review_period": "2026-Q3",
            "accounts": _ACCOUNTS,
            "summary": {
                "total": len(_ACCOUNTS),
                "reviewed": sum(1 for a in _ACCOUNTS if a["reviewed"]),
                "mfa_enrolled": sum(1 for a in _ACCOUNTS if a["mfa"]),
                "marked_for_revocation": len(revoked),
                "dormant_threshold_days": 90,
            },
        },
    }

    output_path = output_dir / "demo_access_review.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info(
        "Evidence saved to %s (%d accounts, %d marked for revocation)",
        output_path, len(_ACCOUNTS), len(revoked),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
