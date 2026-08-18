#!/usr/bin/env python3
"""
Demo fetcher: synthetic encryption-at-rest posture, fanned out per account.

One invocation per target — the runner sets DEMO_ACCOUNT from each target in the
manifest and calls this once per account, writing one file each. Nothing here
touches a network or a credential; the payload is hand-written so a newcomer can
watch a fanout run, and the evidence it produces, without an account of any kind.
This is NOT real evidence. See manifests/demo.yaml.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("demo_encryption_at_rest")

# Hand-written posture for the accounts the shipped demo manifest lists. Keyed by
# account so every run of a given target produces the same evidence — a demo that
# changed shape between runs would teach the wrong thing about the pipeline.
_ACCOUNTS = {
    "demo-prod-1": [
        {"resource": "vol-0a1b2c3d", "kind": "block-volume", "encrypted": True,
         "key": "arn:demo:kms:::key/demo-prod-cmk", "key_rotation": "annual"},
        {"resource": "demo-prod-artifacts", "kind": "object-store", "encrypted": True,
         "key": "arn:demo:kms:::key/demo-prod-cmk", "key_rotation": "annual"},
        {"resource": "demo-prod-db-1", "kind": "database", "encrypted": True,
         "key": "arn:demo:kms:::key/demo-prod-cmk", "key_rotation": "annual"},
    ],
    "demo-prod-2": [
        {"resource": "vol-0e4f5a6b", "kind": "block-volume", "encrypted": True,
         "key": "arn:demo:kms:::key/demo-prod-cmk", "key_rotation": "annual"},
        {"resource": "demo-prod-backups", "kind": "object-store", "encrypted": True,
         "key": "arn:demo:kms:::key/demo-prod-cmk", "key_rotation": "annual"},
    ],
    "demo-sandbox": [
        {"resource": "vol-0f7a8b9c", "kind": "block-volume", "encrypted": True,
         "key": "demo-managed", "key_rotation": "provider-managed"},
    ],
}


def resources_for(account: str) -> list:
    """Posture for `account` — the hand-written set, or a generic clean one."""
    if account in _ACCOUNTS:
        return _ACCOUNTS[account]
    return [
        {"resource": f"{account}-volume-1", "kind": "block-volume", "encrypted": True,
         "key": "demo-managed", "key_rotation": "provider-managed"},
    ]


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    account = os.environ.get("DEMO_ACCOUNT", "demo-unnamed")
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    resources = resources_for(account)
    logger.info("Reading synthetic storage inventory for %s", account)

    evidence = {
        "metadata": {
            "source": "demo",
            "note": "Synthetic evidence — not collected from any real system.",
            "account": account,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "results": {
            "account": account,
            "resources": resources,
            "summary": {
                "total": len(resources),
                "encrypted": sum(1 for r in resources if r["encrypted"]),
                "unencrypted": sum(1 for r in resources if not r["encrypted"]),
            },
        },
    }

    output_path = output_dir / f"demo_encryption_at_rest_{account}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    s = evidence["results"]["summary"]
    logger.info(
        "Evidence saved to %s (%d/%d encrypted)", output_path, s["encrypted"], s["total"]
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
