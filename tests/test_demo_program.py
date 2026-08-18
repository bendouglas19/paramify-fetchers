"""The shipped demo program actually runs, and still ends the way it promises.

`manifests/demo.yaml` is the first thing a new user runs and what the README's
recorded demos show, so its behaviour is a contract of its own: five entries, no
credentials beyond one throwaway env var, and exactly one deliberately failing
fanout target that reports WHY. If any of that drifts, the onboarding path and
the demos go stale silently — nothing else here would notice.

It runs the real fetchers as subprocesses, which is the point: this is the one
category that can be executed in CI, because it reaches no network and needs no
account.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from framework import api

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "manifests" / "demo.yaml"


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory):
    """Run the shipped demo manifest into a temp dir, with the pauses removed."""
    if not MANIFEST.is_file():
        pytest.skip("manifests/demo.yaml is not present")
    m = yaml.safe_load(MANIFEST.read_text())
    out = tmp_path_factory.mktemp("demo-evidence")
    m["run"]["output_dir"] = str(out)
    # The demo pauses between scan stages so a recorded run has something to
    # watch; a test has no such need.
    for entry in m["run"]["fetchers"]:
        if entry["use"] == "demo_vuln_scan":
            entry.setdefault("config", {})["stage_delay_ms"] = 0

    prev = os.environ.get("DEMO_API_TOKEN")
    os.environ["DEMO_API_TOKEN"] = "test-token"
    try:
        summary = api.run(m, REPO_ROOT, manifest_path=MANIFEST)
    finally:
        if prev is None:
            os.environ.pop("DEMO_API_TOKEN", None)
        else:
            os.environ["DEMO_API_TOKEN"] = prev

    run_dir = Path(summary["run_dir"])
    meta = json.loads((run_dir / "_run_metadata.json").read_text())
    return run_dir, meta


def test_demo_manifest_validates() -> None:
    m = yaml.safe_load(MANIFEST.read_text())
    assert api.validate(m, REPO_ROOT) == []


def test_every_entry_ran(demo_run) -> None:
    _, meta = demo_run
    ran = {inv["fetcher_name"] for inv in meta["invocations"]}
    assert ran == {
        "demo_hello", "demo_vuln_scan", "demo_encryption_at_rest",
        "demo_audit_logging", "demo_access_review",
    }


def test_exactly_one_invocation_fails(demo_run) -> None:
    """The partial run is deliberate: one target of one fanout fetcher, no more."""
    _, meta = demo_run
    failed = [inv for inv in meta["invocations"] if inv["exit_code"] != 0]
    assert len(failed) == 1
    assert failed[0]["fetcher_name"] == "demo_audit_logging"
    assert failed[0]["target"] == {"account": "demo-sandbox"}


def test_fanout_failure_is_isolated(demo_run) -> None:
    """The other two accounts still collect — that is what fanout isolation means."""
    _, meta = demo_run
    audit = [inv for inv in meta["invocations"] if inv["fetcher_name"] == "demo_audit_logging"]
    assert len(audit) == 3
    assert sum(1 for inv in audit if inv["exit_code"] == 0) == 2


def test_failed_target_reports_why_in_its_envelope(demo_run) -> None:
    """The partial collection is still written, and carries a reported reason —
    not a slice of stderr. This is the $FETCHER_STATUS_FILE channel end to end."""
    run_dir, _ = demo_run
    env = json.loads((run_dir / "demo_audit_logging_demo-sandbox.json").read_text())
    meta = env["metadata"]
    assert meta["status"] == "failed"
    assert meta["error_code"] == "not_authorized"
    assert "demo-west-2" in meta["error"]
    # ...and the payload says the collection was partial, so a reader of the
    # evidence alone cannot mistake it for a complete one.
    assert env["payload"]["results"]["collection"]["status"] == "partial"


def test_successful_evidence_is_enveloped_and_marked_synthetic(demo_run) -> None:
    run_dir, _ = demo_run
    env = json.loads((run_dir / "demo_hello.json").read_text())
    assert env["metadata"]["status"] == "success"
    assert "Synthetic" in env["payload"]["metadata"]["note"]


def test_optional_secret_is_not_injected_when_omitted(demo_run) -> None:
    """demo.yaml wires api_token and omits the optional service_account_key; the
    fetcher must see the ambient path, not a blank key."""
    run_dir, _ = demo_run
    env = json.loads((run_dir / "demo_access_review.json").read_text())
    assert env["payload"]["metadata"]["auth_method"].startswith("ambient identity")
