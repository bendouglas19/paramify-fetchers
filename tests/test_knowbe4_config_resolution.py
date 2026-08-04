"""KnowBe4 fetchers must never report an unresolved config as a failing control.

The bug this suite pins: the group and campaign names these fetchers match on
were hardcoded to one customer's tenant. Pointed at any other tenant they
emitted ``completion_rate: 0`` and exited 0 — byte-identical to a tenant where
the campaign resolved and genuinely nobody had trained. Two states, one output:

    typo'd config, users DID pass  -> {"completed_training": 0, "completion_rate": 0}
    config OK, nobody passed       -> {"completed_training": 0, "completion_rate": 0}

No assertion could separate them, so the contract now does. A compliance metric
the fetcher could not measure is ``null``; ``0`` means measured and zero. That
one distinction is what makes the failure expressible, and ``test_b_*`` vs
``test_c_*`` below are the pair that would have caught it.

Deliberately NOT a failure: an unresolvable name exits 0 and records itself in
``results.config_resolution``. A typo in one group name must not turn a whole
nightly run red (``paramify run`` exits 1 if any fetcher fails), and evidence
that says "I could not measure this" is more useful than an absent artifact.
A config key that was never wired at all is a different case — ``required: true``
means ``paramify validate`` catches it pre-flight.

The fetchers are bash scripts the runner exec's, so these tests drive them the
way the runner does: a stub ``curl`` on PATH serving canned KnowBe4 pages, and
the config passed as the env vars each fetcher.yaml declares. No network, no
tenant, no jq/curl mocking inside the script itself.

Run: ``pytest tests/test_knowbe4_config_resolution.py``
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
KNOWBE4_ROOT = REPO_ROOT / "fetchers" / "knowbe4"

# Stub curl: resolves https://<region>.api.knowbe4.com/v1/<endpoint>?...page=N to
# $MOCK_DATA/<endpoint with / as _>_p<N>.json, and serves [] for anything absent
# so pagination terminates the way the real API's empty last page does. Honors
# $MOCK_FAIL to emulate curl -f's nonzero exit on a 4xx/5xx.
_STUB_CURL = r"""#!/bin/bash
[ -n "$MOCK_FAIL" ] && exit 22
url=""
for a in "$@"; do case "$a" in https://*) url="$a";; esac; done
page=1
[[ "$url" =~ page=([0-9]+) ]] && page="${BASH_REMATCH[1]}"
ep="${url#*/v1/}"; ep="${ep%%\?*}"
f="$MOCK_DATA/$(echo "$ep" | tr '/' '_')_p${page}.json"
[ -f "$f" ] && { cat "$f"; exit 0; }
printf '%s' '[]'
"""

# ---------------------------------------------------------------------------- #
# Tenant fixtures. Each is the full set of API pages a run will see.
# ---------------------------------------------------------------------------- #

_USERS = [
    {"id": 1, "email": "a@ex.com", "status": "active"},
    {"id": 2, "email": "b@ex.com", "status": "active"},
    {"id": 3, "email": "c@ex.com", "status": "archived"},
]

# Tenant that matches the config the tests pass: campaigns and groups line up.
TENANT_MATCHING = {
    "users": _USERS,
    "groups": [
        {"id": 10, "name": "Engineering"},
        {"id": 11, "name": "Cloud Ops"},
        {"id": 12, "name": "Recruiting"},
    ],
    "groups_10_members": [{"id": 1, "email": "a@ex.com", "status": "active"}],
    "groups_11_members": [{"id": 2, "email": "b@ex.com", "status": "active"}],
    "training_campaigns": [
        {"campaign_id": 100, "name": "2026 Annual Security Awareness Training"},
        {"campaign_id": 101, "name": "Developers Training"},
        {"campaign_id": 102, "name": "Privileged Users Training (Before CloudOps Access)"},
    ],
    "training_enrollments": [
        {"enrollment_id": 1, "campaign_name": "2026 Annual Security Awareness Training",
         "module_name": "SAT", "user": {"id": 1, "email": "a@ex.com"},
         "status": "Passed", "completion_date": "2026-03-01T10:00:00.000Z",
         "policy_acknowledged": False},
        {"enrollment_id": 2, "campaign_name": "2026 Annual Security Awareness Training",
         "module_name": "SAT", "user": {"id": 2, "email": "b@ex.com"},
         "status": "In Progress", "completion_date": None,
         "policy_acknowledged": False},
        {"enrollment_id": 3, "campaign_name": "Developers Training",
         "module_name": "Secure Coding", "user": {"id": 1, "email": "a@ex.com"},
         "status": "Passed", "completion_date": "2026-02-01T10:00:00.000Z",
         "policy_acknowledged": False},
        {"enrollment_id": 4, "campaign_name": "Privileged Users Training (Before CloudOps Access)",
         "module_name": "Privileged Access", "user": {"id": 2, "email": "b@ex.com"},
         "status": "Past Due", "completion_date": None,
         "policy_acknowledged": False},
    ],
}

# Same tenant shape, but every user PASSED the security-awareness campaign. Used
# with a typo'd config: the truth is 100% trained, so a 0% report is provably wrong.
TENANT_ALL_PASSED = {
    **TENANT_MATCHING,
    "training_enrollments": [
        {"enrollment_id": 1, "campaign_name": "2026 Annual Security Awareness Training",
         "module_name": "SAT", "user": {"id": 1, "email": "a@ex.com"},
         "status": "Passed", "completion_date": "2026-03-01T10:00:00.000Z"},
        {"enrollment_id": 2, "campaign_name": "2026 Annual Security Awareness Training",
         "module_name": "SAT", "user": {"id": 2, "email": "b@ex.com"},
         "status": "Passed", "completion_date": "2026-03-02T10:00:00.000Z"},
    ],
}

# Config resolves, and nobody has passed. A genuine failing control.
TENANT_NOBODY_PASSED = {
    **TENANT_MATCHING,
    "training_enrollments": [
        {"enrollment_id": 1, "campaign_name": "2026 Annual Security Awareness Training",
         "module_name": "SAT", "user": {"id": 1, "email": "a@ex.com"},
         "status": "Not Started", "completion_date": None},
        {"enrollment_id": 2, "campaign_name": "2026 Annual Security Awareness Training",
         "module_name": "SAT", "user": {"id": 2, "email": "b@ex.com"},
         "status": "Not Started", "completion_date": None},
    ],
}

# Names that break a jq filter built by string interpolation. The fetchers must
# pass config to jq as data (--args/$ARGS.positional), never as program text.
HOSTILE_NAMES = [
    'Privileged "Admin" Training',
    "Dev\\Ops Training",
    "Cost $ Training",
    "Développeur's Training",
    "Training (Before CloudOps Access)",
]

TENANT_HOSTILE = {
    "users": _USERS,
    "groups": [{"id": 10, "name": n} for n in HOSTILE_NAMES],
    "training_campaigns": [{"campaign_id": 200 + i, "name": n} for i, n in enumerate(HOSTILE_NAMES)],
    "training_enrollments": [
        {"enrollment_id": i, "campaign_name": n, "module_name": "M",
         "user": {"id": 1, "email": "a@ex.com"}, "status": "Passed",
         "completion_date": "2026-03-01T10:00:00.000Z"}
        for i, n in enumerate(HOSTILE_NAMES)
    ],
    "groups_10_members": [{"id": 1, "email": "a@ex.com", "status": "active"}],
}

# Config each fetcher needs to resolve cleanly against TENANT_MATCHING.
GOOD_CONFIG = {
    "knowbe4_security_awareness_training": {
        "KNOWBE4_SECURITY_AWARENESS_CAMPAIGNS": "2026 Annual Security Awareness Training",
    },
    "knowbe4_developer_specific_training": {
        "KNOWBE4_DEVELOPER_GROUPS": "Engineering",
        "KNOWBE4_DEVELOPER_CAMPAIGNS": "Developers Training",
    },
    "knowbe4_high_risk_training": {
        "KNOWBE4_HIGH_RISK_GROUPS": "Cloud Ops",
        "KNOWBE4_ROLE_SPECIFIC_CAMPAIGNS": "Privileged Users Training (Before CloudOps Access)",
    },
}

# Same keys, every value typo'd. Nothing will match.
TYPO_CONFIG = {
    "knowbe4_security_awareness_training": {
        "KNOWBE4_SECURITY_AWARENESS_CAMPAIGNS": "2026 Anual Security Awareness Training",
    },
    "knowbe4_developer_specific_training": {
        "KNOWBE4_DEVELOPER_GROUPS": "Enginering",
        "KNOWBE4_DEVELOPER_CAMPAIGNS": "Developer Training",
    },
    "knowbe4_high_risk_training": {
        "KNOWBE4_HIGH_RISK_GROUPS": "Cloud Opps",
        "KNOWBE4_ROLE_SPECIFIC_CAMPAIGNS": "Priviledged Users Training",
    },
}

CONFIGURABLE = sorted(GOOD_CONFIG)

# Every compliance metric that must go null when the fetcher could not measure.
# Counts of what was *discovered* (matched groups/campaigns, users found) stay
# real numbers — 0 discovered is an accurate 0, not an unmeasured value.
COMPLIANCE_METRICS = (
    "completed_training", "in_progress", "past_due", "not_started",
    "completion_rate", "needs_retraining",
)


# ---------------------------------------------------------------------------- #
# Harness
# ---------------------------------------------------------------------------- #

def _write_tenant(data_dir: Path, tenant: dict) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for endpoint, rows in tenant.items():
        (data_dir / f"{endpoint}_p1.json").write_text(json.dumps(rows))


def run_fetcher(fetcher: str, tenant: dict, config: dict, tmp_path: Path,
                fail_api: bool = False, timeout: int = 180):
    """Run one KnowBe4 fetcher against a canned tenant. Returns (exit, evidence, stderr).

    `evidence` is the parsed payload the fetcher wrote, or None if it wrote nothing.
    """
    short = fetcher.removeprefix("knowbe4_")
    fetcher_dir = KNOWBE4_ROOT / short
    assert fetcher_dir.is_dir(), f"no such fetcher dir: {fetcher_dir}"

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    curl = bin_dir / "curl"
    curl.write_text(_STUB_CURL)
    curl.chmod(0o755)

    data_dir = tmp_path / "data"
    _write_tenant(data_dir, tenant)
    evidence_dir = tmp_path / "evidence"

    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "MOCK_DATA": str(data_dir),
        "EVIDENCE_DIR": str(evidence_dir),
        "KNOWBE4_API_KEY": "test-key",
        "KNOWBE4_REGION": "us",
        **config,
    }
    if fail_api:
        env["MOCK_FAIL"] = "1"

    proc = subprocess.run(
        ["bash", "fetcher.sh"],
        cwd=fetcher_dir, env=env, capture_output=True, text=True, timeout=timeout,
    )
    out = evidence_dir / f"{fetcher}.json"
    evidence = json.loads(out.read_text()) if out.exists() else None
    return proc.returncode, evidence, proc.stderr


@pytest.fixture(autouse=True)
def _require_tools():
    for tool in ("bash", "jq"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not on PATH")


# ---------------------------------------------------------------------------- #
# A — config resolves against the tenant: real numbers, resolved
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("fetcher", CONFIGURABLE)
def test_a_resolved_config_reports_real_numbers(fetcher, tmp_path):
    code, ev, _ = run_fetcher(fetcher, TENANT_MATCHING, GOOD_CONFIG[fetcher], tmp_path)
    assert code == 0
    res = ev["results"]["config_resolution"]
    assert res["status"] == "resolved", res
    assert res["measurable"] is True
    assert res["campaigns"]["unmatched"] == []
    # Measured, so no compliance metric is null.
    summary = ev["results"]["summary"]
    for metric in COMPLIANCE_METRICS:
        if metric in summary:
            assert summary[metric] is not None, f"{metric} should be measured"


def test_a_security_awareness_counts_are_right(tmp_path):
    """One user Passed, one In Progress -> 50%. Pins the arithmetic, not just nullness."""
    code, ev, _ = run_fetcher(
        "knowbe4_security_awareness_training", TENANT_MATCHING,
        GOOD_CONFIG["knowbe4_security_awareness_training"], tmp_path,
    )
    assert code == 0
    s = ev["results"]["summary"]
    assert s["total_users"] == 2          # the archived user is excluded
    assert s["completed_training"] == 1
    assert s["in_progress"] == 1
    assert s["completion_rate"] == 50


# ---------------------------------------------------------------------------- #
# B — config does NOT resolve: null metrics, exit 0, self-diagnosing
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("fetcher", CONFIGURABLE)
def test_b_unresolved_config_does_not_fail_the_fetcher(fetcher, tmp_path):
    """A typo must not turn the run red — it exits 0 and says so in the evidence."""
    code, ev, stderr = run_fetcher(fetcher, TENANT_ALL_PASSED, TYPO_CONFIG[fetcher], tmp_path)
    assert code == 0, f"a config typo must not fail the fetcher; stderr:\n{stderr}"
    assert ev is not None, "unresolved config must still produce an evidence artifact"
    assert ev["results"]["config_resolution"]["status"] == "unresolved"
    # The fetcher emits WARN, but note the runner currently drops stderr on a
    # zero exit (framework/api.py records stderr_tail only when exit_code != 0,
    # and executor.py does not forward stderr to on_line). So the evidence
    # artifact — not this line — is what actually reaches an operator today.
    assert "WARN" in stderr


@pytest.mark.parametrize("fetcher", CONFIGURABLE)
def test_b_unresolved_config_nulls_every_compliance_metric(fetcher, tmp_path):
    """The core contract. Nothing it could not measure may be reported as 0."""
    _, ev, _ = run_fetcher(fetcher, TENANT_ALL_PASSED, TYPO_CONFIG[fetcher], tmp_path)
    summary = ev["results"]["summary"]
    assert ev["results"]["config_resolution"]["measurable"] is False
    for metric in COMPLIANCE_METRICS:
        if metric in summary:
            assert summary[metric] is None, (
                f"{metric} is {summary[metric]!r}; an unmeasured metric must be null, "
                "never 0 — 0 reads as a genuine failing control"
            )


@pytest.mark.parametrize("fetcher", CONFIGURABLE)
def test_b_unresolved_config_names_what_it_looked_for_and_what_exists(fetcher, tmp_path):
    """Self-diagnosing: the fix is visible in the artifact without a shell."""
    _, ev, _ = run_fetcher(fetcher, TENANT_ALL_PASSED, TYPO_CONFIG[fetcher], tmp_path)
    res = ev["results"]["config_resolution"]
    typo_values = set()
    for raw in TYPO_CONFIG[fetcher].values():
        typo_values.update(v.strip() for v in raw.split(","))

    requested = set(res["campaigns"]["requested"]) | set(res.get("groups", {}).get("requested", []))
    assert typo_values <= requested, "must echo back what it was asked to match"
    assert res["campaigns"]["matched"] == []
    assert set(res["campaigns"]["unmatched"]) == set(res["campaigns"]["requested"])
    # And what the tenant actually has, so the typo is obvious.
    present = res["campaigns_present_in_tenant"]
    assert "2026 Annual Security Awareness Training" in present


# ---------------------------------------------------------------------------- #
# C — the pair that pins the distinction B alone cannot
# ---------------------------------------------------------------------------- #

def test_c_genuine_zero_percent_is_still_reported_as_zero(tmp_path):
    """Config resolves, nobody trained. That is a real finding and must survive."""
    code, ev, _ = run_fetcher(
        "knowbe4_security_awareness_training", TENANT_NOBODY_PASSED,
        GOOD_CONFIG["knowbe4_security_awareness_training"], tmp_path,
    )
    assert code == 0
    res = ev["results"]["config_resolution"]
    assert res["status"] == "resolved"
    assert res["measurable"] is True
    s = ev["results"]["summary"]
    assert s["completed_training"] == 0, "measured zero must stay 0, not become null"
    assert s["completion_rate"] == 0
    assert s["total_users"] == 2


def test_c_unmeasured_and_genuine_zero_are_distinguishable(tmp_path):
    """The regression this suite exists for.

    Before the fix these two runs produced byte-identical summaries and both
    exited 0. If this test ever passes trivially again, the bug is back.
    """
    fetcher = "knowbe4_security_awareness_training"
    _, unmeasured, _ = run_fetcher(
        fetcher, TENANT_ALL_PASSED, TYPO_CONFIG[fetcher], tmp_path / "unmeasured")
    _, genuine, _ = run_fetcher(
        fetcher, TENANT_NOBODY_PASSED, GOOD_CONFIG[fetcher], tmp_path / "genuine")

    assert unmeasured["results"]["summary"] != genuine["results"]["summary"]
    assert unmeasured["results"]["summary"]["completion_rate"] is None
    assert genuine["results"]["summary"]["completion_rate"] == 0


# ---------------------------------------------------------------------------- #
# D — config is data, not jq program text
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_d_names_that_would_break_an_interpolated_jq_filter(name, tmp_path):
    """Quotes, backslashes and $ in a campaign name must match, not crash jq."""
    code, ev, stderr = run_fetcher(
        "knowbe4_security_awareness_training", TENANT_HOSTILE,
        {"KNOWBE4_SECURITY_AWARENESS_CAMPAIGNS": name}, tmp_path,
    )
    assert code == 0, f"jq error on {name!r}?\n{stderr}"
    assert "jq: error" not in stderr and "compile error" not in stderr
    res = ev["results"]["config_resolution"]
    assert res["campaigns"]["matched"] == [name], f"{name!r} did not match; {res}"
    assert res["measurable"] is True


def test_d_config_parsing_trims_and_drops_empties(tmp_path):
    """' A , B ,,' is three tokens of whitespace and two real names."""
    code, ev, _ = run_fetcher(
        "knowbe4_high_risk_training", TENANT_MATCHING,
        {
            "KNOWBE4_HIGH_RISK_GROUPS": "  Cloud Ops ,, Engineering  ",
            "KNOWBE4_ROLE_SPECIFIC_CAMPAIGNS": "Privileged Users Training (Before CloudOps Access) ,",
        },
        tmp_path,
    )
    assert code == 0
    res = ev["results"]["config_resolution"]
    assert sorted(res["groups"]["requested"]) == ["Cloud Ops", "Engineering"]
    assert res["campaigns"]["requested"] == [
        "Privileged Users Training (Before CloudOps Access)"]
    assert res["groups"]["unmatched"] == []


def test_d_group_matching_is_exact_not_substring(tmp_path):
    """'IT' must not sweep in 'AUDIT' or 'Legal-IT' the way substring matching did."""
    tenant = {
        **TENANT_MATCHING,
        "groups": [
            {"id": 30, "name": "AUDIT"},
            {"id": 31, "name": "Legal-IT"},
            {"id": 32, "name": "IT"},
        ],
        "groups_32_members": [{"id": 1, "email": "a@ex.com", "status": "active"}],
    }
    _, ev, _ = run_fetcher(
        "knowbe4_high_risk_training", tenant,
        {
            "KNOWBE4_HIGH_RISK_GROUPS": "IT",
            "KNOWBE4_ROLE_SPECIFIC_CAMPAIGNS": "Privileged Users Training (Before CloudOps Access)",
        },
        tmp_path,
    )
    matched = ev["results"]["config_resolution"]["groups"]["matched"]
    assert matched == ["IT"], f"substring bleed: {matched}"


# ---------------------------------------------------------------------------- #
# E — hard API failure is still a failure
# ---------------------------------------------------------------------------- #

@pytest.mark.parametrize("fetcher", CONFIGURABLE + ["knowbe4_module_based_summary"])
def test_e_api_failure_exits_nonzero(fetcher, tmp_path):
    """Unresolved config is exit 0; an unreachable API is not. Keep them distinct."""
    config = GOOD_CONFIG.get(fetcher, {})
    code, _, stderr = run_fetcher(fetcher, TENANT_MATCHING, config, tmp_path, fail_api=True)
    assert code != 0, "a failed API call must still fail the fetcher"
    assert "ERROR" in stderr


# ---------------------------------------------------------------------------- #
# F — the quadratic append is gone
# ---------------------------------------------------------------------------- #

def test_f_scales_to_a_realistic_enrollment_count(tmp_path):
    """3k enrollments must finish fast.

    The per-record ``jq``-rewrite this replaced was quadratic: 1500 enrollments
    took 69s and 3000 took over 120s, so a mid-size tenant blew the runner's
    600s cap (framework/runner/executor.py). The bound here is deliberately far
    below that — a regression to per-record rewriting cannot sneak under it.
    """
    n = 3000
    tenant = {
        "users": _USERS,
        "training_enrollments": [
            {"enrollment_id": i, "campaign_name": "FY26",
             "module_name": f"Mod {i % 20}",
             "user": {"id": i % 200, "email": f"u{i % 200}@ex.com"},
             "status": "Passed" if i % 3 else "In Progress",
             "completion_date": "2026-03-01T10:00:00.000Z",
             "policy_acknowledged": False}
            for i in range(n)
        ],
    }
    start = time.monotonic()
    code, ev, stderr = run_fetcher("knowbe4_module_based_summary", tenant, {}, tmp_path)
    elapsed = time.monotonic() - start

    assert code == 0, stderr
    assert len(ev["results"]["enrollments"]) == n
    assert ev["results"]["summary"]["training_module_summary"]["Mod 0"]["assigned"] == n // 20
    assert elapsed < 30, f"{n} enrollments took {elapsed:.0f}s — per-record rewrite is back?"


def test_f_empty_tenant_summary_is_an_object_not_null(tmp_path):
    """No enrollments is an empty map. `null` made downstream readers special-case it."""
    code, ev, _ = run_fetcher(
        "knowbe4_module_based_summary", {"training_enrollments": []}, {}, tmp_path)
    assert code == 0
    assert ev["results"]["summary"]["training_module_summary"] == {}
    assert ev["results"]["enrollments"] == []
