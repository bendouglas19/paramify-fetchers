"""Live credential probes.

The probes themselves need network and real credentials, so what is tested here
is the behaviour around them: that a probe never raises, never hangs the
preflight, and never turns an environment problem into a doctor failure.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from framework import probe


class _Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_unprobeable_category_returns_none():
    """Token-based categories have a declared secret; doctor already checks it."""
    assert probe.probe_category("datadog") is None
    assert probe.probe_category("gitlab") is None


def test_k8s_probes_the_aws_credential_chain(monkeypatch):
    """k8s reaches EKS with AWS credentials, so it is the same question."""
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return _Completed(stdout=json.dumps({"Arn": "arn:aws:iam::1:user/x", "Account": "1"}))

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/usr/bin/aws")
    result = probe.probe_category("k8s")
    assert result["ok"] is True
    assert seen["argv"][:3] == ["aws", "sts", "get-caller-identity"]


def test_a_timeout_is_reported_not_raised(monkeypatch):
    """A preflight that hangs is worse than one that says it could not tell."""

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=20)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/usr/bin/aws")
    result = probe.probe_category("aws", timeout=20)
    assert result["ok"] is False
    assert "timed out" in result["error"]


def test_expired_credentials_surface_the_last_stderr_line(monkeypatch):
    """The real case this feature exists for: env vars set, credentials dead."""

    def fake_run(argv, **kwargs):
        return _Completed(
            returncode=255,
            stderr="\nTraceback noise\nError: Your session has expired.\n",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/usr/bin/aws")
    result = probe.probe_category("aws")
    assert result["ok"] is False
    assert result["error"] == "Error: Your session has expired."


def test_missing_cli_is_reported_without_running_anything(monkeypatch):
    monkeypatch.setattr(probe.shutil, "which", lambda _: None)

    def explode(*a, **k):
        raise AssertionError("should not shell out when the CLI is absent")

    monkeypatch.setattr(subprocess, "run", explode)
    result = probe.probe_category("aws")
    assert result["ok"] is False
    assert "not on PATH" in result["error"]


def test_unparseable_output_is_a_failure_not_a_crash(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Completed(stdout="not json"))
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/usr/bin/aws")
    result = probe.probe_category("aws")
    assert result["ok"] is False


def test_probe_categories_skips_unprobeable_and_keeps_order(monkeypatch):
    monkeypatch.setattr(
        probe, "probe_category", lambda cat, timeout=20: None if cat == "okta" else {"category": cat}
    )
    got = probe.probe_categories(["aws", "okta", "gcp"])
    assert [r["category"] for r in got] == ["aws", "gcp"]


@pytest.mark.parametrize("category", probe.PROBEABLE)
def test_every_probeable_category_is_actually_implemented(category, monkeypatch):
    """Guards the list drifting away from the dispatch below it."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Completed(returncode=1, stderr="no"))
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/usr/bin/aws")
    assert probe.probe_category(category) is not None
