"""Tests for secret redaction in captured fetcher output (framework/runner/executor.py).

The property that matters: an injected secret value must never survive into the
captured stdout/stderr the runner persists (envelope metadata.error,
_run_metadata.json) or uploads. We prove it two ways — a direct unit test of the
masking, and an END-TO-END run of a real fetcher that prints its own injected
secret and fails, asserting the value is gone from the result AND from the
envelope metadata.error the uploader would ship.
"""

from __future__ import annotations

from framework.contract import (
    EvidenceSet,
    Fetcher,
    ManifestEntry,
    PlatformSpec,
    Secret,
)
from framework.envelope import build_metadata
from framework.runner.executor import _is_sensitive_env_name, _redact, run_entry


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def make_fetcher(path, **ov) -> Fetcher:
    d = dict(
        name="t_fetcher", version="0.1.0", description="test", category="cat",
        runtime_type="python", runtime_entry="fetcher.py", runtime_timeout=None,
        output_type="json", output_path="out.json", output_aggregation=None,
        secrets=[], supports_targets=False, target_schema={}, path=path,
        config_schema={}, evidence_set=None,
    )
    d.update(ov)
    return Fetcher(**d)


# --------------------------------------------------------------------------- #
# Unit: the masking itself
# --------------------------------------------------------------------------- #

def test_redact_masks_a_known_value():
    assert _redact("Authorization: Bearer abcdefgh done", {"abcdefgh"}) == \
        "Authorization: Bearer ***REDACTED*** done"


def test_redact_masks_every_occurrence():
    assert _redact("x=sekretval y=sekretval", {"sekretval"}) == \
        "x=***REDACTED*** y=***REDACTED***"


def test_redact_skips_short_values_to_avoid_corrupting_evidence():
    # "1"/"true" are below the min length — masking them would blank out
    # unrelated text. They are left intact.
    assert _redact("status 1 enabled=true", {"1", "true"}) == "status 1 enabled=true"


def test_redact_longest_first_prevents_partial_leak():
    # Both the full token and a prefix of it are "secret"; the full value must be
    # masked whole, not leave its tail exposed.
    out = _redact("token=abcdef-TAIL", {"abcdef", "abcdef-TAIL"})
    assert out == "token=***REDACTED***"
    assert "TAIL" not in out


def test_redact_safe_on_empty_inputs():
    assert _redact("", {"x"}) == ""
    assert _redact("no secrets here", set()) == "no secrets here"
    assert _redact("no secrets here", None) == "no secrets here"


# --------------------------------------------------------------------------- #
# End-to-end: a real failing fetcher that prints its injected secret
# --------------------------------------------------------------------------- #

_LEAKY_FETCHER = """\
import os, sys
tok = os.environ["API_TOKEN"]
print("stdout sees the token:", tok)
print("ERROR auth failed with token", tok, file=sys.stderr)
sys.exit(1)
"""

_SECRET = "sup3r-s3cr3t-token-value-987"


def test_injected_secret_is_redacted_end_to_end(tmp_path, monkeypatch):
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(_LEAKY_FETCHER)

    monkeypatch.setenv("SRC_TOKEN", _SECRET)
    es = EvidenceSet(reference_id="EVD-1", name="Set")
    fetcher = make_fetcher(fdir, secrets=[Secret(name="api_token", env="API_TOKEN")], evidence_set=es)
    entry = ManifestEntry(use="t_fetcher", secrets={"api_token": "${env:SRC_TOKEN}"})

    result = run_entry(fetcher, entry, tmp_path / "out")[0]
    assert result.exit_code == 1

    # The captured output the runner persists must not contain the secret.
    assert _SECRET not in result.stderr
    assert _SECRET not in result.stdout
    assert "***REDACTED***" in result.stderr

    # And the property the P2 finding is really about: the secret does not reach
    # the envelope metadata.error the uploader ships to Paramify.
    meta = build_metadata(result, fetcher, run_id="2026-01-01T00-00-00Z")
    assert _SECRET not in meta["error"]
    assert "***REDACTED***" in meta["error"]


def test_redaction_does_not_disturb_clean_output(tmp_path, monkeypatch):
    """A fetcher whose output never contains the secret is passed through
    verbatim (no spurious redaction)."""
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(
        'import sys\nprint("collected 3 findings")\nsys.exit(1)\n'
    )
    monkeypatch.setenv("SRC_TOKEN", _SECRET)
    fetcher = make_fetcher(fdir, secrets=[Secret(name="api_token", env="API_TOKEN")])
    entry = ManifestEntry(use="t_fetcher", secrets={"api_token": "${env:SRC_TOKEN}"})

    result = run_entry(fetcher, entry, tmp_path / "out")[0]
    assert "collected 3 findings" in result.stdout
    assert "***REDACTED***" not in result.stdout


# --------------------------------------------------------------------------- #
# passthrough_env: mask ambient CREDENTIALS, preserve identity/region selectors
# --------------------------------------------------------------------------- #

def test_is_sensitive_env_name_classification():
    # Credential material -> masked
    assert _is_sensitive_env_name("AWS_SECRET_ACCESS_KEY") is True
    assert _is_sensitive_env_name("AWS_SESSION_TOKEN") is True
    assert _is_sensitive_env_name("MY_API_PASSWORD") is True
    # Identity/region selectors and path/endpoint vars -> NOT masked (evidence content)
    assert _is_sensitive_env_name("AWS_PROFILE") is False
    assert _is_sensitive_env_name("AWS_DEFAULT_REGION") is False
    assert _is_sensitive_env_name("AWS_ACCESS_KEY_ID") is False          # identifier, appears in evidence
    assert _is_sensitive_env_name("AWS_WEB_IDENTITY_TOKEN_FILE") is False  # path, not the token
    assert _is_sensitive_env_name("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") is False  # endpoint


_PASSTHROUGH_LEAK_FETCHER = """\
import os, sys
print("region is", os.environ.get("DEPLOY_REGION", "?"), file=sys.stderr)
print("cred is", os.environ.get("AMBIENT_API_SECRET", "?"), file=sys.stderr)
sys.exit(1)
"""


def test_passthrough_credential_redacted_but_selector_preserved(tmp_path, monkeypatch):
    """An ambient credential the runner passes through is masked from output, but
    a non-sensitive selector (region) is preserved — masking it would corrupt
    evidence, since regions legitimately appear in evidence."""
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(_PASSTHROUGH_LEAK_FETCHER)

    monkeypatch.setenv("AMBIENT_API_SECRET", "ambient-cred-value-123456")
    monkeypatch.setenv("DEPLOY_REGION", "us-west-2-and-then-some")   # long, but NOT a secret
    fetcher = make_fetcher(fdir, category="cat")
    spec = PlatformSpec(category="cat", passthrough_env=["AMBIENT_API_SECRET", "DEPLOY_REGION"])

    result = run_entry(fetcher, ManifestEntry(use="t_fetcher"), tmp_path / "out", platform_spec=spec)[0]

    assert "ambient-cred-value-123456" not in result.stderr   # credential masked
    assert "***REDACTED***" in result.stderr
    assert "us-west-2-and-then-some" in result.stderr          # selector preserved (evidence content)


# --------------------------------------------------------------------------- #
# The status-file channel is fetcher-authored text, so it gets masked too
# --------------------------------------------------------------------------- #

_LEAKY_STATUS_FETCHER = """\
import json, os, sys
tok = os.environ["API_TOKEN"]
# A real exception message often carries the credential — e.g. the failing URL.
with open(os.environ["FETCHER_STATUS_FILE"], "w") as f:
    json.dump({"error": "401 from https://api.example.com/v1?token=%s" % tok,
               "code": "auth_failed"}, f)
sys.exit(1)
"""


def test_secret_in_the_status_file_is_redacted(tmp_path, monkeypatch):
    """Why the runner reads the status file in the executor and not the envelope.

    metadata.error used to be guaranteed clean because it could only ever be a
    slice of already-masked stderr. Sourcing it from a file the FETCHER wrote
    would have quietly dropped that guarantee — evidence payloads are never
    masked, since the runner only diffs filenames and never reads their content.
    Reading it where the injected values are still in scope is what keeps the
    guarantee intact.
    """
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(_LEAKY_STATUS_FETCHER)

    monkeypatch.setenv("SRC_TOKEN", _SECRET)
    fetcher = make_fetcher(fdir, secrets=[Secret(name="api_token", env="API_TOKEN")],
                           evidence_set=EvidenceSet(reference_id="EVD-1", name="Set"))
    entry = ManifestEntry(use="t_fetcher", secrets={"api_token": "${env:SRC_TOKEN}"})

    result = run_entry(fetcher, entry, tmp_path / "out")[0]

    assert result.exit_code == 1
    assert result.error is not None, "the fetcher did report a reason"
    assert _SECRET not in result.error
    assert "***REDACTED***" in result.error
    assert result.error_code == "auth_failed"

    # And it stays masked in the envelope field the uploader ships to Paramify.
    meta = build_metadata(result, fetcher, run_id="2026-01-01T00-00-00Z")
    assert _SECRET not in meta["error"]
    assert "***REDACTED***" in meta["error"]
    assert meta["error_code"] == "auth_failed"
