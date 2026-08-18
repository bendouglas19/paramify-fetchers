"""Token and base-URL resolution.

These exist because the two were resolved independently in four places and did
not agree: the uploaders accepted only PARAMIFY_UPLOAD_API_TOKEN while the
paramify fetchers accepted either name, so setting the shorter, more obvious
name produced working fetchers and an upload that failed at the last step.
"""

from __future__ import annotations

import sys

import pytest

from framework.paramify_auth import (
    DEFAULT_BASE_URL,
    READ_TOKEN_ENV,
    UPLOAD_TOKEN_ENV,
    can_prompt,
    describe_base_url,
    prompt_for_token,
    resolve_base_url,
    resolve_upload_token,
)

# --------------------------------------------------------------------------- #
# Token
# --------------------------------------------------------------------------- #

def test_no_token_anywhere_is_not_an_error_here():
    """Callers decide whether absence is fatal — a dry run does not need one."""
    assert resolve_upload_token({}) == (None, None)


def test_canonical_name_wins():
    token, source = resolve_upload_token({UPLOAD_TOKEN_ENV: "up", READ_TOKEN_ENV: "read"})
    assert (token, source) == ("up", UPLOAD_TOKEN_ENV)


def test_read_token_is_accepted_as_a_fallback():
    """The actual bug: this combination used to fail at the upload step."""
    assert resolve_upload_token({READ_TOKEN_ENV: "read"}) == ("read", READ_TOKEN_ENV)


def test_whitespace_only_token_counts_as_unset():
    """An empty export is a likelier mistake than a deliberate blank token."""
    assert resolve_upload_token({UPLOAD_TOKEN_ENV: "   "}) == (None, None)


def test_source_is_reported_so_callers_can_show_which_var_was_used():
    _, source = resolve_upload_token({READ_TOKEN_ENV: "read"})
    assert source == READ_TOKEN_ENV


# --------------------------------------------------------------------------- #
# Base URL
# --------------------------------------------------------------------------- #

def test_base_url_defaults_to_production():
    assert resolve_base_url(None, {}) == (DEFAULT_BASE_URL, "default")


def test_config_outranks_env():
    url, source = resolve_base_url(
        "https://acme.internal/api/v0", {"PARAMIFY_API_BASE_URL": "https://stage.paramify.com/api/v0"}
    )
    assert (url, source) == ("https://acme.internal/api/v0", "config")


def test_env_outranks_the_default():
    url, source = resolve_base_url(None, {"PARAMIFY_API_BASE_URL": "https://stage.paramify.com/api/v0"})
    assert source == "PARAMIFY_API_BASE_URL"
    assert url == "https://stage.paramify.com/api/v0"


def test_hosts_are_labelled_for_preflight_output():
    """Uploading to stage when you meant production otherwise succeeds silently."""
    assert describe_base_url("https://app.paramify.com/api/v0") == "production"
    assert describe_base_url("https://stage.paramify.com/api/v0") == "stage"
    assert describe_base_url("https://paramify.acme.internal/api/v0") == "self-hosted"


# --------------------------------------------------------------------------- #
# Prompting. The failure mode being guarded is a prompt in a pipeline: it does
# not get answered, so the job hangs until the runner's timeout kills it — much
# worse than the clean error the caller raises otherwise.
# --------------------------------------------------------------------------- #

class _FakeTTY:
    """Stands in for stdin/stderr: answers isatty() and swallows prompt output."""

    def __init__(self, tty: bool):
        self._tty = tty
        self.written: list[str] = []

    def isatty(self) -> bool:
        return self._tty

    def write(self, text: str) -> int:
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _no_ci_marker(monkeypatch):
    """Clear CI for every test here.

    can_prompt() takes its environment explicitly, but prompt_for_token calls it
    without one, so it reads os.environ — where a CI runner sets CI=true and every
    prompt short-circuits. Faking the TTYs is not enough: on a runner these tests
    measured the CI refusal instead of the path they name, so the three that
    assert None passed for the wrong reason and the one that expects a token
    failed. Autouse because the trap is invisible at the call site.

    Only the environment is set here. Patching sys.stdin/sys.stderr from a fixture
    does not survive: pytest re-activates global capture for the call phase and
    replaces the streams again, so the fake TTYs have to be installed inside the
    test body.
    """
    monkeypatch.delenv("CI", raising=False)


def test_never_prompts_in_ci_even_on_a_terminal(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _FakeTTY(True))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(True))
    assert can_prompt({"CI": "true"}) is False


def test_never_prompts_when_stdin_is_redirected(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _FakeTTY(False))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(True))
    assert can_prompt({}) is False


def test_never_prompts_when_output_is_piped(monkeypatch):
    """`paramify upload | tee log` must not stall waiting on a hidden prompt."""
    monkeypatch.setattr(sys, "stdin", _FakeTTY(True))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(False))
    assert can_prompt({}) is False


def test_prompts_on_a_real_interactive_terminal(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _FakeTTY(True))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(True))
    assert can_prompt({}) is True


def test_prompt_returns_none_instead_of_blocking_when_it_must_not_ask(monkeypatch):
    # Redirected on both ends, with CI cleared, so the refusal comes from the
    # streams rather than from a CI marker.
    monkeypatch.setattr(sys, "stdin", _FakeTTY(False))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(False))
    assert prompt_for_token("https://app.paramify.com/api/v0") is None


def test_an_accepted_token_is_exported_for_the_rest_of_the_process(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _FakeTTY(True))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(True))
    monkeypatch.delenv(UPLOAD_TOKEN_ENV, raising=False)
    monkeypatch.setattr("framework.paramify_auth.getpass.getpass", lambda _: "typed-token")
    assert prompt_for_token("https://app.paramify.com/api/v0") == "typed-token"
    assert resolve_upload_token() == ("typed-token", UPLOAD_TOKEN_ENV)


def test_an_empty_answer_is_not_treated_as_a_token(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _FakeTTY(True))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(True))
    monkeypatch.delenv(UPLOAD_TOKEN_ENV, raising=False)
    monkeypatch.setattr("framework.paramify_auth.getpass.getpass", lambda _: "  ")
    assert prompt_for_token("https://app.paramify.com/api/v0") is None


def test_ctrl_c_at_the_prompt_declines_rather_than_propagating(monkeypatch):
    """Declining should fall through to the normal error, not a traceback."""
    monkeypatch.setattr(sys, "stdin", _FakeTTY(True))
    monkeypatch.setattr(sys, "stderr", _FakeTTY(True))

    def _interrupt(_):
        raise KeyboardInterrupt

    monkeypatch.setattr("framework.paramify_auth.getpass.getpass", _interrupt)
    assert prompt_for_token("https://app.paramify.com/api/v0") is None
