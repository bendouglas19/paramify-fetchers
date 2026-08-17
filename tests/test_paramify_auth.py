"""Token and base-URL resolution.

These exist because the two were resolved independently in four places and did
not agree: the uploaders accepted only PARAMIFY_UPLOAD_API_TOKEN while the
paramify fetchers accepted either name, so setting the shorter, more obvious
name produced working fetchers and an upload that failed at the last step.
"""

from __future__ import annotations

from framework.paramify_auth import (
    DEFAULT_BASE_URL,
    READ_TOKEN_ENV,
    UPLOAD_TOKEN_ENV,
    describe_base_url,
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
