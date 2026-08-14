"""Fixture-based tests for the Azure identity and access evidence fetchers.

Covers the four tenant-scoped Microsoft Entra ID fetchers (Graph) and the two
subscription-scoped Azure RBAC fetchers (ARM). No live API calls, no credentials, and
neither `msgraph` nor `azure-mgmt-authorization` needs to be installed: every heavy
import lives inside a `collect_*()` / `graph_service_client()` body and is never
triggered here.

Three layers are covered, mirroring tests/test_azure_fetchers.py:

**The projection layer** (`project_*`) is each fetcher's only code that touches an SDK
model. Its tests drive it with `SimpleNamespace` stand-ins that mimic attribute access,
including the `None` intermediates the real APIs hand back constantly (a Conditional
Access policy with no `grantControls`, a user who has never signed in, a role
definition with no `permissions`).

For the Graph half there is one normalization the ARM half never needs, and it gets
its own tests: Graph enums are PLAIN `Enum`s rather than `str` subclasses, and Graph
timestamps arrive as `datetime` objects. Both must be unwrapped at the projection
boundary — `str()` on a Graph enum yields "ConditionalAccessPolicyState.Enabled", and
`json.dump(default=str)` on a datetime yields "2026-08-14 12:00:00+00:00" rather than
the ISO-8601 the API sent. The first of those is the source of a real bug in Prowler's
conditional-access projection, reproduced and pinned in
`test_ca_grant_block_split_does_not_inherit_prowlers_enum_repr_bug`.

**The pure transforms** (`*_record`, `summarize`, and friends) take the projections'
output and are plain dict-in/dict-out, so they are tested from literal fixtures. Those
fixtures are SYNTHETIC but not guessed: they are the projections' verified output shape
for msgraph-sdk 1.61.0 and azure-mgmt-authorization 4.0.0.

**The async plumbing** (`paginate`, `resolve_tenant`) is duck-typed over the SDK's
request builders, so it is tested with fakes and driven through `asyncio.run` — there
is no pytest-asyncio dependency.

Run: pytest tests/test_azure_identity_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE_ROOT = REPO_ROOT / "fetchers" / "azure"

SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = AZURE_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"azure_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_graph():
    """Load the Graph plumbing shared by the four Entra fetchers."""
    path = AZURE_ROOT / "_shared" / "entra_graph.py"
    spec = importlib.util.spec_from_file_location("entra_graph_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _collector():
    import sys

    sys.path.insert(0, str(AZURE_ROOT / "_shared"))
    from azure_common import Collector

    return Collector(logging.getLogger("test"))


# --------------------------------------------------------------------------- #
# Graph plumbing — entra_graph.graph_attr / graph_list
# --------------------------------------------------------------------------- #


class FakeGraphEnum(Enum):
    """A Graph enum stand-in.

    Deliberately NOT a `str` subclass: msgraph-sdk's generated enums are plain
    `Enum`s, which is exactly what makes `str()` on one dangerous.
    """

    ENABLED = "enabled"


def test_graph_attr_unwraps_plain_enums_datetimes_and_uuids():
    graph = _load_graph()
    model = SimpleNamespace(
        state=FakeGraphEnum.ENABLED,
        when=datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc),
        naive=datetime(2026, 8, 14, 12, 0, 0),
        nothing=None,
    )

    # A plain Enum does NOT compare equal to its value, so leaving one in place
    # breaks every downstream comparison as well as the evidence.
    assert FakeGraphEnum.ENABLED != "enabled"
    assert graph.graph_attr(model, "state") == "enabled"
    assert type(graph.graph_attr(model, "state")) is str

    # Graph sends "2026-08-14T12:00:00Z"; json.dump(default=str) would write
    # "2026-08-14 12:00:00+00:00" — a space for the T and +00:00 for the Z.
    assert graph.graph_attr(model, "when") == "2026-08-14T12:00:00Z"
    assert graph.graph_attr(model, "naive") == "2026-08-14T12:00:00"

    # Absent attributes and absent parents both read as None rather than raising,
    # which is what lets a projection chain through omitted nested models.
    assert graph.graph_attr(model, "never_set") is None
    assert graph.graph_attr(None, "state") is None
    assert graph.graph_attr(model, "nothing") is None


def test_graph_attr_renders_uuids_as_strings():
    from uuid import UUID

    graph = _load_graph()
    key_id = UUID("33333333-3333-3333-3333-333333333333")
    model = SimpleNamespace(key_id=key_id)
    assert graph.graph_attr(model, "key_id") == "33333333-3333-3333-3333-333333333333"
    assert type(graph.graph_attr(model, "key_id")) is str


def test_graph_list_reads_an_absent_collection_as_empty():
    """Graph omits empty collections instead of sending []."""
    graph = _load_graph()
    model = SimpleNamespace(items=[FakeGraphEnum.ENABLED, "plain"], empty=None)
    assert graph.graph_list(model, "items") == ["enabled", "plain"]
    assert graph.graph_list(model, "empty") == []
    assert graph.graph_list(model, "never_set") == []
    assert graph.graph_list(None, "items") == []


@pytest.mark.parametrize(
    ("authority", "expected_host"),
    [
        (None, "https://graph.microsoft.com"),
        ("", "https://graph.microsoft.com"),
        ("https://login.microsoftonline.com", "https://graph.microsoft.com"),
        ("https://login.microsoftonline.com/", "https://graph.microsoft.com"),
        ("https://login.microsoftonline.us", "https://graph.microsoft.us"),
        ("https://login.chinacloudapi.cn", "https://microsoftgraph.chinacloudapi.cn"),
        # Unrecognized authorities fall back to the public cloud with a warning
        # rather than guessing a host and collecting nothing.
        ("https://login.example.invalid", "https://graph.microsoft.com"),
    ],
)
def test_graph_host_is_derived_from_the_credential_authority(authority, expected_host, monkeypatch):
    """The trap this exists for: pointing the SCOPE at a sovereign cloud is not enough.

    `GraphServiceClient(credentials, scopes=[...])` leaves the transport's base URL at
    graph.microsoft.com, so a sovereign tenant authenticates for the right cloud and
    then queries the wrong one. Host and scope have to move together.
    """
    graph = _load_graph()
    if authority is None:
        monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    else:
        monkeypatch.setenv("AZURE_AUTHORITY_HOST", authority)
    assert graph.graph_host() == expected_host
    assert graph.graph_scope() == f"{expected_host}/.default"


# --------------------------------------------------------------------------- #
# Graph plumbing — pagination
# --------------------------------------------------------------------------- #


class FakePage:
    def __init__(self, values, next_link=None):
        self.value = values
        self.odata_next_link = next_link


class FakeBuilder:
    """A request-builder stand-in that serves a scripted list of pages.

    Mirrors the real contract: `.get()` returns ONE page, and the caller re-issues the
    absolute `odata_next_link` through `.with_url(link).get()`.
    """

    def __init__(self, pages, fail_on_page=None):
        self.pages = list(pages)
        self.fail_on_page = fail_on_page
        self.calls = 0
        self.request_configurations = []

    async def get(self, request_configuration=None):
        self.request_configurations.append(request_configuration)
        self.calls += 1
        if self.fail_on_page is not None and self.calls == self.fail_on_page:
            raise RuntimeError("(429) TooManyRequests")
        return self.pages[self.calls - 1]

    def with_url(self, url):
        # The real builder returns a NEW builder bound to the url; sharing state here
        # is what lets the test count total calls.
        return self


def test_paginate_follows_odata_next_link_to_the_end():
    graph = _load_graph()
    collector = _collector()
    builder = FakeBuilder(
        [
            FakePage(["a", "b"], next_link="https://graph/next1"),
            FakePage(["c"], next_link="https://graph/next2"),
            FakePage(["d"], next_link=None),
        ]
    )
    items = asyncio.run(graph.paginate(collector, "op", builder, request_configuration="cfg"))
    assert items == ["a", "b", "c", "d"]
    assert builder.calls == 3
    # The request configuration ($select) is sent on the FIRST call only — the
    # nextLink already carries the original query.
    assert builder.request_configurations == ["cfg", None, None]
    assert collector.ok is True


def test_paginate_keeps_partial_results_and_records_the_failure():
    """A tenant that 429s on page 2 must yield page 1 AND a non-zero exit.

    Silently returning a truncated collection as if it were complete is the exact
    failure mode the Collector layer exists to prevent — a compliance tool reporting
    "3 users, all covered" for a tenant of 3000 is worse than reporting nothing.
    """
    graph = _load_graph()
    collector = _collector()
    builder = FakeBuilder(
        [FakePage(["a"], next_link="https://graph/next1"), FakePage(["b"])],
        fail_on_page=2,
    )
    items = asyncio.run(graph.paginate(collector, "graph.users.get", builder))
    assert items == ["a"]
    assert collector.ok is False
    assert collector.failures[0]["operation"] == "graph.users.get"


def test_paginate_stops_on_a_repeating_next_link():
    """A server echoing the same nextLink back must not loop until the timeout."""
    graph = _load_graph()
    collector = _collector()
    builder = FakeBuilder([FakePage(["x"], next_link="https://graph/same")] * 10)
    items = asyncio.run(graph.paginate(collector, "op", builder, page_limit=3))
    assert items == ["x", "x", "x"]
    assert collector.ok is False
    assert "refusing to keep paging" in collector.failures[0]["message"]


def test_paginate_tolerates_a_page_with_no_value_collection():
    graph = _load_graph()
    collector = _collector()
    items = asyncio.run(graph.paginate(collector, "op", FakeBuilder([FakePage(None)])))
    assert items == []
    assert collector.ok is True


# --------------------------------------------------------------------------- #
# Graph plumbing — tenant identity and payload assembly
# --------------------------------------------------------------------------- #


class FakeOrganizationBuilder:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    async def get(self):
        if self.error is not None:
            raise self.error
        return self.result


def _client_with_org(result=None, error=None):
    return SimpleNamespace(organization=FakeOrganizationBuilder(result, error))


def test_resolve_tenant_prefers_the_organization_endpoint():
    graph = _load_graph()
    collector = _collector()
    org = SimpleNamespace(
        id=TENANT,
        display_name="Paramify Test",
        verified_domains=[
            SimpleNamespace(name="onmicrosoft.example.com", is_default=False),
            SimpleNamespace(name="paramify.example.com", is_default=True),
        ],
    )
    tenant = asyncio.run(
        graph.resolve_tenant(collector, _client_with_org(FakePage([org])))
    )
    assert tenant == {
        "tenant_id": TENANT,
        "tenant_name": "Paramify Test",
        # The DEFAULT verified domain, not merely the first one.
        "tenant_domain": "paramify.example.com",
        "tenant_source": "organization",
    }
    assert collector.ok is True


def test_resolve_tenant_falls_back_to_the_env_var_without_recording_a_failure(monkeypatch):
    """A denied Organization.Read.All must not fail a run whose evidence collected fine.

    An app registration can legitimately hold every permission the actual evidence
    needs and not this one, so losing the whole run over a provenance read would be
    wrong. The fallback is visible in `tenant_source`.
    """
    graph = _load_graph()
    collector = _collector()
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    tenant = asyncio.run(
        graph.resolve_tenant(
            collector, _client_with_org(error=PermissionError("(403) Forbidden"))
        )
    )
    assert tenant["tenant_id"] == TENANT
    assert tenant["tenant_source"] == "environment"
    assert tenant["tenant_domain"] is None
    assert collector.ok is True


def test_resolve_tenant_records_a_failure_when_both_sources_come_up_empty(monkeypatch):
    """With no tenant at all the evidence has no provenance, which DOES invalidate it."""
    graph = _load_graph()
    collector = _collector()
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    tenant = asyncio.run(
        graph.resolve_tenant(collector, _client_with_org(error=RuntimeError("nope")))
    )
    assert tenant["tenant_id"] is None
    assert tenant["tenant_source"] == graph.TENANT_UNRESOLVED
    assert collector.ok is False
    assert collector.failures[0]["operation"] == "resolve_tenant"


def test_resolve_tenant_handles_an_empty_organization_collection(monkeypatch):
    graph = _load_graph()
    collector = _collector()
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    tenant = asyncio.run(graph.resolve_tenant(collector, _client_with_org(FakePage([]))))
    assert tenant["tenant_source"] == "environment"
    assert collector.ok is True


def test_tenant_scoping_marks_subscription_as_not_used_for_scoping(monkeypatch):
    """Graph evidence is tenant-wide; a subscription id never narrows it."""
    graph = _load_graph()
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    assert graph.tenant_scoping() == {
        "subscription_id": None,
        "subscription_source": "not_applicable",
    }
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUBSCRIPTION)
    assert graph.tenant_scoping() == {
        "subscription_id": SUBSCRIPTION,
        "subscription_source": "target_correlation_only",
    }


def test_tenant_payload_adds_the_tenant_to_the_shared_metadata_block():
    graph = _load_graph()
    collector = _collector()

    import sys

    sys.path.insert(0, str(AZURE_ROOT / "_shared"))
    from azure_common import build_payload

    payload = graph.tenant_payload(
        build_payload,
        tenant={
            "tenant_id": TENANT,
            "tenant_name": "Paramify Test",
            "tenant_domain": "paramify.example.com",
            "tenant_source": "organization",
        },
        subscription_id=None,
        subscription_source="not_applicable",
        collector=collector,
        results={"users": []},
        summary={"total_users": 0},
    )
    assert payload["metadata"]["tenant_id"] == TENANT
    assert payload["metadata"]["tenant_domain"] == "paramify.example.com"
    assert payload["metadata"]["tenant_source"] == "organization"
    # The shared block's own fields survive untouched.
    assert payload["metadata"]["partial_failure"] is False
    assert payload["metadata"]["subscription_source"] == "not_applicable"
    assert payload["results"] == {"users": []}


def test_tenant_filename_key_prefers_the_target_over_the_resolved_tenant(monkeypatch):
    """The filename must stay stable even when the organization read was denied.

    The runner gives every target invocation the same EVIDENCE_DIR and detects an
    invocation's outputs by diffing the directory listing, so two targets writing the
    same filename make the second look like it produced nothing.
    """
    graph = _load_graph()
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    assert graph.tenant_filename_key({"tenant_id": "resolved-other"}) == TENANT
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    assert graph.tenant_filename_key({"tenant_id": TENANT}) == TENANT
    assert graph.tenant_filename_key({}) == "unknown"
    assert graph.tenant_filename_key({"tenant_id": None}) == "unknown"


# --------------------------------------------------------------------------- #
# entra_mfa_status — project_user() / project_registration_details() output,
# then the transforms
# --------------------------------------------------------------------------- #

USER_ENABLED = {  # SYNTHETIC — project_user()'s output shape
    "id": "user-1",
    "display_name": "Ada Lovelace",
    "user_principal_name": "ada@example.com",
    "account_enabled": True,
    "user_type": "Member",
    "last_sign_in": "2026-08-01T09:00:00Z",
    "last_successful_sign_in": "2026-08-01T09:00:00Z",
    "last_non_interactive_sign_in": "2026-08-10T02:00:00Z",
}

USER_DISABLED = {  # SYNTHETIC — a deprovisioned account
    "id": "user-2",
    "display_name": "Old Account",
    "user_principal_name": "old@example.com",
    "account_enabled": False,
    "user_type": "Member",
    "last_sign_in": None,
    "last_successful_sign_in": None,
    "last_non_interactive_sign_in": None,
}

USER_GUEST = {  # SYNTHETIC — an invited external identity
    "id": "user-3",
    "display_name": "Guest User",
    "user_principal_name": "guest_ext#EXT#@example.com",
    "account_enabled": True,
    "user_type": "Guest",
    "last_sign_in": "2026-07-01T09:00:00Z",
    "last_successful_sign_in": "2026-07-01T09:00:00Z",
    "last_non_interactive_sign_in": None,
}

REGISTRATION_MFA_ADMIN = {  # SYNTHETIC — project_registration_details()'s output
    "id": "user-1",
    "is_mfa_capable": True,
    "is_mfa_registered": True,
    "is_passwordless_capable": True,
    "is_sspr_capable": True,
    "is_sspr_registered": True,
    "is_admin": True,
    "methods_registered": ["microsoftAuthenticatorPush", "fido2SecurityKey"],
    "last_updated": "2026-08-12T00:00:00Z",
    "user_preferred_method_for_secondary_authentication": "push",
}


def test_project_user_reads_graph_attributes():
    """The projection's output IS the fixture the transforms are tested against.

    Asserting the whole dict (not a few keys) is deliberate: if the projection's key
    names ever drift from what `user_record` reads, the evidence would go quietly null
    rather than fail, so the two must be pinned to each other.
    """
    mfa = _load("entra_mfa_status")
    user = SimpleNamespace(
        id="user-1",
        display_name="Ada Lovelace",
        user_principal_name="ada@example.com",
        account_enabled=True,
        user_type="Member",
        sign_in_activity=SimpleNamespace(
            last_sign_in_date_time=datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc),
            last_successful_sign_in_date_time=datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc),
            last_non_interactive_sign_in_date_time=datetime(
                2026, 8, 10, 2, 0, tzinfo=timezone.utc
            ),
        ),
    )
    assert mfa.project_user(user) == USER_ENABLED


def test_project_user_survives_an_absent_sign_in_activity():
    """`signInActivity` is absent for a never-signed-in account AND without AuditLog.Read.All."""
    mfa = _load("entra_mfa_status")
    projected = mfa.project_user(
        SimpleNamespace(id="user-9", display_name="New", account_enabled=True)
    )  # must not raise
    assert projected["last_sign_in"] is None
    assert projected["last_successful_sign_in"] is None
    assert projected["user_principal_name"] is None


def test_project_registration_details_reads_graph_attributes():
    mfa = _load("entra_mfa_status")
    detail = SimpleNamespace(
        id="user-1",
        is_mfa_capable=True,
        is_mfa_registered=True,
        is_passwordless_capable=True,
        is_sspr_capable=True,
        is_sspr_registered=True,
        is_admin=True,
        methods_registered=["microsoftAuthenticatorPush", "fido2SecurityKey"],
        last_updated_date_time=datetime(2026, 8, 12, tzinfo=timezone.utc),
        user_preferred_method_for_secondary_authentication="push",
    )
    assert mfa.project_registration_details(detail) == REGISTRATION_MFA_ADMIN


def test_mfa_user_record_coerces_absent_booleans_to_false():
    """Graph omits a false-y field rather than sending `false`.

    A validator regex asserting `"is_mfa_capable": false` would not match `null`, and
    a user with no registration-details row has registered nothing — so both absences
    must read as False, while `has_registration_details` keeps them distinguishable.
    """
    mfa = _load("entra_mfa_status")
    rec = mfa.user_record(USER_ENABLED, None)
    assert rec["is_mfa_capable"] is False
    assert rec["is_mfa_registered"] is False
    assert rec["is_passwordless_capable"] is False
    assert rec["is_admin"] is False
    assert rec["has_registration_details"] is False
    assert rec["methods_registered"] == []

    # A row present but with every flag omitted reads the same way on the flags...
    sparse = mfa.user_record(USER_ENABLED, {"id": "user-1"})
    assert sparse["is_mfa_capable"] is False
    # ... but is still distinguishable from "not in the report at all".
    assert sparse["has_registration_details"] is True


def test_mfa_user_record_reads_an_absent_account_enabled_as_enabled():
    """Prowler defaults accountEnabled to True, and dropping the user would understate risk.

    The field is only absent when it was not selected; assuming disabled would quietly
    remove the account from the coverage denominator.
    """
    mfa = _load("entra_mfa_status")
    rec = mfa.user_record({**USER_ENABLED, "account_enabled": None}, REGISTRATION_MFA_ADMIN)
    assert rec["account_enabled"] is True
    assert mfa.user_record(USER_DISABLED, None)["account_enabled"] is False


def test_mfa_user_record_joins_the_registration_details():
    mfa = _load("entra_mfa_status")
    rec = mfa.user_record(USER_ENABLED, REGISTRATION_MFA_ADMIN)
    assert rec["is_mfa_capable"] is True
    assert rec["is_passwordless_capable"] is True
    assert rec["is_admin"] is True
    assert rec["is_guest"] is False
    assert rec["methods_registered"] == ["fido2SecurityKey", "microsoftAuthenticatorPush"]
    assert rec["preferred_secondary_method"] == "push"
    assert rec["registration_last_updated"] == "2026-08-12T00:00:00Z"
    assert mfa.user_record(USER_GUEST, None)["is_guest"] is True


def test_mfa_join_users_matches_on_the_object_id_and_sorts_stably():
    """userRegistrationDetails.id IS the user's object id, which makes the join a lookup."""
    mfa = _load("entra_mfa_status")
    joined = mfa.join_users(
        [USER_GUEST, USER_ENABLED, USER_DISABLED],
        [REGISTRATION_MFA_ADMIN, {"id": "nobody", "is_mfa_capable": True}],
    )
    assert [u["user_principal_name"] for u in joined] == [
        "ada@example.com",
        "guest_ext#EXT#@example.com",
        "old@example.com",
    ]
    assert joined[0]["is_mfa_capable"] is True
    # A registration row for a user that is not in the users list is simply unused —
    # it must not invent a user record.
    assert len(joined) == 3


def test_mfa_summary_measures_coverage_over_enabled_users():
    """The disabled account must not drag the headline percentage down.

    A disabled account cannot sign in, so counting it as uncovered makes a well-run
    tenant with years of deprovisioned accounts look worse than a small neglected one.
    Both readings are reported so neither can be accused of cherry-picking.
    """
    mfa = _load("entra_mfa_status")
    users = mfa.join_users(
        [USER_ENABLED, USER_DISABLED, USER_GUEST], [REGISTRATION_MFA_ADMIN]
    )
    summary = mfa.summarize(users)

    assert summary["total_users"] == 3
    assert summary["enabled_users"] == 2      # Ada + the guest
    assert summary["disabled_users"] == 1
    assert summary["guest_users"] == 1
    assert summary["mfa_capable_users"] == 1
    assert summary["mfa_capable_enabled_users"] == 1
    # 1 of the 2 enabled users, NOT 1 of 3.
    assert summary["mfa_coverage_percentage"] == 50
    assert summary["mfa_coverage_percentage_all_users"] == 33
    assert summary["enabled_users_without_mfa"] == 1
    # Members only (guests excluded): Ada is the only enabled member, and she is covered.
    assert summary["enabled_member_users"] == 1
    assert summary["member_mfa_coverage_percentage"] == 100
    assert summary["admin_users"] == 1
    assert summary["mfa_capable_admin_users"] == 1
    assert summary["admin_mfa_coverage_percentage"] == 100
    assert summary["passwordless_capable_enabled_users"] == 1
    assert summary["passwordless_coverage_percentage"] == 50
    # Two users had no registration row; that assumption stays visible.
    assert summary["users_without_registration_details"] == 2
    assert summary["users_never_signed_in"] == 1


def test_mfa_summary_empty_tenant():
    mfa = _load("entra_mfa_status")
    summary = mfa.summarize([])
    assert summary["total_users"] == 0
    assert summary["mfa_coverage_percentage"] == 0
    assert summary["admin_mfa_coverage_percentage"] == 0


# --------------------------------------------------------------------------- #
# entra_privileged_roles — project_directory_role() / project_member() output,
# then the transforms
# --------------------------------------------------------------------------- #

ROLE_GLOBAL_ADMIN = {  # SYNTHETIC — project_directory_role()'s output shape
    "id": "role-ga",
    "role_template_id": "62e90394-69f5-4237-9190-012177145e10",
    "display_name": "Global Administrator",
    "description": "Can manage all aspects of Microsoft Entra ID.",
}

ROLE_DIRECTORY_READERS = {  # SYNTHETIC — an activated but NOT privileged role
    "id": "role-dr",
    "role_template_id": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
    "display_name": "Directory Readers",
    "description": "Can read basic directory information.",
}

MEMBER_USER = {  # SYNTHETIC — project_member()'s output shape
    "id": "user-1",
    "odata_type": "#microsoft.graph.user",
    "display_name": "Ada Lovelace",
    "user_principal_name": "ada@example.com",
    "account_enabled": True,
}

MEMBER_SERVICE_PRINCIPAL = {  # SYNTHETIC — a workload identity holding a role
    "id": "sp-1",
    "odata_type": "#microsoft.graph.servicePrincipal",
    "display_name": "terraform-deployer",
    "user_principal_name": None,
    "account_enabled": None,
}

MEMBER_GROUP = {  # SYNTHETIC — a role-assignable group
    "id": "group-1",
    "odata_type": "#microsoft.graph.group",
    "display_name": "Platform Admins",
    "user_principal_name": None,
    "account_enabled": None,
}


def test_project_directory_role_reads_graph_attributes():
    priv = _load("entra_privileged_roles")
    role = SimpleNamespace(
        id="role-ga",
        role_template_id="62e90394-69f5-4237-9190-012177145e10",
        display_name="Global Administrator",
        description="Can manage all aspects of Microsoft Entra ID.",
    )
    assert priv.project_directory_role(role) == ROLE_GLOBAL_ADMIN


def test_project_member_reads_the_concrete_subclass_attributes():
    """The collection is typed directoryObject; kiota deserializes the real subclass.

    A Group has no `user_principal_name`, and reading it must yield None rather than
    raising — which is what lets ONE projection read every principal kind.
    """
    priv = _load("entra_privileged_roles")
    user = SimpleNamespace(
        id="user-1",
        odata_type="#microsoft.graph.user",
        display_name="Ada Lovelace",
        user_principal_name="ada@example.com",
        account_enabled=True,
    )
    assert priv.project_member(user) == MEMBER_USER

    group = SimpleNamespace(
        id="group-1", odata_type="#microsoft.graph.group", display_name="Platform Admins"
    )
    assert priv.project_member(group) == MEMBER_GROUP

    # A bare directoryObject with only an id must also be safe.
    bare = priv.project_member(SimpleNamespace(id="x"))
    assert bare == {
        "id": "x",
        "odata_type": None,
        "display_name": None,
        "user_principal_name": None,
        "account_enabled": None,
    }


@pytest.mark.parametrize(
    ("odata_type", "expected"),
    [
        ("#microsoft.graph.user", "User"),
        ("#microsoft.graph.group", "Group"),
        ("#microsoft.graph.servicePrincipal", "ServicePrincipal"),
        ("#microsoft.graph.device", "Device"),
        # An unmapped kind is reported as itself rather than collapsed to "Unknown":
        # the point of the field is to say WHAT holds the role.
        ("#microsoft.graph.someFutureThing", "SomeFutureThing"),
        (None, "Unknown"),
        ("", "Unknown"),
    ],
)
def test_member_type_maps_odata_type_to_a_principal_kind(odata_type, expected):
    priv = _load("entra_privileged_roles")
    assert priv.member_type(odata_type) == expected


def test_privileged_role_detection_matches_on_name_and_on_the_ga_template_id():
    """Name first, template id second — the redundancy is what makes it safe.

    Prowler's directory-role code matches on the display name (their config.py carries
    ARM RBAC GUIDs, which are a different id space from Entra role template ids), so
    the name is the primary key here too. The template-id fallback means the single
    most consequential role is still caught if it ever came back renamed.
    """
    priv = _load("entra_privileged_roles")
    assert priv.is_privileged_role(ROLE_GLOBAL_ADMIN) is True
    assert priv.is_privileged_role(ROLE_DIRECTORY_READERS) is False
    assert priv.is_privileged_role({"display_name": "Privileged Role Administrator"}) is True
    assert priv.is_privileged_role({"display_name": "Application Administrator"}) is True
    assert priv.is_privileged_role({"display_name": "Guest Inviter"}) is False
    # Recognized by template id alone, even under an unexpected display name.
    assert (
        priv.is_privileged_role(
            {
                "display_name": "Company Administrator",
                "role_template_id": priv.GLOBAL_ADMINISTRATOR_TEMPLATE_ID.upper(),
            }
        )
        is True
    )
    assert priv.is_privileged_role({}) is False


def test_directory_role_record_counts_members_by_principal_kind():
    """A group or service principal holding a privileged role is a distinct finding.

    A role-assignable group moves the real access decision somewhere else, and a
    service principal has no interactive sign-in for MFA or Conditional Access to gate.
    """
    priv = _load("entra_privileged_roles")
    rec = priv.directory_role_record(
        ROLE_GLOBAL_ADMIN, [MEMBER_SERVICE_PRINCIPAL, MEMBER_USER, MEMBER_GROUP]
    )
    assert rec["is_privileged"] is True
    assert rec["is_global_administrator"] is True
    assert rec["member_count"] == 3
    assert rec["user_member_count"] == 1
    assert rec["group_member_count"] == 1
    assert rec["service_principal_member_count"] == 1
    # Sorted by principal name (upn, else display name) for byte-stable re-runs.
    assert [m["display_name"] for m in rec["members"]] == [
        "Ada Lovelace",
        "Platform Admins",
        "terraform-deployer",
    ]
    # accountEnabled is None (not False) on a non-user principal: absent means
    # "not applicable" here, not "disabled".
    assert rec["members"][1]["account_enabled"] is None
    assert rec["members"][0]["account_enabled"] is True


def test_directory_role_record_with_no_members():
    """An activated role with no members was assigned once and revoked."""
    priv = _load("entra_privileged_roles")
    rec = priv.directory_role_record(ROLE_DIRECTORY_READERS, [])
    assert rec["member_count"] == 0
    assert rec["members"] == []
    assert rec["is_privileged"] is False
    assert rec["is_global_administrator"] is False


def test_privileged_roles_summary_headline_is_the_global_admin_count():
    priv = _load("entra_privileged_roles")
    roles = [
        priv.directory_role_record(ROLE_GLOBAL_ADMIN, [MEMBER_USER, MEMBER_SERVICE_PRINCIPAL]),
        priv.directory_role_record(
            {
                "id": "role-aa",
                # A DIFFERENT template id — reusing Global Administrator's would make
                # this role count as a second Global Administrator role.
                "role_template_id": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                "display_name": "Application Administrator",
                "description": "Can create and manage app registrations.",
            },
            [MEMBER_USER],
        ),
        priv.directory_role_record(ROLE_DIRECTORY_READERS, [MEMBER_GROUP]),
    ]
    summary = priv.summarize(roles)

    assert summary["total_directory_roles_activated"] == 3
    assert summary["total_role_assignments"] == 4
    assert summary["global_administrator_count"] == 2
    assert summary["global_administrator_role_activated"] is True
    assert summary["privileged_roles_activated"] == 2
    assert summary["privileged_roles_with_members"] == 2
    assert summary["privileged_role_names_assigned"] == [
        "Application Administrator",
        "Global Administrator",
    ]
    assert summary["privileged_role_assignments"] == 3
    # Ada holds BOTH privileged roles, so three assignments are two humans/identities.
    assert summary["distinct_privileged_principals"] == 2
    assert summary["distinct_principals_with_a_directory_role"] == 3
    assert summary["users_in_privileged_roles"] == 2
    assert summary["service_principals_in_privileged_roles"] == 1
    assert summary["groups_in_privileged_roles"] == 0
    assert summary["privileged_assignment_percentage"] == 75
    assert summary["roles_with_no_members"] == 0


def test_privileged_roles_summary_empty_tenant():
    priv = _load("entra_privileged_roles")
    summary = priv.summarize([])
    assert summary["total_directory_roles_activated"] == 0
    assert summary["global_administrator_count"] == 0
    assert summary["global_administrator_role_activated"] is False
    assert summary["privileged_assignment_percentage"] == 0


# --------------------------------------------------------------------------- #
# entra_conditional_access_policies — project_conditional_access_policy() output,
# then the transforms
# --------------------------------------------------------------------------- #

CA_MFA_ALL_USERS = {  # SYNTHETIC — project_conditional_access_policy()'s output shape
    "id": "policy-1",
    "display_name": "Require MFA for everyone",
    "state": "enabled",
    "created_date_time": "2026-01-01T00:00:00Z",
    "modified_date_time": "2026-06-01T00:00:00Z",
    "include_users": ["All"],
    "exclude_users": ["breakglass-1"],
    "include_groups": [],
    "exclude_groups": [],
    "include_roles": [],
    "exclude_roles": [],
    "include_applications": ["All"],
    "exclude_applications": [],
    "include_user_actions": [],
    "client_app_types": ["all"],
    "sign_in_risk_levels": [],
    "user_risk_levels": [],
    "include_platforms": [],
    "exclude_platforms": [],
    "include_locations": [],
    "exclude_locations": ["trusted-location-1"],
    "built_in_controls": ["mfa"],
    "grant_controls_operator": "OR",
    "authentication_strength": None,
    "terms_of_use": [],
    "has_sign_in_frequency": True,
    "has_persistent_browser": False,
    "has_application_enforced_restrictions": False,
    "has_cloud_app_security": False,
}

CA_BLOCK_LEGACY_REPORT_ONLY = {  # SYNTHETIC — a report-only blocking policy
    "id": "policy-2",
    "display_name": "Block legacy authentication",
    "state": "enabledForReportingButNotEnforced",
    "created_date_time": "2026-02-01T00:00:00Z",
    "modified_date_time": None,
    "include_users": ["All"],
    "exclude_users": [],
    "include_groups": [],
    "exclude_groups": [],
    "include_roles": [],
    "exclude_roles": [],
    "include_applications": ["All"],
    "exclude_applications": [],
    "include_user_actions": [],
    "client_app_types": ["exchangeActiveSync", "other"],
    "sign_in_risk_levels": [],
    "user_risk_levels": [],
    "include_platforms": [],
    "exclude_platforms": [],
    "include_locations": [],
    "exclude_locations": [],
    "built_in_controls": ["block"],
    "grant_controls_operator": "OR",
    "authentication_strength": None,
    "terms_of_use": [],
    "has_sign_in_frequency": False,
    "has_persistent_browser": False,
    "has_application_enforced_restrictions": False,
    "has_cloud_app_security": False,
}


class FakeCAState(Enum):
    ENABLED = "enabled"


class FakeGrantControl(Enum):
    """Stand-in for `ConditionalAccessGrantControl`.

    The class NAME containing "Grant" is the whole point — that is what makes
    Prowler's `"Grant" in str(control)` test true for Block as well.
    """

    BLOCK = "block"
    MFA = "mfa"


def test_project_conditional_access_policy_reads_graph_attributes():
    ca = _load("entra_conditional_access_policies")
    policy = SimpleNamespace(
        id="policy-1",
        display_name="Require MFA for everyone",
        state=FakeCAState.ENABLED,
        created_date_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified_date_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
        conditions=SimpleNamespace(
            users=SimpleNamespace(include_users=["All"], exclude_users=["breakglass-1"]),
            applications=SimpleNamespace(include_applications=["All"]),
            client_app_types=["all"],
            locations=SimpleNamespace(exclude_locations=["trusted-location-1"]),
        ),
        grant_controls=SimpleNamespace(
            built_in_controls=[FakeGrantControl.MFA], operator="OR"
        ),
        session_controls=SimpleNamespace(sign_in_frequency=SimpleNamespace(value=1)),
    )
    assert ca.project_conditional_access_policy(policy) == CA_MFA_ALL_USERS


def test_project_conditional_access_policy_survives_absent_nested_blocks():
    """`grant_controls` is None on a session-controls-only policy, and every
    sub-block of `conditions` is omitted when unset."""
    ca = _load("entra_conditional_access_policies")
    projected = ca.project_conditional_access_policy(
        SimpleNamespace(id="p", display_name="bare", state=None)
    )  # must not raise
    assert projected["built_in_controls"] == []
    assert projected["include_users"] == []
    assert projected["include_applications"] == []
    assert projected["client_app_types"] == []
    assert projected["authentication_strength"] is None
    assert projected["has_sign_in_frequency"] is False

    # ... and the transform lands on the conservative default rather than None.
    rec = ca.policy_record(projected)
    assert rec["state"] == "disabled"
    assert rec["is_enforced"] is False
    assert rec["requires_mfa"] is False


def test_ca_grant_block_split_does_not_inherit_prowlers_enum_repr_bug():
    """Prowler's split is `"Grant" in str(control)`, which is true for EVERY member.

    These are plain `Enum`s, so `str()` yields the member's repr —
    "ConditionalAccessGrantControl.Block" — and the CLASS name contains "Grant". So
    Prowler's `block` list is always empty and its `grant` list always holds
    everything. Splitting on the wire VALUE instead is the only correct reading:
    exactly one member, `block`, denies access.
    """
    ca = _load("entra_conditional_access_policies")

    # Pin the trap itself, so this test explains why the code looks the way it does.
    assert "Grant" in str(FakeGrantControl.BLOCK)
    assert "Grant" in str(FakeGrantControl.MFA)

    assert ca.split_access_controls(["block"]) == {"block": ["block"], "grant": []}
    assert ca.split_access_controls(["mfa", "compliantDevice"]) == {
        "block": [],
        "grant": ["compliantDevice", "mfa"],
    }
    assert ca.split_access_controls(["Block"]) == {"block": ["Block"], "grant": []}
    assert ca.split_access_controls([]) == {"block": [], "grant": []}
    assert ca.split_access_controls(None) == {"block": [], "grant": []}


def test_ca_policy_record_derives_the_flags_a_reviewer_needs():
    ca = _load("entra_conditional_access_policies")
    rec = ca.policy_record(CA_MFA_ALL_USERS)
    assert rec["state"] == "enabled"
    assert rec["is_enforced"] is True
    assert rec["is_report_only"] is False
    assert rec["requires_mfa"] is True
    assert rec["blocks_access"] is False
    assert rec["targets_all_users"] is True
    assert rec["targets_all_applications"] is True
    assert rec["has_user_exclusions"] is True
    assert rec["users"]["exclude"] == ["breakglass-1"]
    assert rec["access_controls"]["grant"] == ["mfa"]
    assert rec["access_controls"]["block"] == []
    assert rec["session_controls"]["sign_in_frequency"] is True
    assert rec["conditions"]["exclude_locations"] == ["trusted-location-1"]

    blocking = ca.policy_record(CA_BLOCK_LEGACY_REPORT_ONLY)
    assert blocking["is_enforced"] is False
    assert blocking["is_report_only"] is True
    assert blocking["blocks_access"] is True
    assert blocking["requires_mfa"] is False
    assert blocking["targets_legacy_authentication"] is True


def test_ca_authentication_strength_counts_as_requiring_mfa():
    """An authentication-strength policy expresses the MFA requirement differently.

    It sets `grantControls.authenticationStrength` instead of putting `mfa` in
    builtInControls, so reading only builtInControls would report a
    phishing-resistant-MFA policy as requiring nothing.
    """
    ca = _load("entra_conditional_access_policies")
    rec = ca.policy_record(
        {
            **CA_MFA_ALL_USERS,
            "built_in_controls": [],
            "authentication_strength": "Phishing-resistant MFA",
        }
    )
    assert rec["requires_mfa"] is True
    assert rec["access_controls"]["authentication_strength"] == "Phishing-resistant MFA"


def test_ca_compliant_device_requirement_is_detected():
    ca = _load("entra_conditional_access_policies")
    rec = ca.policy_record({**CA_MFA_ALL_USERS, "built_in_controls": ["compliantDevice"]})
    assert rec["requires_compliant_device"] is True
    assert rec["requires_mfa"] is False


def test_ca_policy_record_falls_back_to_user_actions_for_target_resources():
    """A policy can target a user ACTION rather than an application.

    Reading only includeApplications would report such a policy as targeting nothing,
    which is why Prowler falls back the same way.
    """
    ca = _load("entra_conditional_access_policies")
    rec = ca.policy_record(
        {
            **CA_MFA_ALL_USERS,
            "include_applications": [],
            "include_user_actions": ["urn:user:registersecurityinfo"],
        }
    )
    assert rec["target_resources"]["include"] == ["urn:user:registersecurityinfo"]
    assert rec["targets_all_applications"] is False


def test_ca_summary_never_counts_a_report_only_policy_as_enforcement():
    """Report-only is the most common way this evidence gets misread.

    Such a policy logs what it WOULD have done and enforces nothing, so it must not
    land in any count of what the tenant actually enforces.
    """
    ca = _load("entra_conditional_access_policies")
    policies = [
        ca.policy_record(CA_MFA_ALL_USERS),
        ca.policy_record(CA_BLOCK_LEGACY_REPORT_ONLY),
        ca.policy_record({**CA_MFA_ALL_USERS, "id": "policy-3", "state": "disabled"}),
    ]
    summary = ca.summarize(policies)

    assert summary["total_policies"] == 3
    assert summary["enabled_policies"] == 1
    assert summary["report_only_policies"] == 1
    assert summary["disabled_policies"] == 1
    assert summary["enforced_percentage"] == 33
    # The MFA policy is the only enforced one, so every "what it does" count is 1 or 0.
    assert summary["enforced_policies_requiring_mfa"] == 1
    # The blocking policy is report-only, so it does NOT count as blocking.
    assert summary["enforced_policies_blocking_access"] == 0
    assert summary["enforced_policies_targeting_legacy_authentication"] == 0
    assert summary["enforced_policies_targeting_all_users"] == 1
    assert summary["enforced_mfa_for_all_users_and_apps"] == 1
    assert summary["enforced_policies_with_session_controls"] == 1
    assert summary["enforced_policies_with_exclusions"] == 1
    assert summary["distinct_excluded_principals"] == 1


def test_ca_summary_admin_portal_and_management_api_coverage():
    """The CIS Azure clauses: enabled + All users + that resource + MFA."""
    ca = _load("entra_conditional_access_policies")

    # A policy targeting All applications covers both named resources.
    covered = ca.summarize([ca.policy_record(CA_MFA_ALL_USERS)])
    assert covered["mfa_required_for_admin_portals"] is True
    assert covered["mfa_required_for_azure_management_api"] is True

    # Named explicitly rather than via All.
    admin_only = ca.summarize(
        [
            ca.policy_record(
                {**CA_MFA_ALL_USERS, "include_applications": [ca.MICROSOFT_ADMIN_PORTALS]}
            )
        ]
    )
    assert admin_only["mfa_required_for_admin_portals"] is True
    assert admin_only["mfa_required_for_azure_management_api"] is False

    # Report-only does not protect anything...
    report_only = ca.summarize(
        [ca.policy_record({**CA_MFA_ALL_USERS, "state": "enabledForReportingButNotEnforced"})]
    )
    assert report_only["mfa_required_for_admin_portals"] is False

    # ... and neither does an enabled MFA policy scoped to one pilot group.
    pilot = ca.summarize(
        [ca.policy_record({**CA_MFA_ALL_USERS, "include_users": ["group-pilot"]})]
    )
    assert pilot["mfa_required_for_admin_portals"] is False


def test_ca_summary_empty_tenant():
    """0 policies is ambiguous on a free-tier tenant — see the fetcher's note."""
    ca = _load("entra_conditional_access_policies")
    summary = ca.summarize([])
    assert summary["total_policies"] == 0
    assert summary["enforced_percentage"] == 0
    assert summary["mfa_required_for_admin_portals"] is False


# --------------------------------------------------------------------------- #
# entra_app_registrations — project_application() output, then the transforms
# --------------------------------------------------------------------------- #

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

APP_MIXED_CREDENTIALS = {  # SYNTHETIC — project_application()'s output shape
    "id": "app-object-1",
    "app_id": "44444444-4444-4444-4444-444444444444",
    "display_name": "ci-deployer",
    "created_date_time": "2024-01-01T00:00:00Z",
    "sign_in_audience": "AzureADMyOrg",
    "credentials": [
        {
            "display_name": "rotated-secret",
            "credential_type": "password",
            "key_id": "55555555-5555-5555-5555-555555555555",
            "start_date_time": "2026-01-01T00:00:00Z",
            "end_date_time": "2027-01-01T00:00:00Z",   # healthy: ~140 days out
            "usage": None,
            "certificate_type": None,
        },
        {
            "display_name": "old-secret",
            "credential_type": "password",
            "key_id": "66666666-6666-6666-6666-666666666666",
            "start_date_time": "2023-01-01T00:00:00Z",
            "end_date_time": "2024-01-01T00:00:00Z",   # expired
            "usage": None,
            "certificate_type": None,
        },
        {
            "display_name": "signing-cert",
            "credential_type": "certificate",
            "key_id": "77777777-7777-7777-7777-777777777777",
            "start_date_time": "2026-01-01T00:00:00Z",
            "end_date_time": "2026-08-20T00:00:00Z",   # expiring soon: 5 days out
            "usage": "Verify",
            "certificate_type": "AsymmetricX509Cert",
        },
        {
            "display_name": "never-expires",
            "credential_type": "password",
            "key_id": "88888888-8888-8888-8888-888888888888",
            "start_date_time": "2026-01-01T00:00:00Z",
            "end_date_time": None,                      # the worst case
            "usage": None,
            "certificate_type": None,
        },
    ],
}

APP_NO_CREDENTIALS = {  # SYNTHETIC — a federated-identity app with nothing to rotate
    "id": "app-object-2",
    "app_id": "99999999-9999-9999-9999-999999999999",
    "display_name": "workload-identity-app",
    "created_date_time": "2026-05-01T00:00:00Z",
    "sign_in_audience": "AzureADMultipleOrgs",
    "credentials": [],
}


def test_project_application_reads_both_credential_collections():
    apps = _load("entra_app_registrations")
    app = SimpleNamespace(
        id="app-object-1",
        app_id="44444444-4444-4444-4444-444444444444",
        display_name="ci-deployer",
        created_date_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        sign_in_audience="AzureADMyOrg",
        password_credentials=[
            SimpleNamespace(
                display_name="rotated-secret",
                key_id="55555555-5555-5555-5555-555555555555",
                start_date_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                end_date_time=datetime(2027, 1, 1, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                display_name="old-secret",
                key_id="66666666-6666-6666-6666-666666666666",
                start_date_time=datetime(2023, 1, 1, tzinfo=timezone.utc),
                end_date_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                display_name="never-expires",
                key_id="88888888-8888-8888-8888-888888888888",
                start_date_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                end_date_time=None,
            ),
        ],
        key_credentials=[
            SimpleNamespace(
                display_name="signing-cert",
                key_id="77777777-7777-7777-7777-777777777777",
                start_date_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                end_date_time=datetime(2026, 8, 20, tzinfo=timezone.utc),
                usage="Verify",
                type="AsymmetricX509Cert",
            )
        ],
    )
    projected = apps.project_application(app)
    # Passwords first, then certificates — the order the projection concatenates them.
    assert [c["display_name"] for c in projected["credentials"]] == [
        "rotated-secret",
        "old-secret",
        "never-expires",
        "signing-cert",
    ]
    assert [c["credential_type"] for c in projected["credentials"]] == [
        "password",
        "password",
        "password",
        "certificate",
    ]
    assert projected["app_id"] == "44444444-4444-4444-4444-444444444444"
    assert projected["created_date_time"] == "2024-01-01T00:00:00Z"
    # secretText is deliberately never projected: Graph only returns it on create,
    # and a field that is always null would mislead a reader of the evidence.
    assert "secret_text" not in projected["credentials"][0]


def test_project_application_survives_absent_credential_collections():
    """Graph omits both collections when empty rather than sending []."""
    apps = _load("entra_app_registrations")
    projected = apps.project_application(
        SimpleNamespace(id="app-object-2", display_name="workload-identity-app")
    )  # must not raise
    assert projected["credentials"] == []
    assert projected["app_id"] is None


@pytest.mark.parametrize(
    ("end_date_time", "expected"),
    [
        # (has_expiry, expired, expiring_soon, healthy)
        ("2027-01-01T00:00:00Z", (True, False, False, True)),    # ~140 days out
        ("2026-09-20T00:00:00Z", (True, False, False, True)),    # 36 days out
        ("2026-09-13T00:00:00Z", (True, False, True, False)),    # 30 days out: on the line
        ("2026-08-20T00:00:00Z", (True, False, True, False)),    # 5 days out
        ("2024-01-01T00:00:00Z", (True, True, False, False)),    # expired
        (None, (False, False, False, False)),                     # never expires
        ("not-a-timestamp", (False, False, False, False)),        # unparseable
    ],
)
def test_credential_expiry_classification(end_date_time, expected):
    """The three states are mutually exclusive, and the null case is its own.

    A never-expiring credential has `expired` and `expiring_soon` both False, so a
    reader checking only those two flags would see a clean record — which is exactly
    why `has_expiry` exists and is not treated as redundant.
    """
    apps = _load("entra_app_registrations")
    rec = apps.credential_record(
        {"credential_type": "password", "end_date_time": end_date_time}, NOW
    )
    assert (
        rec["has_expiry"],
        rec["expired"],
        rec["expiring_soon"],
        rec["healthy"],
    ) == expected
    assert rec["rotation_threshold_days"] == 30


def test_credential_record_reports_days_until_expiry():
    apps = _load("entra_app_registrations")
    rec = apps.credential_record(
        {"credential_type": "password", "end_date_time": "2026-08-20T00:00:00Z"}, NOW
    )
    assert rec["days_until_expiry"] == 5
    expired = apps.credential_record(
        {"credential_type": "password", "end_date_time": "2026-08-04T12:00:00Z"}, NOW
    )
    assert expired["days_until_expiry"] == -10
    assert expired["expired"] is True
    never = apps.credential_record({"credential_type": "password", "end_date_time": None}, NOW)
    assert never["days_until_expiry"] is None


def test_credential_record_treats_a_naive_timestamp_as_utc():
    """Graph always sends UTC; Prowler makes the same assumption explicitly."""
    apps = _load("entra_app_registrations")
    aware = apps.credential_record(
        {"credential_type": "password", "end_date_time": "2026-08-20T00:00:00Z"}, NOW
    )
    naive = apps.credential_record(
        {"credential_type": "password", "end_date_time": "2026-08-20T00:00:00"}, NOW
    )
    assert naive["days_until_expiry"] == aware["days_until_expiry"] == 5
    # A datetime that never went through the projection must work too.
    from_datetime = apps.credential_record(
        {"credential_type": "password", "end_date_time": NOW + timedelta(days=5)}, NOW
    )
    assert from_datetime["days_until_expiry"] == 5


def test_application_record_rolls_up_credential_health():
    apps = _load("entra_app_registrations")
    rec = apps.application_record(APP_MIXED_CREDENTIALS, NOW)
    assert rec["credential_count"] == 4
    assert rec["password_credential_count"] == 3
    assert rec["certificate_credential_count"] == 1
    assert rec["has_expired_credential"] is True
    assert rec["has_credential_expiring_soon"] is True
    assert rec["has_credential_without_expiry"] is True
    assert rec["all_credentials_healthy"] is False
    assert rec["is_single_tenant"] is True
    # Sorted by end date with the never-expiring credential last, so the soonest
    # expiry reads first and a re-run is byte-stable.
    assert [c["display_name"] for c in rec["credentials"]] == [
        "old-secret",
        "signing-cert",
        "rotated-secret",
        "never-expires",
    ]

    empty = apps.application_record(APP_NO_CREDENTIALS, NOW)
    assert empty["has_credentials"] is False
    # An app with nothing to rotate is NOT "all healthy" — that would let a tenant
    # improve its score by registering unused apps.
    assert empty["all_credentials_healthy"] is False
    assert empty["is_single_tenant"] is False


def test_app_registrations_summary_measures_rotation_over_credentials():
    """An app with one good and one stale secret has one thing to fix, not half a thing."""
    apps = _load("entra_app_registrations")
    records = [
        apps.application_record(APP_MIXED_CREDENTIALS, NOW),
        apps.application_record(APP_NO_CREDENTIALS, NOW),
    ]
    summary = apps.summarize(records)

    assert summary["total_app_registrations"] == 2
    assert summary["apps_with_credentials"] == 1
    assert summary["apps_without_credentials"] == 1
    assert summary["multi_tenant_apps"] == 1
    assert summary["total_credentials"] == 4
    assert summary["password_credentials"] == 3
    assert summary["certificate_credentials"] == 1
    # The three states stay separate.
    assert summary["expired_credentials"] == 1
    assert summary["credentials_expiring_soon"] == 1
    assert summary["credentials_without_expiry"] == 1
    assert summary["healthy_credentials"] == 1
    # 1 of 4 CREDENTIALS, and the credential-less app is not in the denominator.
    assert summary["credential_rotation_compliance_percentage"] == 25
    assert summary["rotation_threshold_days"] == 30
    assert summary["apps_with_expired_credentials"] == 1
    assert summary["apps_with_credentials_without_expiry"] == 1
    assert summary["apps_with_all_credentials_healthy"] == 0


def test_app_registrations_summary_empty_tenant():
    apps = _load("entra_app_registrations")
    summary = apps.summarize([])
    assert summary["total_app_registrations"] == 0
    assert summary["total_credentials"] == 0
    assert summary["credential_rotation_compliance_percentage"] == 0


# --------------------------------------------------------------------------- #
# rbac_role_assignments — project_role_assignment() output, then the transforms
# --------------------------------------------------------------------------- #

OWNER_GUID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_GUID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
UAA_GUID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
READER_GUID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

ASSIGNMENT_OWNER = {  # SYNTHETIC — project_role_assignment()'s output shape
    "id": (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/roleAssignments/aaaaaaaa-0000-0000-0000-000000000001"
    ),
    "name": "aaaaaaaa-0000-0000-0000-000000000001",
    "scope": f"/subscriptions/{SUBSCRIPTION}",
    "principal_id": "principal-1",
    "principal_type": "User",
    "role_definition_id": (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        f"/roleDefinitions/{OWNER_GUID}"
    ),
    "description": None,
    "condition": None,
    "condition_version": None,
    "created_on": "2026-01-01 00:00:00+00:00",
    "updated_on": "2026-01-01 00:00:00+00:00",
    "delegated_managed_identity_resource_id": None,
}

ASSIGNMENT_READER_ON_RG = {  # SYNTHETIC — a narrow, resource-group-scoped assignment
    "id": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg/providers"
        "/Microsoft.Authorization/roleAssignments/aaaaaaaa-0000-0000-0000-000000000002"
    ),
    "name": "aaaaaaaa-0000-0000-0000-000000000002",
    "scope": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg",
    "principal_id": "principal-2",
    "principal_type": "ServicePrincipal",
    "role_definition_id": (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        f"/roleDefinitions/{READER_GUID}"
    ),
    "description": "read-only monitoring",
    "condition": None,
    "condition_version": None,
    "created_on": None,
    "updated_on": None,
    "delegated_managed_identity_resource_id": None,
}

ROLE_NAMES = {  # SYNTHETIC — project_role_definition() output, keyed by lowered GUID
    OWNER_GUID: {"name": OWNER_GUID, "role_name": "Owner", "role_type": "BuiltInRole"},
    CONTRIBUTOR_GUID: {
        "name": CONTRIBUTOR_GUID,
        "role_name": "Contributor",
        "role_type": "BuiltInRole",
    },
    READER_GUID: {"name": READER_GUID, "role_name": "Reader", "role_type": "BuiltInRole"},
}


def test_project_role_assignment_reads_sdk_attributes():
    rbac = _load("rbac_role_assignments")
    assignment = SimpleNamespace(
        id=ASSIGNMENT_OWNER["id"],
        name=ASSIGNMENT_OWNER["name"],
        scope=ASSIGNMENT_OWNER["scope"],
        principal_id="principal-1",
        principal_type="User",
        role_definition_id=ASSIGNMENT_OWNER["role_definition_id"],
        created_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert rbac.project_role_assignment(assignment) == ASSIGNMENT_OWNER


def test_project_role_assignment_survives_a_bare_model():
    rbac = _load("rbac_role_assignments")
    projected = rbac.project_role_assignment(SimpleNamespace(id="x", name="x"))
    assert projected["principal_type"] is None
    assert projected["condition"] is None
    assert projected["created_on"] is None


def test_role_definition_guid_is_taken_from_the_tail():
    """The full role definition id is SCOPE-qualified; only the GUID is invariant.

    The same built-in role arrives under a different id depending on the scope it was
    read at, so comparing full ids against the constants would silently never match —
    which is why Prowler splits on "/" too.
    """
    rbac = _load("rbac_role_assignments")
    assert rbac.role_definition_guid(ASSIGNMENT_OWNER["role_definition_id"]) == OWNER_GUID
    assert (
        rbac.role_definition_guid(
            f"/providers/Microsoft.Management/managementGroups/mg1/providers"
            f"/Microsoft.Authorization/roleDefinitions/{OWNER_GUID}"
        )
        == OWNER_GUID
    )
    assert rbac.role_definition_guid(None) is None


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("/", "root"),
        ("/providers/Microsoft.Management/managementGroups/mg-root", "management_group"),
        (f"/subscriptions/{SUBSCRIPTION}", "subscription"),
        (f"/subscriptions/{SUBSCRIPTION}/", "subscription"),
        (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg", "resource_group"),
        # ARM is inconsistent about the segment's casing across API versions.
        (f"/subscriptions/{SUBSCRIPTION}/resourcegroups/paramify-rg", "resource_group"),
        (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg/providers"
            "/Microsoft.Storage/storageAccounts/pfdata",
            "resource",
        ),
        (None, "unknown"),
        ("", "unknown"),
        ("not-a-scope", "unknown"),
    ],
)
def test_scope_level_classifies_how_much_a_scope_covers(scope, expected):
    """The same role is a different fact at a different scope."""
    rbac = _load("rbac_role_assignments")
    assert rbac.scope_level(scope) == expected


def test_assignment_record_flags_over_broad_builtins_by_guid():
    rbac = _load("rbac_role_assignments")
    rec = rbac.assignment_record(ASSIGNMENT_OWNER, ROLE_NAMES)
    assert rec["role_name"] == "Owner"
    assert rec["role_name_resolved"] is True
    assert rec["is_over_broad_builtin"] is True
    assert rec["over_broad_role"] == "Owner"
    assert rec["can_grant_roles"] is True
    assert rec["at_subscription_scope"] is True
    assert rec["scope_level"] == "subscription"
    assert rec["inherited_from_above_subscription"] is False
    assert rec["is_custom_role"] is False
    assert rec["has_condition"] is False

    narrow = rbac.assignment_record(ASSIGNMENT_READER_ON_RG, ROLE_NAMES)
    assert narrow["role_name"] == "Reader"
    assert narrow["is_over_broad_builtin"] is False
    assert narrow["over_broad_role"] is None
    assert narrow["can_grant_roles"] is False
    assert narrow["at_subscription_scope"] is False
    assert narrow["scope_level"] == "resource_group"
    assert narrow["scope_resource_group"] == "paramify-rg"


def test_assignment_record_flags_an_unresolvable_role_by_guid_anyway():
    """Prowler's User Access Administrator check compares the RESOLVED NAME.

    An assignment inherited from a management group can reference a role definition
    this subscription's list call does not return, so the name lookup misses and
    Prowler reports a clean pass for exactly those assignments. Deciding on the GUID
    instead holds regardless, and `role_name_resolved: false` says the name is unknown
    rather than letting "unknown" look like a real role name.
    """
    rbac = _load("rbac_role_assignments")
    inherited = {
        **ASSIGNMENT_OWNER,
        "scope": "/providers/Microsoft.Management/managementGroups/mg-root",
        "role_definition_id": (
            "/providers/Microsoft.Management/managementGroups/mg-root/providers"
            f"/Microsoft.Authorization/roleDefinitions/{UAA_GUID}"
        ),
    }
    rec = rbac.assignment_record(inherited, {})  # empty lookup: nothing resolvable
    assert rec["role_name"] is None
    assert rec["role_name_resolved"] is False
    assert rec["is_over_broad_builtin"] is True
    assert rec["over_broad_role"] == "User Access Administrator"
    assert rec["can_grant_roles"] is True
    assert rec["inherited_from_above_subscription"] is True
    assert rec["at_subscription_scope"] is False


def test_assignment_record_matches_the_guid_case_insensitively():
    """ARM is inconsistent about GUID casing across API versions."""
    rbac = _load("rbac_role_assignments")
    upper = {
        **ASSIGNMENT_OWNER,
        "role_definition_id": ASSIGNMENT_OWNER["role_definition_id"].replace(
            OWNER_GUID, OWNER_GUID.upper()
        ),
    }
    assert rbac.assignment_record(upper, ROLE_NAMES)["is_over_broad_builtin"] is True


def test_assignment_record_reports_an_abac_condition():
    """A condition narrows a broad role's real reach, so it is its own fact."""
    rbac = _load("rbac_role_assignments")
    rec = rbac.assignment_record(
        {
            **ASSIGNMENT_OWNER,
            "condition": "@Resource[Microsoft.Storage/storageAccounts:name] StringEquals 'pfdata'",
            "condition_version": "2.0",
        },
        ROLE_NAMES,
    )
    assert rec["has_condition"] is True
    assert rec["condition_version"] == "2.0"
    # Still over-broad on paper — the condition is reported, not used to clear it.
    assert rec["is_over_broad_builtin"] is True


def test_role_assignments_summary_counts_breadth_and_distinct_principals():
    rbac = _load("rbac_role_assignments")
    contributor = {
        **ASSIGNMENT_OWNER,
        "id": ASSIGNMENT_OWNER["id"].replace("000001", "000003"),
        "name": "aaaaaaaa-0000-0000-0000-000000000003",
        # Same principal as the Owner assignment, at a resource group this time.
        "scope": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg",
        "role_definition_id": (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
            f"/roleDefinitions/{CONTRIBUTOR_GUID}"
        ),
    }
    assignments = [
        rbac.assignment_record(ASSIGNMENT_OWNER, ROLE_NAMES),
        rbac.assignment_record(ASSIGNMENT_READER_ON_RG, ROLE_NAMES),
        rbac.assignment_record(contributor, ROLE_NAMES),
    ]
    summary = rbac.summarize(assignments)

    assert summary["total_role_assignments"] == 3
    assert summary["distinct_principals"] == 2
    assert summary["over_broad_builtin_assignments"] == 2
    # Both over-broad assignments belong to the SAME principal — one identity to
    # review, not two.
    assert summary["distinct_principals_with_over_broad_roles"] == 1
    assert summary["over_broad_percentage"] == 66
    assert summary["least_privilege_assignments"] == 1
    assert summary["owner_assignments"] == 1
    assert summary["contributor_assignments"] == 1
    assert summary["user_access_administrator_assignments"] == 0
    assert summary["rbac_administrator_assignments"] == 0
    # Owner can delegate; Contributor cannot.
    assert summary["role_granting_assignments"] == 1
    assert summary["assignments_at_subscription_scope"] == 1
    assert summary["assignments_at_resource_group_scope"] == 2
    assert summary["assignments_at_management_group_scope"] == 0
    assert summary["over_broad_at_subscription_scope_or_above"] == 1
    assert summary["assignments_by_principal_type"] == {"User": 2, "ServicePrincipal": 1}
    assert summary["builtin_role_assignments"] == 3
    assert summary["unresolved_role_definitions"] == 0
    assert summary["custom_role_assignments"] == 0


def test_role_assignments_summary_counts_an_absent_principal_type_as_unknown():
    rbac = _load("rbac_role_assignments")
    summary = rbac.summarize(
        [rbac.assignment_record({**ASSIGNMENT_OWNER, "principal_type": None}, ROLE_NAMES)]
    )
    assert summary["assignments_by_principal_type"] == {"Unknown": 1}


def test_role_assignments_summary_empty_subscription():
    rbac = _load("rbac_role_assignments")
    summary = rbac.summarize([])
    assert summary["total_role_assignments"] == 0
    assert summary["over_broad_percentage"] == 0
    assert summary["assignments_by_principal_type"] == {}


def test_role_assignments_reuses_prowlers_role_guids():
    """These are Azure-wide constants; a wrong digit would silently stop matching."""
    rbac = _load("rbac_role_assignments")
    assert rbac.OWNER_ROLE_ID == "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    assert rbac.CONTRIBUTOR_ROLE_ID == "b24988ac-6180-42a0-ab88-20f7382dd24c"
    assert rbac.USER_ACCESS_ADMINISTRATOR_ROLE_ID == "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
    assert (
        rbac.ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID
        == "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
    )
    assert set(rbac.OVER_BROAD_BUILTIN_ROLES.values()) == {
        "Owner",
        "Contributor",
        "User Access Administrator",
        "Role Based Access Control Administrator",
    }
    # Contributor is broad but cannot delegate — that is what makes it Contributor.
    assert rbac.CONTRIBUTOR_ROLE_ID not in rbac.ROLE_GRANTING_ROLES
    assert rbac.OWNER_ROLE_ID in rbac.ROLE_GRANTING_ROLES


# --------------------------------------------------------------------------- #
# rbac_custom_roles — project_role_definition() output, then the transforms
# --------------------------------------------------------------------------- #

CUSTOM_ROLE_OWNER_EQUIVALENT = {  # SYNTHETIC — project_role_definition()'s output shape
    "id": (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/roleDefinitions/cccccccc-0000-0000-0000-000000000001"
    ),
    "name": "cccccccc-0000-0000-0000-000000000001",
    "role_name": "Deployment Reader",     # the name says Reader; the actions say Owner
    "role_type": "CustomRole",
    "description": "Deploys things.",
    "assignable_scopes": [f"/subscriptions/{SUBSCRIPTION}"],
    "permissions": [
        {"actions": ["*"], "not_actions": [], "data_actions": [], "not_data_actions": []}
    ],
    "created_on": "2026-01-01 00:00:00+00:00",
    "updated_on": None,
}

CUSTOM_ROLE_LEAST_PRIVILEGE = {  # SYNTHETIC — a genuinely narrow custom role
    "id": (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/roleDefinitions/cccccccc-0000-0000-0000-000000000002"
    ),
    "name": "cccccccc-0000-0000-0000-000000000002",
    "role_name": "Blob Lister",
    "role_type": "CustomRole",
    "description": "Lists blobs.",
    "assignable_scopes": [f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg"],
    "permissions": [
        {
            "actions": ["Microsoft.Storage/storageAccounts/read"],
            "not_actions": [],
            "data_actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
            "not_data_actions": [],
        }
    ],
    "created_on": None,
    "updated_on": None,
}


def test_project_role_definition_reads_sdk_attributes():
    roles = _load("rbac_custom_roles")
    definition = SimpleNamespace(
        id=CUSTOM_ROLE_OWNER_EQUIVALENT["id"],
        name=CUSTOM_ROLE_OWNER_EQUIVALENT["name"],
        role_name="Deployment Reader",
        role_type="CustomRole",
        description="Deploys things.",
        assignable_scopes=[f"/subscriptions/{SUBSCRIPTION}"],
        permissions=[
            SimpleNamespace(actions=["*"], not_actions=[], data_actions=[], not_data_actions=[])
        ],
        created_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_on=None,
    )
    assert roles.project_role_definition(definition) == CUSTOM_ROLE_OWNER_EQUIVALENT


def test_project_role_definition_reads_absent_action_lists_as_empty():
    """The SDK leaves an unset action list as None rather than an empty list."""
    roles = _load("rbac_custom_roles")
    projected = roles.project_role_definition(
        SimpleNamespace(id="x", name="x", role_name="Bare", role_type="CustomRole",
                        permissions=[SimpleNamespace(actions=["*/read"])])
    )  # must not raise
    assert projected["assignable_scopes"] == []
    assert projected["permissions"] == [
        {"actions": ["*/read"], "not_actions": [], "data_actions": [], "not_data_actions": []}
    ]


@pytest.mark.parametrize(
    ("pattern", "action", "expected"),
    [
        # An Azure action wildcard's `*` spans `/` — it is NOT a path glob.
        ("*", "Microsoft.Authorization/roleAssignments/write", True),
        ("*/write", "Microsoft.Authorization/roleAssignments/write", True),
        ("Microsoft.Authorization/*", "Microsoft.Authorization/roleAssignments/write", True),
        (
            "Microsoft.Authorization/roleAssignments/*",
            "Microsoft.Authorization/roleAssignments/write",
            True,
        ),
        (
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/roleAssignments/write",
            True,
        ),
        # ARM treats action strings case-insensitively; hand-written and
        # Terraform-generated roles differ in casing constantly.
        (
            "microsoft.authorization/roleassignments/write",
            "Microsoft.Authorization/roleAssignments/write",
            True,
        ),
        ("*/read", "Microsoft.Authorization/roleAssignments/write", False),
        ("Microsoft.Compute/*", "Microsoft.Authorization/roleAssignments/write", False),
        # A prefix without a wildcard must not match a longer action.
        ("Microsoft.Authorization", "Microsoft.Authorization/roleAssignments/write", False),
        ("", "anything", False),
        ("*", "", False),
    ],
)
def test_action_matches_uses_azures_wildcard_semantics(pattern, action, expected):
    """This is why the escalation check cannot be a literal `in` test.

    Prowler's checks compare action strings directly, so they see none of the wildcard
    forms above — every one of which confers roleAssignments/write.
    """
    roles = _load("rbac_custom_roles")
    assert roles.action_matches(pattern, action) is expected


def test_grants_action_subtracts_not_actions():
    """"Grant `*`, deny the dangerous bits" is the commonest least-privilege idiom.

    Ignoring notActions would report every such role as an escalation path — and it is
    exactly how the built-in Contributor role is defined.
    """
    roles = _load("rbac_custom_roles")
    write = roles.ROLE_ASSIGNMENT_WRITE

    wide_open = {"actions": ["*"], "not_actions": []}
    assert roles.grants_action(wide_open, write) is True

    # The real Contributor shape.
    contributor = {"actions": ["*"], "not_actions": ["Microsoft.Authorization/*/write"]}
    assert roles.grants_action(contributor, write) is False

    # A notAction that does not cover the action does not rescue it.
    narrow_deny = {"actions": ["*"], "not_actions": ["Microsoft.Compute/*"]}
    assert roles.grants_action(narrow_deny, write) is True

    # Nothing granted in the first place.
    read_only = {"actions": ["*/read"], "not_actions": []}
    assert roles.grants_action(read_only, write) is False


def test_role_grants_action_checks_each_block_independently():
    """Azure unions allow lists across blocks; each notActions subtracts from its own.

    So a permissive block is not rescued by a notActions in a different block.
    """
    roles = _load("rbac_custom_roles")
    write = roles.ROLE_ASSIGNMENT_WRITE
    two_blocks = {
        "permissions": [
            {"actions": ["*"], "not_actions": []},
            {"actions": ["*/read"], "not_actions": ["Microsoft.Authorization/*/write"]},
        ]
    }
    assert roles.role_grants_action(two_blocks, write) is True


def test_role_grants_action_ignores_the_data_plane():
    """`dataActions: ["*"]` cannot confer a management operation.

    Such a role can read every blob in the subscription but cannot write a role
    assignment, and testing the data plane here would report exactly that role as an
    escalation path.
    """
    roles = _load("rbac_custom_roles")
    data_only = {
        "permissions": [
            {"actions": [], "not_actions": [], "data_actions": ["*"], "not_data_actions": []}
        ]
    }
    assert roles.role_grants_action(data_only, roles.ROLE_ASSIGNMENT_WRITE) is False
    # Data-plane breadth is still reported, just not as escalation.
    rec = roles.custom_role_record({**CUSTOM_ROLE_LEAST_PRIVILEGE, **data_only})
    assert rec["has_data_actions"] is True
    assert rec["wildcard_actions"]["data_plane"] == ["*"]
    assert rec["can_escalate_privileges"] is False


def test_custom_role_record_flags_an_owner_equivalent_role():
    """A role named "Deployment Reader" that grants `*` is an Owner under another name."""
    roles = _load("rbac_custom_roles")
    rec = roles.custom_role_record(CUSTOM_ROLE_OWNER_EQUIVALENT)
    assert rec["role_name"] == "Deployment Reader"
    assert rec["role_definition_guid"] == CUSTOM_ROLE_OWNER_EQUIVALENT["name"]
    assert rec["has_wildcard_action"] is True
    assert rec["has_all_actions_wildcard"] is True
    assert rec["is_owner_equivalent"] is True
    assert rec["is_contributor_equivalent"] is False
    assert rec["can_assign_roles"] is True
    assert rec["can_write_role_definitions"] is True
    assert rec["can_escalate_privileges"] is True
    assert rec["privilege_escalation_actions"] == sorted(roles.PRIVILEGE_ESCALATION_ACTIONS)
    assert rec["can_administer_resource_locks"] is True
    assert rec["wildcard_actions"] == {"control_plane": ["*"], "data_plane": []}
    assert rec["has_root_assignable_scope"] is False


def test_custom_role_record_distinguishes_contributor_shaped_from_owner_shaped():
    """One permission separates the two built-ins, so it separates their clones too.

    Owner and Contributor both grant `*`; Contributor subtracts
    Microsoft.Authorization/*/write. Reporting a Contributor-shaped custom role as an
    Owner would be a false positive on a deliberately safe pattern.
    """
    roles = _load("rbac_custom_roles")
    rec = roles.custom_role_record(
        {
            **CUSTOM_ROLE_OWNER_EQUIVALENT,
            "permissions": [
                {
                    "actions": ["*"],
                    "not_actions": [
                        "Microsoft.Authorization/*/write",
                        "Microsoft.Authorization/*/delete",
                    ],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        }
    )
    assert rec["has_all_actions_wildcard"] is True
    assert rec["is_owner_equivalent"] is False
    assert rec["is_contributor_equivalent"] is True
    assert rec["can_assign_roles"] is False
    assert rec["can_escalate_privileges"] is False
    assert rec["has_not_actions"] is True
    # The lock power is also taken away by the same notAction.
    assert rec["can_administer_resource_locks"] is False


def test_custom_role_record_detects_escalation_behind_a_scoped_wildcard():
    """`Microsoft.Authorization/*` is the form a literal comparison misses."""
    roles = _load("rbac_custom_roles")
    rec = roles.custom_role_record(
        {
            **CUSTOM_ROLE_LEAST_PRIVILEGE,
            "permissions": [
                {
                    "actions": ["Microsoft.Authorization/*", "Microsoft.Compute/*/read"],
                    "not_actions": [],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        }
    )
    assert rec["has_all_actions_wildcard"] is False   # no bare `*`
    assert rec["is_owner_equivalent"] is False
    # ... but it can still make itself an Owner.
    assert rec["can_assign_roles"] is True
    assert rec["can_escalate_privileges"] is True
    assert roles.ROLE_ASSIGNMENT_WRITE in rec["privilege_escalation_actions"]
    assert rec["wildcard_actions"]["control_plane"] == [
        "Microsoft.Authorization/*",
        "Microsoft.Compute/*/read",
    ]


def test_custom_role_record_on_a_least_privilege_role():
    roles = _load("rbac_custom_roles")
    rec = roles.custom_role_record(CUSTOM_ROLE_LEAST_PRIVILEGE)
    assert rec["has_wildcard_action"] is False
    assert rec["is_owner_equivalent"] is False
    assert rec["is_contributor_equivalent"] is False
    assert rec["can_escalate_privileges"] is False
    assert rec["privilege_escalation_actions"] == []
    assert rec["can_administer_resource_locks"] is False
    assert rec["action_count"] == 1
    assert rec["data_action_count"] == 1
    assert rec["has_data_actions"] is True
    assert rec["has_not_actions"] is False
    assert rec["assignable_scope_count"] == 1


def test_custom_role_record_flags_a_root_assignable_scope():
    """A role assignable at "/" may be granted anywhere in the tenant."""
    roles = _load("rbac_custom_roles")
    rec = roles.custom_role_record(
        {**CUSTOM_ROLE_LEAST_PRIVILEGE, "assignable_scopes": ["/", f"/subscriptions/{SUBSCRIPTION}"]}
    )
    assert rec["has_root_assignable_scope"] is True
    assert rec["assignable_scope_count"] == 2


def test_custom_role_record_detects_explicit_lock_administration():
    """Prowler's literal Microsoft.Authorization/locks/ prefix match, generalized."""
    roles = _load("rbac_custom_roles")
    rec = roles.custom_role_record(
        {
            **CUSTOM_ROLE_LEAST_PRIVILEGE,
            "permissions": [
                {
                    "actions": ["Microsoft.Authorization/locks/*"],
                    "not_actions": [],
                    "data_actions": [],
                    "not_data_actions": [],
                }
            ],
        }
    )
    assert rec["can_administer_resource_locks"] is True
    assert rec["can_escalate_privileges"] is False


def test_custom_roles_summary_reports_the_builtin_count_so_zero_is_legible():
    """"0 custom roles" must not read the same as a call that returned nothing.

    A non-zero built-in count proves the list call worked, which is what makes the
    least-privilege ideal (no custom roles at all) distinguishable from a failure.
    """
    roles = _load("rbac_custom_roles")
    custom = [
        roles.custom_role_record(CUSTOM_ROLE_OWNER_EQUIVALENT),
        roles.custom_role_record(CUSTOM_ROLE_LEAST_PRIVILEGE),
    ]
    summary = roles.summarize(custom, total_definitions=120)

    assert summary["total_role_definitions"] == 120
    assert summary["builtin_role_definitions"] == 118
    assert summary["custom_role_definitions"] == 2
    assert summary["custom_roles_with_privilege_escalation"] == 1
    assert summary["custom_roles_that_can_assign_roles"] == 1
    assert summary["custom_roles_that_can_write_role_definitions"] == 1
    assert summary["custom_roles_with_escalation_names"] == ["Deployment Reader"]
    assert summary["custom_roles_with_wildcard_actions"] == 1
    assert summary["custom_roles_with_all_actions_wildcard"] == 1
    assert summary["owner_equivalent_custom_roles"] == 1
    assert summary["contributor_equivalent_custom_roles"] == 0
    assert summary["custom_roles_with_data_actions"] == 1
    assert summary["custom_roles_with_root_assignable_scope"] == 0
    assert summary["custom_roles_administering_resource_locks"] == 1
    assert summary["least_privilege_custom_roles"] == 1
    assert summary["least_privilege_percentage"] == 50


def test_custom_roles_summary_with_no_custom_roles():
    roles = _load("rbac_custom_roles")
    summary = roles.summarize([], total_definitions=120)
    assert summary["custom_role_definitions"] == 0
    assert summary["builtin_role_definitions"] == 120
    assert summary["least_privilege_percentage"] == 0
    assert summary["custom_roles_with_escalation_names"] == []


# --------------------------------------------------------------------------- #
# Contract wiring — every fetcher.yaml agrees with its fetcher.py
# --------------------------------------------------------------------------- #

GRAPH_FETCHERS = (
    "entra_mfa_status",
    "entra_privileged_roles",
    "entra_conditional_access_policies",
    "entra_app_registrations",
)
RBAC_FETCHERS = ("rbac_role_assignments", "rbac_custom_roles")
IDENTITY_FETCHERS = GRAPH_FETCHERS + RBAC_FETCHERS


def _spec(short_name: str) -> dict:
    import yaml

    return yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())


@pytest.mark.parametrize("short_name", IDENTITY_FETCHERS)
def test_fetcher_yaml_declares_the_ambient_credential_contract(short_name):
    spec = _spec(short_name)
    assert spec["name"] == f"azure_{short_name}"
    assert spec["category"] == "azure"
    assert spec["version"] == "0.1.0"
    assert spec["secrets"] == []  # DefaultAzureCredential — nothing handed over
    assert spec["supports_targets"] is True
    assert spec["runtime"] == {"type": "python", "entry": "fetcher.py"}
    assert spec["output"]["type"] == "json"
    assert spec["output"]["path"] == f"azure_{short_name}.json"
    assert spec["output"]["aggregation"] == "per_target"
    # The subscription_id target field is shared with the rest of the Azure category
    # so one manifest can carry a single target shape across all of them.
    assert spec["target_schema"]["subscription_id"]["env"] == "AZURE_SUBSCRIPTION_ID"
    assert spec["target_schema"]["subscription_id"]["required"] is False
    assert spec["target_schema"]["environment"]["env"] == "AZURE_ENVIRONMENT"
    assert spec["evidence_set"]["reference_id"].startswith("EVD-AZURE-")
    assert spec["evidence_set"]["name"]
    assert spec["evidence_set"]["instructions"]
    # ksis is deliberately omitted from this set of fetchers.
    assert "ksis" not in spec
    assert "validators" not in spec


@pytest.mark.parametrize("short_name", GRAPH_FETCHERS)
def test_graph_fetcher_yaml_declares_the_tenant_as_its_fanout_unit(short_name):
    """Graph data is tenant-wide, so the tenant is what a target must name."""
    spec = _spec(short_name)
    assert spec["target_schema"]["tenant_id"]["env"] == "AZURE_TENANT_ID"
    assert spec["target_schema"]["tenant_id"]["required"] is False
    instructions = spec["evidence_set"]["instructions"]
    # The omission of provider_registration_status has to be documented, or its
    # absence reads as an oversight next to the ARM fetchers that do call it.
    assert "tenant-wide" in instructions
    assert "resource provider" in instructions


@pytest.mark.parametrize("short_name", RBAC_FETCHERS)
def test_rbac_fetcher_yaml_stays_subscription_scoped(short_name):
    """The ARM half fans out per subscription and has no tenant_id field."""
    spec = _spec(short_name)
    assert "tenant_id" not in spec["target_schema"]
    assert "Microsoft.Authorization" in spec["evidence_set"]["instructions"]


def test_evidence_set_reference_ids_are_unique():
    ids = [_spec(s)["evidence_set"]["reference_id"] for s in IDENTITY_FETCHERS]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("short_name", IDENTITY_FETCHERS)
def test_every_fetcher_writes_a_status_file_before_a_non_zero_exit(short_name):
    """Statically pin the failure-reporting contract on all six.

    Without a $FETCHER_STATUS_FILE the runner falls back to the tail of stderr for
    metadata.error, which reports the last log line — often a harmless INFO — as the
    cause of the failure.
    """
    source = (AZURE_ROOT / short_name / "fetcher.py").read_text()
    assert "write_status(" in source
    assert "classify_failure_code(" in source
    assert "failure_reason(" in source
    # And the SDK loggers are quieted, or their per-request INFO lines dominate the
    # stderr tail the runner reports.
    assert 'logging.getLogger("azure").setLevel(logging.WARNING)' in source or (
        '"azure", "msgraph", "kiota", "httpx", "httpcore"' in source
    )


@pytest.mark.parametrize("short_name", GRAPH_FETCHERS)
def test_graph_fetchers_do_not_call_provider_registration_status(short_name):
    """There is no ARM resource provider behind Graph, and the omission is deliberate.

    Asserted rather than assumed: a later reader comparing these four against the ARM
    fetchers would otherwise be within their rights to "fix" the inconsistency.
    """
    source = (AZURE_ROOT / short_name / "fetcher.py").read_text()
    # Comments are stripped first — the omission IS documented in a comment naming the
    # helper, so a naive substring scan would match its own explanation.
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    assert "provider_registration_status" not in code
    # The reason must be written down next to the omission.
    assert "not an ARM resource provider" in source


@pytest.mark.parametrize("short_name", RBAC_FETCHERS)
def test_rbac_fetchers_ask_for_provider_registration_first(short_name):
    """Azure returns an empty list, not an error, for an unregistered provider."""
    source = (AZURE_ROOT / short_name / "fetcher.py").read_text()
    assert 'provider_registration_status(\n            collector, subscription_id, cred, "Microsoft.Authorization"\n        )' in source


# --------------------------------------------------------------------------- #
# The failure path, end to end, with no SDK involved
# --------------------------------------------------------------------------- #


def test_graph_fetcher_writes_evidence_and_a_status_file_when_auth_fails(tmp_path, monkeypatch):
    """A Graph fetcher that cannot authenticate must still produce parseable evidence.

    Run against one of the four: the reason text and the exit path come from
    `azure_common` (unit-tested in tests/test_azure_fetchers.py) and the Graph client
    construction is the only difference between them, which is what is forced to fail
    here.
    """
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)

    module = _load("entra_mfa_status")
    # Force the credential to fail even where azure-identity is installed, so this
    # asserts the failure path rather than reaching the network.
    monkeypatch.setattr(
        module, "credential", lambda: (_ for _ in ()).throw(ImportError("no sdk"))
    )

    assert module.main() != 0

    written = list(evidence_dir.glob("*.json"))
    assert len(written) == 1
    # The filename is keyed by the TENANT, so two targets cannot collide in the one
    # EVIDENCE_DIR the runner shares between them.
    assert written[0].name == f"azure_entra_mfa_status_{TENANT}.json"

    payload = json.loads(written[0].read_text())
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"]
    assert payload["metadata"]["subscription_source"] == "not_applicable"
    assert payload["results"]["users"] == []
    assert payload["summary"]["total_users"] == 0
    # A Graph payload carries the tenant; there is no subscription to carry.
    assert payload["metadata"]["tenant_source"] == "unresolved"

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    import sys

    sys.path.insert(0, str(AZURE_ROOT / "_shared"))
    from azure_common import STATUS_CODES

    assert status["code"] in STATUS_CODES


def test_rbac_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    tmp_path, monkeypatch
):
    """The ARM half's failure path: no subscription means no evidence is collectable."""
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)

    module = _load("rbac_role_assignments")
    monkeypatch.setattr(
        module, "credential", lambda: (_ for _ in ()).throw(ImportError("no sdk"))
    )
    monkeypatch.setattr(
        module,
        "resolve_subscription",
        lambda collector: {"subscription_id": None, "subscription_source": "unresolved"},
    )

    assert module.main() != 0

    written = list(evidence_dir.glob("*.json"))
    assert len(written) == 1
    payload = json.loads(written[0].read_text())
    assert payload["metadata"]["subscription_source"] == "unresolved"
    assert payload["metadata"]["partial_failure"] is True
    # Registration is "unknown", NOT "not_registered": the call never ran, and
    # claiming the provider is unregistered would be a fact we do not have.
    assert payload["results"]["provider_registration_status"] == "unknown"

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
