"""Fixture-based tests for the Azure app-platform and governance fetchers.

Covers fetchers/azure/{app_service_configuration, function_app_configuration,
policy_assignments, databricks_workspace_configuration}. The three older Azure
fetchers are covered by tests/test_azure_fetchers.py, which also unit-tests the
shared `azure_common` helpers these four build on.

No live API calls, no credentials, and no azure-* package needs to be installed: the
heavy `azure.*` imports live inside `azure_common.credential()` and each fetcher's
`collect_*()` / `policy_client()`, and are never triggered here. Two layers are
covered.

**The projection layer** (`project_*`) is each fetcher's only code that touches an
azure-mgmt model. It reads model ATTRIBUTES into a flat snake_case dict. Its tests
drive it with `SimpleNamespace` stand-ins that mimic attribute access, including the
`None` intermediates the real API hands back constantly (no managed identity, a
workspace with no creation parameters, a Databricks workspace on platform-managed
keys).

Attribute access is what makes that layer portable, and for these SDKs it is also
load-bearing in a second way: azure-mgmt-web 11.x, azure-mgmt-databricks 3.x and
azure-mgmt-resource-policy 1.x are all on the newer generator, where `as_dict()`
emits the camelCase WIRE shape nested under "properties" while attributes stay flat
snake_case. Verified against those installed versions, and against a live
subscription for policy_assignments.

**The pure transforms** (`*_record`, `summarize`, `parse_definition_reference`,
`is_not_authorized`, …) take the projection's output and are plain dict-in/dict-out,
so they are tested from literal fixtures. Those fixtures are SYNTHETIC but not
guessed: they are the projections' verified output shape for the SDK versions above.

Run: pytest tests/test_azure_appservice_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
from enum import Enum
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE_ROOT = REPO_ROOT / "fetchers" / "azure"

SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = AZURE_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"azure_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# App Service web apps — project_site() / project_site_config() /
# project_auth_settings() output, then the transforms
# --------------------------------------------------------------------------- #

WEB_APP_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg"
    "/providers/Microsoft.Web/sites/pf-web"
)

HARDENED_SITE = {  # SYNTHETIC — project_site()'s output shape
    "id": WEB_APP_ID,
    "name": "pf-web",
    "location": "eastus",
    "kind": "app,linux",
    "state": "Running",
    "default_host_name": "pf-web.azurewebsites.net",
    "https_only": True,
    "client_cert_enabled": True,
    "client_cert_mode": "Required",
    "public_network_access": "Disabled",
    "virtual_network_subnet_id": f"/subscriptions/{SUBSCRIPTION}/subnets/app",
    "identity": {
        "principal_id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "33333333-3333-3333-3333-333333333333",
        "type": "SystemAssigned",
    },
}

# The default app: the API OMITS httpsOnly / clientCertEnabled / publicNetworkAccess
# when they sit at their (permissive) service defaults, and omits `identity` entirely
# on an app with no managed identity.
DEFAULT_SITE = {  # SYNTHETIC
    "id": WEB_APP_ID.replace("pf-web", "pf-legacy"),
    "name": "pf-legacy",
    "location": "eastus",
    "kind": "app",
    "state": "Running",
    "default_host_name": "pf-legacy.azurewebsites.net",
    "https_only": None,
    "client_cert_enabled": None,
    "client_cert_mode": None,
    "public_network_access": None,
    "virtual_network_subnet_id": None,
    "identity": {"principal_id": None, "tenant_id": None, "type": None},
}

HARDENED_CONFIG = {  # SYNTHETIC — project_site_config()'s output shape
    "id": f"{WEB_APP_ID}/config/web",
    "name": "pf-web",
    "linux_fx_version": "PYTHON|3.12",
    "windows_fx_version": None,
    "java_version": None,
    "php_version": None,
    "python_version": None,
    "net_framework_version": None,
    "node_version": None,
    "http20_enabled": True,
    "ftps_state": "Disabled",
    "min_tls_version": "1.2",
    "remote_debugging_enabled": None,
    "always_on": True,
    "http_logging_enabled": True,
}

LEGACY_CONFIG = {  # SYNTHETIC — a Windows app on an old stack, FTP wide open
    "id": f"{WEB_APP_ID}/config/web",
    "name": "pf-legacy",
    "linux_fx_version": "",
    "windows_fx_version": None,
    "java_version": "1.8",
    "php_version": "7.4",
    "python_version": None,
    "net_framework_version": "v4.0",
    "node_version": None,
    "http20_enabled": None,
    "ftps_state": "AllAllowed",
    "min_tls_version": "1.0",
    "remote_debugging_enabled": True,
    "always_on": None,
    "http_logging_enabled": None,
}

AUTH_ON = {  # SYNTHETIC — project_auth_settings()'s output shape
    "platform_enabled": True,
    "platform_runtime_version": "~1",
    "require_authentication": True,
    "unauthenticated_client_action": "RedirectToLoginPage",
}


def test_project_site_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against.

    Asserting the whole dict (not a few keys) is deliberate: if the projection's key
    names ever drift from what `web_app_record` reads, the evidence would go quietly
    null rather than fail, so the two must be pinned to each other.
    """
    app = _load("app_service_configuration")
    site = SimpleNamespace(
        id=HARDENED_SITE["id"],
        name="pf-web",
        location="eastus",
        kind="app,linux",
        state="Running",
        default_host_name="pf-web.azurewebsites.net",
        https_only=True,
        client_cert_enabled=True,
        client_cert_mode="Required",
        public_network_access="Disabled",
        virtual_network_subnet_id=HARDENED_SITE["virtual_network_subnet_id"],
        identity=SimpleNamespace(
            principal_id=HARDENED_SITE["identity"]["principal_id"],
            tenant_id=HARDENED_SITE["identity"]["tenant_id"],
            type="SystemAssigned",
        ),
    )
    assert app.project_site(site) == HARDENED_SITE


def test_project_site_survives_an_app_with_no_identity():
    """`identity` is absent (not empty) on every app without a managed identity."""
    app = _load("app_service_configuration")
    projected = app.project_site(
        SimpleNamespace(
            id=DEFAULT_SITE["id"],
            name="pf-legacy",
            location="eastus",
            kind="app",
            state="Running",
            default_host_name="pf-legacy.azurewebsites.net",
        )
    )  # must not raise
    assert projected == DEFAULT_SITE

    rec = app.web_app_record(projected)
    assert rec["managed_identity_enabled"] is False
    assert rec["https_only"] is False  # coerced, not passed through as None
    assert rec["effective_client_cert_mode"] == "Ignore"
    assert rec["vnet_integrated"] is False
    assert rec["resource_group"] == "paramify-rg"


def test_project_site_config_reads_sdk_attributes_and_unwraps_enums():
    """`ftps_state` / `min_tls_version` are `str` enums; `str()` on one is a trap.

    A member compares equal to its value, but `str(FtpsState.DISABLED)` is
    "FtpsState.DISABLED" — so leaving the enum in place would put an enum repr in the
    evidence and break the summary's membership test against ("1.2", "1.3").
    """

    class FakeFtpsState(str, Enum):
        DISABLED = "Disabled"

    class FakeTlsVersion(str, Enum):
        ONE2 = "1.2"

    app = _load("app_service_configuration")
    config = SimpleNamespace(
        id=HARDENED_CONFIG["id"],
        name="pf-web",
        linux_fx_version="PYTHON|3.12",
        http20_enabled=True,
        ftps_state=FakeFtpsState.DISABLED,
        min_tls_version=FakeTlsVersion.ONE2,
        always_on=True,
        http_logging_enabled=True,
    )
    projected = app.project_site_config(config)
    assert projected == HARDENED_CONFIG
    assert type(projected["ftps_state"]) is str
    assert type(projected["min_tls_version"]) is str


def test_project_auth_settings_reads_platform_and_global_validation():
    app = _load("app_service_configuration")
    settings = SimpleNamespace(
        platform=SimpleNamespace(enabled=True, runtime_version="~1"),
        global_validation=SimpleNamespace(
            require_authentication=True, unauthenticated_client_action="RedirectToLoginPage"
        ),
    )
    assert app.project_auth_settings(settings) == AUTH_ON

    # Easy Auth was never configured: both nested blocks are absent, and reading
    # `.enabled` off them must not raise.
    bare = app.project_auth_settings(SimpleNamespace())
    assert bare == {
        "platform_enabled": None,
        "platform_runtime_version": None,
        "require_authentication": None,
        "unauthenticated_client_action": None,
    }
    assert app.authentication_record(bare)["auth_enabled"] is False


@pytest.mark.parametrize(
    ("enabled", "mode", "expected"),
    [
        (False, "OptionalInteractiveUser", "Ignore"),
        (True, "OptionalInteractiveUser", "Optional"),
        (True, "Optional", "Allow"),
        (True, "Required", "Required"),
        (False, "Required", "Ignore"),  # the toggle is off; the stale mode must not win
        (None, None, "Ignore"),
    ],
)
def test_effective_client_cert_mode_matches_prowlers_clauses(enabled, mode, expected):
    app = _load("app_service_configuration")
    assert app.effective_client_cert_mode(enabled, mode) == expected


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("app", True),
        ("app,linux", True),
        ("app,linux,container", True),
        (None, True),  # Prowler's default: an app with no kind is a web app
        ("functionapp", False),
        ("functionapp,linux", False),
        ("FunctionApp", False),  # ARM's casing is not guaranteed
    ],
)
def test_is_web_app_splits_web_apps_from_function_apps(kind, expected):
    app = _load("app_service_configuration")
    assert app.is_web_app(kind) is expected


def test_web_app_record_and_configuration_record_coerce_absent_booleans():
    """Azure omits a false-y field; `null` must not reach a validator asserting false."""
    app = _load("app_service_configuration")
    rec = app.web_app_record(HARDENED_SITE)
    assert rec["https_only"] is True
    assert rec["client_cert_enabled"] is True
    assert rec["effective_client_cert_mode"] == "Required"
    assert rec["managed_identity_enabled"] is True
    assert rec["vnet_integrated"] is True
    assert rec["configuration"] is None  # filled by the enrichment
    assert rec["authentication"] is None

    config = app.configuration_record(LEGACY_CONFIG)
    assert config["http20_enabled"] is False
    assert config["always_on"] is False
    assert config["http_logging_enabled"] is False
    assert config["remote_debugging_enabled"] is True
    # Every runtime field survives, including the ones this app does not use — that
    # is what a supported-runtime control is evidenced from.
    assert config["java_version"] == "1.8"
    assert config["php_version"] == "7.4"
    assert config["net_framework_version"] == "v4.0"


def test_web_app_identity_type_none_is_not_a_managed_identity():
    """ARM returns the literal string "None" as the identity type, not a null."""
    app = _load("app_service_configuration")
    site = dict(HARDENED_SITE, identity={"principal_id": None, "tenant_id": None, "type": "None"})
    assert app.web_app_record(site)["managed_identity_enabled"] is False


def test_app_service_summary_counts_transport_identity_and_runtime():
    app = _load("app_service_configuration")
    hardened = app.web_app_record(HARDENED_SITE)
    hardened["configuration"] = app.configuration_record(HARDENED_CONFIG)
    hardened["authentication"] = app.authentication_record(AUTH_ON)
    legacy = app.web_app_record(DEFAULT_SITE)
    legacy["configuration"] = app.configuration_record(LEGACY_CONFIG)

    summary = app.summarize([hardened, legacy])
    assert summary["total_web_apps"] == 2
    assert summary["https_only_apps"] == 1
    assert summary["https_only_percentage"] == 50
    assert summary["managed_identity_apps"] == 1
    assert summary["auth_enabled_apps"] == 1
    assert summary["client_cert_required_apps"] == 1
    assert summary["minimum_tls_1_2_apps"] == 1
    assert summary["http2_enabled_apps"] == 1
    assert summary["ftp_deployment_disabled_apps"] == 1
    assert summary["ftp_encrypted_or_disabled_apps"] == 1
    assert summary["remote_debugging_enabled_apps"] == 1
    assert summary["always_on_apps"] == 1
    assert summary["http_logging_enabled_apps"] == 1
    assert summary["vnet_integrated_apps"] == 1
    assert summary["public_network_access_disabled_apps"] == 1
    assert summary["apps_with_declared_runtime"] == 2


def test_app_service_summary_empty_subscription():
    app = _load("app_service_configuration")
    summary = app.summarize([])
    assert summary["total_web_apps"] == 0
    assert summary["https_only_percentage"] == 0
    assert summary["managed_identity_percentage"] == 0


# --------------------------------------------------------------------------- #
# Function apps — project_function_app() / project_host_keys() /
# project_application_settings() output, then the transforms
# --------------------------------------------------------------------------- #

FUNCTION_APP_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg"
    "/providers/Microsoft.Web/sites/pf-func"
)

FUNCTION_SITE = {  # SYNTHETIC — project_function_app()'s output shape
    "id": FUNCTION_APP_ID,
    "name": "pf-func",
    "location": "eastus",
    "kind": "functionapp,linux",
    "state": "Running",
    "public_network_access": "Disabled",
    "virtual_network_subnet_id": f"/subscriptions/{SUBSCRIPTION}/subnets/func",
    "https_only": True,
    "identity": {
        "principal_id": "44444444-4444-4444-4444-444444444444",
        "tenant_id": "33333333-3333-3333-3333-333333333333",
        "type": "SystemAssigned",
    },
}

EXPOSED_FUNCTION_SITE = {  # SYNTHETIC — every permissive field omitted by the API
    "id": FUNCTION_APP_ID.replace("pf-func", "pf-open"),
    "name": "pf-open",
    "location": "eastus",
    "kind": "functionapp",
    "state": "Running",
    "public_network_access": None,
    "virtual_network_subnet_id": None,
    "https_only": None,
    "identity": {"principal_id": None, "tenant_id": None, "type": None},
}

FUNCTION_CONFIG = {  # SYNTHETIC — project_function_config()'s output shape
    "linux_fx_version": "Python|3.11",
    "windows_fx_version": None,
    "net_framework_version": None,
    "ftps_state": "Disabled",
    "min_tls_version": "1.2",
    "http20_enabled": True,
    "remote_debugging_enabled": None,
    "always_on": None,
}

HOST_KEYS = {  # SYNTHETIC — project_host_keys()'s output shape (NAMES only)
    "function_key_names": ["default", "reporting"],
    "system_key_names": ["durabletask_extension"],
    "master_key_configured": True,
}

APP_SETTINGS = {  # SYNTHETIC — project_application_settings()'s output (NAMES only)
    "names": [
        "APPLICATIONINSIGHTS_CONNECTION_STRING",
        "AzureWebJobsStorage",
        "FUNCTIONS_EXTENSION_VERSION",
        "FUNCTIONS_WORKER_RUNTIME",
    ]
}


def test_project_function_app_reads_sdk_attributes():
    fn = _load("function_app_configuration")
    site = SimpleNamespace(
        id=FUNCTION_SITE["id"],
        name="pf-func",
        location="eastus",
        kind="functionapp,linux",
        state="Running",
        public_network_access="Disabled",
        virtual_network_subnet_id=FUNCTION_SITE["virtual_network_subnet_id"],
        https_only=True,
        identity=SimpleNamespace(
            principal_id=FUNCTION_SITE["identity"]["principal_id"],
            tenant_id=FUNCTION_SITE["identity"]["tenant_id"],
            type="SystemAssigned",
        ),
    )
    assert fn.project_function_app(site) == FUNCTION_SITE

    bare = fn.project_function_app(
        SimpleNamespace(
            id=EXPOSED_FUNCTION_SITE["id"], name="pf-open", location="eastus", kind="functionapp",
            state="Running",
        )
    )  # must not raise
    assert bare == EXPOSED_FUNCTION_SITE


@pytest.mark.parametrize(
    ("kind", "expected"),
    [("functionapp", True), ("functionapp,linux", True), ("app", False), (None, False)],
)
def test_is_function_app(kind, expected):
    fn = _load("function_app_configuration")
    assert fn.is_function_app(kind) is expected


def test_project_host_keys_emits_names_and_presence_but_never_key_material():
    """The secret values must be dropped at the SDK boundary, not downstream.

    This is the fetcher's central promise: an evidence file is a place many people
    can read, so a function key must never reach it. The assertion is on the whole
    serialized projection, not on individual fields, so a future field addition that
    carries a value through fails here.
    """
    fn = _load("function_app_configuration")
    secret = "AAAAsupersecretkeyvalueBBBB=="
    host_keys = SimpleNamespace(
        master_key="masterkey-" + secret,
        function_keys={"default": secret, "reporting": secret},
        system_keys={"durabletask_extension": secret},
    )
    projected = fn.project_host_keys(host_keys)
    assert projected == HOST_KEYS
    assert secret not in json.dumps(projected)

    rec = fn.access_keys_record(projected)
    assert rec["status"] == "collected"
    assert rec["function_keys_configured"] is True
    assert rec["master_key_configured"] is True
    assert rec["function_key_names"] == ["default", "reporting"]
    assert secret not in json.dumps(rec)


def test_project_host_keys_survives_an_app_with_no_keys():
    """`function_keys` / `system_keys` are None (not {}) on an app with none."""
    fn = _load("function_app_configuration")
    projected = fn.project_host_keys(SimpleNamespace(master_key=None))  # must not raise
    assert projected == {
        "function_key_names": [],
        "system_key_names": [],
        "master_key_configured": False,
    }
    assert fn.access_keys_record(projected)["function_keys_configured"] is False


def test_project_application_settings_emits_names_only():
    """Application settings routinely hold connection strings — names only, always."""
    fn = _load("function_app_configuration")
    secret = "DefaultEndpointsProtocol=https;AccountKey=SECRETVALUE=="
    settings = SimpleNamespace(
        properties={
            "AzureWebJobsStorage": secret,
            "FUNCTIONS_EXTENSION_VERSION": "~4",
            "FUNCTIONS_WORKER_RUNTIME": "python",
            "APPLICATIONINSIGHTS_CONNECTION_STRING": secret,
        }
    )
    projected = fn.project_application_settings(settings)
    assert projected == APP_SETTINGS
    assert "SECRETVALUE" not in json.dumps(projected)
    # Not even the benign-looking values: "~4" is an application-setting value too.
    assert "~4" not in json.dumps(projected)

    rec = fn.application_settings_record(projected)
    assert rec["count"] == 4
    assert rec["functions_extension_version_configured"] is True
    assert rec["functions_worker_runtime_configured"] is True
    assert rec["application_insights_configured"] is True
    assert "SECRETVALUE" not in json.dumps(rec)
    assert "~4" not in json.dumps(rec)

    bare = fn.project_application_settings(SimpleNamespace())  # properties absent
    assert bare == {"names": []}
    empty = fn.application_settings_record(bare)
    assert empty["count"] == 0
    assert empty["functions_extension_version_configured"] is False
    assert empty["application_insights_configured"] is False


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("(AuthorizationFailed) The client does not have authorization to perform action", True),
        ("Operation returned an invalid status '(403) Forbidden'", True),
        (
            "(ScopeLocked) The scope '/subscriptions/s/.../sites/f' cannot perform write "
            "operation because following scope(s) are locked",
            True,
        ),
        ("Operation returned an invalid status '(500) Internal Server Error'", False),
        ("getaddrinfo failed", False),
    ],
)
def test_is_not_authorized_separates_a_permission_gap_from_a_broken_call(message, expected):
    """A missing action or a ReadOnly lock is evidence; a 500 is a collection failure."""
    fn = _load("function_app_configuration")
    assert fn.is_not_authorized(RuntimeError(message)) is expected


def test_unavailable_blocks_keep_booleans_null_not_false():
    """"Not allowed to look" must not read as "nothing is configured"."""
    fn = _load("function_app_configuration")
    keys = fn.unavailable_block(fn.NOT_AUTHORIZED, RuntimeError("(403) Forbidden\nfor pf-func"))
    assert keys["status"] == "not_authorized"
    assert keys["function_keys_configured"] is None
    assert keys["master_key_configured"] is None
    assert keys["function_key_names"] == []
    assert "\n" not in keys["reason"]

    settings = fn.unavailable_settings_block(fn.NOT_AUTHORIZED, None)
    assert settings["status"] == "not_authorized"
    assert settings["count"] is None
    assert settings["functions_extension_version_configured"] is None
    assert settings["reason"] is None


def test_function_app_record_public_access_reads_absent_as_reachable():
    """ARM omits publicNetworkAccess unless set; anything but "Disabled" is public."""
    fn = _load("function_app_configuration")
    private = fn.function_app_record(FUNCTION_SITE)
    assert private["public_access"] is False
    assert private["public_network_access"] == "Disabled"
    assert private["vnet_integrated"] is True
    assert private["https_only"] is True
    assert private["managed_identity_enabled"] is True
    assert private["resource_group"] == "paramify-rg"

    exposed = fn.function_app_record(EXPOSED_FUNCTION_SITE)
    assert exposed["public_access"] is True
    assert exposed["https_only"] is False
    assert exposed["vnet_integrated"] is False
    assert exposed["managed_identity_enabled"] is False


def test_function_app_summary_counts_exposure_keys_and_permission_gaps():
    fn = _load("function_app_configuration")
    collected = fn.function_app_record(FUNCTION_SITE)
    collected["configuration"] = fn.configuration_record(FUNCTION_CONFIG)
    collected["access_keys"] = fn.access_keys_record(HOST_KEYS)
    collected["application_settings"] = fn.application_settings_record(APP_SETTINGS)

    blocked = fn.function_app_record(EXPOSED_FUNCTION_SITE)
    blocked["configuration"] = fn.configuration_record(FUNCTION_CONFIG)
    blocked["access_keys"] = fn.unavailable_block(fn.NOT_AUTHORIZED, "403")
    blocked["application_settings"] = fn.unavailable_settings_block(fn.NOT_AUTHORIZED, "403")

    summary = fn.summarize([collected, blocked])
    assert summary["total_function_apps"] == 2
    assert summary["https_only_apps"] == 1
    assert summary["publicly_accessible_apps"] == 1
    assert summary["public_network_access_disabled_apps"] == 1
    assert summary["vnet_integrated_apps"] == 1
    assert summary["managed_identity_apps"] == 1
    assert summary["minimum_tls_1_2_apps"] == 2
    assert summary["ftp_deployment_disabled_apps"] == 2
    assert summary["apps_with_declared_runtime"] == 2
    assert summary["access_keys_configured_apps"] == 1
    # The permission gap is part of the evidence: without these counts a reader could
    # read "1 of 2 apps has keys" as a fact about the other app rather than about the
    # run's permissions.
    assert summary["access_keys_not_authorized_apps"] == 1
    assert summary["application_settings_not_authorized_apps"] == 1
    assert summary["application_insights_configured_apps"] == 1
    assert summary["functions_extension_version_configured_apps"] == 1


def test_function_app_summary_empty_subscription():
    fn = _load("function_app_configuration")
    summary = fn.summarize([])
    assert summary["total_function_apps"] == 0
    assert summary["https_only_percentage"] == 0
    assert summary["access_keys_not_authorized_apps"] == 0


# --------------------------------------------------------------------------- #
# Policy assignments — project_policy_assignment() output, then the transforms
# (verified against a live subscription: an ASC Default assignment at subscription
#  scope, and an inherited management-group assignment whose definition id is
#  UPPER-CASED by ARM)
# --------------------------------------------------------------------------- #

ASC_ASSIGNMENT = {  # SYNTHETIC — shaped from the live SecurityCenterBuiltIn response
    "id": (
        f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
        "/policyAssignments/SecurityCenterBuiltIn"
    ),
    "name": "SecurityCenterBuiltIn",
    "type": "Microsoft.Authorization/policyAssignments",
    "display_name": f"ASC Default (subscription: {SUBSCRIPTION})",
    "description": None,
    "policy_definition_id": (
        "/providers/Microsoft.Authorization/policySetDefinitions"
        "/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
    ),
    "scope": f"/subscriptions/{SUBSCRIPTION}",
    "not_scopes": None,
    "enforcement_mode": "Default",
    "parameters": {},
    "location": None,
    "identity_type": None,
}

# The live inherited assignment: scoped to a management group, DoNotEnforce, and its
# policy_definition_id arrives fully UPPER-CASED.
INHERITED_ASSIGNMENT = {  # SYNTHETIC
    "id": (
        "/providers/Microsoft.Management/managementGroups/mg-root/providers"
        "/Microsoft.Authorization/policyAssignments/sys.blockwesteurope"
    ),
    "name": "sys.blockwesteurope",
    "type": "Microsoft.Authorization/policyAssignments",
    "display_name": "Microsoft Azure region access restriction blocking West Europe region",
    "description": None,
    "policy_definition_id": (
        "/PROVIDERS/MICROSOFT.AUTHORIZATION/POLICYDEFINITIONS"
        "/7509877F-D414-4D79-8D1F-D600EA78D087"
    ),
    "scope": "/providers/Microsoft.Management/managementGroups/mg-root",
    "not_scopes": [f"/subscriptions/{SUBSCRIPTION}/resourceGroups/exempt-rg"],
    "enforcement_mode": "DoNotEnforce",
    "parameters": {"tagName": "environment"},
    "location": None,
    "identity_type": None,
}


@pytest.mark.parametrize(
    ("definition_id", "expected"),
    [
        (
            "/providers/Microsoft.Authorization/policyDefinitions/abc",
            {
                "kind": "policy_definition",
                "name": "abc",
                "source_scope": "built_in",
                "management_group_id": None,
                "subscription_id": None,
            },
        ),
        (
            "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9",
            {
                "kind": "policy_set_definition",
                "name": "1f3afdf9",
                "source_scope": "built_in",
                "management_group_id": None,
                "subscription_id": None,
            },
        ),
        (
            # ARM upper-cases the whole path on some management-group assignments
            # (confirmed live), so the segment match must be case-insensitive.
            "/PROVIDERS/MICROSOFT.AUTHORIZATION/POLICYDEFINITIONS/7509877F",
            {
                "kind": "policy_definition",
                "name": "7509877F",
                "source_scope": "built_in",
                "management_group_id": None,
                "subscription_id": None,
            },
        ),
        (
            f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization"
            "/policyDefinitions/custom-1",
            {
                "kind": "policy_definition",
                "name": "custom-1",
                "source_scope": "subscription",
                "management_group_id": None,
                "subscription_id": SUBSCRIPTION,
            },
        ),
        (
            "/providers/Microsoft.Management/managementGroups/mg-root/providers"
            "/Microsoft.Authorization/policyDefinitions/mg-custom",
            {
                "kind": "policy_definition",
                "name": "mg-custom",
                "source_scope": "management_group",
                "management_group_id": "mg-root",
                "subscription_id": None,
            },
        ),
        (
            None,
            {
                "kind": None,
                "name": None,
                "source_scope": "unknown",
                "management_group_id": None,
                "subscription_id": None,
            },
        ),
    ],
)
def test_parse_definition_reference_covers_every_id_shape(definition_id, expected):
    """Which getter can read the definition is decided entirely by this parse."""
    pol = _load("policy_assignments")
    assert pol.parse_definition_reference(definition_id) == expected


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (f"/subscriptions/{SUBSCRIPTION}", "subscription"),
        (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg", "resource_group"),
        ("/providers/Microsoft.Management/managementGroups/mg-root", "management_group"),
        (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers"
            "/Microsoft.Storage/storageAccounts/acct",
            "resource",
        ),
        (None, "unknown"),
    ],
)
def test_scope_kind_classifies_the_assignment_scope(scope, expected):
    pol = _load("policy_assignments")
    assert pol.scope_kind(scope) == expected


def test_project_policy_assignment_reads_attributes_and_unwraps_wrappers():
    """`enforcement_mode` is a `str` enum and each parameter is a one-field model.

    Both would otherwise land in the evidence as reprs: "EnforcementMode.DEFAULT" and
    the ParameterValuesValue object.
    """

    class FakeEnforcementMode(str, Enum):
        DO_NOT_ENFORCE = "DoNotEnforce"

    pol = _load("policy_assignments")
    assignment = SimpleNamespace(
        id=INHERITED_ASSIGNMENT["id"],
        name="sys.blockwesteurope",
        type="Microsoft.Authorization/policyAssignments",
        display_name=INHERITED_ASSIGNMENT["display_name"],
        policy_definition_id=INHERITED_ASSIGNMENT["policy_definition_id"],
        scope=INHERITED_ASSIGNMENT["scope"],
        not_scopes=INHERITED_ASSIGNMENT["not_scopes"],
        enforcement_mode=FakeEnforcementMode.DO_NOT_ENFORCE,
        parameters={"tagName": SimpleNamespace(value="environment")},
    )
    projected = pol.project_policy_assignment(assignment)
    assert projected == INHERITED_ASSIGNMENT
    assert type(projected["enforcement_mode"]) is str

    # Live shape: `parameters` is None on some assignments and {} on others, and
    # `identity` is absent whenever the assignment has no managed identity.
    bare = pol.project_policy_assignment(
        SimpleNamespace(
            id=ASC_ASSIGNMENT["id"],
            name="SecurityCenterBuiltIn",
            type="Microsoft.Authorization/policyAssignments",
            display_name=ASC_ASSIGNMENT["display_name"],
            policy_definition_id=ASC_ASSIGNMENT["policy_definition_id"],
            scope=ASC_ASSIGNMENT["scope"],
            enforcement_mode="Default",
        )
    )  # must not raise
    assert bare == ASC_ASSIGNMENT


def test_project_policy_definition_unwraps_the_policy_type_enum():
    class FakePolicyType(str, Enum):
        BUILT_IN = "BuiltIn"

    pol = _load("policy_assignments")
    projected = pol.project_policy_definition(
        SimpleNamespace(
            display_name="Microsoft cloud security benchmark",
            policy_type=FakePolicyType.BUILT_IN,
            description=None,
        )
    )
    assert projected == {
        "display_name": "Microsoft cloud security benchmark",
        "policy_type": "BuiltIn",
        "description": None,
    }
    assert type(projected["policy_type"]) is str


def test_assignment_record_makes_enforcement_explicit():
    pol = _load("policy_assignments")
    asc = pol.assignment_record(ASC_ASSIGNMENT)
    assert asc["enforced"] is True
    assert asc["scope_kind"] == "subscription"
    assert asc["inherited_from_management_group"] is False
    assert asc["not_scopes"] == []
    assert asc["excluded_scope_count"] == 0
    # The block is present before enrichment, so the evidence has one layout only.
    assert asc["policy_definition"]["status"] == "unavailable"
    assert asc["policy_definition"]["kind"] == "policy_set_definition"
    assert asc["policy_definition"]["source_scope"] == "built_in"

    inherited = pol.assignment_record(INHERITED_ASSIGNMENT)
    assert inherited["enforced"] is False  # DoNotEnforce = evaluate and report only
    assert inherited["scope_kind"] == "management_group"
    assert inherited["inherited_from_management_group"] is True
    assert inherited["excluded_scope_count"] == 1
    assert inherited["parameters"] == {"tagName": "environment"}


def test_assignment_record_reads_absent_enforcement_mode_as_enforced():
    """ARM omits enforcementMode at its "Default" service default."""
    pol = _load("policy_assignments")
    rec = pol.assignment_record(dict(ASC_ASSIGNMENT, enforcement_mode=None))
    assert rec["enforced"] is True


def test_definition_block_shape_is_the_same_resolved_or_not():
    pol = _load("policy_assignments")
    reference = pol.parse_definition_reference(ASC_ASSIGNMENT["policy_definition_id"])
    resolved = pol.definition_block(
        pol.RESOLVED,
        reference,
        {"display_name": "Microsoft cloud security benchmark", "policy_type": "BuiltIn"},
    )
    assert resolved["status"] == "resolved"
    assert resolved["display_name"] == "Microsoft cloud security benchmark"
    assert resolved["policy_type"] == "BuiltIn"
    assert resolved["reason"] is None

    failed = pol.definition_block(
        pol.UNAVAILABLE, reference, None, RuntimeError("(403) Forbidden\nat management group")
    )
    assert set(failed) == set(resolved)
    assert failed["display_name"] is None
    assert "\n" not in failed["reason"]


def test_policy_summary_counts_enforcement_and_what_is_assigned():
    pol = _load("policy_assignments")
    asc = pol.assignment_record(ASC_ASSIGNMENT)
    asc["policy_definition"] = pol.definition_block(
        pol.RESOLVED,
        pol.parse_definition_reference(ASC_ASSIGNMENT["policy_definition_id"]),
        {"display_name": "Microsoft cloud security benchmark", "policy_type": "BuiltIn"},
    )
    inherited = pol.assignment_record(INHERITED_ASSIGNMENT)
    inherited["policy_definition"] = pol.definition_block(
        pol.UNAVAILABLE,
        pol.parse_definition_reference(INHERITED_ASSIGNMENT["policy_definition_id"]),
        None,
        "not readable at that management group",
    )

    summary = pol.summarize([asc, inherited])
    assert summary["total_policy_assignments"] == 2
    assert summary["enforced_assignments"] == 1
    assert summary["audit_only_assignments"] == 1
    assert summary["enforced_percentage"] == 50
    assert summary["initiative_assignments"] == 1
    assert summary["single_definition_assignments"] == 1
    assert summary["built_in_definition_assignments"] == 1
    assert summary["custom_definition_assignments"] == 0
    assert summary["unresolved_definition_assignments"] == 1
    assert summary["subscription_scoped_assignments"] == 1
    assert summary["inherited_assignments"] == 1
    assert summary["assignments_with_excluded_scopes"] == 1
    assert summary["assignments_with_parameters"] == 1
    # Prowler's single policy check, as two fields.
    assert summary["security_center_builtin_assigned"] is True
    assert summary["security_center_builtin_enforced"] is True


def test_policy_summary_empty_subscription():
    pol = _load("policy_assignments")
    summary = pol.summarize([])
    assert summary["total_policy_assignments"] == 0
    assert summary["enforced_percentage"] == 0
    assert summary["security_center_builtin_assigned"] is False


# --------------------------------------------------------------------------- #
# Databricks workspaces — project_workspace() output, then the transforms
# --------------------------------------------------------------------------- #

WORKSPACE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg"
    "/providers/Microsoft.Databricks/workspaces/pf-dbx"
)

ISOLATED_WORKSPACE = {  # SYNTHETIC — project_workspace()'s output shape
    "id": WORKSPACE_ID,
    "name": "pf-dbx",
    "location": "eastus",
    "provisioning_state": "Succeeded",
    "managed_resource_group_id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/dbx-managed",
    "sku": {"name": "premium", "tier": "premium"},
    "public_network_access": "Disabled",
    "required_nsg_rules": "NoAzureDatabricksRules",
    "no_public_ip_enabled": True,
    "custom_managed_vnet_id": f"/subscriptions/{SUBSCRIPTION}/virtualNetworks/vnet-dbx",
    "managed_disk_encryption": {
        "key_source": "Microsoft.Keyvault",
        "key_name": "dbx-cmk",
        "key_version": "abc123",
        "key_vault_uri": "https://paramify-kv.vault.azure.net/",
        "rotation_to_latest_key_version_enabled": True,
    },
}

DEFAULT_WORKSPACE = {  # SYNTHETIC — a standard workspace created with all defaults
    "id": WORKSPACE_ID.replace("pf-dbx", "pf-dbx-open"),
    "name": "pf-dbx-open",
    "location": "eastus",
    "provisioning_state": "Succeeded",
    "managed_resource_group_id": None,
    "sku": {"name": "standard", "tier": None},
    "public_network_access": None,
    "required_nsg_rules": None,
    "no_public_ip_enabled": None,
    "custom_managed_vnet_id": None,
    "managed_disk_encryption": {
        "key_source": None,
        "key_name": None,
        "key_version": None,
        "key_vault_uri": None,
        "rotation_to_latest_key_version_enabled": None,
    },
}


def test_project_workspace_reads_sdk_attributes_through_the_wrappers():
    """The isolation settings are `WorkspaceCustom*Parameter` models, not plain values.

    Reading `parameters.enable_no_public_ip` without the second `.value` hop yields a
    model object, which `json.dump(default=str)` would write into the evidence as a
    repr — and which is truthy even when the setting is False.
    """

    class FakeKeySource(str, Enum):
        MICROSOFT_KEYVAULT = "Microsoft.Keyvault"

    dbx = _load("databricks_workspace_configuration")
    workspace = SimpleNamespace(
        id=ISOLATED_WORKSPACE["id"],
        name="pf-dbx",
        location="eastus",
        provisioning_state="Succeeded",
        managed_resource_group_id=ISOLATED_WORKSPACE["managed_resource_group_id"],
        sku=SimpleNamespace(name="premium", tier="premium"),
        public_network_access="Disabled",
        required_nsg_rules="NoAzureDatabricksRules",
        parameters=SimpleNamespace(
            enable_no_public_ip=SimpleNamespace(value=True),
            custom_virtual_network_id=SimpleNamespace(
                value=ISOLATED_WORKSPACE["custom_managed_vnet_id"]
            ),
        ),
        encryption=SimpleNamespace(
            entities=SimpleNamespace(
                managed_disk=SimpleNamespace(
                    key_source=FakeKeySource.MICROSOFT_KEYVAULT,
                    key_vault_properties=SimpleNamespace(
                        key_name="dbx-cmk",
                        key_version="abc123",
                        key_vault_uri="https://paramify-kv.vault.azure.net/",
                    ),
                    rotation_to_latest_key_version_enabled=True,
                )
            )
        ),
    )
    projected = dbx.project_workspace(workspace)
    assert projected == ISOLATED_WORKSPACE
    assert type(projected["managed_disk_encryption"]["key_source"]) is str


def test_project_workspace_survives_absent_parameters_and_encryption():
    """`parameters` and `encryption.entities.managed_disk` are absent by default.

    That is the deepest optional chain in this fetcher — four hops, any of which can
    be None on a workspace created without the isolation or CMK features.
    """
    dbx = _load("databricks_workspace_configuration")
    projected = dbx.project_workspace(
        SimpleNamespace(
            id=DEFAULT_WORKSPACE["id"],
            name="pf-dbx-open",
            location="eastus",
            provisioning_state="Succeeded",
            sku=SimpleNamespace(name="standard"),
        )
    )  # must not raise
    assert projected == DEFAULT_WORKSPACE

    # A half-present encryption block (entities set, managed_disk absent) is just as safe.
    half = dbx.project_workspace(
        SimpleNamespace(
            id=DEFAULT_WORKSPACE["id"],
            name="pf-dbx-open",
            encryption=SimpleNamespace(entities=SimpleNamespace()),
        )
    )
    assert half["managed_disk_encryption"]["key_vault_uri"] is None


def test_workspace_record_detects_cmk_and_keeps_absent_no_public_ip_legible():
    dbx = _load("databricks_workspace_configuration")
    isolated = dbx.workspace_record(ISOLATED_WORKSPACE)
    assert isolated["public_network_access_disabled"] is True
    assert isolated["no_public_ip_enabled"] is True
    assert isolated["no_public_ip_setting_present"] is True
    assert isolated["vnet_injected"] is True
    assert isolated["premium_sku"] is True
    assert isolated["resource_group"] == "paramify-rg"
    assert isolated["managed_disk_encryption"]["customer_managed_key"] is True
    assert isolated["managed_disk_encryption"]["rotation_to_latest_key_version_enabled"] is True

    default = dbx.workspace_record(DEFAULT_WORKSPACE)
    assert default["public_network_access_disabled"] is False  # absent = reachable
    assert default["no_public_ip_enabled"] is False
    # ... but the absence is stated, so "false" is not read as "nodes have public IPs"
    # on a workspace that has no such setting at all (Prowler keeps this as None).
    assert default["no_public_ip_setting_present"] is False
    assert default["vnet_injected"] is False
    assert default["premium_sku"] is False
    assert default["managed_disk_encryption"]["customer_managed_key"] is False
    assert default["managed_disk_encryption"]["rotation_to_latest_key_version_enabled"] is False


def test_workspace_cmk_detected_from_key_source_without_vault_properties():
    """key_source alone is enough; the vault properties can be withheld."""
    dbx = _load("databricks_workspace_configuration")
    rec = dbx.managed_disk_encryption_record({"key_source": "Microsoft.Keyvault"})
    assert rec["customer_managed_key"] is True
    assert dbx.managed_disk_encryption_record({"key_source": "Default"})["customer_managed_key"] is (
        False
    )
    assert dbx.managed_disk_encryption_record(None)["customer_managed_key"] is False


def test_databricks_summary_tracks_isolation_and_cmk_coverage():
    dbx = _load("databricks_workspace_configuration")
    workspaces = [
        dbx.workspace_record(ISOLATED_WORKSPACE),
        dbx.workspace_record(DEFAULT_WORKSPACE),
    ]
    summary = dbx.summarize(workspaces)
    assert summary["total_workspaces"] == 2
    assert summary["public_network_access_disabled_workspaces"] == 1
    assert summary["publicly_accessible_workspaces"] == 1
    assert summary["no_public_ip_workspaces"] == 1
    assert summary["vnet_injected_workspaces"] == 1
    assert summary["network_isolated_workspaces"] == 1
    assert summary["network_isolated_percentage"] == 50
    assert summary["customer_managed_key_workspaces"] == 1
    assert summary["platform_managed_key_workspaces"] == 1
    assert summary["cmk_percentage"] == 50
    assert summary["key_rotation_enabled_workspaces"] == 1
    assert summary["premium_sku_workspaces"] == 1


def test_databricks_summary_empty_subscription():
    dbx = _load("databricks_workspace_configuration")
    summary = dbx.summarize([])
    assert summary["total_workspaces"] == 0
    assert summary["cmk_percentage"] == 0
    assert summary["network_isolated_percentage"] == 0


# --------------------------------------------------------------------------- #
# Contract wiring — every fetcher.yaml agrees with its fetcher.py
# --------------------------------------------------------------------------- #

APPSERVICE_FETCHERS = (
    "app_service_configuration",
    "function_app_configuration",
    "policy_assignments",
    "databricks_workspace_configuration",
)


@pytest.mark.parametrize("short_name", APPSERVICE_FETCHERS)
def test_fetcher_yaml_declares_the_ambient_credential_contract(short_name):
    import yaml

    spec = yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())
    assert spec["name"] == f"azure_{short_name}"
    assert spec["category"] == "azure"
    assert spec["secrets"] == []  # DefaultAzureCredential — nothing handed over
    assert spec["supports_targets"] is True
    assert spec["runtime"] == {"type": "python", "entry": "fetcher.py"}
    assert spec["output"]["type"] == "json"
    assert spec["output"]["path"] == f"azure_{short_name}.json"
    assert spec["output"]["aggregation"] == "per_target"
    assert spec["target_schema"]["subscription_id"]["env"] == "AZURE_SUBSCRIPTION_ID"
    assert spec["target_schema"]["subscription_id"]["required"] is False
    assert spec["evidence_set"]["reference_id"].startswith("EVD-AZURE-")
    assert spec["evidence_set"]["instructions"]
    # KSI mapping is deliberately not declared for these four.
    assert "ksis" not in spec
    assert "validators" not in spec


def test_function_app_yaml_documents_the_extra_permissions():
    """Reader is not enough for this one, and whoever wires it must be told so."""
    import yaml

    spec = yaml.safe_load(
        (AZURE_ROOT / "function_app_configuration" / "fetcher.yaml").read_text()
    )
    instructions = spec["evidence_set"]["instructions"]
    assert "Microsoft.Web/sites/host/listkeys/action" in instructions
    assert "Microsoft.Web/sites/config/list/Action" in instructions
    assert "not_authorized" in instructions


def test_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    tmp_path, monkeypatch
):
    """The failure path end-to-end, with no Azure SDK involved.

    Run against policy_assignments — the one of these four whose client comes from a
    package that may not be installed at all — so the chain still produces parseable
    evidence, a non-zero exit and a well-formed $FETCHER_STATUS_FILE reason. The other
    three take the identical path through `azure_common` (unit-tested in
    tests/test_azure_fetchers.py), and tests/test_failure_reporting_contract.py
    statically asserts that every fetcher in the tree writes the status file before
    exiting.
    """
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    module = _load("policy_assignments")
    # Force both auth steps to fail even where azure-* happens to be installed, so
    # this test asserts the failure path rather than reaching the network.
    monkeypatch.setattr(module, "credential", lambda: (_ for _ in ()).throw(ImportError("no sdk")))
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
    assert payload["metadata"]["api_failures"]
    assert payload["results"]["policy_assignments"] == []
    assert payload["summary"]["total_policy_assignments"] == 0

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    assert status["code"] in {
        "auth_failed",
        "not_authorized",
        "target_unreachable",
        "rate_limited",
        "bad_config",
        "partial_failure",
        "internal_error",
    }
