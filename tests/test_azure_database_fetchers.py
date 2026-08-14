"""Fixture-based tests for the Azure managed-database evidence fetchers.

Companion to tests/test_azure_fetchers.py, covering the five database fetchers:
sql_encryption_status, sql_server_configuration, postgresql_configuration,
mysql_configuration and cosmosdb_configuration.

No live API calls, no credentials, and no azure-* package needs to be installed: the
heavy `azure.*` imports live inside `azure_common.credential()` and each fetcher's
`collect_*()`, and are never triggered here. Two layers are covered.

**The projection layer** (`project_*`) is each fetcher's only code that touches an
azure-mgmt model. It reads model ATTRIBUTES into a flat snake_case dict. Its tests
drive it with `SimpleNamespace` stand-ins that mimic attribute access, including the
`None` intermediates the real API hands back constantly (a server with no
`auth_config`, an account with no `backup_policy`, a vulnerability assessment with no
`recurring_scans`).

Attribute access is what makes that layer portable, and the four database SDKs are
split down the middle on generator style — which is exactly why `as_dict()` is not
used anywhere:

- azure-mgmt-sql 4.0.0 and azure-mgmt-cosmosdb 10.0.0 are on the newer `_model_base`
  runtime. They keep a nested `properties` model, and `as_dict()` emits that camelCase
  wire shape; attribute access forwards the flattened snake_case names into it, and
  nested models come back TYPED (`server.administrators` is a
  `ServerExternalAdministrator`, not a plain dict), so attribute reads work one level
  down too. Verified against those exact versions.
- azure-mgmt-postgresqlflexibleservers 2.0.0 and azure-mgmt-rdbms 10.1.1 are still on
  the msrest generator, which flattens `properties.*` onto the model itself.

Attributes are flat snake_case on all four, so the projections need no spelling or
nesting tolerance. Every enum-typed field (`ServerKeyType`,
`TransparentDataEncryptionState`, `MinimalTlsVersion`, `DatabaseAccountKind`, …) is a
real `Enum` member, so `model_attr`'s unwrapping is load-bearing rather than cosmetic
— `str(ServerKeyType.AZURE_KEY_VAULT)` is "ServerKeyType.AZURE_KEY_VAULT", which a
lowercased comparison would silently read as "not a CMK".

**The pure transforms** (`*_record`, `summarize`, and friends) take the projection's
output and are plain dict-in/dict-out, so they are tested from literal fixtures. Those
fixtures are SYNTHETIC but not guessed: they are the projections' verified output shape
for the SDK versions above. No live subscription was available to confirm them against
real resources — the test subscription has no database resources — so the field NAMES
are verified against the installed SDK models while the VALUES are representative.

Run: pytest tests/test_azure_database_fetchers.py  (needs `pip install -e .`)
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
    spec = importlib.util.spec_from_file_location(f"azure_db_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _arm_id(provider: str, kind: str, name: str, group: str = "paramify-rg") -> str:
    return (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
        f"/providers/{provider}/{kind}/{name}"
    )


# --------------------------------------------------------------------------- #
# Azure SQL — transparent data encryption and its key source
# --------------------------------------------------------------------------- #

SQL_SERVER_ID = _arm_id("Microsoft.Sql", "servers", "sql-cmk")

CMK_SERVER = {  # SYNTHETIC — project_sql_server()'s output shape
    "id": SQL_SERVER_ID,
    "name": "sql-cmk",
    "type": "Microsoft.Sql/servers",
    "location": "eastus",
    "version": "12.0",
    "state": "Ready",
    "fully_qualified_domain_name": "sql-cmk.database.windows.net",
}

CMK_PROTECTOR = {  # SYNTHETIC — project_encryption_protector()'s output shape
    "id": f"{SQL_SERVER_ID}/encryptionProtector/current",
    "name": "current",
    "type": "Microsoft.Sql/servers/encryptionProtector",
    "kind": "azurekeyvault",
    "server_key_name": "kv_tde-key_0123",
    "server_key_type": "AzureKeyVault",
    "uri": "https://paramify-kv.vault.azure.net/keys/tde-key/0123",
    "auto_rotation_enabled": True,
}

SERVICE_MANAGED_PROTECTOR = {  # SYNTHETIC — the platform-key default
    "id": f"{SQL_SERVER_ID}/encryptionProtector/current",
    "name": "current",
    "type": "Microsoft.Sql/servers/encryptionProtector",
    "kind": "servicemanaged",
    "server_key_name": "ServiceManaged",
    "server_key_type": "ServiceManaged",
    "uri": None,
    # Azure omits autoRotationEnabled when it was never enabled.
    "auto_rotation_enabled": None,
}

MASTER_DATABASE = {  # SYNTHETIC — project_database()'s output shape
    "id": f"{SQL_SERVER_ID}/databases/master",
    "name": "master",
    "type": "Microsoft.Sql/servers/databases",
    "location": "eastus",
    "managed_by": None,
    "status": "Online",
}

USER_DATABASE = {  # SYNTHETIC
    "id": f"{SQL_SERVER_ID}/databases/appdb",
    "name": "appdb",
    "type": "Microsoft.Sql/servers/databases",
    "location": "eastus",
    "managed_by": None,
    "status": "Online",
}

TDE_ENABLED = {  # SYNTHETIC — project_transparent_data_encryption()'s output shape
    "id": f"{SQL_SERVER_ID}/databases/appdb/transparentDataEncryption/current",
    "name": "current",
    "type": "Microsoft.Sql/servers/databases/transparentDataEncryption",
    "state": "Enabled",
}

TDE_DISABLED = {**TDE_ENABLED, "state": "Disabled"}


def test_project_sql_server_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against.

    Asserting the whole dict (not a few keys) is deliberate: if the projection's key
    names ever drift from what `server_record` reads, the evidence would go quietly
    null rather than fail, so the two must be pinned to each other.
    """
    sql = _load("sql_encryption_status")
    server = SimpleNamespace(
        id=SQL_SERVER_ID,
        name="sql-cmk",
        type="Microsoft.Sql/servers",
        location="eastus",
        version="12.0",
        state="Ready",
        fully_qualified_domain_name="sql-cmk.database.windows.net",
    )
    assert sql.project_sql_server(server) == CMK_SERVER


def test_project_encryption_protector_reads_sdk_attributes():
    sql = _load("sql_encryption_status")
    protector = SimpleNamespace(
        id=CMK_PROTECTOR["id"],
        name="current",
        type="Microsoft.Sql/servers/encryptionProtector",
        kind="azurekeyvault",
        server_key_name="kv_tde-key_0123",
        server_key_type="AzureKeyVault",
        uri="https://paramify-kv.vault.azure.net/keys/tde-key/0123",
        auto_rotation_enabled=True,
    )
    assert sql.project_encryption_protector(protector) == CMK_PROTECTOR


def test_project_encryption_protector_unwraps_the_server_key_type_enum():
    """`ServerKeyType` is a str enum; leaving it in place inverts CMK detection.

    A member compares equal to its value, but `str(ServerKeyType.AZURE_KEY_VAULT)` is
    "ServerKeyType.AZURE_KEY_VAULT" — so a lowercased comparison against it would
    report a CMK-protected server as service-managed, and would put an enum repr in
    the evidence.
    """

    class FakeServerKeyType(str, Enum):
        AZURE_KEY_VAULT = "AzureKeyVault"

    sql = _load("sql_encryption_status")
    projected = sql.project_encryption_protector(
        SimpleNamespace(id="e", name="current", server_key_type=FakeServerKeyType.AZURE_KEY_VAULT)
    )
    assert projected["server_key_type"] == "AzureKeyVault"
    assert type(projected["server_key_type"]) is str
    assert sql.server_record(CMK_SERVER, projected, [])["customer_managed_key"] is True


def test_project_transparent_data_encryption_reads_state_not_status():
    """azure-mgmt-sql 4.0.0 renamed Prowler's `.status` to `.state`.

    Reading Prowler's spelling on 4.0.0 would report every database's TDE as unknown,
    which is the difference between "encrypted" and "we could not tell".
    """

    class FakeTdeState(str, Enum):
        ENABLED = "Enabled"

    sql = _load("sql_encryption_status")
    tde = SimpleNamespace(
        id=TDE_ENABLED["id"],
        name="current",
        type="Microsoft.Sql/servers/databases/transparentDataEncryption",
        state=FakeTdeState.ENABLED,
        # A stale `status` attribute must NOT be what gets read.
        status="Disabled",
    )
    assert sql.project_transparent_data_encryption(tde) == TDE_ENABLED


def test_project_sql_models_survive_absent_nested_models():
    """A bare server / protector / database must project to None, not raise."""
    sql = _load("sql_encryption_status")
    bare_server = sql.project_sql_server(SimpleNamespace(id=SQL_SERVER_ID, name="sql-cmk"))
    assert bare_server["version"] is None
    assert bare_server["fully_qualified_domain_name"] is None

    bare_protector = sql.project_encryption_protector(SimpleNamespace(id="e", name="current"))
    assert bare_protector["server_key_type"] is None
    assert bare_protector["auto_rotation_enabled"] is None

    bare_tde = sql.project_transparent_data_encryption(SimpleNamespace(id="t", name="current"))
    assert bare_tde["state"] is None


def test_sql_encryption_protector_record_coerces_auto_rotation():
    """Azure omits autoRotationEnabled when off; `null` must read as False."""
    sql = _load("sql_encryption_status")
    assert sql.encryption_protector_record(None) is None

    cmk = sql.encryption_protector_record(CMK_PROTECTOR)
    assert cmk["server_key_type"] == "AzureKeyVault"
    assert cmk["key_vault_key_uri"].endswith("/keys/tde-key/0123")
    assert cmk["auto_rotation_enabled"] is True

    managed = sql.encryption_protector_record(SERVICE_MANAGED_PROTECTOR)
    assert managed["auto_rotation_enabled"] is False
    assert managed["key_vault_key_uri"] is None


def test_sql_database_record_tde_is_tri_state():
    """An uncollected TDE state must stay None, never be read as disabled.

    Reading a collection gap as "disabled" would publish a missing read as a finding.
    """
    sql = _load("sql_encryption_status")
    enabled = sql.database_record(USER_DATABASE, TDE_ENABLED)
    assert enabled["tde_enabled"] is True
    assert enabled["tde_state"] == "Enabled"
    assert enabled["is_system_database"] is False

    disabled = sql.database_record(USER_DATABASE, TDE_DISABLED)
    assert disabled["tde_enabled"] is False

    unknown = sql.database_record(USER_DATABASE, None)
    assert unknown["tde_enabled"] is None
    assert unknown["tde_state"] is None

    master = sql.database_record(MASTER_DATABASE, TDE_ENABLED)
    assert master["is_system_database"] is True


def test_sql_server_record_excludes_master_from_user_database_counts():
    """`master` is Azure-managed and its TDE state is not customer-controlled."""
    sql = _load("sql_encryption_status")
    databases = [
        sql.database_record(MASTER_DATABASE, TDE_ENABLED),
        sql.database_record(USER_DATABASE, TDE_ENABLED),
    ]
    record = sql.server_record(CMK_SERVER, CMK_PROTECTOR, databases)

    assert record["customer_managed_key"] is True
    assert record["server_key_type"] == "AzureKeyVault"
    assert record["resource_group"] == "paramify-rg"
    assert record["total_databases"] == 2
    assert record["total_user_databases"] == 1  # master excluded
    assert record["tde_enabled_user_databases"] == 1
    assert record["all_user_databases_tde_enabled"] is True


def test_sql_server_record_flags_a_tde_disabled_user_database():
    sql = _load("sql_encryption_status")
    databases = [sql.database_record(USER_DATABASE, TDE_DISABLED)]
    record = sql.server_record(CMK_SERVER, CMK_PROTECTOR, databases)
    assert record["tde_disabled_user_databases"] == 1
    assert record["all_user_databases_tde_enabled"] is False


def test_sql_server_with_no_user_databases_is_not_vacuously_encrypted():
    """`all()` over an empty list is True — which would be a false assurance."""
    sql = _load("sql_encryption_status")
    record = sql.server_record(
        CMK_SERVER, SERVICE_MANAGED_PROTECTOR, [sql.database_record(MASTER_DATABASE, TDE_ENABLED)]
    )
    assert record["total_user_databases"] == 0
    assert record["all_user_databases_tde_enabled"] is None


def test_sql_server_record_with_no_protector_is_not_a_cmk():
    sql = _load("sql_encryption_status")
    record = sql.server_record(CMK_SERVER, None, [])
    assert record["encryption_protector"] is None
    assert record["server_key_type"] is None
    assert record["customer_managed_key"] is False


def test_sql_summary_tracks_cmk_coverage_not_encrypted_total():
    sql = _load("sql_encryption_status")
    cmk = sql.server_record(
        CMK_SERVER,
        CMK_PROTECTOR,
        [
            sql.database_record(MASTER_DATABASE, TDE_ENABLED),
            sql.database_record(USER_DATABASE, TDE_ENABLED),
        ],
    )
    managed = sql.server_record(
        {**CMK_SERVER, "id": _arm_id("Microsoft.Sql", "servers", "sql-managed"),
         "name": "sql-managed"},
        SERVICE_MANAGED_PROTECTOR,
        [sql.database_record(USER_DATABASE, TDE_DISABLED)],
    )

    summary = sql.summarize([cmk, managed])
    assert summary["total_sql_servers"] == 2
    assert summary["customer_managed_key_servers"] == 1
    assert summary["service_managed_key_servers"] == 1
    assert summary["cmk_percentage"] == 50
    # There is deliberately NO encrypted/total percentage over ALL databases: TDE is on
    # by default on Azure SQL, so such a number would sit at a constant 100.
    assert "encrypted_percentage" not in summary
    assert summary["key_auto_rotation_servers"] == 1
    assert summary["total_databases"] == 3
    assert summary["total_user_databases"] == 2  # master excluded
    assert summary["tde_enabled_user_databases"] == 1
    assert summary["tde_disabled_user_databases"] == 1
    assert summary["tde_percentage"] == 50
    assert summary["servers_with_a_tde_disabled_user_database"] == 1


def test_sql_summary_empty_subscription():
    sql = _load("sql_encryption_status")
    summary = sql.summarize([])
    assert summary["total_sql_servers"] == 0
    assert summary["cmk_percentage"] == 0
    assert summary["tde_percentage"] == 0


# --------------------------------------------------------------------------- #
# Azure SQL — network, authentication and audit posture
# --------------------------------------------------------------------------- #

CONFIG_SERVER = {  # SYNTHETIC — sql_server_configuration.project_sql_server()'s output
    "id": SQL_SERVER_ID,
    "name": "sql-cmk",
    "type": "Microsoft.Sql/servers",
    "location": "eastus",
    "version": "12.0",
    "state": "Ready",
    "fully_qualified_domain_name": "sql-cmk.database.windows.net",
    "public_network_access": "Disabled",
    "minimal_tls_version": "1.2",
    "restrict_outbound_network_access": "Disabled",
    "administrators": {
        "sid": "22222222-2222-2222-2222-222222222222",
        "login": "sql-admins",
        "administrator_type": "ActiveDirectory",
        "principal_type": "Group",
        "tenant_id": SUBSCRIPTION,
        "azure_ad_only_authentication": True,
    },
}

AZURE_SERVICES_RULE = {  # SYNTHETIC — project_firewall_rule()'s output shape
    "id": f"{SQL_SERVER_ID}/firewallRules/AllowAllWindowsAzureIps",
    "name": "AllowAllWindowsAzureIps",
    "start_ip_address": "0.0.0.0",
    "end_ip_address": "0.0.0.0",
}

INTERNET_RULE = {  # SYNTHETIC
    "id": f"{SQL_SERVER_ID}/firewallRules/AllowAll",
    "name": "AllowAll",
    "start_ip_address": "0.0.0.0",
    "end_ip_address": "255.255.255.255",
}

CORPORATE_RULE = {  # SYNTHETIC
    "id": f"{SQL_SERVER_ID}/firewallRules/corp",
    "name": "corp",
    "start_ip_address": "203.0.113.0",
    "end_ip_address": "203.0.113.255",
}

AUDIT_POLICY_120 = {  # SYNTHETIC — project_auditing_policy()'s output shape
    "id": f"{SQL_SERVER_ID}/auditingSettings/default",
    "name": "default",
    "type": "Microsoft.Sql/servers/auditingSettings",
    "state": "Enabled",
    "retention_days": 120,
    "is_azure_monitor_target_enabled": True,
}

VA_CONFIGURED = {  # SYNTHETIC — project_vulnerability_assessment()'s output shape
    "id": f"{SQL_SERVER_ID}/vulnerabilityAssessments/default",
    "name": "default",
    "type": "Microsoft.Sql/servers/vulnerabilityAssessments",
    "storage_container_path": "https://paramifyva.blob.core.windows.net/vulnerability-assessment/",
    "recurring_scans": {
        "is_enabled": True,
        "emails": ["security@example.com"],
        "email_subscription_admins": True,
    },
}

ALERT_POLICY_ENABLED = {  # SYNTHETIC — project_security_alert_policy()'s output shape
    "id": f"{SQL_SERVER_ID}/securityAlertPolicies/Default",
    "name": "Default",
    "type": "Microsoft.Sql/servers/securityAlertPolicies",
    "state": "Enabled",
    "email_account_admins": True,
    "email_addresses": ["security@example.com"],
    "retention_days": 30,
}


def test_config_project_sql_server_reads_the_typed_administrators_model():
    """`server.administrators` is a TYPED model on `_model_base`, not a plain dict.

    If it came back as a dict, `model_attr(admins, "sid")` would silently return None
    and the Entra-admin evidence would go blank — verified against azure-mgmt-sql
    4.0.0 that it is a `ServerExternalAdministrator`.
    """
    cfg = _load("sql_server_configuration")
    server = SimpleNamespace(
        id=SQL_SERVER_ID,
        name="sql-cmk",
        type="Microsoft.Sql/servers",
        location="eastus",
        version="12.0",
        state="Ready",
        fully_qualified_domain_name="sql-cmk.database.windows.net",
        public_network_access="Disabled",
        minimal_tls_version="1.2",
        restrict_outbound_network_access="Disabled",
        administrators=SimpleNamespace(
            sid="22222222-2222-2222-2222-222222222222",
            login="sql-admins",
            administrator_type="ActiveDirectory",
            principal_type="Group",
            tenant_id=SUBSCRIPTION,
            azure_ad_only_authentication=True,
        ),
    )
    assert cfg.project_sql_server(server) == CONFIG_SERVER


def test_config_project_sql_server_survives_an_absent_administrators_block():
    """A server with no Entra admin omits `administrators` entirely."""
    cfg = _load("sql_server_configuration")
    projected = cfg.project_sql_server(
        SimpleNamespace(id=SQL_SERVER_ID, name="sql-cmk", minimal_tls_version="1.0")
    )  # must not raise
    assert projected["administrators"] == {
        "sid": None,
        "login": None,
        "administrator_type": None,
        "principal_type": None,
        "tenant_id": None,
        "azure_ad_only_authentication": None,
    }
    record = cfg.server_record(projected, [], [], None, None)
    assert record["entra_administrator_configured"] is False
    assert record["administrators"]["azure_ad_only_authentication"] is False


def test_config_project_vulnerability_assessment_survives_absent_recurring_scans():
    cfg = _load("sql_server_configuration")
    projected = cfg.project_vulnerability_assessment(
        SimpleNamespace(id="v", name="default", storage_container_path=None)
    )  # must not raise
    assert projected["recurring_scans"] == {
        "is_enabled": None,
        "emails": None,
        "email_subscription_admins": None,
    }
    record = cfg.vulnerability_assessment_record(projected)
    assert record["enabled"] is False
    # Coerced: a validator asserting `false` would not match `null`.
    assert record["recurring_scans"] == {
        "is_enabled": False,
        "emails": [],
        "email_subscription_admins": False,
    }


def test_config_firewall_rule_flags_the_two_exposures_separately():
    """0.0.0.0-0.0.0.0 and 0.0.0.0-255.255.255.255 are different findings."""
    cfg = _load("sql_server_configuration")
    azure_services = cfg.firewall_rule_record(AZURE_SERVICES_RULE)
    assert azure_services["allows_all_azure_services"] is True
    assert azure_services["allows_entire_internet"] is False

    internet = cfg.firewall_rule_record(INTERNET_RULE)
    assert internet["allows_all_azure_services"] is False
    assert internet["allows_entire_internet"] is True

    corporate = cfg.firewall_rule_record(CORPORATE_RULE)
    assert corporate["allows_all_azure_services"] is False
    assert corporate["allows_entire_internet"] is False


@pytest.mark.parametrize(
    ("state", "retention", "expected_enabled", "expected_over_90"),
    [
        ("Enabled", 120, True, True),
        ("Enabled", 91, True, True),
        # Exactly 90 FAILS — CIS requires retention to exceed 90 days.
        ("Enabled", 90, True, False),
        ("Enabled", 7, True, False),
        # 0 is Azure's "retain indefinitely", the STRONGEST setting — reading it as
        # 0 < 91 would report the best possible retention as the worst.
        ("Enabled", 0, True, True),
        # Retention is irrelevant when auditing is off.
        ("Disabled", 365, False, False),
        ("Enabled", None, True, False),
    ],
)
def test_config_auditing_retention_thresholds(state, retention, expected_enabled, expected_over_90):
    cfg = _load("sql_server_configuration")
    record = cfg.auditing_policy_record(
        {**AUDIT_POLICY_120, "state": state, "retention_days": retention}
    )
    assert record["enabled"] is expected_enabled
    assert record["retention_over_90_days"] is expected_over_90


def test_config_auditing_retention_zero_is_marked_unlimited():
    cfg = _load("sql_server_configuration")
    record = cfg.auditing_policy_record({**AUDIT_POLICY_120, "retention_days": 0})
    assert record["retention_unlimited"] is True
    assert cfg.auditing_policy_record(AUDIT_POLICY_120)["retention_unlimited"] is False


def test_config_security_alert_policy_and_vulnerability_assessment_records():
    cfg = _load("sql_server_configuration")
    assert cfg.security_alert_policy_record(None) is None
    assert cfg.vulnerability_assessment_record(None) is None

    alert = cfg.security_alert_policy_record(ALERT_POLICY_ENABLED)
    assert alert["enabled"] is True
    assert alert["email_addresses"] == ["security@example.com"]

    disabled = cfg.security_alert_policy_record({**ALERT_POLICY_ENABLED, "state": "Disabled"})
    assert disabled["enabled"] is False

    assessment = cfg.vulnerability_assessment_record(VA_CONFIGURED)
    assert assessment["enabled"] is True
    assert assessment["recurring_scans"]["email_subscription_admins"] is True


def test_config_vulnerability_assessment_without_a_container_path_is_not_enabled():
    """Scan results have nowhere to go without a storage container — Prowler's reading."""
    cfg = _load("sql_server_configuration")
    record = cfg.vulnerability_assessment_record(
        {**VA_CONFIGURED, "storage_container_path": None}
    )
    assert record["enabled"] is False


@pytest.mark.parametrize(
    ("tls_version", "expected"),
    [("1.3", True), ("1.2", True), ("1.1", False), ("1.0", False), ("None", False), (None, False)],
)
def test_config_minimal_tls_version_recommendation(tls_version, expected):
    """Azure SQL spells these as bare version numbers, unlike Storage's "TLS1_2"."""
    cfg = _load("sql_server_configuration")
    record = cfg.server_record(
        {**CONFIG_SERVER, "minimal_tls_version": tls_version}, [], [], None, None
    )
    assert record["minimal_tls_version_recommended"] is expected


@pytest.mark.parametrize(
    ("public_network_access", "expected"),
    [("Disabled", True), ("SecuredByPerimeter", True), ("Enabled", False), (None, False)],
)
def test_config_public_network_access_reading(public_network_access, expected):
    cfg = _load("sql_server_configuration")
    record = cfg.server_record(
        {**CONFIG_SERVER, "public_network_access": public_network_access}, [], [], None, None
    )
    assert record["public_network_access_disabled"] is expected


def test_config_server_record_rolls_up_the_whole_posture():
    cfg = _load("sql_server_configuration")
    rules = [
        cfg.firewall_rule_record(AZURE_SERVICES_RULE),
        cfg.firewall_rule_record(CORPORATE_RULE),
    ]
    record = cfg.server_record(
        CONFIG_SERVER,
        rules,
        [cfg.auditing_policy_record(AUDIT_POLICY_120)],
        ALERT_POLICY_ENABLED,
        VA_CONFIGURED,
    )
    assert record["resource_group"] == "paramify-rg"
    assert record["entra_administrator_configured"] is True
    assert record["administrators"]["azure_ad_only_authentication"] is True
    assert record["total_firewall_rules"] == 2
    assert record["allows_all_azure_services"] is True
    assert record["allows_entire_internet"] is False
    assert record["auditing_enabled"] is True
    assert record["auditing_retention_over_90_days"] is True
    assert record["defender_for_sql_enabled"] is True
    assert record["vulnerability_assessment_enabled"] is True


def test_config_summary_counts_every_posture_dimension():
    cfg = _load("sql_server_configuration")
    strong = cfg.server_record(
        CONFIG_SERVER,
        [cfg.firewall_rule_record(CORPORATE_RULE)],
        [cfg.auditing_policy_record(AUDIT_POLICY_120)],
        ALERT_POLICY_ENABLED,
        VA_CONFIGURED,
    )
    weak = cfg.server_record(
        {
            **CONFIG_SERVER,
            "id": _arm_id("Microsoft.Sql", "servers", "sql-weak"),
            "name": "sql-weak",
            "public_network_access": "Enabled",
            "minimal_tls_version": "1.0",
            "administrators": {**CONFIG_SERVER["administrators"],
                               "administrator_type": None,
                               "azure_ad_only_authentication": None},
        },
        [cfg.firewall_rule_record(INTERNET_RULE)],
        [cfg.auditing_policy_record({**AUDIT_POLICY_120, "state": "Disabled"})],
        None,
        None,
    )

    summary = cfg.summarize([strong, weak])
    assert summary["total_sql_servers"] == 2
    assert summary["auditing_enabled_servers"] == 1
    assert summary["auditing_percentage"] == 50
    assert summary["auditing_retention_over_90_days_servers"] == 1
    assert summary["public_network_access_disabled_servers"] == 1
    assert summary["recommended_minimal_tls_servers"] == 1
    assert summary["entra_administrator_servers"] == 1
    assert summary["entra_only_authentication_servers"] == 1
    assert summary["servers_allowing_all_azure_services"] == 0
    assert summary["servers_allowing_entire_internet"] == 1
    assert summary["total_firewall_rules"] == 2
    assert summary["defender_for_sql_enabled_servers"] == 1
    assert summary["vulnerability_assessment_enabled_servers"] == 1
    assert summary["vulnerability_assessment_recurring_scan_servers"] == 1
    assert summary["vulnerability_assessment_admin_notification_servers"] == 1


def test_config_summary_empty_subscription():
    cfg = _load("sql_server_configuration")
    summary = cfg.summarize([])
    assert summary["total_sql_servers"] == 0
    assert summary["auditing_percentage"] == 0


# --------------------------------------------------------------------------- #
# PostgreSQL flexible servers
# --------------------------------------------------------------------------- #

PG_SERVER_ID = _arm_id("Microsoft.DBforPostgreSQL", "flexibleServers", "pg-main")

PG_SERVER = {  # SYNTHETIC — project_postgresql_server()'s output shape
    "id": PG_SERVER_ID,
    "name": "pg-main",
    "type": "Microsoft.DBforPostgreSQL/flexibleServers",
    "location": "eastus",
    "version": "16",
    "state": "Ready",
    "fully_qualified_domain_name": "pg-main.postgres.database.azure.com",
    "active_directory_auth": "Enabled",
    "password_auth": "Disabled",
    "auth_tenant_id": SUBSCRIPTION,
    "public_network_access": "Disabled",
    "delegated_subnet_resource_id": None,
    "backup_retention_days": 14,
    "geo_redundant_backup": "Enabled",
    "high_availability_mode": "ZoneRedundant",
    "high_availability_state": "Healthy",
}

PG_PARAMETERS_STRONG = {
    "require_secure_transport": "ON",
    "log_checkpoints": "ON",
    "log_connections": "ON",
    "log_disconnections": "ON",
    # Removed in PostgreSQL 16 — absent, not off (see the fetcher's docstring).
    "connection_throttling": None,
    "log_retention_days": "7",
}

PG_ADMIN = {  # SYNTHETIC — project_entra_admin()'s output shape
    "id": f"{PG_SERVER_ID}/administrators/33333333-3333-3333-3333-333333333333",
    "name": "33333333-3333-3333-3333-333333333333",
    "object_id": "33333333-3333-3333-3333-333333333333",
    "principal_name": "pg-dbas",
    "principal_type": "Group",
    "tenant_id": SUBSCRIPTION,
}


def test_project_postgresql_server_reads_the_nested_msrest_models():
    """azure-mgmt-postgresqlflexibleservers is msrest: `properties.*` is flattened.

    `auth_config` / `backup` / `high_availability` / `network` are still nested models
    below that, so each is its own None-tolerant hop.
    """
    pg = _load("postgresql_configuration")
    server = SimpleNamespace(
        id=PG_SERVER_ID,
        name="pg-main",
        type="Microsoft.DBforPostgreSQL/flexibleServers",
        location="eastus",
        version="16",
        state="Ready",
        fully_qualified_domain_name="pg-main.postgres.database.azure.com",
        auth_config=SimpleNamespace(
            active_directory_auth="Enabled", password_auth="Disabled", tenant_id=SUBSCRIPTION
        ),
        network=SimpleNamespace(public_network_access="Disabled", delegated_subnet_resource_id=None),
        backup=SimpleNamespace(backup_retention_days=14, geo_redundant_backup="Enabled"),
        high_availability=SimpleNamespace(mode="ZoneRedundant", state="Healthy"),
    )
    assert pg.project_postgresql_server(server) == PG_SERVER


def test_project_postgresql_server_survives_absent_nested_models():
    pg = _load("postgresql_configuration")
    projected = pg.project_postgresql_server(
        SimpleNamespace(id=PG_SERVER_ID, name="pg-main", version="16")
    )  # must not raise
    assert projected["active_directory_auth"] is None
    assert projected["geo_redundant_backup"] is None
    assert projected["high_availability_mode"] is None
    assert projected["public_network_access"] is None

    record = pg.server_record(projected, {}, [], [])
    assert record["active_directory_auth_enabled"] is False
    assert record["geo_redundant_backup_enabled"] is False
    assert record["high_availability_enabled"] is False


def test_postgresql_parameter_value_uppercases_and_stays_none_when_absent():
    """Prowler's `.value.upper()`, made None-safe.

    None must NOT become "OFF": reporting an uncollected parameter as disabled would
    publish a collection gap as a finding.
    """
    pg = _load("postgresql_configuration")
    assert pg.parameter_value({"name": "log_connections", "value": "on"}) == "ON"
    assert pg.parameter_value({"name": "logfiles.retention_days", "value": "7"}) == "7"
    assert pg.parameter_value({"name": "x", "value": None}) is None
    assert pg.parameter_value(None) is None


@pytest.mark.parametrize(
    ("days", "expected"),
    [
        ("4", True),
        ("7", True),
        # Prowler's window is strictly (3, 8): Azure's supported range for this
        # parameter tops out at 7, so a larger value means it was never applied.
        ("3", False),
        ("8", False),
        ("30", False),
        ("0", False),
        ("not-a-number", False),  # must not raise
        (None, False),
    ],
)
def test_postgresql_log_retention_window(days, expected):
    pg = _load("postgresql_configuration")
    assert pg._log_retention_compliant(days) is expected


def test_postgresql_entra_authentication_needs_both_auth_and_an_admin():
    """Entra auth switched on with no administrator assigned is not usable."""
    pg = _load("postgresql_configuration")
    admins = [pg.entra_admin_record(PG_ADMIN)]

    both = pg.server_record(PG_SERVER, PG_PARAMETERS_STRONG, [], admins)
    assert both["active_directory_auth_enabled"] is True
    assert both["total_entra_id_admins"] == 1
    assert both["entra_id_authentication_configured"] is True

    no_admins = pg.server_record(PG_SERVER, PG_PARAMETERS_STRONG, [], [])
    assert no_admins["active_directory_auth_enabled"] is True
    assert no_admins["entra_id_authentication_configured"] is False

    auth_off = pg.server_record(
        {**PG_SERVER, "active_directory_auth": "Disabled"}, PG_PARAMETERS_STRONG, [], admins
    )
    assert auth_off["entra_id_authentication_configured"] is False


def test_postgresql_server_record_reads_the_by_name_parameters():
    pg = _load("postgresql_configuration")
    record = pg.server_record(PG_SERVER, PG_PARAMETERS_STRONG, [], [])
    assert record["require_secure_transport_enabled"] is True
    assert record["log_checkpoints_enabled"] is True
    assert record["log_connections_enabled"] is True
    assert record["log_disconnections_enabled"] is True
    # Absent on PG16+, so not enabled — but the raw value stays None, not "OFF".
    assert record["connection_throttling"] is None
    assert record["connection_throttling_enabled"] is False
    assert record["log_retention_compliant"] is True
    assert record["geo_redundant_backup_enabled"] is True
    assert record["high_availability_enabled"] is True
    assert record["public_network_access_disabled"] is True


def test_postgresql_high_availability_disabled_mode():
    pg = _load("postgresql_configuration")
    record = pg.server_record(
        {**PG_SERVER, "high_availability_mode": "Disabled"}, PG_PARAMETERS_STRONG, [], []
    )
    assert record["high_availability_enabled"] is False


def test_postgresql_firewall_rule_flags_the_azure_services_pseudo_rule():
    pg = _load("postgresql_configuration")
    azure_services = pg.firewall_rule_record(
        {"id": "r", "name": "AllowAllAzureServices",
         "start_ip_address": "0.0.0.0", "end_ip_address": "0.0.0.0"}
    )
    assert azure_services["allows_all_azure_services"] is True
    assert azure_services["allows_entire_internet"] is False

    internet = pg.firewall_rule_record(
        {"id": "r", "name": "open", "start_ip_address": "0.0.0.0",
         "end_ip_address": "255.255.255.255"}
    )
    assert internet["allows_entire_internet"] is True


def test_postgresql_summary():
    pg = _load("postgresql_configuration")
    strong = pg.server_record(
        PG_SERVER, PG_PARAMETERS_STRONG, [], [pg.entra_admin_record(PG_ADMIN)]
    )
    weak = pg.server_record(
        {
            **PG_SERVER,
            "id": _arm_id("Microsoft.DBforPostgreSQL", "flexibleServers", "pg-weak"),
            "name": "pg-weak",
            "active_directory_auth": "Disabled",
            "geo_redundant_backup": "Disabled",
            "high_availability_mode": "Disabled",
            "public_network_access": "Enabled",
        },
        {**PG_PARAMETERS_STRONG, "require_secure_transport": "OFF", "log_checkpoints": "OFF",
         "log_retention_days": "30"},
        [
            pg.firewall_rule_record(
                {"id": "r", "name": "azure", "start_ip_address": "0.0.0.0",
                 "end_ip_address": "0.0.0.0"}
            )
        ],
        [],
    )

    summary = pg.summarize([strong, weak])
    assert summary["total_postgresql_servers"] == 2
    assert summary["require_secure_transport_servers"] == 1
    assert summary["require_secure_transport_percentage"] == 50
    assert summary["entra_id_authentication_servers"] == 1
    assert summary["entra_id_authentication_configured_servers"] == 1
    assert summary["total_entra_id_admins"] == 1
    assert summary["log_checkpoints_servers"] == 1
    assert summary["log_connections_servers"] == 2
    assert summary["connection_throttling_servers"] == 0
    assert summary["log_retention_compliant_servers"] == 1
    assert summary["public_network_access_disabled_servers"] == 1
    assert summary["servers_allowing_all_azure_services"] == 1
    assert summary["servers_allowing_entire_internet"] == 0
    assert summary["total_firewall_rules"] == 1
    assert summary["geo_redundant_backup_servers"] == 1
    assert summary["high_availability_servers"] == 1


def test_postgresql_summary_empty_subscription():
    pg = _load("postgresql_configuration")
    summary = pg.summarize([])
    assert summary["total_postgresql_servers"] == 0
    assert summary["require_secure_transport_percentage"] == 0


def test_postgresql_benign_error_recognition():
    """Two Azure answers that are evidence, not failures."""
    pg = _load("postgresql_configuration")

    class FakeResourceNotFound(Exception):
        pass

    FakeResourceNotFound.__name__ = "ResourceNotFoundError"
    assert pg.is_not_found(FakeResourceNotFound("gone")) is True
    assert pg.is_not_found(RuntimeError("(ConfigurationNotExists) no such parameter")) is True
    assert pg.is_not_found(RuntimeError("(AuthorizationFailed) nope")) is False

    assert pg.is_entra_auth_disabled(
        RuntimeError("Microsoft Entra authentication is not enabled for this server")
    ) is True
    assert pg.is_entra_auth_disabled(RuntimeError("(AuthorizationFailed) nope")) is False


def test_postgresql_operation_group_tolerates_the_sdk_rename():
    """2.0.0 renamed `administrators` to `administrators_microsoft_entra`."""
    pg = _load("postgresql_configuration")
    new_sdk = SimpleNamespace(administrators_microsoft_entra="new")
    old_sdk = SimpleNamespace(administrators="old")
    assert pg._operation_group(new_sdk, "administrators_microsoft_entra", "administrators") == "new"
    assert pg._operation_group(old_sdk, "administrators_microsoft_entra", "administrators") == "old"
    assert pg._operation_group(SimpleNamespace(), "administrators") is None


# --------------------------------------------------------------------------- #
# MySQL flexible servers
# --------------------------------------------------------------------------- #

MY_SERVER_ID = _arm_id("Microsoft.DBforMySQL", "flexibleServers", "mysql-main")

MY_SERVER = {  # SYNTHETIC — project_mysql_server()'s output shape
    "id": MY_SERVER_ID,
    "name": "mysql-main",
    "type": "Microsoft.DBforMySQL/flexibleServers",
    "location": "eastus",
    "version": "8.0.21",
    "state": "Ready",
    "fully_qualified_domain_name": "mysql-main.mysql.database.azure.com",
    "public_network_access": "Disabled",
    "delegated_subnet_resource_id": None,
    "backup_retention_days": 7,
    "geo_redundant_backup": "Enabled",
    "high_availability_mode": "ZoneRedundant",
    "high_availability_state": "Healthy",
}

MY_CONFIGURATIONS = [  # SYNTHETIC — project_configuration()'s output shape
    {"id": f"{MY_SERVER_ID}/configurations/require_secure_transport",
     "name": "require_secure_transport", "value": "ON", "source": "system-default"},
    {"id": f"{MY_SERVER_ID}/configurations/tls_version",
     "name": "tls_version", "value": "TLSv1.2,TLSv1.3", "source": "user-override"},
    {"id": f"{MY_SERVER_ID}/configurations/audit_log_enabled",
     "name": "audit_log_enabled", "value": "ON", "source": "user-override"},
    {"id": f"{MY_SERVER_ID}/configurations/audit_log_events",
     "name": "audit_log_events", "value": "CONNECTION,ADMIN", "source": "user-override"},
    {"id": f"{MY_SERVER_ID}/configurations/max_connections",
     "name": "max_connections", "value": "340", "source": "system-default"},
]


def test_project_mysql_server_reads_the_nested_msrest_models():
    my = _load("mysql_configuration")
    server = SimpleNamespace(
        id=MY_SERVER_ID,
        name="mysql-main",
        type="Microsoft.DBforMySQL/flexibleServers",
        location="eastus",
        version="8.0.21",
        state="Ready",
        fully_qualified_domain_name="mysql-main.mysql.database.azure.com",
        network=SimpleNamespace(public_network_access="Disabled", delegated_subnet_resource_id=None),
        backup=SimpleNamespace(backup_retention_days=7, geo_redundant_backup="Enabled"),
        high_availability=SimpleNamespace(mode="ZoneRedundant", state="Healthy"),
    )
    assert my.project_mysql_server(server) == MY_SERVER


def test_project_mysql_configuration_omits_the_static_documentation_fields():
    """`description` / `allowed_values` are engine docs, identical on every server."""
    my = _load("mysql_configuration")
    projected = my.project_configuration(
        SimpleNamespace(
            id="c",
            name="require_secure_transport",
            value="ON",
            source="system-default",
            description="Whether client connections must use SSL.",
            allowed_values="ON,OFF",
        )
    )
    assert projected == {"id": "c", "name": "require_secure_transport", "value": "ON",
                         "source": "system-default"}


def test_mysql_configuration_map_keys_by_parameter_name():
    """A map, not a list — that is how every reader uses it, and it diffs cleanly."""
    my = _load("mysql_configuration")
    parameters = my.configuration_map(MY_CONFIGURATIONS)
    assert parameters["require_secure_transport"] == "ON"
    assert parameters["tls_version"] == "TLSv1.2,TLSv1.3"
    assert parameters["max_connections"] == "340"
    # A parameter with no name cannot be keyed and is dropped rather than becoming None.
    assert my.configuration_map([{"id": "x", "name": None, "value": "1"}]) == {}


@pytest.mark.parametrize(
    ("tls_value", "expected_versions", "expected_compliant"),
    [
        ("TLSv1.2,TLSv1.3", ["TLSv1.2", "TLSv1.3"], True),
        ("TLSv1.2", ["TLSv1.2"], True),
        # tls_version is a list of ACCEPTED versions, not a floor: a weak version
        # anywhere in it means the server still accepts it.
        ("TLSv1,TLSv1.1,TLSv1.2", ["TLSv1", "TLSv1.1", "TLSv1.2"], False),
        ("TLSv1.1,TLSv1.2,TLSv1.3", ["TLSv1.1", "TLSv1.2", "TLSv1.3"], False),
        ("TLSv1.2, TLSv1.3", ["TLSv1.2", "TLSv1.3"], True),  # whitespace tolerated
        (None, [], False),  # not configured is not compliant
        ("", [], False),
    ],
)
def test_mysql_tls_version_is_a_list_of_accepted_versions(
    tls_value, expected_versions, expected_compliant
):
    my = _load("mysql_configuration")
    configurations = [{"id": "c", "name": "tls_version", "value": tls_value, "source": "s"}]
    record = my.server_record(MY_SERVER, configurations)
    assert record["tls_versions_accepted"] == expected_versions
    assert record["tls_version_compliant"] is expected_compliant


@pytest.mark.parametrize(
    ("events", "expected"),
    [
        ("CONNECTION,ADMIN", True),
        ("connection", True),
        ("ADMIN,GENERAL", False),
        ("", False),
        (None, False),
    ],
)
def test_mysql_audit_log_connection_events(events, expected):
    """Prowler splits audit_log_events on "," and looks for the connection class."""
    my = _load("mysql_configuration")
    configurations = [{"id": "c", "name": "audit_log_events", "value": events, "source": "s"}]
    record = my.server_record(MY_SERVER, configurations)
    assert record["audit_log_connection_events"] is expected


def test_mysql_server_record_reads_the_full_parameter_set():
    my = _load("mysql_configuration")
    record = my.server_record(MY_SERVER, MY_CONFIGURATIONS)
    assert record["resource_group"] == "paramify-rg"
    assert record["version"] == "8.0.21"
    assert record["require_secure_transport_enabled"] is True
    assert record["tls_version_compliant"] is True
    assert record["audit_log_enabled_state"] is True
    assert record["audit_log_connection_events"] is True
    assert record["geo_redundant_backup_enabled"] is True
    assert record["high_availability_enabled"] is True
    assert record["public_network_access_disabled"] is True
    # Every parameter is kept, not just the four the posture fields read.
    assert record["total_configuration_parameters"] == 5
    assert record["configurations"]["max_connections"] == "340"


def test_mysql_server_with_no_configurations_reads_as_not_configured():
    """An empty parameter list must not read as "enabled" anywhere."""
    my = _load("mysql_configuration")
    record = my.server_record(MY_SERVER, [])
    assert record["require_secure_transport_enabled"] is False
    assert record["tls_version_compliant"] is False
    assert record["audit_log_enabled_state"] is False
    assert record["audit_log_connection_events"] is False
    assert record["total_configuration_parameters"] == 0


def test_mysql_summary():
    my = _load("mysql_configuration")
    strong = my.server_record(MY_SERVER, MY_CONFIGURATIONS)
    weak = my.server_record(
        {
            **MY_SERVER,
            "id": _arm_id("Microsoft.DBforMySQL", "flexibleServers", "mysql-weak"),
            "name": "mysql-weak",
            "geo_redundant_backup": "Disabled",
            "high_availability_mode": "Disabled",
            "public_network_access": "Enabled",
        },
        [
            {"id": "c", "name": "require_secure_transport", "value": "OFF", "source": "s"},
            {"id": "c", "name": "tls_version", "value": "TLSv1,TLSv1.2", "source": "s"},
            {"id": "c", "name": "audit_log_enabled", "value": "OFF", "source": "s"},
        ],
    )

    summary = my.summarize([strong, weak])
    assert summary["total_mysql_servers"] == 2
    assert summary["require_secure_transport_servers"] == 1
    assert summary["require_secure_transport_percentage"] == 50
    assert summary["tls_version_compliant_servers"] == 1
    assert summary["audit_log_enabled_servers"] == 1
    assert summary["audit_log_connection_event_servers"] == 1
    assert summary["public_network_access_disabled_servers"] == 1
    assert summary["geo_redundant_backup_servers"] == 1
    assert summary["high_availability_servers"] == 1
    assert summary["total_configuration_parameters"] == 8


def test_mysql_summary_empty_subscription():
    my = _load("mysql_configuration")
    summary = my.summarize([])
    assert summary["total_mysql_servers"] == 0
    assert summary["require_secure_transport_percentage"] == 0


# --------------------------------------------------------------------------- #
# Cosmos DB accounts
# --------------------------------------------------------------------------- #

COSMOS_ID = _arm_id("Microsoft.DocumentDB", "databaseAccounts", "cosmos-cmk")

COSMOS_HARDENED = {  # SYNTHETIC — project_database_account()'s output shape
    "id": COSMOS_ID,
    "name": "cosmos-cmk",
    "type": "Microsoft.DocumentDB/databaseAccounts",
    "location": "East US",
    "kind": "GlobalDocumentDB",
    "tags": {"env": "prod"},
    "database_account_offer_type": "Standard",
    "document_endpoint": "https://cosmos-cmk.documents.azure.com:443/",
    "disable_local_auth": True,
    "default_identity": "FirstPartyIdentity",
    "is_virtual_network_filter_enabled": True,
    "public_network_access": "Disabled",
    "minimal_tls_version": "Tls12",
    "network_acl_bypass": "None",
    "virtual_network_rules": [
        {"id": "/subscriptions/s/subnets/app", "ignore_missing_v_net_service_endpoint": False}
    ],
    "ip_rules": ["203.0.113.4"],
    "private_endpoint_connections": [
        {"id": f"{COSMOS_ID}/privateEndpointConnections/pec1", "name": "pec1",
         "type": "Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections",
         "provisioning_state": "Succeeded"}
    ],
    "key_vault_key_uri": "https://paramify-kv.vault.azure.net/keys/cosmos-key",
    "enable_automatic_failover": True,
    "enable_multiple_write_locations": False,
    "backup_policy_type": "Continuous",
}

# The permissive default account: Azure OMITS disableLocalAuth,
# enableAutomaticFailover and isVirtualNetworkFilterEnabled when they are false, so
# the projection reports None and "absent" must read as disabled.
COSMOS_DEFAULT = {  # SYNTHETIC
    "id": _arm_id("Microsoft.DocumentDB", "databaseAccounts", "cosmos-default"),
    "name": "cosmos-default",
    "type": "Microsoft.DocumentDB/databaseAccounts",
    "location": "East US",
    "kind": "MongoDB",
    "tags": None,
    "database_account_offer_type": "Standard",
    "document_endpoint": "https://cosmos-default.documents.azure.com:443/",
    "disable_local_auth": None,
    "default_identity": None,
    "is_virtual_network_filter_enabled": None,
    "public_network_access": "Enabled",
    "minimal_tls_version": None,
    "network_acl_bypass": None,
    "virtual_network_rules": [],
    "ip_rules": [],
    "private_endpoint_connections": [],
    "key_vault_key_uri": None,
    "enable_automatic_failover": None,
    "enable_multiple_write_locations": None,
    "backup_policy_type": "Periodic",
}


def test_project_database_account_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    cdb = _load("cosmosdb_configuration")
    account = SimpleNamespace(
        id=COSMOS_ID,
        name="cosmos-cmk",
        type="Microsoft.DocumentDB/databaseAccounts",
        location="East US",
        kind="GlobalDocumentDB",
        tags={"env": "prod"},
        database_account_offer_type="Standard",
        document_endpoint="https://cosmos-cmk.documents.azure.com:443/",
        disable_local_auth=True,
        default_identity="FirstPartyIdentity",
        is_virtual_network_filter_enabled=True,
        public_network_access="Disabled",
        minimal_tls_version="Tls12",
        network_acl_bypass="None",
        virtual_network_rules=[
            SimpleNamespace(
                id="/subscriptions/s/subnets/app", ignore_missing_v_net_service_endpoint=False
            )
        ],
        ip_rules=[SimpleNamespace(ip_address_or_range="203.0.113.4")],
        private_endpoint_connections=[
            SimpleNamespace(
                id=f"{COSMOS_ID}/privateEndpointConnections/pec1",
                name="pec1",
                type="Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections",
                provisioning_state="Succeeded",
            )
        ],
        key_vault_key_uri="https://paramify-kv.vault.azure.net/keys/cosmos-key",
        enable_automatic_failover=True,
        enable_multiple_write_locations=False,
        # The SDK hands back the TYPED subclass the discriminator selected.
        backup_policy=SimpleNamespace(type="Continuous"),
    )
    assert cdb.project_database_account(account) == COSMOS_HARDENED


def test_project_database_account_survives_absent_nested_models():
    """`backup_policy` and every list block are absent on a default account."""
    cdb = _load("cosmosdb_configuration")
    projected = cdb.project_database_account(
        SimpleNamespace(id=COSMOS_ID, name="cosmos-bare")
    )  # must not raise
    assert projected["backup_policy_type"] is None
    assert projected["private_endpoint_connections"] == []
    assert projected["virtual_network_rules"] == []
    assert projected["ip_rules"] == []
    assert projected["key_vault_key_uri"] is None

    record = cdb.account_record(projected)
    assert record["customer_managed_key"] is False
    assert record["disable_local_auth"] is False
    assert record["continuous_backup"] is False
    assert record["tags"] == {}


def test_project_database_account_unwraps_the_sdk_string_enums():
    """`kind`, `public_network_access` and `minimal_tls_version` are all str enums."""

    class FakeKind(str, Enum):
        GLOBAL_DOCUMENT_DB = "GlobalDocumentDB"

    class FakeTls(str, Enum):
        TLS12 = "Tls12"

    cdb = _load("cosmosdb_configuration")
    projected = cdb.project_database_account(
        SimpleNamespace(
            id=COSMOS_ID, name="c", kind=FakeKind.GLOBAL_DOCUMENT_DB,
            minimal_tls_version=FakeTls.TLS12,
        )
    )
    assert projected["kind"] == "GlobalDocumentDB"
    assert type(projected["kind"]) is str
    assert cdb.account_record(projected)["minimal_tls_version_recommended"] is True


def test_cosmos_account_record_hardened():
    cdb = _load("cosmosdb_configuration")
    record = cdb.account_record(COSMOS_HARDENED)
    assert record["resource_group"] == "paramify-rg"
    assert record["customer_managed_key"] is True
    assert record["key_vault_key_uri"].endswith("/keys/cosmos-key")
    assert record["disable_local_auth"] is True
    assert record["is_virtual_network_filter_enabled"] is True
    assert record["public_network_access_disabled"] is True
    assert record["minimal_tls_version_recommended"] is True
    assert record["uses_private_endpoints"] is True
    assert record["enable_automatic_failover"] is True
    assert record["continuous_backup"] is True
    assert record["ip_rules"] == ["203.0.113.4"]


def test_cosmos_account_record_coerces_the_omitted_booleans():
    """Azure omits these when false; `null` must read as False, not as unknown.

    A validator regex asserting `"disable_local_auth": false` would not match `null`,
    so passing the raw value through was the latent evidence bug this prevents.
    """
    cdb = _load("cosmosdb_configuration")
    record = cdb.account_record(COSMOS_DEFAULT)
    assert record["disable_local_auth"] is False
    assert record["is_virtual_network_filter_enabled"] is False
    assert record["enable_automatic_failover"] is False
    assert record["enable_multiple_write_locations"] is False
    assert record["customer_managed_key"] is False
    assert record["uses_private_endpoints"] is False
    assert record["continuous_backup"] is False
    assert record["public_network_access_disabled"] is False


@pytest.mark.parametrize(
    ("tls_version", "expected"),
    [
        ("Tls12", True),
        ("Tls13", True),
        ("Tls11", False),
        ("Tls", False),
        # An account that never set the property accepts TLS 1.0, so absent is NOT
        # compliant — the opposite of how an omitted boolean is read.
        (None, False),
    ],
)
def test_cosmos_minimal_tls_version(tls_version, expected):
    cdb = _load("cosmosdb_configuration")
    record = cdb.account_record({**COSMOS_HARDENED, "minimal_tls_version": tls_version})
    assert record["minimal_tls_version_recommended"] is expected


@pytest.mark.parametrize(
    ("public_network_access", "expected"),
    [("Disabled", True), ("SecuredByPerimeter", True), ("Enabled", False), (None, False)],
)
def test_cosmos_public_network_access(public_network_access, expected):
    cdb = _load("cosmosdb_configuration")
    record = cdb.account_record(
        {**COSMOS_HARDENED, "public_network_access": public_network_access}
    )
    assert record["public_network_access_disabled"] is expected


def test_cosmos_summary_tracks_cmk_coverage_not_encrypted_total():
    cdb = _load("cosmosdb_configuration")
    accounts = [cdb.account_record(COSMOS_HARDENED), cdb.account_record(COSMOS_DEFAULT)]

    summary = cdb.summarize(accounts)
    assert summary["total_cosmosdb_accounts"] == 2
    assert summary["customer_managed_key_accounts"] == 1
    assert summary["platform_managed_key_accounts"] == 1
    assert summary["cmk_percentage"] == 50
    # Cosmos DB is always encrypted at rest, so there is deliberately no
    # encrypted/total percentage — it would be a constant 100.
    assert "encrypted_percentage" not in summary
    assert summary["local_auth_disabled_accounts"] == 1
    assert summary["virtual_network_filter_accounts"] == 1
    assert summary["public_network_access_disabled_accounts"] == 1
    assert summary["recommended_minimal_tls_accounts"] == 1
    assert summary["private_endpoint_accounts"] == 1
    assert summary["automatic_failover_accounts"] == 1
    assert summary["multiple_write_location_accounts"] == 0
    assert summary["continuous_backup_accounts"] == 1
    assert summary["accounts_by_kind"] == {"GlobalDocumentDB": 1, "MongoDB": 1}


def test_cosmos_accounts_by_kind_is_sorted_and_handles_an_unknown_kind():
    """Sorted so the summary block is byte-stable between runs."""
    cdb = _load("cosmosdb_configuration")
    accounts = [
        cdb.account_record({**COSMOS_HARDENED, "kind": "Parse"}),
        cdb.account_record({**COSMOS_DEFAULT, "kind": None}),
        cdb.account_record({**COSMOS_HARDENED, "kind": "MongoDB"}),
    ]
    assert list(cdb.summarize(accounts)["accounts_by_kind"]) == ["MongoDB", "Parse", "unknown"]


def test_cosmos_summary_empty_subscription():
    cdb = _load("cosmosdb_configuration")
    summary = cdb.summarize([])
    assert summary["total_cosmosdb_accounts"] == 0
    assert summary["cmk_percentage"] == 0
    assert summary["accounts_by_kind"] == {}


# --------------------------------------------------------------------------- #
# Shared benign-error recognition (the local `is_not_found` helper)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "short_name", ["sql_encryption_status", "sql_server_configuration", "postgresql_configuration"]
)
def test_not_found_is_recognized_as_absence_not_failure(short_name):
    """An un-configured optional sub-resource answers 404, which is evidence.

    A server with no vulnerability assessment or no security alert policy is the
    common case; recording it as an API failure would exit 1 on a healthy estate.
    """
    module = _load(short_name)

    class FakeResourceNotFound(Exception):
        pass

    FakeResourceNotFound.__name__ = "ResourceNotFoundError"

    assert module.is_not_found(FakeResourceNotFound("nope")) is True
    assert module.is_not_found(RuntimeError("(ResourceNotFound) default was not found")) is True
    assert module.is_not_found(RuntimeError("Operation returned (404)")) is True
    assert module.is_not_found(RuntimeError("(AuthorizationFailed) does not have authorization")) is (
        False
    )
    assert module.is_not_found(RuntimeError("(429) TooManyRequests")) is False


# --------------------------------------------------------------------------- #
# Contract wiring — every database fetcher.yaml agrees with its fetcher.py
# --------------------------------------------------------------------------- #

DATABASE_FETCHERS = (
    "sql_encryption_status",
    "sql_server_configuration",
    "postgresql_configuration",
    "mysql_configuration",
    "cosmosdb_configuration",
)


@pytest.mark.parametrize("short_name", DATABASE_FETCHERS)
def test_fetcher_yaml_declares_the_ambient_credential_contract(short_name):
    import yaml

    spec = yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())
    assert spec["name"] == f"azure_{short_name}"
    assert spec["category"] == "azure"
    assert spec["version"] == "0.1.0"
    assert spec["secrets"] == []  # DefaultAzureCredential — nothing handed over
    assert spec["supports_targets"] is True
    assert spec["runtime"] == {"type": "python", "entry": "fetcher.py"}
    assert spec["output"]["type"] == "json"
    assert spec["output"]["path"] == f"azure_{short_name}.json"
    assert spec["output"]["aggregation"] == "per_target"
    assert spec["target_schema"]["subscription_id"]["env"] == "AZURE_SUBSCRIPTION_ID"
    assert spec["target_schema"]["subscription_id"]["required"] is False
    assert spec["target_schema"]["environment"]["env"] == "AZURE_ENVIRONMENT"
    assert spec["evidence_set"]["reference_id"].startswith("EVD-AZURE-")
    assert spec["evidence_set"]["name"]
    assert spec["evidence_set"]["instructions"]
    # No validators ship with these — evidence collection only.
    assert "validators" not in spec


@pytest.mark.parametrize("short_name", DATABASE_FETCHERS)
def test_fetcher_yaml_evidence_set_reference_ids_are_unique(short_name):
    import yaml

    reference_ids = [
        yaml.safe_load((AZURE_ROOT / name / "fetcher.yaml").read_text())["evidence_set"][
            "reference_id"
        ]
        for name in DATABASE_FETCHERS
    ]
    assert len(set(reference_ids)) == len(reference_ids)


@pytest.mark.parametrize("short_name", DATABASE_FETCHERS)
def test_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    short_name, tmp_path, monkeypatch
):
    """The failure path end-to-end, with no Azure SDK involved.

    With no subscription resolvable, each fetcher must still write parseable
    evidence, exit non-zero, and leave a well-formed reason in
    $FETCHER_STATUS_FILE — otherwise the runner reports the tail of stderr (often a
    harmless INFO line) as the cause. Run for all five because each has its own
    main().
    """
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    module = _load(short_name)
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
    assert written[0].name == f"azure_{short_name}_unknown.json"
    payload = json.loads(written[0].read_text())
    assert payload["metadata"]["subscription_source"] == "unresolved"
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"]
    # The raw evidence dict, never an envelope — the runner wraps it.
    assert set(payload) == {"metadata", "results", "summary"}
    assert payload["results"]["provider_registration_status"] == "unknown"

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    assert status["code"] in {
        "auth_failed", "not_authorized", "target_unreachable",
        "rate_limited", "bad_config", "partial_failure", "internal_error",
    }
