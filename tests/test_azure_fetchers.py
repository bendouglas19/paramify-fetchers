"""Fixture-based tests for the Azure evidence fetchers.

No live API calls, no credentials, and no azure-* package needs to be installed:
the heavy `azure.*` imports live inside `azure_common.credential()` and each
fetcher's `collect_*()`, and are never triggered here. Two layers are covered.

**The projection layer** (`project_*`) is each fetcher's only code that touches an
azure-mgmt model. It reads model ATTRIBUTES into a flat snake_case dict. Its tests
drive it with `SimpleNamespace` stand-ins that mimic attribute access, including
the `None` intermediates the real API hands back constantly (`encryption` absent,
a subnet with no NSG, a plan with no extensions).

Attribute access is what makes that layer portable. The three packages are not on
the same code generator, and `as_dict()` is where that shows: azure-mgmt-storage
25.x / azure-mgmt-network 31.x use the `_model_base` runtime and emit the camelCase
WIRE shape nested under "properties" (NSG rules nested twice), while
azure-mgmt-security 7.0.0 is still msrest and emits flat snake_case. Attributes are
flat snake_case on BOTH — msrest flattens `properties.*` onto the model, and
`_model_base` generates a `__getattr__` forwarding the same names to
`self.properties` — so the projections need no spelling or nesting tolerance.

**The pure transforms** (`*_record`, `summarize`, and friends) take the projection's
output and are plain dict-in/dict-out, so they are tested from literal fixtures.
Those fixtures are SYNTHETIC but not guessed: they are the projections' verified
output shape for the SDK versions above.

Run: pytest tests/test_azure_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE_ROOT = REPO_ROOT / "fetchers" / "azure"


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = AZURE_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"azure_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_shared():
    path = AZURE_ROOT / "_shared" / "azure_common.py"
    spec = importlib.util.spec_from_file_location("azure_common_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Shared helpers — azure_common
# --------------------------------------------------------------------------- #

NSG_ID = (
    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
    "/providers/Microsoft.Network/networkSecurityGroups/nsg-app"
)


def test_resource_group_from_id():
    common = _load_shared()
    assert common.resource_group_from_id(NSG_ID) == "paramify-rg"
    # ARM is inconsistent about the segment's casing across services/API versions.
    assert common.resource_group_from_id(NSG_ID.replace("resourceGroups", "resourcegroups")) == (
        "paramify-rg"
    )
    # Subscription-scoped resources have no resource group at all.
    assert common.resource_group_from_id("/subscriptions/abc/providers/Microsoft.Security/x") is None
    assert common.resource_group_from_id(None) is None


def test_basename_and_sanitize():
    common = _load_shared()
    assert common.basename(NSG_ID) == "nsg-app"
    assert common.basename(None) is None
    assert common.sanitize_for_filename("11111111-1111-1111-1111-111111111111") == (
        "11111111-1111-1111-1111-111111111111"
    )
    assert common.sanitize_for_filename("sub/with space") == "sub_with_space"
    assert common.sanitize_for_filename("") == "unknown"


def test_model_attr_is_none_tolerant_and_unwraps_enums():
    """The single primitive every projection is built from."""
    from enum import Enum

    class Tier(str, Enum):
        STANDARD = "Standard"

    common = _load_shared()
    model = SimpleNamespace(name="acct", tier=Tier.STANDARD, nothing=None)

    assert common.model_attr(model, "name") == "acct"
    # An absent attribute and an absent parent both read as None rather than raising,
    # which is what lets a projection chain through omitted nested models.
    assert common.model_attr(model, "never_set") is None
    assert common.model_attr(None, "name") is None
    assert common.model_attr(model, "nothing") is None
    # Enum members are `str` subclasses that compare equal to their value, but
    # `str()` on one yields "Tier.STANDARD" — so they must not survive the boundary.
    assert common.model_attr(model, "tier") == "Standard"
    assert type(common.model_attr(model, "tier")) is str
    assert str(common.model_attr(model, "tier")).lower() == "standard"


def test_collector_swallows_and_records():
    """The whole point of Collector: a failed call must not look like success."""
    import logging

    common = _load_shared()
    collector = common.Collector(logging.getLogger("test"))
    assert collector.ok is True

    def _boom():
        raise RuntimeError("boom")

    assert collector.guard("op.one", _boom, default=[]) == []
    assert collector.ok is False
    assert collector.failures[0]["operation"] == "op.one"
    assert collector.failures[0]["type"] == "RuntimeError"


def test_classify_failure_code_maps_to_the_contract_enum():
    common = _load_shared()
    assert common.classify_failure_code([]) == "partial_failure"
    assert (
        common.classify_failure_code([{"type": "ClientAuthenticationError", "message": "no token"}])
        == "auth_failed"
    )
    assert (
        common.classify_failure_code(
            [{"type": "HttpResponseError", "message": "(AuthorizationFailed) does not have authorization"}]
        )
        == "not_authorized"
    )
    assert (
        common.classify_failure_code(
            [{"type": "HttpResponseError", "message": "Operation returned (429) TooManyRequests"}]
        )
        == "rate_limited"
    )
    assert (
        common.classify_failure_code(
            [{"type": "ServiceRequestError", "message": "getaddrinfo failed"}]
        )
        == "target_unreachable"
    )
    assert (
        common.classify_failure_code(
            [{"type": "ModuleNotFoundError", "message": "No module named 'azure.mgmt.storage'"}]
        )
        == "internal_error"
    )
    # Anything we can't name stays honest rather than guessing a category.
    assert (
        common.classify_failure_code([{"type": "ValueError", "message": "weird"}])
        == "partial_failure"
    )
    # Every code it can return must be in the contract's closed set.
    assert common.STATUS_CODES >= {
        "auth_failed", "not_authorized", "target_unreachable",
        "rate_limited", "bad_config", "partial_failure", "internal_error",
    }


def test_failure_reason_is_one_line_and_marks_truncation():
    common = _load_shared()
    assert common.failure_reason([]) == "collection failed"

    reason = common.failure_reason(
        [
            {
                "operation": "storage.storage_accounts.list",
                "type": "ClientAuthenticationError",
                "message": "line one\nline two",
            },
            {"operation": "other", "type": "ValueError", "message": "x"},
        ]
    )
    assert reason == (
        "2 Azure API failure(s); first: storage.storage_accounts.list: "
        "ClientAuthenticationError: line one line two"
    )

    clipped = common.failure_reason(
        [{"operation": "op", "type": "E", "message": "y" * 500}], limit=20
    )
    assert clipped.endswith("y" * 20 + " ...")


def test_write_status_writes_the_contract_shape(tmp_path, monkeypatch):
    common = _load_shared()
    status_file = tmp_path / "nested" / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))

    common.write_status("Azure API read\ntimeout after 30s", "target_unreachable")
    written = json.loads(status_file.read_text())
    assert written == {"error": "Azure API read timeout after 30s", "code": "target_unreachable"}


def test_write_status_omits_an_unrecognized_code(tmp_path, monkeypatch):
    """A bogus code must not reach the runner — `error` is what's required."""
    common = _load_shared()
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))

    common.write_status("something broke", "made_up_code")
    assert json.loads(status_file.read_text()) == {"error": "something broke"}


def test_write_status_is_a_noop_without_the_env_var(monkeypatch):
    """Backward compatibility: an unset FETCHER_STATUS_FILE must write nothing."""
    common = _load_shared()
    monkeypatch.delenv("FETCHER_STATUS_FILE", raising=False)
    common.write_status("no channel configured", "auth_failed")  # must not raise


def test_resolve_subscription_prefers_the_target(monkeypatch):
    import logging

    common = _load_shared()
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "22222222-2222-2222-2222-222222222222")
    collector = common.Collector(logging.getLogger("test"))
    assert common.resolve_subscription(collector) == {
        "subscription_id": "22222222-2222-2222-2222-222222222222",
        "subscription_source": "target",
    }
    # No SDK import happened, so no failure could have been recorded.
    assert collector.ok is True


def test_build_payload_flags_partial_failure(monkeypatch):
    import logging

    common = _load_shared()
    monkeypatch.setenv("AZURE_ENVIRONMENT", "preprod")
    collector = common.Collector(logging.getLogger("test"))
    collector.record("op", RuntimeError("nope"))

    payload = common.build_payload(
        subscription_id="sub-1",
        subscription_source="target",
        collector=collector,
        results={"things": []},
        summary={"total": 0},
    )
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["environment"] == "preprod"
    assert payload["metadata"]["subscription_source"] == "target"
    assert len(payload["metadata"]["api_failures"]) == 1
    assert payload["results"] == {"things": []}


def test_coverage_percentage_is_zero_when_empty():
    common = _load_shared()
    assert common.coverage_percentage(0, 0) == 0
    assert common.coverage_percentage(1, 3) == 33


# --------------------------------------------------------------------------- #
# Storage accounts — project_storage_account() output, then the transforms
# --------------------------------------------------------------------------- #

CMK_ACCOUNT = {  # SYNTHETIC — project_storage_account()'s output shape
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
        "/providers/Microsoft.Storage/storageAccounts/pfcmk"
    ),
    "name": "pfcmk",
    "location": "eastus",
    "encryption_type": "Microsoft.Keyvault",
    "infrastructure_encryption": True,
    "enable_https_traffic_only": True,
    "minimum_tls_version": "TLS1_2",
    "allow_blob_public_access": False,
    "public_network_access": "Disabled",
    "network_rule_set": {"bypass": "Logging", "default_action": "Deny"},
    "private_endpoint_connections": [
        {"id": "/subscriptions/s/rg/pec1", "name": "pec1", "type": "Microsoft.Storage/x"}
    ],
    "key_expiration_period_in_days": 90,
    "allow_shared_key_access": False,
    "default_to_entra_authorization": True,
    "replication_settings": "Standard_GRS",
    "allow_cross_tenant_replication": False,
}

# The permissive default account: the API OMITS allowCrossTenantReplication /
# allowSharedKeyAccess / the whole networkAcls block when they sit at their
# service defaults, so the projection reports None and "absent" must read as the
# default, not as None.
DEFAULT_ACCOUNT = {  # SYNTHETIC
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
        "/providers/Microsoft.Storage/storageAccounts/pfdefault"
    ),
    "name": "pfdefault",
    "location": "eastus",
    "encryption_type": "Microsoft.Storage",
    "infrastructure_encryption": None,
    "enable_https_traffic_only": True,
    "minimum_tls_version": "TLS1_0",
    "allow_blob_public_access": True,
    "public_network_access": None,
    "network_rule_set": {"bypass": None, "default_action": None},
    "private_endpoint_connections": [],
    "key_expiration_period_in_days": None,
    "allow_shared_key_access": None,
    "default_to_entra_authorization": None,
    "replication_settings": "Standard_LRS",
    "allow_cross_tenant_replication": None,
}

BLOB_PROPERTIES = {  # SYNTHETIC — project_blob_service_properties()'s output shape
    "id": "/subscriptions/s/blobServices/default",
    "name": "default",
    "type": "Microsoft.Storage/storageAccounts/blobServices",
    "default_service_version": "2021-04-10",
    "container_delete_retention_policy": {"enabled": True, "days": 14},
    "is_versioning_enabled": True,
}

FILE_PROPERTIES = {  # SYNTHETIC — project_file_service_properties()'s output shape
    "id": "/subscriptions/s/fileServices/default",
    "name": "default",
    "type": "Microsoft.Storage/storageAccounts/fileServices",
    "share_delete_retention_policy": {"enabled": True, "days": 7},
    # The SDK hands SMB settings over as one ";"-delimited string per field.
    "smb_protocol_settings": {
        "channel_encryption": "AES-256-GCM;",
        "supported_versions": "SMB3.0;SMB3.1.1",
    },
}


def test_storage_cmk_detected_from_key_source():
    st = _load("storage_encryption_status")
    rec = st.account_record(CMK_ACCOUNT)
    assert rec["encryption_type"] == "Microsoft.Keyvault"
    assert rec["customer_managed_key"] is True
    assert rec["infrastructure_encryption"] is True
    assert rec["resource_group"] == "paramify-rg"
    assert rec["replication_settings"] == "Standard_GRS"
    assert rec["key_expiration_period_in_days"] == 90
    assert rec["allow_shared_key_access"] is False
    assert rec["default_to_entra_authorization"] is True
    assert rec["allow_cross_tenant_replication"] is False
    assert rec["public_network_access"] == "Disabled"
    assert rec["network_rule_set"] == {"bypass": "Logging", "default_action": "Deny"}
    assert rec["private_endpoint_connections"][0]["name"] == "pec1"


def test_storage_platform_key_and_permissive_defaults():
    st = _load("storage_encryption_status")
    rec = st.account_record(DEFAULT_ACCOUNT)
    assert rec["customer_managed_key"] is False
    assert rec["encryption_type"] == "Microsoft.Storage"
    assert rec["infrastructure_encryption"] is None  # absent, not False — never set
    assert rec["allow_blob_public_access"] is True
    assert rec["minimum_tls_version"] == "TLS1_0"
    assert rec["key_expiration_period_in_days"] is None
    assert rec["private_endpoint_connections"] == []
    # Absent == the permissive service default (Prowler's reading).
    assert rec["allow_shared_key_access"] is True
    assert rec["allow_cross_tenant_replication"] is True
    assert rec["network_rule_set"] == {"bypass": "AzureServices", "default_action": "Allow"}


def test_project_storage_account_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against.

    Asserting the whole dict (not a few keys) is deliberate: if the projection's
    key names ever drift from what `account_record` reads, the evidence would go
    quietly null rather than fail, so the two must be pinned to each other.
    """
    st = _load("storage_encryption_status")
    account = SimpleNamespace(
        id=CMK_ACCOUNT["id"],
        name="pfcmk",
        location="eastus",
        encryption=SimpleNamespace(
            key_source="Microsoft.Keyvault", require_infrastructure_encryption=True
        ),
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        allow_blob_public_access=False,
        public_network_access="Disabled",
        network_rule_set=SimpleNamespace(bypass="Logging", default_action="Deny"),
        private_endpoint_connections=[
            SimpleNamespace(
                id="/subscriptions/s/rg/pec1", name="pec1", type="Microsoft.Storage/x"
            )
        ],
        key_policy=SimpleNamespace(key_expiration_period_in_days=90),
        allow_shared_key_access=False,
        # The SDK still spells Entra ID by its former name.
        default_to_o_auth_authentication=True,
        sku=SimpleNamespace(name="Standard_GRS"),
        allow_cross_tenant_replication=False,
    )
    assert st.project_storage_account(account) == CMK_ACCOUNT


def test_project_storage_account_survives_absent_nested_models():
    """`encryption` / `key_policy` / `sku` absent must read as None, not raise.

    The API omits whole blocks when a feature was never configured, so every hop
    in the projection is None-tolerant. The permissive Prowler defaults are then
    the transform's job, not the projection's.
    """
    st = _load("storage_encryption_status")
    bare = SimpleNamespace(id=DEFAULT_ACCOUNT["id"], name="pfdefault", location="eastus")
    projected = st.project_storage_account(bare)  # must not raise

    assert projected["encryption_type"] is None
    assert projected["infrastructure_encryption"] is None
    assert projected["key_expiration_period_in_days"] is None
    assert projected["replication_settings"] is None
    assert projected["network_rule_set"] == {"bypass": None, "default_action": None}
    assert projected["private_endpoint_connections"] == []

    # ... and the transform still lands on the permissive service defaults.
    rec = st.account_record(projected)
    assert rec["customer_managed_key"] is False
    assert rec["allow_shared_key_access"] is True
    assert rec["allow_cross_tenant_replication"] is True
    assert rec["default_to_entra_authorization"] is False
    assert rec["network_rule_set"] == {"bypass": "AzureServices", "default_action": "Allow"}


def test_project_storage_account_unwraps_the_sdk_string_enums():
    """azure-mgmt types `key_source` as a `str` enum; `str()` on it is a trap.

    A member compares equal to its value, but `str(KeySource.MICROSOFT_KEYVAULT)`
    is "KeySource.MICROSOFT_KEYVAULT" — so leaving the enum in place would make
    `account_record`'s lowercased comparison report a CMK account as
    platform-managed, and would put an enum repr in the evidence. The removed
    `as_dict()` used to unwrap these, so the projection must.
    """
    from enum import Enum

    class FakeKeySource(str, Enum):
        MICROSOFT_KEYVAULT = "Microsoft.Keyvault"

    st = _load("storage_encryption_status")
    account = SimpleNamespace(
        id=CMK_ACCOUNT["id"],
        name="pfcmk",
        encryption=SimpleNamespace(key_source=FakeKeySource.MICROSOFT_KEYVAULT),
    )
    projected = st.project_storage_account(account)
    assert projected["encryption_type"] == "Microsoft.Keyvault"
    assert type(projected["encryption_type"]) is str
    assert st.account_record(projected)["customer_managed_key"] is True


def test_project_blob_and_file_service_properties_read_sdk_attributes():
    st = _load("storage_encryption_status")
    blob = SimpleNamespace(
        id=BLOB_PROPERTIES["id"],
        name="default",
        type="Microsoft.Storage/storageAccounts/blobServices",
        default_service_version="2021-04-10",
        container_delete_retention_policy=SimpleNamespace(enabled=True, days=14),
        is_versioning_enabled=True,
    )
    assert st.project_blob_service_properties(blob) == BLOB_PROPERTIES

    files = SimpleNamespace(
        id=FILE_PROPERTIES["id"],
        name="default",
        type="Microsoft.Storage/storageAccounts/fileServices",
        share_delete_retention_policy=SimpleNamespace(enabled=True, days=7),
        protocol_settings=SimpleNamespace(
            smb=SimpleNamespace(channel_encryption="AES-256-GCM;", versions="SMB3.0;SMB3.1.1")
        ),
    )
    assert st.project_file_service_properties(files) == FILE_PROPERTIES


def test_project_file_service_properties_survives_absent_protocol_settings():
    """`protocol_settings.smb` is the deepest optional chain — both hops can be None."""
    st = _load("storage_encryption_status")
    projected = st.project_file_service_properties(
        SimpleNamespace(id="x", name="default", type="t")
    )  # must not raise
    assert projected["smb_protocol_settings"] == {
        "channel_encryption": None,
        "supported_versions": None,
    }
    assert projected["share_delete_retention_policy"] == {"enabled": None, "days": None}
    # An SMB block present but with no `smb` child must be just as safe.
    half = st.project_file_service_properties(
        SimpleNamespace(id="x", name="default", type="t", protocol_settings=SimpleNamespace())
    )
    assert half["smb_protocol_settings"]["supported_versions"] is None

    rec = st.file_service_properties_record(projected)
    assert rec["share_delete_retention_policy"] == {"enabled": False, "days": 0}
    assert rec["smb_protocol_settings"] == {"channel_encryption": [], "supported_versions": []}


def test_storage_blob_and_file_service_enrichment():
    st = _load("storage_encryption_status")
    blob = st.blob_properties_record(BLOB_PROPERTIES)
    assert blob["versioning_enabled"] is True
    assert blob["container_delete_retention_policy"] == {"enabled": True, "days": 14}
    assert blob["default_service_version"] == "2021-04-10"

    files = st.file_service_properties_record(FILE_PROPERTIES)
    assert files["share_delete_retention_policy"] == {"enabled": True, "days": 7}
    # The SDK hands back one ";"-delimited string with a trailing separator.
    assert files["smb_protocol_settings"]["channel_encryption"] == ["AES-256-GCM"]
    assert files["smb_protocol_settings"]["supported_versions"] == ["SMB3.0", "SMB3.1.1"]


def test_storage_missing_retention_block_reads_as_disabled():
    """An omitted soft-delete block means the feature was never turned on."""
    st = _load("storage_encryption_status")
    blob = st.blob_properties_record({"id": "x", "name": "default", "properties": {}})
    assert blob["container_delete_retention_policy"] == {"enabled": False, "days": 0}
    assert blob["versioning_enabled"] is False


def test_storage_benign_unsupported_service_is_recognized():
    """Prowler skips this exact message; recording it would fail the whole run."""
    st = _load("storage_encryption_status")
    assert st._is_benign_unsupported(RuntimeError("Blob is not supported for the account.")) is True
    assert st._is_benign_unsupported(RuntimeError("File is not supported for the account.")) is True
    assert st._is_benign_unsupported(RuntimeError("(AuthorizationFailed) nope")) is False


def test_storage_summary_tracks_cmk_coverage_not_encrypted_total():
    st = _load("storage_encryption_status")
    cmk = st.account_record(CMK_ACCOUNT)
    cmk["blob_properties"] = st.blob_properties_record(BLOB_PROPERTIES)
    cmk["file_service_properties"] = st.file_service_properties_record(FILE_PROPERTIES)
    accounts = [cmk, st.account_record(DEFAULT_ACCOUNT)]

    summary = st.summarize(accounts)
    assert summary["total_storage_accounts"] == 2
    assert summary["customer_managed_key_storage"] == 1
    assert summary["platform_managed_key_storage"] == 1
    assert summary["cmk_percentage"] == 50
    # There is deliberately NO encrypted/total percentage: Azure Storage is always
    # encrypted at rest, so such a number would be a constant 100 and prove nothing.
    assert "encrypted_percentage" not in summary
    assert summary["infrastructure_encryption_accounts"] == 1
    assert summary["minimum_tls_1_2_accounts"] == 1
    assert summary["public_blob_access_accounts"] == 1
    assert summary["shared_key_access_accounts"] == 1  # the default account only
    assert summary["private_endpoint_accounts"] == 1
    assert summary["key_expiration_policy_accounts"] == 1
    assert summary["blob_versioning_accounts"] == 1
    assert summary["container_soft_delete_accounts"] == 1
    assert summary["share_soft_delete_accounts"] == 1


def test_storage_summary_empty_subscription():
    st = _load("storage_encryption_status")
    summary = st.summarize([])
    assert summary["total_storage_accounts"] == 0
    assert summary["cmk_percentage"] == 0


# --------------------------------------------------------------------------- #
# Network security groups — project_security_group() / project_virtual_network()
# output, then the transforms
# --------------------------------------------------------------------------- #

NSG_SSH_OPEN = {  # SYNTHETIC — project_security_group()'s output shape
    "id": NSG_ID,
    "name": "nsg-app",
    "location": "eastus",
    "security_rules": [
        {
            "id": f"{NSG_ID}/securityRules/allow-ssh",
            "name": "allow-ssh",
            "destination_port_range": "22",
            "destination_port_ranges": None,
            "protocol": "Tcp",
            "source_address_prefix": "Internet",
            "source_address_prefixes": None,
            "access": "Allow",
            "direction": "Inbound",
        },
        {
            "id": f"{NSG_ID}/securityRules/deny-rdp",
            "name": "deny-rdp",
            "destination_port_range": "3389",
            "destination_port_ranges": None,
            "protocol": "Tcp",
            "source_address_prefix": "*",
            "source_address_prefixes": None,
            "access": "Deny",
            "direction": "Inbound",
        },
    ],
}

NSG_LOCKED_DOWN = {  # SYNTHETIC — SSH only from a corporate range, RDP via a range
    "id": NSG_ID.replace("nsg-app", "nsg-db"),
    "name": "nsg-db",
    "location": "eastus",
    "security_rules": [
        {
            "id": "r1",
            "name": "allow-ssh-corp",
            "destination_port_range": "22",
            "destination_port_ranges": None,
            "protocol": "Tcp",
            "source_address_prefix": "10.0.0.0/8",
            "source_address_prefixes": None,
            "access": "Allow",
            "direction": "Inbound",
        },
        {
            # Plural, list-valued form: the singular field is null when a rule
            # uses ranges, so ignoring it would hide a real open rule.
            "id": "r2",
            "name": "allow-range-from-anywhere",
            "destination_port_range": None,
            "destination_port_ranges": ["3380-3400"],
            "protocol": "*",
            "source_address_prefix": None,
            "source_address_prefixes": ["0.0.0.0/0"],
            "access": "Allow",
            "direction": "Inbound",
        },
    ],
}

VNET_WITH_UNPROTECTED_SUBNET = {  # SYNTHETIC — project_virtual_network()'s output
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
        "/providers/Microsoft.Network/virtualNetworks/vnet-main"
    ),
    "name": "vnet-main",
    "location": "eastus",
    "enable_ddos_protection": True,
    "subnets": [
        {"id": "/subscriptions/s/subnets/app", "name": "app", "nsg_id": NSG_ID},
        {"id": "/subscriptions/s/subnets/bare", "name": "bare", "nsg_id": None},
    ],
}


def _fake_rule(**fields):
    """A `SecurityRule` stand-in: only the attributes the SDK actually set exist."""
    return SimpleNamespace(**fields)


def test_project_security_group_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    net = _load("network_security_groups")
    group = SimpleNamespace(
        id=NSG_ID,
        name="nsg-app",
        location="eastus",
        security_rules=[
            _fake_rule(
                id=f"{NSG_ID}/securityRules/allow-ssh",
                name="allow-ssh",
                protocol="Tcp",
                source_address_prefix="Internet",
                destination_port_range="22",
                access="Allow",
                direction="Inbound",
                priority=100,
            ),
            _fake_rule(
                id=f"{NSG_ID}/securityRules/deny-rdp",
                name="deny-rdp",
                protocol="Tcp",
                source_address_prefix="*",
                destination_port_range="3389",
                access="Deny",
                direction="Inbound",
                priority=200,
            ),
        ],
    )
    assert net.project_security_group(group) == NSG_SSH_OPEN


def test_project_security_group_survives_a_group_with_no_rules():
    """`security_rules` is None (not []) on an NSG the API returned no rules for."""
    net = _load("network_security_groups")
    projected = net.project_security_group(
        SimpleNamespace(id=NSG_ID, name="nsg-empty", location="eastus")
    )  # must not raise
    assert projected["security_rules"] == []
    assert net.security_group_record(projected)["security_rules"] == []


def test_project_security_rule_leaves_absent_fields_none():
    """A bare rule's fields are None from the projection; defaults are the transform's job."""
    net = _load("network_security_groups")
    projected = net.project_security_rule(_fake_rule(id="r", name="bare"))
    assert projected["access"] is None
    assert projected["direction"] is None
    assert projected["destination_port_ranges"] is None
    assert projected["source_address_prefixes"] is None


def test_project_virtual_network_reads_sdk_attributes():
    net = _load("network_security_groups")
    vnet = SimpleNamespace(
        id=VNET_WITH_UNPROTECTED_SUBNET["id"],
        name="vnet-main",
        location="eastus",
        enable_ddos_protection=True,
        subnets=[
            SimpleNamespace(
                id="/subscriptions/s/subnets/app",
                name="app",
                network_security_group=SimpleNamespace(id=NSG_ID, location="eastus"),
            ),
            # A subnet with nothing attached: network_security_group is None, and
            # reading `.id` off it must not raise.
            SimpleNamespace(id="/subscriptions/s/subnets/bare", name="bare"),
        ],
    )
    assert net.project_virtual_network(vnet) == VNET_WITH_UNPROTECTED_SUBNET


def test_project_virtual_network_survives_a_vnet_with_no_subnets():
    net = _load("network_security_groups")
    projected = net.project_virtual_network(
        SimpleNamespace(id="/subscriptions/s/virtualNetworks/v", name="v", location="eastus")
    )  # must not raise
    assert projected["subnets"] == []
    assert projected["enable_ddos_protection"] is None
    assert net.virtual_network_record(projected)["enable_ddos_protection"] is False


def test_nsg_rule_defaults_are_conservative():
    """Absent access/direction must read as Allow/Inbound, as Prowler reads them."""
    net = _load("network_security_groups")
    rec = net.security_rule_record({"id": "r", "name": "bare"})
    assert rec["access"] == "Allow"
    assert rec["direction"] == "Inbound"
    assert rec["destination_port_ranges"] == []
    assert rec["source_address_prefixes"] == []


@pytest.mark.parametrize(
    ("port_range", "port", "expected"),
    [
        ("22", 22, True),
        ("*", 22, True),
        ("20-30", 22, True),
        ("3380-3400", 3389, True),
        ("23-30", 22, False),
        ("2200", 22, False),
        ("", 22, False),
        (None, 22, False),
        ("not-a-range", 22, False),  # must not raise
    ],
)
def test_port_range_match(port_range, port, expected):
    net = _load("network_security_groups")
    assert net._port_in_range(port_range, port) is expected


def test_rule_opens_port_to_internet_matches_prowlers_five_clauses():
    net = _load("network_security_groups")
    rules = net.security_group_record(NSG_SSH_OPEN)["security_rules"]
    ssh_allow, rdp_deny = rules
    assert net.rule_opens_port_to_internet(ssh_allow, 22) is True
    assert net.rule_opens_port_to_internet(ssh_allow, 3389) is False   # wrong port
    assert net.rule_opens_port_to_internet(rdp_deny, 3389) is False    # access=Deny


def test_rule_opens_port_to_internet_via_the_plural_list_form():
    net = _load("network_security_groups")
    corp_ssh, wide_range = net.security_group_record(NSG_LOCKED_DOWN)["security_rules"]
    assert net.rule_opens_port_to_internet(corp_ssh, 22) is False      # corp source only
    assert net.rule_opens_port_to_internet(wide_range, 3389) is True   # 3380-3400 from 0.0.0.0/0


def test_vnet_subnet_nsg_association_and_ddos():
    net = _load("network_security_groups")
    rec = net.virtual_network_record(VNET_WITH_UNPROTECTED_SUBNET)
    assert rec["enable_ddos_protection"] is True
    assert rec["resource_group"] == "paramify-rg"
    assert [s["name"] for s in rec["subnets"]] == ["app", "bare"]
    assert rec["subnets"][0]["nsg_id"] == NSG_ID
    assert rec["subnets"][1]["nsg_id"] is None


def test_network_summary_counts_exposure_and_subnet_coverage():
    net = _load("network_security_groups")
    groups = [
        net.security_group_record(NSG_SSH_OPEN),
        net.security_group_record(NSG_LOCKED_DOWN),
    ]
    vnets = [net.virtual_network_record(VNET_WITH_UNPROTECTED_SUBNET)]

    summary = net.summarize(groups, vnets)
    assert summary["total_network_security_groups"] == 2
    assert summary["total_security_rules"] == 4
    assert summary["ssh_open_to_internet_groups"] == 1      # nsg-app only
    assert summary["rdp_open_to_internet_groups"] == 1      # nsg-db, via the 3380-3400 range
    assert summary["inbound_allow_rules"] == 3
    assert summary["internet_sourced_allow_rules"] == 2
    assert summary["total_virtual_networks"] == 1
    assert summary["ddos_protected_virtual_networks"] == 1
    assert summary["total_subnets"] == 2
    assert summary["subnets_with_nsg"] == 1
    assert summary["subnets_without_nsg"] == 1
    assert summary["subnet_nsg_coverage_percentage"] == 50


def test_network_summary_empty_subscription():
    net = _load("network_security_groups")
    summary = net.summarize([], [])
    assert summary["total_network_security_groups"] == 0
    assert summary["subnet_nsg_coverage_percentage"] == 0


# --------------------------------------------------------------------------- #
# Defender for Cloud plans — project_pricing() output, then the transforms
# (azure-mgmt-security 7.0.0 is msrest: attributes are already flat snake_case,
#  and `is_enabled` is a STRING enum)
# --------------------------------------------------------------------------- #

STANDARD_PLAN = {  # SYNTHETIC — project_pricing()'s output shape
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Security"
        "/pricings/VirtualMachines"
    ),
    "name": "VirtualMachines",
    "pricing_tier": "Standard",
    "free_trial_remaining_time": "P25D",
    "extensions": [
        {"name": "AgentlessVmScanning", "is_enabled": "True"},
        {"name": "FileIntegrityMonitoring", "is_enabled": "False"},
    ],
}

FREE_PLAN = {  # SYNTHETIC — a Free plan the API returns no extensions for
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Security"
        "/pricings/KeyVaults"
    ),
    "name": "KeyVaults",
    "pricing_tier": "Free",
    "free_trial_remaining_time": "P0D",
    "extensions": [],
}

def test_project_pricing_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    df = _load("defender_plans")
    pricing = SimpleNamespace(
        id=STANDARD_PLAN["id"],
        name="VirtualMachines",
        type="Microsoft.Security/pricings",
        pricing_tier="Standard",
        # msrest deserializes an ISO-8601 duration into a timedelta.
        free_trial_remaining_time=timedelta(days=25),
        extensions=[
            SimpleNamespace(name="AgentlessVmScanning", is_enabled="True"),
            SimpleNamespace(name="FileIntegrityMonitoring", is_enabled="False"),
        ],
    )
    assert df.project_pricing(pricing) == STANDARD_PLAN


def test_project_pricing_survives_a_plan_with_no_extensions():
    """A Free plan has `extensions` set to None, not to an empty list."""
    df = _load("defender_plans")
    projected = df.project_pricing(
        SimpleNamespace(
            id=FREE_PLAN["id"],
            name="KeyVaults",
            pricing_tier="Free",
            free_trial_remaining_time=timedelta(0),
        )
    )  # must not raise
    assert projected == FREE_PLAN
    assert df.pricing_record(projected)["extensions"] == {}


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (timedelta(0), "P0D"),
        (timedelta(days=25), "P25D"),
        (timedelta(days=30), "P30D"),
        (timedelta(days=1, hours=3), "P1DT3H"),
        (timedelta(hours=3, minutes=4, seconds=5), "PT3H4M5S"),
        (timedelta(seconds=5), "PT5S"),
        (timedelta(minutes=90), "PT1H30M"),
        (timedelta(days=2, seconds=30, microseconds=500000), "P2DT30.5S"),
        ("P25D", "P25D"),  # already a string (a future SDK) — passes through
        (None, None),
    ],
)
def test_defender_free_trial_duration_keeps_the_wire_format(delta, expected):
    """`free_trial_remaining_time` arrives as a timedelta; the evidence wants "P25D".

    These are the SDK serializer's own outputs for the same inputs. Rendering the
    timedelta with `str()` instead would write "25 days, 0:00:00" into the
    evidence — a payload change for identical input.
    """
    df = _load("defender_plans")
    assert df._iso8601_duration(delta) == expected


def test_defender_string_boolean_enum_is_not_read_as_always_true():
    """`is_enabled` is the literal string "False" — bool("False") would be True."""
    df = _load("defender_plans")
    rec = df.pricing_record(STANDARD_PLAN)
    assert rec["extensions"] == {
        "AgentlessVmScanning": True,
        "FileIntegrityMonitoring": False,
    }


def test_defender_plan_projection():
    df = _load("defender_plans")
    rec = df.pricing_record(STANDARD_PLAN)
    assert rec["resource_name"] == "VirtualMachines"
    assert rec["resource_id"].endswith("/pricings/VirtualMachines")
    assert rec["pricing_tier"] == "Standard"
    assert rec["free_trial_remaining_time"] == "P25D"

    free = df.pricing_record(FREE_PLAN)
    assert free["pricing_tier"] == "Free"
    assert free["extensions"] == {}


def test_defender_provider_not_registered_is_recognized():
    """Not registered = the service isn't in use. Valid evidence, NOT a failure."""
    df = _load("defender_plans")

    class FakeResourceNotFound(Exception):
        def __init__(self):
            self.message = (
                "(Subscription Not Registered) Subscription Not Registered - Please register "
                "to Microsoft.Security in order to view your security status"
            )
            super().__init__(self.message)

    assert df.is_provider_not_registered(FakeResourceNotFound()) is True
    assert df.is_provider_not_registered(RuntimeError("(AuthorizationFailed) nope")) is False


def test_defender_summary_tracks_standard_tier_coverage():
    df = _load("defender_plans")
    plans = [df.pricing_record(STANDARD_PLAN), df.pricing_record(FREE_PLAN)]
    summary = df.summarize(plans, df.REGISTERED)
    assert summary["provider_registration_status"] == "registered"
    assert summary["total_plans"] == 2
    assert summary["standard_tier_plans"] == 1
    assert summary["free_tier_plans"] == 1
    assert summary["standard_tier_percentage"] == 50
    assert summary["plans_with_enabled_extensions"] == 1
    assert summary["total_enabled_extensions"] == 1


def test_defender_summary_when_provider_is_not_registered():
    df = _load("defender_plans")
    summary = df.summarize([], df.NOT_REGISTERED)
    assert summary["provider_registration_status"] == "not_registered"
    assert summary["total_plans"] == 0
    assert summary["standard_tier_percentage"] == 0


# --------------------------------------------------------------------------- #
# Contract wiring — every Azure fetcher.yaml agrees with its fetcher.py
# --------------------------------------------------------------------------- #

AZURE_FETCHERS = ("storage_encryption_status", "network_security_groups", "defender_plans")


@pytest.mark.parametrize("short_name", AZURE_FETCHERS)
def test_fetcher_yaml_declares_the_ambient_credential_contract(short_name):
    import yaml

    spec = yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())
    assert spec["name"] == f"azure_{short_name}"
    assert spec["category"] == "azure"
    assert spec["secrets"] == []  # DefaultAzureCredential — nothing handed over
    assert spec["supports_targets"] is True
    assert spec["output"]["aggregation"] == "per_target"
    assert spec["target_schema"]["subscription_id"]["env"] == "AZURE_SUBSCRIPTION_ID"
    assert spec["target_schema"]["subscription_id"]["required"] is False
    assert spec["evidence_set"]["reference_id"].startswith("EVD-AZURE-")


def test_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    tmp_path, monkeypatch
):
    """The failure path end-to-end, with no Azure SDK involved.

    With AZURE_SUBSCRIPTION_ID unset, `resolve_subscription` tries the SDK import
    and fails, so the fetcher must still write parseable evidence, exit non-zero,
    and leave a well-formed reason in $FETCHER_STATUS_FILE.

    Run against one fetcher, not all three: the reason text and the exit path come
    from `azure_common` (unit-tested above), and
    tests/test_failure_reporting_contract.py statically asserts that every fetcher
    in the tree writes the status file before exiting. This covers the remaining
    question — that the whole chain produces a valid file at runtime.
    """
    short_name = "storage_encryption_status"
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
    payload = json.loads(written[0].read_text())
    assert payload["metadata"]["subscription_source"] == "unresolved"
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"]

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    common = _load_shared()
    assert status["code"] in common.STATUS_CODES
