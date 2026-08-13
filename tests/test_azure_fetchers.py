"""Fixture-based tests for the Azure evidence fetchers.

These exercise each fetcher's PURE transform functions against fixture responses
(no live API calls, no credentials, no azure-* packages needed — the heavy
`azure.*` imports live inside `azure_common.credential()` and each fetcher's
`collect_*()` and are never triggered here), plus the shared helpers in
`fetchers/azure/_shared/azure_common.py`.

**Fixture provenance.** No live Azure tenant was available, so the fixtures are
SYNTHETIC — but not guessed. Each was produced by constructing the real SDK model
(azure-mgmt-storage 25.1.0, azure-mgmt-network 31.0.1, azure-mgmt-security 7.0.0)
and dumping `model.as_dict()`, so the key names and nesting are the SDK's own. That
matters because the three packages are NOT on the same generator:

- azure-mgmt-storage / azure-mgmt-network are on the newer `_model_base` runtime,
  whose `as_dict()` emits the WIRE shape — camelCase keys nested under
  `"properties"` (and security rules are nested twice: nsg.properties.securityRules
  [i].properties.destinationPortRange).
- azure-mgmt-security is still msrest, whose `as_dict()` emits FLAT snake_case
  (`pricing_tier`, `is_enabled`).

The transforms therefore read both spellings and both nestings; the tests below
pin that tolerance, because an SDK bump that flips a package between generators
would otherwise silently empty the evidence rather than fail.

Run: pytest tests/test_azure_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

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
# Storage accounts — azure-mgmt-storage 25.1.0 StorageAccount.as_dict()
# (wire shape: camelCase under "properties")
# --------------------------------------------------------------------------- #

CMK_ACCOUNT = {  # SYNTHETIC, dumped from StorageAccount(...).as_dict()
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
        "/providers/Microsoft.Storage/storageAccounts/pfcmk"
    ),
    "name": "pfcmk",
    "location": "eastus",
    "sku": {"name": "Standard_GRS"},
    "properties": {
        "networkAcls": {"bypass": "Logging", "defaultAction": "Deny"},
        "allowSharedKeyAccess": False,
        "keyPolicy": {"keyExpirationPeriodInDays": 90},
        "encryption": {"keySource": "Microsoft.Keyvault", "requireInfrastructureEncryption": True},
        "minimumTlsVersion": "TLS1_2",
        "publicNetworkAccess": "Disabled",
        "defaultToOAuthAuthentication": True,
        "allowBlobPublicAccess": False,
        "supportsHttpsTrafficOnly": True,
        "allowCrossTenantReplication": False,
        "privateEndpointConnections": [
            {"id": "/subscriptions/s/rg/pec1", "name": "pec1", "type": "Microsoft.Storage/x"}
        ],
    },
}

# The permissive default account: the API OMITS allowCrossTenantReplication /
# allowSharedKeyAccess / the whole networkAcls block when they sit at their
# service defaults, so "absent" must read as the default, not as None.
DEFAULT_ACCOUNT = {  # SYNTHETIC
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
        "/providers/Microsoft.Storage/storageAccounts/pfdefault"
    ),
    "name": "pfdefault",
    "location": "eastus",
    "sku": {"name": "Standard_LRS"},
    "properties": {
        "encryption": {"keySource": "Microsoft.Storage"},
        "minimumTlsVersion": "TLS1_0",
        "supportsHttpsTrafficOnly": True,
        "allowBlobPublicAccess": True,
    },
}

# The same account as the FLAT snake_case shape an msrest-generation SDK would
# emit — proves the transform survives a generator flip.
FLAT_ACCOUNT = {  # SYNTHETIC
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/other-rg"
        "/providers/Microsoft.Storage/storageAccounts/pfflat"
    ),
    "name": "pfflat",
    "location": "westus2",
    "sku": {"name": "Premium_ZRS"},
    "encryption": {"key_source": "Microsoft.Keyvault", "require_infrastructure_encryption": False},
    "minimum_tls_version": "TLS1_2",
    "enable_https_traffic_only": True,
    "allow_blob_public_access": False,
    "network_rule_set": {"bypass": "AzureServices", "default_action": "Deny"},
    "key_policy": {"key_expiration_period_in_days": 30},
}

BLOB_PROPERTIES = {  # SYNTHETIC, from BlobServiceProperties(...).as_dict()
    "id": "/subscriptions/s/blobServices/default",
    "name": "default",
    "type": "Microsoft.Storage/storageAccounts/blobServices",
    "properties": {
        "defaultServiceVersion": "2021-04-10",
        "containerDeleteRetentionPolicy": {"enabled": True, "days": 14},
        "isVersioningEnabled": True,
    },
}

FILE_PROPERTIES = {  # SYNTHETIC, from FileServiceProperties(...).as_dict()
    "id": "/subscriptions/s/fileServices/default",
    "name": "default",
    "type": "Microsoft.Storage/storageAccounts/fileServices",
    "properties": {
        "shareDeleteRetentionPolicy": {"enabled": True, "days": 7},
        "protocolSettings": {
            "smb": {"versions": "SMB3.0;SMB3.1.1", "channelEncryption": "AES-256-GCM;"}
        },
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


def test_storage_transform_reads_the_flat_snake_case_shape():
    """An SDK generator flip must not silently empty the evidence."""
    st = _load("storage_encryption_status")
    rec = st.account_record(FLAT_ACCOUNT)
    assert rec["customer_managed_key"] is True
    assert rec["enable_https_traffic_only"] is True
    assert rec["minimum_tls_version"] == "TLS1_2"
    assert rec["key_expiration_period_in_days"] == 30
    assert rec["resource_group"] == "other-rg"
    assert rec["network_rule_set"]["default_action"] == "Deny"


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
# Network security groups — azure-mgmt-network 31.0.1 as_dict()
# (rules nested TWICE: nsg.properties.securityRules[i].properties.*)
# --------------------------------------------------------------------------- #

NSG_SSH_OPEN = {  # SYNTHETIC, from NetworkSecurityGroup(...).as_dict()
    "id": NSG_ID,
    "name": "nsg-app",
    "location": "eastus",
    "properties": {
        "securityRules": [
            {
                "id": f"{NSG_ID}/securityRules/allow-ssh",
                "name": "allow-ssh",
                "properties": {
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "Internet",
                    "destinationPortRange": "22",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 100,
                },
            },
            {
                "id": f"{NSG_ID}/securityRules/deny-rdp",
                "name": "deny-rdp",
                "properties": {
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "3389",
                    "access": "Deny",
                    "direction": "Inbound",
                    "priority": 200,
                },
            },
        ]
    },
}

NSG_LOCKED_DOWN = {  # SYNTHETIC — SSH only from a corporate range, RDP via a range
    "id": NSG_ID.replace("nsg-app", "nsg-db"),
    "name": "nsg-db",
    "location": "eastus",
    "properties": {
        "securityRules": [
            {
                "id": "r1",
                "name": "allow-ssh-corp",
                "properties": {
                    "protocol": "Tcp",
                    "sourceAddressPrefix": "10.0.0.0/8",
                    "destinationPortRange": "22",
                    "access": "Allow",
                    "direction": "Inbound",
                },
            },
            {
                # Plural, list-valued form: the singular field is null when a rule
                # uses ranges, so ignoring it would hide a real open rule.
                "id": "r2",
                "name": "allow-range-from-anywhere",
                "properties": {
                    "protocol": "*",
                    "sourceAddressPrefixes": ["0.0.0.0/0"],
                    "destinationPortRanges": ["3380-3400"],
                    "access": "Allow",
                    "direction": "Inbound",
                },
            },
        ]
    },
}

VNET_WITH_UNPROTECTED_SUBNET = {  # SYNTHETIC, from VirtualNetwork(...).as_dict()
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/paramify-rg"
        "/providers/Microsoft.Network/virtualNetworks/vnet-main"
    ),
    "name": "vnet-main",
    "location": "eastus",
    "properties": {
        "enableDdosProtection": True,
        "subnets": [
            {
                "id": "/subscriptions/s/subnets/app",
                "name": "app",
                "properties": {"networkSecurityGroup": {"id": NSG_ID, "location": "eastus"}},
            },
            {"id": "/subscriptions/s/subnets/bare", "name": "bare", "properties": {}},
        ],
    },
}


def test_nsg_rule_projection_reads_the_double_nesting():
    net = _load("network_security_groups")
    rec = net.security_group_record(NSG_SSH_OPEN)
    assert rec["name"] == "nsg-app"
    assert rec["resource_group"] == "paramify-rg"
    assert len(rec["security_rules"]) == 2
    ssh = rec["security_rules"][0]
    assert ssh["destination_port_range"] == "22"
    assert ssh["protocol"] == "Tcp"
    assert ssh["source_address_prefix"] == "Internet"
    assert ssh["access"] == "Allow"
    assert ssh["direction"] == "Inbound"


def test_nsg_rule_defaults_are_conservative():
    """Absent access/direction must read as Allow/Inbound, as Prowler reads them."""
    net = _load("network_security_groups")
    rec = net.security_rule_record({"id": "r", "name": "bare", "properties": {}})
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
# Defender for Cloud plans — azure-mgmt-security 7.0.0 Pricing.as_dict()
# (msrest generation: FLAT snake_case, and is_enabled is a STRING enum)
# --------------------------------------------------------------------------- #

STANDARD_PLAN = {  # SYNTHETIC, from Pricing(...).as_dict()
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Security"
        "/pricings/VirtualMachines"
    ),
    "name": "VirtualMachines",
    "type": "Microsoft.Security/pricings",
    "pricing_tier": "Standard",
    "free_trial_remaining_time": "P25D",
    "extensions": [
        {"name": "AgentlessVmScanning", "is_enabled": "True"},
        {"name": "FileIntegrityMonitoring", "is_enabled": "False"},
    ],
}

FREE_PLAN = {  # SYNTHETIC
    "id": (
        "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Security"
        "/pricings/KeyVaults"
    ),
    "name": "KeyVaults",
    "type": "Microsoft.Security/pricings",
    "pricing_tier": "Free",
    "free_trial_remaining_time": "P0D",
}

CAMEL_PLAN = {  # SYNTHETIC — the wire shape, if this SDK is ever regenerated
    "id": "/subscriptions/s/providers/Microsoft.Security/pricings/StorageAccounts",
    "name": "StorageAccounts",
    "properties": {
        "pricingTier": "Standard",
        "freeTrialRemainingTime": "P30D",
        "extensions": [{"name": "OnUploadMalwareScanning", "isEnabled": "True"}],
    },
}


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


def test_defender_plan_reads_the_camel_case_wire_shape():
    df = _load("defender_plans")
    rec = df.pricing_record(CAMEL_PLAN)
    assert rec["pricing_tier"] == "Standard"
    assert rec["free_trial_remaining_time"] == "P30D"
    assert rec["extensions"] == {"OnUploadMalwareScanning": True}


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


@pytest.mark.parametrize("short_name", AZURE_FETCHERS)
def test_declared_ksis_exist_in_the_reference_list(short_name):
    """`ksis:` may only name ids from framework/reference/ksis.yaml."""
    import yaml

    known = {
        entry["id"]
        for entry in yaml.safe_load(
            (REPO_ROOT / "framework" / "reference" / "ksis.yaml").read_text()
        )["ksis"]
    }
    spec = yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())
    assert spec["ksis"], f"azure_{short_name} declares no KSIs"
    assert set(spec["ksis"]) <= known, f"unknown KSI in azure_{short_name}: {set(spec['ksis']) - known}"


@pytest.mark.parametrize("short_name", AZURE_FETCHERS)
def test_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    short_name, tmp_path, monkeypatch
):
    """The failure path end-to-end, with no Azure SDK involved.

    With AZURE_SUBSCRIPTION_ID unset, `resolve_subscription` tries the SDK import
    and fails, so the fetcher must still write parseable evidence, exit non-zero,
    and leave a well-formed reason in $FETCHER_STATUS_FILE.
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
    payload = json.loads(written[0].read_text())
    assert payload["metadata"]["subscription_source"] == "unresolved"
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"]

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    common = _load_shared()
    assert status["code"] in common.STATUS_CODES
