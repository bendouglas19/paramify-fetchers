"""Fixture-based tests for the Azure compute and container evidence fetchers.

Covers azure_disk_encryption_status, azure_vm_hardening_status,
azure_aks_cluster_configuration and azure_container_registry_configuration. The
shared helpers in `fetchers/azure/_shared/azure_common.py` are exercised by
tests/test_azure_fetchers.py and not re-tested here.

No live API calls, no credentials, and no azure-* package needs to be installed:
the heavy `azure.*` imports live inside `azure_common.credential()` and inside each
fetcher's guarded client factory, and are never triggered here. Two layers are
covered.

**The projection layer** (`project_*`) is each fetcher's only code that touches an
azure-mgmt model. It reads model ATTRIBUTES into a flat snake_case dict. Its tests
drive it with `SimpleNamespace` stand-ins that mimic attribute access, including the
`None` intermediates the real API hands back constantly (a generation-1 VM with no
security profile, a Windows VM with no linux configuration, a cluster that never
enabled Defender, a registry with no network rule set).

Attribute access is what makes that layer portable, and all four packages here are on
the newer `_model_base` generator, whose `as_dict()` emits the camelCase WIRE shape
with nearly everything nested under "properties" — while attribute reads stay flat
snake_case, because the generated `__getattr__` forwards the flattened names to
`self.properties`. The projections therefore need no spelling or nesting tolerance.

The other reason the projection layer exists is enums: these SDKs type most
interesting fields as `str` enum members. `str(EncryptionType.ENCRYPTION_AT_REST_WITH_CUSTOMER_KEY)`
is "EncryptionType.ENCRYPTION_AT_REST_WITH_CUSTOMER_KEY", not the wire value, so a
lowercased comparison against it silently inverts the CMK reading. `model_attr`
unwraps them at the boundary; the tests below pin that for the fields whose readings
depend on it.

**The pure transforms** (`*_record`, `summarize`, and friends) take the projection's
output and are plain dict-in/dict-out, so they are tested from literal fixtures.
Those fixtures are SYNTHETIC but not guessed: they are the projections' verified
output shape for azure-mgmt-compute 38.2.0, azure-mgmt-containerservice 41.5.0,
azure-mgmt-containerregistry 15.0.0 and azure-mgmt-monitor 6.0.2, whose model
attribute names were read off the installed packages.

Run: pytest tests/test_azure_compute_fetchers.py  (needs `pip install -e .`)
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
RG_PREFIX = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/paramify-rg/providers"


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = AZURE_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"azure_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Managed disks — project_disk() output, then the transforms
# --------------------------------------------------------------------------- #

DISK_ID = f"{RG_PREFIX}/Microsoft.Compute/disks/vm-app-os"
UNATTACHED_DISK_ID = f"{RG_PREFIX}/Microsoft.Compute/disks/orphan-data"
SHARED_DISK_ID = f"{RG_PREFIX}/Microsoft.Compute/disks/shared-data"
VM_ID = f"{RG_PREFIX}/Microsoft.Compute/virtualMachines/vm-app"
VM2_ID = f"{RG_PREFIX}/Microsoft.Compute/virtualMachines/vm-db"
DES_ID = f"{RG_PREFIX}/Microsoft.Compute/diskEncryptionSets/des-prod"
VAULT_ID = f"{RG_PREFIX}/Microsoft.KeyVault/vaults/kv-prod"

CMK_DISK = {  # SYNTHETIC — project_disk()'s output shape
    "id": DISK_ID,
    "name": "vm-app-os",
    "location": "eastus",
    "encryption_type": "EncryptionAtRestWithCustomerKey",
    "disk_encryption_set_id": DES_ID,
    "encryption_settings_collection": {
        "enabled": True,
        "encryption_settings_version": "2.0",
        "encryption_settings": [
            {
                "disk_encryption_key_vault_id": VAULT_ID,
                "key_encryption_key_vault_id": VAULT_ID,
                "has_key_encryption_key": True,
            }
        ],
    },
    "os_type": "Linux",
    "disk_size_gb": 30,
    "disk_state": "Attached",
    "sku_name": "Premium_LRS",
    "managed_by": VM_ID,
    "managed_by_extended": None,
    "network_access_policy": "DenyAll",
    "public_network_access": "Disabled",
}

# The default disk: platform key, never attached to anything, and with every
# optional block omitted by the API.
UNATTACHED_PLATFORM_DISK = {  # SYNTHETIC
    "id": UNATTACHED_DISK_ID,
    "name": "orphan-data",
    "location": "eastus",
    "encryption_type": "EncryptionAtRestWithPlatformKey",
    "disk_encryption_set_id": None,
    "encryption_settings_collection": {
        "enabled": None,
        "encryption_settings_version": None,
        "encryption_settings": [],
    },
    "os_type": None,
    "disk_size_gb": 1024,
    "disk_state": "Unattached",
    "sku_name": "Standard_LRS",
    "managed_by": None,
    "managed_by_extended": None,
    "network_access_policy": None,
    "public_network_access": None,
}

# A shared disk: attached to two VMs at once, via managed_by_extended.
SHARED_DOUBLE_ENCRYPTED_DISK = {  # SYNTHETIC
    **UNATTACHED_PLATFORM_DISK,
    "id": SHARED_DISK_ID,
    "name": "shared-data",
    "encryption_type": "EncryptionAtRestWithPlatformAndCustomerKeys",
    "disk_encryption_set_id": DES_ID,
    "disk_state": "Attached",
    "managed_by": VM_ID,
    "managed_by_extended": [VM2_ID],
}


def test_project_disk_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against.

    Asserting the whole dict (not a few keys) is deliberate: if the projection's key
    names ever drift from what `disk_record` reads, the evidence would go quietly
    null rather than fail, so the two must be pinned to each other.
    """
    dk = _load("disk_encryption_status")
    disk = SimpleNamespace(
        id=DISK_ID,
        name="vm-app-os",
        location="eastus",
        encryption=SimpleNamespace(
            type="EncryptionAtRestWithCustomerKey", disk_encryption_set_id=DES_ID
        ),
        encryption_settings_collection=SimpleNamespace(
            enabled=True,
            encryption_settings_version="2.0",
            encryption_settings=[
                SimpleNamespace(
                    # The key URLs are read by the SDK but deliberately NOT projected.
                    disk_encryption_key=SimpleNamespace(
                        secret_url="https://kv-prod.vault.azure.net/secrets/bek/1",
                        source_vault=SimpleNamespace(id=VAULT_ID),
                    ),
                    key_encryption_key=SimpleNamespace(
                        key_url="https://kv-prod.vault.azure.net/keys/kek/1",
                        source_vault=SimpleNamespace(id=VAULT_ID),
                    ),
                )
            ],
        ),
        os_type="Linux",
        disk_size_gb=30,
        disk_state="Attached",
        sku=SimpleNamespace(name="Premium_LRS", tier="Premium"),
        managed_by=VM_ID,
        managed_by_extended=None,
        network_access_policy="DenyAll",
        public_network_access="Disabled",
    )
    assert dk.project_disk(disk) == CMK_DISK


def test_project_disk_omits_the_key_vault_urls():
    """The Key Vault secret/key URLs address the volume key itself — never collected."""
    dk = _load("disk_encryption_status")
    element = SimpleNamespace(
        disk_encryption_key=SimpleNamespace(
            secret_url="https://kv-prod.vault.azure.net/secrets/bek/1",
            source_vault=SimpleNamespace(id=VAULT_ID),
        ),
        key_encryption_key=None,
    )
    projected = dk.project_encryption_settings(element)
    assert projected == {
        "disk_encryption_key_vault_id": VAULT_ID,
        "key_encryption_key_vault_id": None,
        "has_key_encryption_key": False,
    }
    assert "secret_url" not in json.dumps(projected)


def test_project_disk_survives_absent_nested_models():
    """`encryption` / `encryption_settings_collection` / `sku` absent must read as None."""
    dk = _load("disk_encryption_status")
    bare = SimpleNamespace(id=UNATTACHED_DISK_ID, name="orphan-data", location="eastus")
    projected = dk.project_disk(bare)  # must not raise

    assert projected["encryption_type"] is None
    assert projected["disk_encryption_set_id"] is None
    assert projected["sku_name"] is None
    assert projected["encryption_settings_collection"] == {
        "enabled": None,
        "encryption_settings_version": None,
        "encryption_settings": [],
    }

    # An absent encryption block means the API told us nothing, and Prowler's reading
    # of that is "not customer-managed".
    rec = dk.disk_record(projected)
    assert rec["customer_managed_key"] is False
    assert rec["azure_disk_encryption_enabled"] is False
    assert rec["attached"] is False


def test_project_disk_unwraps_the_sdk_string_enums():
    """`encryption.type` is a `str` enum; `str()` on it is a trap.

    A member compares equal to its value, but
    `str(EncryptionType.ENCRYPTION_AT_REST_WITH_CUSTOMER_KEY)` is
    "EncryptionType.ENCRYPTION_AT_REST_WITH_CUSTOMER_KEY" — so leaving the enum in
    place would make `is_customer_managed`'s comparison read a platform-key disk and
    a CMK disk identically (neither equals the platform-key literal), and would put
    an enum repr in the evidence.
    """

    class FakeEncryptionType(str, Enum):
        PLATFORM = "EncryptionAtRestWithPlatformKey"

    dk = _load("disk_encryption_status")
    projected = dk.project_disk(
        SimpleNamespace(
            id=DISK_ID,
            name="vm-app-os",
            encryption=SimpleNamespace(type=FakeEncryptionType.PLATFORM),
        )
    )
    assert projected["encryption_type"] == "EncryptionAtRestWithPlatformKey"
    assert type(projected["encryption_type"]) is str
    # The whole point: the platform key must be recognized as NOT customer-managed.
    assert dk.disk_record(projected)["customer_managed_key"] is False


def test_disk_cmk_reading_matches_prowlers_condition():
    dk = _load("disk_encryption_status")
    assert dk.is_customer_managed("EncryptionAtRestWithCustomerKey") is True
    assert dk.is_customer_managed("EncryptionAtRestWithPlatformAndCustomerKeys") is True
    assert dk.is_customer_managed("EncryptionAtRestWithPlatformKey") is False
    # Absent reads as the platform default, as Prowler reads it.
    assert dk.is_customer_managed(None) is False
    assert dk.is_customer_managed("") is False


def test_disk_record_projects_cmk_and_ade():
    dk = _load("disk_encryption_status")
    rec = dk.disk_record(CMK_DISK)
    assert rec["resource_group"] == "paramify-rg"
    assert rec["encryption_type"] == "EncryptionAtRestWithCustomerKey"
    assert rec["customer_managed_key"] is True
    assert rec["double_encryption"] is False
    assert rec["disk_encryption_set_id"] == DES_ID
    assert rec["azure_disk_encryption_enabled"] is True
    assert rec["encryption_settings_version"] == "2.0"
    assert rec["encryption_settings"][0]["has_key_encryption_key"] is True
    assert rec["attached"] is True
    assert rec["vms_attached"] == [VM_ID]
    assert rec["network_access_restricted"] is True
    assert rec["disk_size_gb"] == 30


def test_disk_record_unattached_and_shared_attachment():
    """`vms_attached` is Prowler's construction: managed_by then managed_by_extended."""
    dk = _load("disk_encryption_status")
    orphan = dk.disk_record(UNATTACHED_PLATFORM_DISK)
    assert orphan["attached"] is False
    assert orphan["vms_attached"] == []
    assert orphan["customer_managed_key"] is False
    # Coerced to False, NOT passed through as None: Azure omits the block entirely
    # when ADE was never enabled, and a validator asserting `false` would not match
    # `null`.
    assert orphan["azure_disk_encryption_enabled"] is False
    assert orphan["network_access_restricted"] is False

    shared = dk.disk_record(SHARED_DOUBLE_ENCRYPTED_DISK)
    assert shared["vms_attached"] == [VM_ID, VM2_ID]
    assert shared["attached"] is True
    assert shared["customer_managed_key"] is True
    assert shared["double_encryption"] is True


def test_disk_summary_splits_attached_from_unattached_cmk_coverage():
    """The split is why this is its own evidence set (Prowler has two checks for it)."""
    dk = _load("disk_encryption_status")
    disks = [
        dk.disk_record(CMK_DISK),
        dk.disk_record(UNATTACHED_PLATFORM_DISK),
        dk.disk_record(SHARED_DOUBLE_ENCRYPTED_DISK),
    ]
    summary = dk.summarize(disks)

    assert summary["total_disks"] == 3
    assert summary["customer_managed_key_disks"] == 2
    assert summary["platform_managed_key_disks"] == 1
    assert summary["cmk_percentage"] == 66
    # There is deliberately NO encrypted/total percentage: managed disks are always
    # encrypted at rest, so such a number would be a constant 100 and prove nothing.
    assert "encrypted_percentage" not in summary

    assert summary["attached_total_disks"] == 2
    assert summary["attached_customer_managed_key_disks"] == 2
    assert summary["attached_cmk_percentage"] == 100
    assert summary["unattached_total_disks"] == 1
    assert summary["unattached_customer_managed_key_disks"] == 0
    assert summary["unattached_cmk_percentage"] == 0

    assert summary["double_encryption_disks"] == 1
    assert summary["disk_encryption_set_disks"] == 2
    assert summary["azure_disk_encryption_disks"] == 1
    assert summary["network_access_restricted_disks"] == 1
    assert summary["os_disks"] == 1
    assert summary["data_disks"] == 2


def test_disk_summary_empty_subscription():
    dk = _load("disk_encryption_status")
    summary = dk.summarize([])
    assert summary["total_disks"] == 0
    assert summary["cmk_percentage"] == 0
    assert summary["unattached_cmk_percentage"] == 0


# --------------------------------------------------------------------------- #
# Virtual machines + scale sets — project_virtual_machine() / project_scale_set()
# output, then the transforms
# --------------------------------------------------------------------------- #

VMSS_ID = f"{RG_PREFIX}/Microsoft.Compute/virtualMachineScaleSets/vmss-web"
POOL_ID = f"{RG_PREFIX}/Microsoft.Network/loadBalancers/lb-web/backendAddressPools/pool-1"

HARDENED_LINUX_VM = {  # SYNTHETIC — project_virtual_machine()'s output shape
    "id": VM_ID,
    "name": "vm-app",
    "location": "eastus",
    "vm_size": "Standard_D2s_v5",
    "provisioning_state": "Succeeded",
    "virtual_machine_scale_set_id": None,
    "storage_profile": {
        "os_disk": {
            "name": "vm-app-os",
            "operating_system_type": "Linux",
            "disk_size_gb": 30,
            "managed_disk": {"id": DISK_ID, "storage_account_type": "Premium_LRS"},
            "vhd_uri": None,
        },
        "data_disks": [
            {
                "lun": 0,
                "name": "vm-app-data0",
                "disk_size_gb": 256,
                "managed_disk": {"id": SHARED_DISK_ID, "storage_account_type": "Premium_LRS"},
                "vhd_uri": None,
            }
        ],
        "image_reference": {
            "id": None,
            "publisher": "Canonical",
            "offer": "0001-com-ubuntu-server-jammy",
            "sku": "22_04-lts-gen2",
            "version": "latest",
            "exact_version": "22.04.202406040",
            "community_gallery_image_id": None,
            "shared_gallery_image_id": None,
        },
    },
    "security_profile": {
        "security_type": "TrustedLaunch",
        "encryption_at_host": True,
        "uefi_settings": {"secure_boot_enabled": True, "v_tpm_enabled": True},
    },
    "linux_configuration": {
        "disable_password_authentication": True,
        "provision_vm_agent": True,
    },
    "extensions": [],
}

# The legacy VM: generation 1 (no security profile at all), an unmanaged page-blob
# data disk, and Windows (so no linux configuration).
LEGACY_WINDOWS_VM = {  # SYNTHETIC
    "id": VM2_ID,
    "name": "vm-db",
    "location": "eastus",
    "vm_size": "Standard_D4s_v3",
    "provisioning_state": "Succeeded",
    "virtual_machine_scale_set_id": None,
    "storage_profile": {
        "os_disk": {
            "name": "vm-db-os",
            "operating_system_type": "Windows",
            "disk_size_gb": 127,
            "managed_disk": {"id": f"{RG_PREFIX}/Microsoft.Compute/disks/vm-db-os",
                             "storage_account_type": "StandardSSD_LRS"},
            "vhd_uri": None,
        },
        "data_disks": [
            {
                "lun": 0,
                "name": "vm-db-data0",
                "disk_size_gb": 512,
                "managed_disk": {"id": None, "storage_account_type": None},
                "vhd_uri": "https://legacy.blob.core.windows.net/vhds/vm-db-data0.vhd",
            }
        ],
        "image_reference": {
            "id": None,
            "publisher": "MicrosoftWindowsServer",
            "offer": "WindowsServer",
            "sku": "2019-Datacenter",
            "version": "latest",
            "exact_version": None,
            "community_gallery_image_id": None,
            "shared_gallery_image_id": None,
        },
    },
    "security_profile": None,
    "linux_configuration": None,
    "extensions": [],
}

MDE_EXTENSION = {  # SYNTHETIC — project_vm_extension()'s output shape
    "id": f"{VM_ID}/extensions/MDE.Linux",
    "name": "MDE.Linux",
    "publisher": "Microsoft.Azure.AzureDefenderForServers",
    "type_handler_version": "1.0",
    "provisioning_state": "Succeeded",
    "auto_upgrade_minor_version": True,
    "enable_automatic_upgrade": True,
}

SCALE_SET = {  # SYNTHETIC — project_scale_set()'s output shape
    "id": VMSS_ID,
    "name": "vmss-web",
    "location": "eastus",
    "sku_name": "Standard_D2s_v5",
    "sku_capacity": 3,
    "orchestration_mode": "Uniform",
    "upgrade_policy_mode": "Automatic",
    "security_profile": {
        "security_type": "TrustedLaunch",
        "encryption_at_host": None,
        "uefi_settings": {"secure_boot_enabled": True, "v_tpm_enabled": True},
    },
    "linux_configuration": {"disable_password_authentication": True},
    "image_reference": {
        "id": None,
        "publisher": "Canonical",
        "offer": "0001-com-ubuntu-server-jammy",
        "sku": "22_04-lts-gen2",
        "version": "latest",
        "exact_version": None,
        "community_gallery_image_id": None,
        "shared_gallery_image_id": None,
    },
    "load_balancer_backend_pools": [POOL_ID],
    "instance_ids": [],
}


def test_project_virtual_machine_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    vm_mod = _load("vm_hardening_status")
    vm = SimpleNamespace(
        id=VM_ID,
        name="vm-app",
        location="eastus",
        provisioning_state="Succeeded",
        hardware_profile=SimpleNamespace(vm_size="Standard_D2s_v5"),
        storage_profile=SimpleNamespace(
            os_disk=SimpleNamespace(
                name="vm-app-os",
                os_type="Linux",
                disk_size_gb=30,
                managed_disk=SimpleNamespace(id=DISK_ID, storage_account_type="Premium_LRS"),
            ),
            data_disks=[
                SimpleNamespace(
                    lun=0,
                    name="vm-app-data0",
                    disk_size_gb=256,
                    managed_disk=SimpleNamespace(
                        id=SHARED_DISK_ID, storage_account_type="Premium_LRS"
                    ),
                )
            ],
            image_reference=SimpleNamespace(
                publisher="Canonical",
                offer="0001-com-ubuntu-server-jammy",
                sku="22_04-lts-gen2",
                version="latest",
                exact_version="22.04.202406040",
            ),
        ),
        security_profile=SimpleNamespace(
            security_type="TrustedLaunch",
            encryption_at_host=True,
            uefi_settings=SimpleNamespace(secure_boot_enabled=True, v_tpm_enabled=True),
        ),
        os_profile=SimpleNamespace(
            linux_configuration=SimpleNamespace(
                disable_password_authentication=True, provision_vm_agent=True
            )
        ),
    )
    assert vm_mod.project_virtual_machine(vm) == HARDENED_LINUX_VM


def test_project_virtual_machine_survives_a_generation_1_windows_vm():
    """No security profile, no linux configuration, an unmanaged data disk."""
    vm_mod = _load("vm_hardening_status")
    vm = SimpleNamespace(
        id=VM2_ID,
        name="vm-db",
        location="eastus",
        provisioning_state="Succeeded",
        hardware_profile=SimpleNamespace(vm_size="Standard_D4s_v3"),
        storage_profile=SimpleNamespace(
            os_disk=SimpleNamespace(
                name="vm-db-os",
                os_type="Windows",
                disk_size_gb=127,
                managed_disk=SimpleNamespace(
                    id=f"{RG_PREFIX}/Microsoft.Compute/disks/vm-db-os",
                    storage_account_type="StandardSSD_LRS",
                ),
            ),
            # An unmanaged disk: no managed_disk, a vhd URI instead.
            data_disks=[
                SimpleNamespace(
                    lun=0,
                    name="vm-db-data0",
                    disk_size_gb=512,
                    vhd=SimpleNamespace(
                        uri="https://legacy.blob.core.windows.net/vhds/vm-db-data0.vhd"
                    ),
                )
            ],
            image_reference=SimpleNamespace(
                publisher="MicrosoftWindowsServer", offer="WindowsServer",
                sku="2019-Datacenter", version="latest",
            ),
        ),
        # A Windows VM's os_profile has windows_configuration, not linux_configuration.
        os_profile=SimpleNamespace(windows_configuration=SimpleNamespace(provision_vm_agent=True)),
    )
    assert vm_mod.project_virtual_machine(vm) == LEGACY_WINDOWS_VM


def test_project_virtual_machine_survives_an_empty_vm():
    """Every profile absent must read as None, not raise."""
    vm_mod = _load("vm_hardening_status")
    projected = vm_mod.project_virtual_machine(
        SimpleNamespace(id=VM_ID, name="vm-app", location="eastus")
    )  # must not raise
    assert projected["storage_profile"] is None
    assert projected["security_profile"] is None
    assert projected["linux_configuration"] is None
    assert projected["vm_size"] is None

    rec = vm_mod.virtual_machine_record(projected)
    assert rec["trusted_launch_enabled"] is False
    assert rec["managed_disks_only"] is False
    # Null, not False: a VM with no linux configuration has no such setting, which is
    # a different fact from "passwords are allowed".
    assert rec["password_authentication_disabled"] is None
    assert rec["linux_configuration"] is None
    # The absent security profile still normalizes to the full shape, so a validator
    # can assert on the fields without tolerating a null parent.
    assert rec["security_profile"] == {
        "security_type": None,
        "encryption_at_host": False,
        "uefi_settings": {"secure_boot_enabled": False, "v_tpm_enabled": False},
    }


def test_project_virtual_machine_unwraps_the_sdk_string_enums():
    """`security_type` is a `str` enum; the TrustedLaunch comparison depends on unwrapping."""

    class FakeSecurityTypes(str, Enum):
        TRUSTED_LAUNCH = "TrustedLaunch"

    vm_mod = _load("vm_hardening_status")
    projected = vm_mod.project_virtual_machine(
        SimpleNamespace(
            id=VM_ID,
            name="vm-app",
            security_profile=SimpleNamespace(
                security_type=FakeSecurityTypes.TRUSTED_LAUNCH,
                uefi_settings=SimpleNamespace(secure_boot_enabled=True, v_tpm_enabled=True),
            ),
        )
    )
    assert projected["security_profile"]["security_type"] == "TrustedLaunch"
    assert type(projected["security_profile"]["security_type"]) is str
    assert vm_mod.virtual_machine_record(projected)["trusted_launch_enabled"] is True


def test_trusted_launch_needs_all_four_of_prowlers_clauses():
    vm_mod = _load("vm_hardening_status")
    full = HARDENED_LINUX_VM["security_profile"]
    assert vm_mod.trusted_launch_enabled(full) is True
    assert vm_mod.trusted_launch_enabled(None) is False
    assert vm_mod.trusted_launch_enabled({**full, "security_type": "Standard"}) is False
    assert (
        vm_mod.trusted_launch_enabled(
            {**full, "uefi_settings": {"secure_boot_enabled": True, "v_tpm_enabled": False}}
        )
        is False
    )
    assert (
        vm_mod.trusted_launch_enabled(
            {**full, "uefi_settings": {"secure_boot_enabled": None, "v_tpm_enabled": None}}
        )
        is False
    )
    # ConfidentialVM implies the same boot integrity but is NOT what Prowler's check
    # accepts, so the summary must not count it (the raw security_type is in the
    # record for a reviewer who reads it differently).
    assert vm_mod.trusted_launch_enabled({**full, "security_type": "ConfidentialVM"}) is False


def test_managed_disk_reading_needs_the_os_disk_and_every_data_disk():
    """Prowler's vm_ensure_using_managed_disks: one unmanaged data disk fails the VM."""
    vm_mod = _load("vm_hardening_status")
    hardened = vm_mod.virtual_machine_record(HARDENED_LINUX_VM)
    legacy = vm_mod.virtual_machine_record(LEGACY_WINDOWS_VM)

    assert hardened["managed_disks_only"] is True
    assert hardened["storage_profile"]["os_disk"]["managed"] is True
    assert hardened["storage_profile"]["data_disks"][0]["managed"] is True
    # The OS disk record carries the operating system and no LUN; a data disk the
    # reverse.
    assert "lun" not in hardened["storage_profile"]["os_disk"]
    assert hardened["storage_profile"]["os_disk"]["operating_system_type"] == "Linux"
    assert hardened["storage_profile"]["data_disks"][0]["lun"] == 0

    assert legacy["managed_disks_only"] is False
    assert legacy["storage_profile"]["os_disk"]["managed"] is True
    assert legacy["storage_profile"]["data_disks"][0]["managed"] is False
    assert legacy["storage_profile"]["data_disks"][0]["vhd_uri"].endswith(".vhd")
    # A Windows VM has no SSH-key setting at all.
    assert legacy["password_authentication_disabled"] is None


def test_vm_image_reference_keeps_the_marketplace_coordinates():
    """Prowler keeps only image_reference.id, which is None for every marketplace image."""
    vm_mod = _load("vm_hardening_status")
    rec = vm_mod.virtual_machine_record(HARDENED_LINUX_VM)
    image = rec["storage_profile"]["image_reference"]
    assert image["id"] is None
    assert image["publisher"] == "Canonical"
    assert image["sku"] == "22_04-lts-gen2"
    assert image["exact_version"] == "22.04.202406040"


def test_project_vm_extension_reads_sdk_attributes():
    vm_mod = _load("vm_hardening_status")
    extension = SimpleNamespace(
        id=MDE_EXTENSION["id"],
        name="MDE.Linux",
        # The model declares both a top-level `type` (the ARM resource type) and a
        # properties-level one; the top-level wins on attribute access, so neither is
        # projected — `name` and `publisher` identify the agent unambiguously.
        type="Microsoft.Compute/virtualMachines/extensions",
        publisher="Microsoft.Azure.AzureDefenderForServers",
        type_handler_version="1.0",
        provisioning_state="Succeeded",
        auto_upgrade_minor_version=True,
        enable_automatic_upgrade=True,
    )
    assert vm_mod.project_vm_extension(extension) == MDE_EXTENSION


def test_extension_record_falls_back_to_the_id_for_a_name():
    vm_mod = _load("vm_hardening_status")
    rec = vm_mod.extension_record({"id": f"{VM_ID}/extensions/AzureMonitorLinuxAgent"})
    assert rec["name"] == "AzureMonitorLinuxAgent"
    assert rec["auto_upgrade_minor_version"] is False
    assert rec["enable_automatic_upgrade"] is False


def test_project_scale_set_walks_the_load_balancer_pools():
    """The association is four optional hops deep; Prowler stacks getattr the same way."""
    vm_mod = _load("vm_hardening_status")
    scale_set = SimpleNamespace(
        id=VMSS_ID,
        name="vmss-web",
        location="eastus",
        sku=SimpleNamespace(name="Standard_D2s_v5", capacity=3, tier="Standard"),
        orchestration_mode="Uniform",
        upgrade_policy=SimpleNamespace(mode="Automatic"),
        virtual_machine_profile=SimpleNamespace(
            security_profile=SimpleNamespace(
                security_type="TrustedLaunch",
                uefi_settings=SimpleNamespace(secure_boot_enabled=True, v_tpm_enabled=True),
            ),
            os_profile=SimpleNamespace(
                linux_configuration=SimpleNamespace(disable_password_authentication=True)
            ),
            storage_profile=SimpleNamespace(
                image_reference=SimpleNamespace(
                    publisher="Canonical",
                    offer="0001-com-ubuntu-server-jammy",
                    sku="22_04-lts-gen2",
                    version="latest",
                )
            ),
            network_profile=SimpleNamespace(
                network_interface_configurations=[
                    SimpleNamespace(
                        name="nic0",
                        ip_configurations=[
                            SimpleNamespace(
                                name="ip0",
                                load_balancer_backend_address_pools=[
                                    SimpleNamespace(id=POOL_ID)
                                ],
                            ),
                            # A second IP config with no pools at all.
                            SimpleNamespace(name="ip1"),
                        ],
                    ),
                    # A NIC config with no IP configurations.
                    SimpleNamespace(name="nic1"),
                ]
            ),
        ),
    )
    assert vm_mod.project_scale_set(scale_set) == SCALE_SET


def test_project_scale_set_survives_a_scale_set_with_no_vm_profile():
    vm_mod = _load("vm_hardening_status")
    projected = vm_mod.project_scale_set(
        SimpleNamespace(id=VMSS_ID, name="vmss-web", location="eastus")
    )  # must not raise
    assert projected["load_balancer_backend_pools"] == []
    assert projected["security_profile"] is None
    assert projected["linux_configuration"] is None

    rec = vm_mod.scale_set_record(projected)
    assert rec["associated_with_load_balancer"] is False
    assert rec["trusted_launch_enabled"] is False
    assert rec["instance_count"] == 0


def test_scale_set_name_from_id_parses_the_arm_id():
    """Prowler parses the id rather than trusting `name`; ARM's casing varies."""
    vm_mod = _load("vm_hardening_status")
    assert vm_mod.scale_set_name_from_id(VMSS_ID) == "vmss-web"
    assert vm_mod.scale_set_name_from_id(
        VMSS_ID.replace("virtualMachineScaleSets", "virtualmachinescalesets")
    ) == "vmss-web"
    assert vm_mod.scale_set_name_from_id("/subscriptions/s/resourceGroups/rg") is None
    assert vm_mod.scale_set_name_from_id(None) is None


def test_vm_summary_counts_hardening_over_the_right_denominators():
    vm_mod = _load("vm_hardening_status")
    hardened = vm_mod.virtual_machine_record(HARDENED_LINUX_VM)
    hardened["extensions"] = [vm_mod.extension_record(MDE_EXTENSION)]
    vms = [hardened, vm_mod.virtual_machine_record(LEGACY_WINDOWS_VM)]
    scale_sets = [
        vm_mod.scale_set_record({**SCALE_SET, "instance_ids": ["0", "1", "2"]}),
        vm_mod.scale_set_record(
            {**SCALE_SET, "id": f"{VMSS_ID}-idle", "load_balancer_backend_pools": [],
             "instance_ids": []}
        ),
    ]

    summary = vm_mod.summarize(vms, scale_sets)
    assert summary["total_virtual_machines"] == 2
    assert summary["trusted_launch_vms"] == 1
    assert summary["trusted_launch_percentage"] == 50
    assert summary["secure_boot_vms"] == 1
    assert summary["vtpm_vms"] == 1
    assert summary["encryption_at_host_vms"] == 1
    assert summary["confidential_vms"] == 0
    assert summary["managed_disk_vms"] == 1
    assert summary["unmanaged_disk_vms"] == 1
    assert summary["managed_disk_percentage"] == 50
    # SSH-key enforcement is a percentage of LINUX VMs only: the Windows VM has no
    # such setting, and counting it in the denominator would report a fully hardened
    # estate as 50%.
    assert summary["linux_vms"] == 1
    assert summary["linux_ssh_key_only_vms"] == 1
    assert summary["linux_ssh_key_only_percentage"] == 100
    assert summary["vms_with_extensions"] == 1
    assert summary["total_extensions"] == 1
    assert summary["vms_in_scale_sets"] == 0

    assert summary["total_scale_sets"] == 2
    assert summary["scale_sets_with_load_balancer"] == 1
    assert summary["empty_scale_sets"] == 1
    assert summary["trusted_launch_scale_sets"] == 2
    assert summary["total_scale_set_instances"] == 3


def test_vm_summary_empty_subscription():
    vm_mod = _load("vm_hardening_status")
    summary = vm_mod.summarize([], [])
    assert summary["total_virtual_machines"] == 0
    assert summary["trusted_launch_percentage"] == 0
    assert summary["linux_ssh_key_only_percentage"] == 0


# --------------------------------------------------------------------------- #
# AKS clusters — project_managed_cluster() output, then the transforms
# --------------------------------------------------------------------------- #

CLUSTER_ID = f"{RG_PREFIX}/Microsoft.ContainerService/managedClusters/aks-prod"

PRIVATE_CLUSTER = {  # SYNTHETIC — project_managed_cluster()'s output shape
    "id": CLUSTER_ID,
    "name": "aks-prod",
    "location": "eastus",
    "provisioning_state": "Succeeded",
    "sku_tier": "Standard",
    "public_fqdn": "aks-prod-abc.hcp.eastus.azmk8s.io",
    "private_fqdn": "aks-prod-abc.privatelink.eastus.azmk8s.io",
    "public_network_access": "Disabled",
    "enable_private_cluster": True,
    "authorized_ip_ranges": None,
    "disable_run_command": True,
    "rbac_enabled": True,
    "azure_rbac_enabled": True,
    "entra_managed_identity": True,
    "local_accounts_disabled": True,
    "workload_identity_enabled": True,
    "oidc_issuer_enabled": True,
    "network_policy": "azure",
    "network_plugin": "azure",
    "outbound_type": "userDefinedRouting",
    "kubernetes_version": "1.29",
    "current_kubernetes_version": "1.29.4",
    "auto_upgrade_channel": "stable",
    "node_os_upgrade_channel": "NodeImage",
    "defender_enabled": True,
    "defender_log_analytics_workspace_id": (
        f"{RG_PREFIX}/Microsoft.OperationalInsights/workspaces/law-prod"
    ),
    "azure_monitor_enabled": True,
    "disk_encryption_set_id": DES_ID,
    "node_resource_group": "MC_paramify-rg_aks-prod_eastus",
    "agent_pool_profiles": [
        {
            "name": "system",
            "enable_node_public_ip": False,
            "mode": "System",
            "count": 3,
            "vm_size": "Standard_D2s_v5",
            "os_type": "Linux",
            "os_sku": "AzureLinux",
            "os_disk_type": "Managed",
            "enable_encryption_at_host": True,
            "enable_auto_scaling": True,
            "orchestrator_version": "1.29.4",
            "vnet_subnet_id": f"{RG_PREFIX}/Microsoft.Network/virtualNetworks/vnet/subnets/aks",
        }
    ],
}

# The default cluster: public API server, no network policy, no auto-upgrade, and
# every optional profile omitted by the API.
DEFAULT_CLUSTER = {  # SYNTHETIC
    "id": CLUSTER_ID.replace("aks-prod", "aks-sandbox"),
    "name": "aks-sandbox",
    "location": "eastus",
    "provisioning_state": "Succeeded",
    "sku_tier": "Free",
    "public_fqdn": "aks-sandbox-xyz.hcp.eastus.azmk8s.io",
    "private_fqdn": None,
    "public_network_access": None,
    "enable_private_cluster": None,
    "authorized_ip_ranges": None,
    "disable_run_command": None,
    "rbac_enabled": True,
    "azure_rbac_enabled": None,
    "entra_managed_identity": None,
    "local_accounts_disabled": None,
    "workload_identity_enabled": None,
    "oidc_issuer_enabled": None,
    "network_policy": None,
    "network_plugin": "kubenet",
    "outbound_type": "loadBalancer",
    "kubernetes_version": "1.28",
    "current_kubernetes_version": "1.28.9",
    "auto_upgrade_channel": "none",
    "node_os_upgrade_channel": None,
    "defender_enabled": None,
    "defender_log_analytics_workspace_id": None,
    "azure_monitor_enabled": None,
    "disk_encryption_set_id": None,
    "node_resource_group": "MC_paramify-rg_aks-sandbox_eastus",
    "agent_pool_profiles": [
        {
            "name": "nodepool1",
            "enable_node_public_ip": True,
            "mode": "System",
            "count": 1,
            "vm_size": "Standard_B2s",
            "os_type": None,
            "os_sku": None,
            "os_disk_type": None,
            "enable_encryption_at_host": None,
            "enable_auto_scaling": None,
            "orchestrator_version": None,
            "vnet_subnet_id": None,
        }
    ],
}


def test_project_managed_cluster_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    aks = _load("aks_cluster_configuration")
    cluster = SimpleNamespace(
        id=CLUSTER_ID,
        name="aks-prod",
        location="eastus",
        provisioning_state="Succeeded",
        sku=SimpleNamespace(name="Base", tier="Standard"),
        fqdn="aks-prod-abc.hcp.eastus.azmk8s.io",
        private_fqdn="aks-prod-abc.privatelink.eastus.azmk8s.io",
        public_network_access="Disabled",
        api_server_access_profile=SimpleNamespace(
            enable_private_cluster=True, authorized_ip_ranges=None, disable_run_command=True
        ),
        enable_rbac=True,
        aad_profile=SimpleNamespace(managed=True, enable_azure_rbac=True),
        disable_local_accounts=True,
        oidc_issuer_profile=SimpleNamespace(enabled=True),
        network_profile=SimpleNamespace(
            network_policy="azure", network_plugin="azure", outbound_type="userDefinedRouting"
        ),
        kubernetes_version="1.29",
        current_kubernetes_version="1.29.4",
        auto_upgrade_profile=SimpleNamespace(
            upgrade_channel="stable", node_os_upgrade_channel="NodeImage"
        ),
        security_profile=SimpleNamespace(
            defender=SimpleNamespace(
                security_monitoring=SimpleNamespace(enabled=True),
                log_analytics_workspace_resource_id=(
                    f"{RG_PREFIX}/Microsoft.OperationalInsights/workspaces/law-prod"
                ),
            ),
            workload_identity=SimpleNamespace(enabled=True),
        ),
        azure_monitor_profile=SimpleNamespace(metrics=SimpleNamespace(enabled=True)),
        disk_encryption_set_id=DES_ID,
        node_resource_group="MC_paramify-rg_aks-prod_eastus",
        agent_pool_profiles=[
            SimpleNamespace(
                name="system",
                enable_node_public_ip=False,
                mode="System",
                count=3,
                vm_size="Standard_D2s_v5",
                os_type="Linux",
                os_sku="AzureLinux",
                os_disk_type="Managed",
                enable_encryption_at_host=True,
                enable_auto_scaling=True,
                orchestrator_version="1.29.4",
                vnet_subnet_id=(
                    f"{RG_PREFIX}/Microsoft.Network/virtualNetworks/vnet/subnets/aks"
                ),
            )
        ],
    )
    assert aks.project_managed_cluster(cluster) == PRIVATE_CLUSTER


def test_project_managed_cluster_survives_the_absent_profiles():
    """Defender is three hops deep and Azure Monitor two; both subtrees are omitted."""
    aks = _load("aks_cluster_configuration")
    cluster = SimpleNamespace(
        id=DEFAULT_CLUSTER["id"],
        name="aks-sandbox",
        location="eastus",
        provisioning_state="Succeeded",
        sku=SimpleNamespace(tier="Free"),
        fqdn="aks-sandbox-xyz.hcp.eastus.azmk8s.io",
        enable_rbac=True,
        network_profile=SimpleNamespace(network_plugin="kubenet", outbound_type="loadBalancer"),
        kubernetes_version="1.28",
        current_kubernetes_version="1.28.9",
        auto_upgrade_profile=SimpleNamespace(upgrade_channel="none"),
        node_resource_group="MC_paramify-rg_aks-sandbox_eastus",
        agent_pool_profiles=[
            SimpleNamespace(
                name="nodepool1", enable_node_public_ip=True, mode="System", count=1,
                vm_size="Standard_B2s",
            )
        ],
    )
    assert aks.project_managed_cluster(cluster) == DEFAULT_CLUSTER


def test_project_managed_cluster_unwraps_the_sdk_string_enums():
    """`network_policy` / `upgrade_channel` are `str` enums whose repr is not the value."""

    class FakeNetworkPolicy(str, Enum):
        AZURE = "azure"

    class FakeUpgradeChannel(str, Enum):
        NONE = "none"

    aks = _load("aks_cluster_configuration")
    projected = aks.project_managed_cluster(
        SimpleNamespace(
            id=CLUSTER_ID,
            name="aks-prod",
            network_profile=SimpleNamespace(network_policy=FakeNetworkPolicy.AZURE),
            auto_upgrade_profile=SimpleNamespace(upgrade_channel=FakeUpgradeChannel.NONE),
        )
    )
    assert projected["network_policy"] == "azure"
    assert type(projected["network_policy"]) is str
    rec = aks.cluster_record(projected)
    assert rec["network_policy_enabled"] is True
    # "none" is the literal the API returns for no automatic upgrades — an enum repr
    # would not match it and the cluster would be reported as auto-upgrading.
    assert rec["auto_upgrade_enabled"] is False


def test_cluster_record_derives_the_prowler_readings():
    aks = _load("aks_cluster_configuration")
    rec = aks.cluster_record(PRIVATE_CLUSTER)
    assert rec["resource_group"] == "paramify-rg"
    assert rec["private_cluster"] is True
    # A private cluster has no public API endpoint, so it needs no IP allow-list.
    assert rec["authorized_ip_ranges"] == []
    assert rec["api_server_access_restricted"] is True
    assert rec["rbac_enabled"] is True
    assert rec["azure_rbac_enabled"] is True
    assert rec["local_accounts_disabled"] is True
    assert rec["workload_identity_enabled"] is True
    assert rec["network_policy_enabled"] is True
    assert rec["auto_upgrade_enabled"] is True
    assert rec["defender_enabled"] is True
    assert rec["azure_monitor_enabled"] is True
    assert rec["node_public_ip_pools"] == []
    assert rec["agent_pool_profiles"][0]["enable_encryption_at_host"] is True


def test_cluster_record_reads_the_permissive_defaults_as_off():
    """Azure omits these when off; coerced to False so a validator can assert `false`."""
    aks = _load("aks_cluster_configuration")
    rec = aks.cluster_record(DEFAULT_CLUSTER)
    assert rec["private_cluster"] is False
    assert rec["api_server_access_restricted"] is False
    assert rec["azure_rbac_enabled"] is False
    assert rec["local_accounts_disabled"] is False
    assert rec["workload_identity_enabled"] is False
    assert rec["oidc_issuer_enabled"] is False
    assert rec["defender_enabled"] is False
    assert rec["azure_monitor_enabled"] is False
    assert rec["network_policy"] is None
    assert rec["network_policy_enabled"] is False
    assert rec["auto_upgrade_enabled"] is False
    # Prowler's private-nodes reading: a pool handing its nodes public IPs puts them
    # on the Internet.
    assert rec["node_public_ip_pools"] == ["nodepool1"]


def test_cluster_api_server_restricted_by_authorized_ip_ranges_alone():
    aks = _load("aks_cluster_configuration")
    rec = aks.cluster_record(
        {**DEFAULT_CLUSTER, "authorized_ip_ranges": ["203.0.113.0/24"]}
    )
    assert rec["private_cluster"] is False
    assert rec["authorized_ip_ranges"] == ["203.0.113.0/24"]
    assert rec["api_server_access_restricted"] is True


def test_aks_summary_counts_one_reading_per_prowler_check():
    aks = _load("aks_cluster_configuration")
    clusters = [aks.cluster_record(PRIVATE_CLUSTER), aks.cluster_record(DEFAULT_CLUSTER)]
    summary = aks.summarize(clusters)

    assert summary["total_clusters"] == 2
    assert summary["private_clusters"] == 1
    assert summary["private_cluster_percentage"] == 50
    assert summary["api_server_access_restricted_clusters"] == 1
    assert summary["api_server_access_restricted_percentage"] == 50
    assert summary["clusters_with_authorized_ip_ranges"] == 0
    assert summary["rbac_enabled_clusters"] == 2
    assert summary["azure_rbac_enabled_clusters"] == 1
    assert summary["local_accounts_disabled_clusters"] == 1
    assert summary["workload_identity_clusters"] == 1
    assert summary["network_policy_clusters"] == 1
    assert summary["auto_upgrade_clusters"] == 1
    assert summary["defender_enabled_clusters"] == 1
    assert summary["azure_monitor_enabled_clusters"] == 1
    assert summary["clusters_with_public_node_ips"] == 1
    assert summary["total_agent_pools"] == 2
    assert summary["kubernetes_versions"] == ["1.28", "1.29"]


def test_aks_summary_empty_subscription():
    aks = _load("aks_cluster_configuration")
    summary = aks.summarize([])
    assert summary["total_clusters"] == 0
    assert summary["private_cluster_percentage"] == 0
    assert summary["kubernetes_versions"] == []


# --------------------------------------------------------------------------- #
# Container registries — project_registry() / project_diagnostic_setting() output,
# then the transforms
# --------------------------------------------------------------------------- #

REGISTRY_ID = f"{RG_PREFIX}/Microsoft.ContainerRegistry/registries/acrprod"
SETTING_ID = f"{REGISTRY_ID}/providers/Microsoft.Insights/diagnosticSettings/to-law"

LOCKED_DOWN_REGISTRY = {  # SYNTHETIC — project_registry()'s output shape
    "id": REGISTRY_ID,
    "name": "acrprod",
    "location": "eastus",
    "sku": "Premium",
    "login_server": "acrprod.azurecr.io",
    "admin_user_enabled": False,
    "anonymous_pull_enabled": False,
    "public_network_access": "Disabled",
    "network_rule_bypass_options": "AzureServices",
    "network_rule_set": {
        "default_action": "Deny",
        "ip_rules": [{"action": "Allow", "ip_address_or_range": "203.0.113.5"}],
    },
    "data_endpoint_enabled": True,
    "private_endpoint_connections": [
        {
            "id": f"{REGISTRY_ID}/privateEndpointConnections/pe-acr",
            "name": "pe-acr",
            "type": "Microsoft.ContainerRegistry/registries/privateEndpointConnections",
            "status": "Approved",
            "provisioning_state": "Succeeded",
        }
    ],
    "encryption_status": "enabled",
    "zone_redundancy": "Enabled",
    "policies": {
        "quarantine_policy_status": "enabled",
        "trust_policy_status": "enabled",
        "trust_policy_type": "Notary",
        "retention_policy_status": "enabled",
        "retention_policy_days": 7,
        "export_policy_status": "disabled",
        "azure_ad_authentication_as_arm_policy_status": "enabled",
    },
    "monitor_diagnostic_settings": [],
}

# The default registry: the shared admin account on, anonymous pull on, and every
# network / policy block omitted by the API.
OPEN_REGISTRY = {  # SYNTHETIC
    "id": REGISTRY_ID.replace("acrprod", "acrsandbox"),
    "name": "acrsandbox",
    "location": "eastus",
    "sku": "Basic",
    "login_server": "acrsandbox.azurecr.io",
    "admin_user_enabled": True,
    "anonymous_pull_enabled": True,
    "public_network_access": None,
    "network_rule_bypass_options": None,
    "network_rule_set": {"default_action": None, "ip_rules": []},
    "data_endpoint_enabled": None,
    "private_endpoint_connections": [],
    "encryption_status": None,
    "zone_redundancy": None,
    "policies": {
        "quarantine_policy_status": None,
        "trust_policy_status": None,
        "trust_policy_type": None,
        "retention_policy_status": None,
        "retention_policy_days": None,
        "export_policy_status": None,
        "azure_ad_authentication_as_arm_policy_status": None,
    },
    "monitor_diagnostic_settings": [],
}

DIAGNOSTIC_SETTING = {  # SYNTHETIC — project_diagnostic_setting()'s output shape
    "id": SETTING_ID,
    "name": "to-law",
    "storage_account_id": (
        f"{RG_PREFIX}/Microsoft.Storage/storageAccounts/pflogs"
    ),
    "workspace_id": f"{RG_PREFIX}/Microsoft.OperationalInsights/workspaces/law-prod",
    "event_hub_name": None,
    "logs": [
        {"category": "ContainerRegistryLoginEvents", "category_group": None, "enabled": True},
        {"category": "ContainerRegistryRepositoryEvents", "category_group": None, "enabled": False},
    ],
    "metrics": [{"category": "AllMetrics", "enabled": True}],
}


def test_project_registry_reads_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    acr = _load("container_registry_configuration")
    registry = SimpleNamespace(
        id=REGISTRY_ID,
        name="acrprod",
        location="eastus",
        sku=SimpleNamespace(name="Premium", tier="Premium"),
        login_server="acrprod.azurecr.io",
        admin_user_enabled=False,
        anonymous_pull_enabled=False,
        # The SDK's field is `public_network_access`, NOT
        # `public_network_access_enabled` (which is what Prowler reads, and always
        # misses).
        public_network_access="Disabled",
        network_rule_bypass_options="AzureServices",
        network_rule_set=SimpleNamespace(
            default_action="Deny",
            ip_rules=[SimpleNamespace(action="Allow", ip_address_or_range="203.0.113.5")],
        ),
        data_endpoint_enabled=True,
        private_endpoint_connections=[
            SimpleNamespace(
                id=f"{REGISTRY_ID}/privateEndpointConnections/pe-acr",
                name="pe-acr",
                type="Microsoft.ContainerRegistry/registries/privateEndpointConnections",
                private_link_service_connection_state=SimpleNamespace(status="Approved"),
                provisioning_state="Succeeded",
            )
        ],
        encryption=SimpleNamespace(status="enabled"),
        zone_redundancy="Enabled",
        policies=SimpleNamespace(
            quarantine_policy=SimpleNamespace(status="enabled"),
            trust_policy=SimpleNamespace(status="enabled", type="Notary"),
            retention_policy=SimpleNamespace(status="enabled", days=7),
            export_policy=SimpleNamespace(status="disabled"),
            azure_ad_authentication_as_arm_policy=SimpleNamespace(status="enabled"),
        ),
    )
    assert acr.project_registry(registry) == LOCKED_DOWN_REGISTRY


def test_project_registry_survives_the_absent_blocks():
    acr = _load("container_registry_configuration")
    registry = SimpleNamespace(
        id=OPEN_REGISTRY["id"],
        name="acrsandbox",
        location="eastus",
        sku=SimpleNamespace(name="Basic"),
        login_server="acrsandbox.azurecr.io",
        admin_user_enabled=True,
        anonymous_pull_enabled=True,
    )
    assert acr.project_registry(registry) == OPEN_REGISTRY


def test_project_registry_unwraps_the_sdk_string_enums():
    """`sku.name` / `public_network_access` are `str` enums; the reading depends on it."""

    class FakeSkuName(str, Enum):
        PREMIUM = "Premium"

    class FakePublicNetworkAccess(str, Enum):
        DISABLED = "Disabled"

    acr = _load("container_registry_configuration")
    projected = acr.project_registry(
        SimpleNamespace(
            id=REGISTRY_ID,
            name="acrprod",
            sku=SimpleNamespace(name=FakeSkuName.PREMIUM),
            public_network_access=FakePublicNetworkAccess.DISABLED,
        )
    )
    assert projected["sku"] == "Premium"
    assert type(projected["sku"]) is str
    rec = acr.registry_record(projected)
    # An enum repr here would read as "not Disabled" and report the registry as
    # publicly reachable.
    assert rec["public_network_access_enabled"] is False


def test_registry_record_derives_the_prowler_readings():
    acr = _load("container_registry_configuration")
    rec = acr.registry_record(LOCKED_DOWN_REGISTRY)
    assert rec["resource_group"] == "paramify-rg"
    assert rec["admin_user_enabled"] is False
    assert rec["anonymous_pull_enabled"] is False
    assert rec["public_network_access"] == "Disabled"
    assert rec["public_network_access_enabled"] is False
    assert rec["network_rules_default_deny"] is True
    assert rec["private_link_in_use"] is True
    assert rec["private_endpoint_connections"][0]["status"] == "Approved"
    assert rec["customer_managed_key"] is True
    assert rec["policies"]["trust_policy_status"] == "enabled"


def test_registry_record_reads_an_absent_public_network_access_as_public():
    """"Enabled" is the service default, so an omitted field means publicly reachable."""
    acr = _load("container_registry_configuration")
    rec = acr.registry_record(OPEN_REGISTRY)
    assert rec["public_network_access"] is None
    assert rec["public_network_access_enabled"] is True
    assert rec["network_rules_default_deny"] is False
    # Coerced to booleans, not passed through as None.
    assert rec["admin_user_enabled"] is True
    assert rec["anonymous_pull_enabled"] is True
    assert rec["data_endpoint_enabled"] is False
    assert rec["private_link_in_use"] is False
    assert rec["customer_managed_key"] is False


def test_project_diagnostic_setting_reads_sdk_attributes():
    acr = _load("container_registry_configuration")
    setting = SimpleNamespace(
        id=SETTING_ID,
        name="to-law",
        storage_account_id=f"{RG_PREFIX}/Microsoft.Storage/storageAccounts/pflogs",
        workspace_id=f"{RG_PREFIX}/Microsoft.OperationalInsights/workspaces/law-prod",
        logs=[
            SimpleNamespace(
                category="ContainerRegistryLoginEvents", category_group=None, enabled=True
            ),
            SimpleNamespace(
                category="ContainerRegistryRepositoryEvents", category_group=None, enabled=False
            ),
        ],
        metrics=[SimpleNamespace(category="AllMetrics", enabled=True)],
    )
    assert acr.project_diagnostic_setting(setting) == DIAGNOSTIC_SETTING


def test_project_diagnostic_setting_names_itself_from_the_id():
    """Prowler derives the display name from the id's last segment."""
    acr = _load("container_registry_configuration")
    projected = acr.project_diagnostic_setting(SimpleNamespace(id=SETTING_ID))
    assert projected["name"] == "to-law"
    assert projected["logs"] == []
    assert projected["metrics"] == []


def test_diagnostic_setting_record_and_the_enabled_log_reading():
    acr = _load("container_registry_configuration")
    rec = acr.diagnostic_setting_record(DIAGNOSTIC_SETTING)
    assert rec["storage_account_name"] == "pflogs"
    assert rec["logs"][0]["enabled"] is True
    assert rec["logs"][1]["enabled"] is False

    with_logs = {**LOCKED_DOWN_REGISTRY, "monitor_diagnostic_settings": [rec]}
    assert acr.has_enabled_log(acr.registry_record(with_logs)) is True
    # A setting can exist with every category switched off, which is not logging.
    all_off = acr.diagnostic_setting_record(
        {
            "id": SETTING_ID,
            "name": "to-law",
            "logs": [{"category": "ContainerRegistryLoginEvents", "enabled": None}],
        }
    )
    assert acr.has_enabled_log({"monitor_diagnostic_settings": [all_off]}) is False
    assert acr.has_enabled_log(acr.registry_record(LOCKED_DOWN_REGISTRY)) is False


def test_diagnostic_settings_resource_uri_strips_the_leading_slash():
    """The SDK substitutes the value into "/{resourceUri}/providers/..." unquoted."""
    acr = _load("container_registry_configuration")
    assert acr.diagnostic_settings_resource_uri(REGISTRY_ID) == REGISTRY_ID.lstrip("/")
    assert not acr.diagnostic_settings_resource_uri(REGISTRY_ID).startswith("/")
    assert acr.diagnostic_settings_resource_uri("") == ""


def test_acr_summary_counts_the_standing_findings():
    acr = _load("container_registry_configuration")
    locked = acr.registry_record(
        {
            **LOCKED_DOWN_REGISTRY,
            "monitor_diagnostic_settings": [
                acr.diagnostic_setting_record(DIAGNOSTIC_SETTING)
            ],
        }
    )
    registries = [locked, acr.registry_record(OPEN_REGISTRY)]
    summary = acr.summarize(registries)

    assert summary["total_registries"] == 2
    assert summary["admin_user_enabled_registries"] == 1
    assert summary["admin_user_disabled_percentage"] == 50
    assert summary["anonymous_pull_enabled_registries"] == 1
    assert summary["public_network_access_registries"] == 1
    assert summary["private_network_access_registries"] == 1
    assert summary["private_network_access_percentage"] == 50
    assert summary["network_rules_default_deny_registries"] == 1
    assert summary["private_link_registries"] == 1
    assert summary["customer_managed_key_registries"] == 1
    assert summary["content_trust_registries"] == 1
    assert summary["quarantine_policy_registries"] == 1
    assert summary["retention_policy_registries"] == 1
    assert summary["premium_sku_registries"] == 1
    assert summary["registries_with_diagnostic_settings"] == 1
    assert summary["registries_with_enabled_logs"] == 1


def test_acr_summary_empty_subscription():
    acr = _load("container_registry_configuration")
    summary = acr.summarize([])
    assert summary["total_registries"] == 0
    assert summary["admin_user_disabled_percentage"] == 0
    assert summary["private_network_access_percentage"] == 0


# --------------------------------------------------------------------------- #
# Contract wiring — every fetcher.yaml here agrees with its fetcher.py
# --------------------------------------------------------------------------- #

COMPUTE_FETCHERS = (
    "disk_encryption_status",
    "vm_hardening_status",
    "aks_cluster_configuration",
    "container_registry_configuration",
)


@pytest.mark.parametrize("short_name", COMPUTE_FETCHERS)
def test_fetcher_yaml_declares_the_ambient_credential_contract(short_name):
    import yaml

    spec = yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())
    assert spec["name"] == f"azure_{short_name}"
    assert spec["category"] == "azure"
    assert spec["secrets"] == []  # DefaultAzureCredential — nothing handed over
    assert spec["supports_targets"] is True
    assert spec["output"]["aggregation"] == "per_target"
    assert spec["output"]["path"] == f"azure_{short_name}.json"
    assert spec["target_schema"]["subscription_id"]["env"] == "AZURE_SUBSCRIPTION_ID"
    assert spec["target_schema"]["subscription_id"]["required"] is False
    assert spec["evidence_set"]["reference_id"].startswith("EVD-AZURE-")


@pytest.mark.parametrize("short_name", COMPUTE_FETCHERS)
def test_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    short_name, tmp_path, monkeypatch
):
    """The failure path end-to-end, with no Azure SDK involved.

    With no subscription resolvable, each fetcher must still write parseable
    evidence, exit non-zero, and leave a well-formed one-line reason in
    $FETCHER_STATUS_FILE — without which the runner reports the tail of stderr (often
    a harmless INFO line) as the cause.

    Run for all four rather than one: each has its own `main()` with its own results
    block and filename, and the summary must survive being computed over an empty
    collection.
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
    assert payload["results"]["provider_registration_status"] == "unknown"
    assert payload["summary"]["provider_registration_status"] == "unknown"

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    assert status["code"] in {
        "auth_failed", "not_authorized", "target_unreachable",
        "rate_limited", "bad_config", "partial_failure", "internal_error",
    }
