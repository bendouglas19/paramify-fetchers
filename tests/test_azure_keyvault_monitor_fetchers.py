"""Fixture-based tests for the Azure key-management, monitoring and backup fetchers.

Covers azure_key_vault_configuration, azure_key_vault_key_rotation,
azure_diagnostic_settings, azure_activity_log_alerts and
azure_backup_recovery_status. Companion to tests/test_azure_fetchers.py, which
covers the storage / network / Defender set and the shared `azure_common` helpers;
nothing is duplicated from there.

No live API calls, no credentials, and no azure-* package needs to be installed:
the heavy `azure.*` imports live inside `azure_common.credential()` and each
fetcher's `collect_*()`, and are never triggered here. Two layers are covered.

**The projection layer** (`project_*`) is each fetcher's only code that touches an
SDK model. It reads model ATTRIBUTES into a flat snake_case dict, and its tests
drive it with `SimpleNamespace` stand-ins that mimic attribute access — including
the `None` intermediates the real API hands back constantly (a vault with no
`network_acls`, an alert rule with no `condition`, a protected item whose base
class carries no health fields).

**The pure transforms** (`*_record`, `summarize`, and friends) take the
projection's output and are plain dict-in/dict-out, so they are tested from
literal fixtures. Those fixtures are SYNTHETIC but not guessed: they are the
projections' verified output shape for the installed SDK versions
(azure-mgmt-keyvault 14.0.1, azure-keyvault-keys 4.11.1, azure-mgmt-monitor 6.0.2,
azure-mgmt-recoveryservices 4.1.0, azure-mgmt-recoveryservicesbackup 10.0.0).

Three traps in this set earned their own tests, all three verified against those
SDKs rather than assumed:

1. **`properties` is NOT flattened** on azure-mgmt-keyvault or the recovery
   packages — `vault.tenant_id` is absent and the value lives at
   `vault.properties.tenant_id` (the backup package cannot flatten, since
   `properties` is polymorphic). The `properties_bag()` helper each of those
   fetchers defines locally reads either shape.
2. **`Permissions.keys` is spelled `keys_property`** on azure-mgmt-keyvault 14.x:
   the model is Mapping-like, so the generator renamed the field to keep `.keys()`
   working — and reading `keys` there hands back the BOUND METHOD.
3. **One package renders the same date two ways**: `KeyAttributes.created` is an
   `int` epoch while the inherited `SecretAttributes.created` is a `datetime`, and
   the data plane's `KeyProperties.created_on` is a `datetime` again.

Run: pytest tests/test_azure_keyvault_monitor_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
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


def _load_shared():
    path = AZURE_ROOT / "_shared" / "azure_common.py"
    spec = importlib.util.spec_from_file_location("azure_common_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# properties_bag — the local helper three of these fetchers define
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "short_name", ["key_vault_configuration", "key_vault_key_rotation", "backup_recovery_status"]
)
def test_properties_bag_reads_either_sdk_shape(short_name):
    """The nested and the flattened generator shapes must project identically.

    azure-mgmt-keyvault 14.x and the recovery packages nest everything under
    `properties`; older msrest-generated releases flatten those names onto the
    resource and then have no `properties` attribute at all. One projection has to
    be right on both, so the helper falls back to the model itself.
    """
    module = _load(short_name)
    nested = SimpleNamespace(id="x", properties=SimpleNamespace(tenant_id="tid"))
    flattened = SimpleNamespace(id="x", tenant_id="tid")

    assert module.properties_bag(nested).tenant_id == "tid"
    assert module.properties_bag(flattened).tenant_id == "tid"
    # A resource whose `properties` the API omitted must not blow up either.
    assert module.properties_bag(SimpleNamespace(id="x")) is not None


# --------------------------------------------------------------------------- #
# Key Vault configuration — project_vault() output, then the transforms
# --------------------------------------------------------------------------- #

VAULT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-paramify-fetcher-test"
    "/providers/Microsoft.KeyVault/vaults/kv-pf-hardened"
)
VAULT_ID_DEFAULT = VAULT_ID.replace("kv-pf-hardened", "kv-pf-default")

HARDENED_VAULT = {  # SYNTHETIC — project_vault()'s output shape
    "id": VAULT_ID,
    "name": "kv-pf-hardened",
    "location": "eastus",
    "type": "Microsoft.KeyVault/vaults",
    "tenant_id": "22222222-2222-2222-2222-222222222222",
    "enable_rbac_authorization": True,
    "access_policies": [],
    "enable_soft_delete": True,
    "enable_purge_protection": True,
    "soft_delete_retention_in_days": 90,
    "public_network_access": "Disabled",
    "network_acls": {
        "bypass": "None",
        "default_action": "Deny",
        "ip_rules": ["203.0.113.0/24"],
        "virtual_network_rules": ["/subscriptions/s/subnets/app"],
    },
    "private_endpoint_connections": [
        {"id": "/subscriptions/s/pec1", "provisioning_state": "Succeeded", "connection_status": "Approved"}
    ],
    "sku": {"family": "A", "name": "premium"},
    "vault_uri": "https://kv-pf-hardened.vault.azure.net/",
    "enabled_for_deployment": False,
    "enabled_for_disk_encryption": True,
    "enabled_for_template_deployment": False,
    "provisioning_state": "Succeeded",
}

# The permissive default vault: ARM OMITS enableRbacAuthorization /
# enablePurgeProtection / publicNetworkAccess / the whole networkAcls block when
# they sit at their service defaults, so the projection reports None and "absent"
# must read as that default rather than as None.
DEFAULT_VAULT = {  # SYNTHETIC
    "id": VAULT_ID_DEFAULT,
    "name": "kv-pf-default",
    "location": "eastus",
    "type": "Microsoft.KeyVault/vaults",
    "tenant_id": "22222222-2222-2222-2222-222222222222",
    "enable_rbac_authorization": None,
    "access_policies": [
        {
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "object_id": "33333333-3333-3333-3333-333333333333",
            "application_id": None,
            "permissions": {
                "keys": ["get", "list"],
                "secrets": ["get"],
                "certificates": [],
                "storage": [],
            },
        }
    ],
    "enable_soft_delete": True,
    "enable_purge_protection": None,
    "soft_delete_retention_in_days": 7,
    "public_network_access": None,
    "network_acls": {
        "bypass": None,
        "default_action": None,
        "ip_rules": [],
        "virtual_network_rules": [],
    },
    "private_endpoint_connections": [],
    "sku": {"family": "A", "name": "standard"},
    "vault_uri": "https://kv-pf-default.vault.azure.net/",
    "enabled_for_deployment": None,
    "enabled_for_disk_encryption": None,
    "enabled_for_template_deployment": None,
    "provisioning_state": "Succeeded",
}


def test_project_vault_reads_sdk_attributes_through_properties():
    """The projection's output IS the fixture the transforms are tested against.

    Asserting the whole dict (not a few keys) is deliberate: if the projection's key
    names ever drift from what `vault_record` reads, the evidence would go quietly
    null rather than fail, so the two must be pinned to each other.
    """
    kv = _load("key_vault_configuration")
    vault = SimpleNamespace(
        id=VAULT_ID,
        name="kv-pf-hardened",
        location="eastus",
        type="Microsoft.KeyVault/vaults",
        # azure-mgmt-keyvault 14.x nests ALL of this under `properties`.
        properties=SimpleNamespace(
            tenant_id="22222222-2222-2222-2222-222222222222",
            enable_rbac_authorization=True,
            access_policies=[],
            enable_soft_delete=True,
            enable_purge_protection=True,
            soft_delete_retention_in_days=90,
            public_network_access="Disabled",
            network_acls=SimpleNamespace(
                bypass="None",
                default_action="Deny",
                ip_rules=[SimpleNamespace(value="203.0.113.0/24")],
                virtual_network_rules=[
                    SimpleNamespace(id="/subscriptions/s/subnets/app")
                ],
            ),
            private_endpoint_connections=[
                SimpleNamespace(
                    id="/subscriptions/s/pec1",
                    properties=SimpleNamespace(
                        provisioning_state="Succeeded",
                        private_link_service_connection_state=SimpleNamespace(
                            status="Approved"
                        ),
                    ),
                )
            ],
            sku=SimpleNamespace(family="A", name="premium"),
            vault_uri="https://kv-pf-hardened.vault.azure.net/",
            enabled_for_deployment=False,
            enabled_for_disk_encryption=True,
            enabled_for_template_deployment=False,
            provisioning_state="Succeeded",
        ),
    )
    assert kv.project_vault(vault) == HARDENED_VAULT


def test_project_vault_survives_absent_nested_models():
    """`sku` / `network_acls` / `access_policies` absent must read as None, not raise."""
    kv = _load("key_vault_configuration")
    bare = SimpleNamespace(
        id=VAULT_ID_DEFAULT,
        name="kv-pf-default",
        properties=SimpleNamespace(tenant_id="tid"),
    )
    projected = kv.project_vault(bare)  # must not raise

    assert projected["enable_rbac_authorization"] is None
    assert projected["enable_purge_protection"] is None
    assert projected["access_policies"] == []
    assert projected["private_endpoint_connections"] == []
    assert projected["sku"] == {"family": None, "name": None}
    assert projected["network_acls"] == {
        "bypass": None,
        "default_action": None,
        "ip_rules": [],
        "virtual_network_rules": [],
    }

    # ... and the transform still lands on the permissive service defaults.
    rec = kv.vault_record(projected)
    assert rec["rbac_authorization_enabled"] is False
    assert rec["access_model"] == "access_policy"
    assert rec["purge_protection_enabled"] is False
    assert rec["recoverable"] is False
    assert rec["public_network_access"] == "Enabled"
    assert rec["public_network_access_disabled"] is False
    assert rec["network_acls"]["default_action"] == "Allow"
    assert rec["network_acl_default_deny"] is False


def test_project_access_policy_reads_the_renamed_keys_field():
    """`Permissions.keys` is `keys_property` on azure-mgmt-keyvault 14.x.

    The model is Mapping-like, so the generator renamed the field to keep `.keys()`
    working — and `getattr(permissions, "keys")` there returns the BOUND METHOD,
    which is truthy and would render as "<bound method ...>" in the evidence. The
    renamed spelling must win, and a non-list answer must be discarded.
    """
    kv = _load("key_vault_configuration")

    class MappingLikePermissions:
        """Mimics the real model: `keys` is a method, the field is `keys_property`."""

        def __init__(self):
            self.keys_property = ["get", "list", "wrapKey"]
            self.secrets = ["get"]
            self.certificates = None
            self.storage = None

        def keys(self):  # the collision that forced the rename
            return ["keys_property", "secrets"]

    projected = kv.project_access_policy(
        SimpleNamespace(
            tenant_id="tid",
            object_id="oid",
            application_id=None,
            permissions=MappingLikePermissions(),
        )
    )
    assert projected["permissions"]["keys"] == ["get", "list", "wrapKey"]
    assert projected["permissions"]["secrets"] == ["get"]
    assert projected["permissions"]["certificates"] == []
    assert projected["permissions"]["storage"] == []


def test_project_access_policy_falls_back_to_the_older_keys_spelling():
    """An msrest-generated azure-mgmt-keyvault spells it plainly `keys` — a list."""
    kv = _load("key_vault_configuration")
    projected = kv.project_access_policy(
        SimpleNamespace(
            tenant_id="tid",
            object_id="oid",
            permissions=SimpleNamespace(keys=["get"], secrets=["list"]),
        )
    )
    assert projected["permissions"]["keys"] == ["get"]


def test_project_access_policy_unwraps_permission_verb_enums():
    """Verbs arrive as `str` enum MEMBERS inside a list, which model_attr can't reach.

    `model_attr` unwraps an enum handed to it directly; a list of them needs the
    projection's own pass, or a `str()`-based renderer would write
    "KeyPermissions.GET" into the evidence.
    """
    kv = _load("key_vault_configuration")

    class KeyPermissions(str, Enum):
        GET = "get"
        LIST = "list"

    projected = kv.project_access_policy(
        SimpleNamespace(
            tenant_id="tid",
            object_id="oid",
            permissions=SimpleNamespace(
                keys_property=[KeyPermissions.GET, KeyPermissions.LIST]
            ),
        )
    )
    assert projected["permissions"]["keys"] == ["get", "list"]
    assert all(type(v) is str for v in projected["permissions"]["keys"])


def test_key_vault_rbac_and_recoverability_records():
    kv = _load("key_vault_configuration")
    rec = kv.vault_record(HARDENED_VAULT)
    assert rec["rbac_authorization_enabled"] is True
    assert rec["access_model"] == "rbac"
    assert rec["access_policy_count"] == 0
    assert rec["soft_delete_enabled"] is True
    assert rec["purge_protection_enabled"] is True
    assert rec["recoverable"] is True
    assert rec["public_network_access_disabled"] is True
    assert rec["network_acl_default_deny"] is True
    assert rec["resource_group"] == "rg-paramify-fetcher-test"
    assert rec["private_endpoint_connections"][0]["connection_status"] == "Approved"

    default = kv.vault_record(DEFAULT_VAULT)
    assert default["access_model"] == "access_policy"
    assert default["access_policy_count"] == 1
    # Soft delete on, purge protection absent => not recoverable: a deleted vault
    # can still be purged inside the retention window.
    assert default["soft_delete_enabled"] is True
    assert default["purge_protection_enabled"] is False
    assert default["recoverable"] is False


def test_key_vault_summary_tracks_rbac_and_recoverability():
    kv = _load("key_vault_configuration")
    vaults = [kv.vault_record(HARDENED_VAULT), kv.vault_record(DEFAULT_VAULT)]
    summary = kv.summarize(vaults)
    assert summary["total_key_vaults"] == 2
    assert summary["rbac_authorization_vaults"] == 1
    assert summary["access_policy_vaults"] == 1
    assert summary["rbac_authorization_percentage"] == 50
    assert summary["soft_delete_vaults"] == 2
    assert summary["purge_protection_vaults"] == 1
    assert summary["recoverable_vaults"] == 1
    assert summary["recoverable_percentage"] == 50
    assert summary["public_network_access_disabled_vaults"] == 1
    assert summary["network_acl_default_deny_vaults"] == 1
    assert summary["private_endpoint_vaults"] == 1
    assert summary["premium_sku_vaults"] == 1
    assert summary["total_access_policies"] == 1


def test_key_vault_summary_empty_subscription():
    kv = _load("key_vault_configuration")
    summary = kv.summarize([])
    assert summary["total_key_vaults"] == 0
    assert summary["rbac_authorization_percentage"] == 0
    assert summary["recoverable_percentage"] == 0


# --------------------------------------------------------------------------- #
# Key Vault key rotation — the two-plane fetcher
# --------------------------------------------------------------------------- #

# Epoch seconds, which is how azure-mgmt-keyvault types a KEY's dates.
EPOCH_CREATED = 1749081600   # 2025-06-05T00:00:00Z
EPOCH_EXPIRES = 1780617600   # 2026-06-05T00:00:00Z

MANAGEMENT_KEY = {  # SYNTHETIC — project_management_key()'s output shape
    "id": f"{VAULT_ID}/keys/storage-cmk",
    "name": "storage-cmk",
    "location": "eastus",
    "enabled": True,
    "created": EPOCH_CREATED,
    "updated": EPOCH_CREATED,
    "expires": EPOCH_EXPIRES,
    "not_before": None,
    "recovery_level": "Recoverable+Purgeable",
    "key_type": "RSA",
    "key_size": 2048,
    "curve_name": None,
    "rotation_policy": None,
}

DATA_PLANE_ROTATION_POLICY = {  # SYNTHETIC — project_rotation_policy()'s output
    "id": "https://kv-pf-hardened.vault.azure.net/keys/storage-cmk/rotationpolicy",
    "expires_in": "P2Y",
    "created": datetime(2025, 6, 5, tzinfo=timezone.utc),
    "updated": datetime(2025, 6, 5, tzinfo=timezone.utc),
    "lifetime_actions": [
        {"action": "Rotate", "time_after_create": "P18M", "time_before_expiry": None},
        {"action": "Notify", "time_after_create": None, "time_before_expiry": "P30D"},
    ],
}


def test_iso8601_timestamp_normalizes_every_shape_one_package_returns():
    """The same field arrives as an int here and a datetime there — in ONE package.

    azure-mgmt-keyvault 14.x types `KeyAttributes.created` as `int` (epoch seconds,
    straight off the wire) but the inherited `SecretAttributes.created` as
    `datetime` (format="unix-timestamp"), and the data plane's
    `KeyProperties.created_on` is a `datetime` again. Without normalizing,
    `json.dump(default=str)` writes 1749081600 for a key's expiry and
    "2026-06-05 00:00:00+00:00" for a secret's — two renderings of one field in one
    evidence file.
    """
    kr = _load("key_vault_key_rotation")
    assert kr._iso8601_timestamp(EPOCH_CREATED) == "2025-06-05T00:00:00Z"
    assert kr._iso8601_timestamp(float(EPOCH_CREATED)) == "2025-06-05T00:00:00Z"
    assert (
        kr._iso8601_timestamp(datetime(2025, 6, 5, tzinfo=timezone.utc))
        == "2025-06-05T00:00:00Z"
    )
    # A naive datetime is read as UTC rather than as local time, so the evidence
    # does not shift with the collector's timezone.
    assert kr._iso8601_timestamp(datetime(2025, 6, 5)) == "2025-06-05T00:00:00Z"
    # A non-UTC offset is converted, not truncated.
    assert (
        kr._iso8601_timestamp(datetime(2025, 6, 5, 2, tzinfo=timezone(timedelta(hours=2))))
        == "2025-06-05T00:00:00Z"
    )
    assert kr._iso8601_timestamp("2025-06-05T00:00:00Z") == "2025-06-05T00:00:00Z"
    assert kr._iso8601_timestamp(None) is None
    # bool is an int subclass; an epoch of True is nonsense, not 1970-01-01.
    assert kr._iso8601_timestamp(True) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (timedelta(days=90), "P90D"),
        (timedelta(0), "P0D"),
        (timedelta(days=1, hours=3), "P1DT3H"),
        (timedelta(hours=3, minutes=4, seconds=5), "PT3H4M5S"),
        ("P90D", "P90D"),  # what the installed SDKs actually return
        (None, None),
    ],
)
def test_rotation_durations_keep_the_wire_format(value, expected):
    """Rotation policy durations must read "P90D", never "90 days, 0:00:00".

    The installed SDKs type `expires_in` / `time_before_expiry` as `str`, but an
    msrest-generated duration field deserializes to a `timedelta` and
    `json.dump(default=str)` would then change the payload for identical input —
    the bug this helper was written for on azure-mgmt-security's
    free_trial_remaining_time.
    """
    kr = _load("key_vault_key_rotation")
    assert kr._iso8601_duration(value) == expected


def test_project_management_key_reads_the_nested_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    kr = _load("key_vault_key_rotation")
    key = SimpleNamespace(
        id=MANAGEMENT_KEY["id"],
        name="storage-cmk",
        location="eastus",
        properties=SimpleNamespace(
            attributes=SimpleNamespace(
                enabled=True,
                created=EPOCH_CREATED,
                updated=EPOCH_CREATED,
                expires=EPOCH_EXPIRES,
                not_before=None,
                recovery_level="Recoverable+Purgeable",
            ),
            kty="RSA",
            key_size=2048,
            curve_name=None,
            rotation_policy=None,
        ),
    )
    assert kr.project_management_key(key) == MANAGEMENT_KEY


def test_project_management_secret_never_reads_the_value():
    """The evidence must never carry secret material.

    `SecretProperties.value` exists on the model. This pins that the projection
    does not read it, and does not read the caller-supplied `content_type` either.
    """
    kr = _load("key_vault_key_rotation")
    secret = SimpleNamespace(
        id=f"{VAULT_ID}/secrets/db-password",
        name="db-password",
        location="eastus",
        properties=SimpleNamespace(
            value="SUPER-SECRET-VALUE",
            content_type="text/plain",
            attributes=SimpleNamespace(
                enabled=True,
                created=datetime(2025, 6, 5, tzinfo=timezone.utc),
                updated=datetime(2025, 6, 5, tzinfo=timezone.utc),
                expires=None,
                not_before=None,
            ),
        ),
    )
    projected = kr.project_management_secret(secret)
    assert "value" not in projected
    assert "content_type" not in projected
    assert "SUPER-SECRET-VALUE" not in json.dumps(projected, default=str)

    rec = kr.secret_record(projected)
    assert rec["name"] == "db-password"
    assert rec["created"] == "2025-06-05T00:00:00Z"
    assert rec["expires"] is None
    assert rec["expiration_set"] is False
    assert "SUPER-SECRET-VALUE" not in json.dumps(rec, default=str)


def test_project_key_properties_maps_the_data_plane_spelling():
    """The data plane spells the dates `*_on` and returns real datetimes."""
    kr = _load("key_vault_key_rotation")
    projected = kr.project_key_properties(
        SimpleNamespace(
            id="https://kv-pf-hardened.vault.azure.net/keys/storage-cmk/abc",
            name="storage-cmk",
            enabled=True,
            created_on=datetime(2025, 6, 5, tzinfo=timezone.utc),
            updated_on=datetime(2025, 6, 5, tzinfo=timezone.utc),
            expires_on=None,
            not_before=None,
            recovery_level="Recoverable+Purgeable",
        )
    )
    assert projected["name"] == "storage-cmk"
    assert projected["created"] == datetime(2025, 6, 5, tzinfo=timezone.utc)
    assert projected["expires"] is None
    # Shape parity with the management-plane projection is what lets one record
    # function read either plane.
    assert set(projected) == set(MANAGEMENT_KEY)


def test_both_planes_project_a_rotation_policy_to_one_shape():
    """The control plane NESTS what the data plane flattens, and cases it differently.

    Data plane: `lifetime_actions[].action` is a "Rotate"/"Notify" enum and the
    durations sit on the action. Control plane: the verb is
    `lifetime_actions[].action.type` ("rotate", lowercase) and the durations sit on
    `lifetime_actions[].trigger`. Both must project to one dict, or the merged
    evidence would be shaped by whichever plane answered.
    """
    kr = _load("key_vault_key_rotation")

    class DataPlaneAction(str, Enum):
        ROTATE = "Rotate"

    data_plane = kr.project_rotation_policy(
        SimpleNamespace(
            id="policy-id",
            expires_in="P2Y",
            created_on=datetime(2025, 6, 5, tzinfo=timezone.utc),
            updated_on=datetime(2025, 6, 5, tzinfo=timezone.utc),
            lifetime_actions=[
                SimpleNamespace(
                    action=DataPlaneAction.ROTATE,
                    time_after_create="P18M",
                    time_before_expiry=None,
                )
            ],
        )
    )
    management = kr.project_management_rotation_policy(
        SimpleNamespace(
            id="policy-id",
            attributes=SimpleNamespace(
                expiry_time="P2Y",
                created=datetime(2025, 6, 5, tzinfo=timezone.utc),
                updated=datetime(2025, 6, 5, tzinfo=timezone.utc),
            ),
            lifetime_actions=[
                SimpleNamespace(
                    action=SimpleNamespace(type="rotate"),
                    trigger=SimpleNamespace(
                        time_after_create="P18M", time_before_expiry=None
                    ),
                )
            ],
        )
    )
    assert set(data_plane) == set(management)
    # The enum unwrapped to its wire string, not "DataPlaneAction.ROTATE".
    assert data_plane["lifetime_actions"][0]["action"] == "Rotate"
    assert management["lifetime_actions"][0]["action"] == "rotate"
    assert data_plane["lifetime_actions"][0]["time_after_create"] == "P18M"
    assert management["lifetime_actions"][0]["time_after_create"] == "P18M"
    # ... and both are read as rotating despite the case difference.
    assert kr.has_rotate_action(kr.rotation_policy_record(data_plane)) is True
    assert kr.has_rotate_action(kr.rotation_policy_record(management)) is True


def test_project_rotation_policy_of_none_is_none():
    kr = _load("key_vault_key_rotation")
    assert kr.project_rotation_policy(None) is None
    assert kr.project_management_rotation_policy(None) is None
    assert kr.rotation_policy_record(None) is None
    assert kr.has_rotate_action(None) is False
    # A policy with only a Notify action is NOT rotation (Prowler's exact reading).
    assert (
        kr.has_rotate_action({"lifetime_actions": [{"action": "Notify"}]}) is False
    )


def test_key_record_reports_expiration_and_rotation():
    kr = _load("key_vault_key_rotation")
    rec = kr.key_record(MANAGEMENT_KEY, kr.SOURCE_MANAGEMENT_PLANE)
    assert rec["name"] == "storage-cmk"
    assert rec["created"] == "2025-06-05T00:00:00Z"
    assert rec["expires"] == "2026-06-05T00:00:00Z"
    assert rec["expiration_set"] is True
    assert rec["key_type"] == "RSA"
    assert rec["key_size"] == 2048
    # No policy came back, so there is no source to claim one from.
    assert rec["rotation_policy"] is None
    assert rec["rotation_enabled"] is False
    assert rec["rotation_policy_source"] is None
    # ... and nobody asserted the answer was definitive, so it is not counted as one.
    assert rec["rotation_policy_readable"] is False


def test_key_record_readability_separates_no_policy_from_no_visibility():
    """"This key does not rotate" and "we could not see whether it does" differ.

    Only the caller knows whether the plane it asked actually answered, so it says
    so — and that flag, not the presence of a policy, is the denominator the
    rotation percentage is measured over.
    """
    kr = _load("key_vault_key_rotation")
    unseen = kr.key_record({"name": "k"}, kr.SOURCE_MANAGEMENT_PLANE)
    answered = kr.key_record({"name": "k"}, kr.SOURCE_MANAGEMENT_PLANE, policy_readable=True)

    assert unseen["rotation_policy"] is None and unseen["rotation_policy_readable"] is False
    # A definitive "there is no rotation policy" — readable, but still not rotating.
    assert answered["rotation_policy"] is None
    assert answered["rotation_policy_readable"] is True
    assert answered["rotation_enabled"] is False
    assert answered["rotation_policy_source"] is None

    # A key with no expiry: `expires` absent means no expiration date is set, which
    # is what keyvault_rbac_key_expiration_set fails on.
    no_expiry = kr.key_record({**MANAGEMENT_KEY, "expires": None})
    assert no_expiry["expires"] is None
    assert no_expiry["expiration_set"] is False
    # An absent `enabled` reads as the service default (enabled), the same way the
    # storage fetcher reads an absent allow_shared_key_access as its default.
    assert kr.key_record({"name": "k"})["enabled"] is True
    assert kr.key_record({"name": "k", "enabled": False})["enabled"] is False


def test_merge_rotation_policies_attaches_by_name():
    kr = _load("key_vault_key_rotation")
    keys = [kr.key_record(MANAGEMENT_KEY, kr.SOURCE_MANAGEMENT_PLANE)]
    merged = kr.merge_rotation_policies(keys, {"storage-cmk": DATA_PLANE_ROTATION_POLICY})

    assert len(merged) == 1
    assert merged[0]["rotation_enabled"] is True
    assert merged[0]["rotation_policy_source"] == "data_plane"
    assert merged[0]["rotation_policy_readable"] is True
    assert merged[0]["rotation_policy"]["expires_in"] == "P2Y"
    assert merged[0]["rotation_policy"]["created"] == "2025-06-05T00:00:00Z"
    actions = merged[0]["rotation_policy"]["lifetime_actions"]
    assert [a["action"] for a in actions] == ["Rotate", "Notify"]
    assert actions[0]["time_after_create"] == "P18M"
    assert actions[1]["time_before_expiry"] == "P30D"


def test_management_plane_policy_survives_a_closed_data_plane():
    """Verified live: ARM's keys.get returns rotationPolicy — keys.list does not.

    So a collector holding only ARM Reader still gets rotation policies, and the
    merge must not erase a management-plane answer when the data plane had nothing
    to say about that key (a 404, or no rotation-policy data action).
    """
    kr = _load("key_vault_key_rotation")
    from_management = kr.key_record(
        {
            **MANAGEMENT_KEY,
            "rotation_policy": {
                "id": None,
                "expires_in": "P2Y",
                "created": None,
                "updated": None,
                "lifetime_actions": [
                    {"action": "rotate", "time_after_create": "P18M", "time_before_expiry": None}
                ],
            },
        },
        kr.SOURCE_MANAGEMENT_PLANE,
        policy_readable=True,
    )
    assert from_management["rotation_enabled"] is True
    assert from_management["rotation_policy_source"] == "management_plane"

    merged = kr.merge_rotation_policies([from_management], {"storage-cmk": None})
    assert merged[0]["rotation_enabled"] is True
    assert merged[0]["rotation_policy_source"] == "management_plane"
    assert merged[0]["rotation_policy_readable"] is True

    # The data plane wins when it DOES answer.
    merged = kr.merge_rotation_policies(
        [from_management], {"storage-cmk": DATA_PLANE_ROTATION_POLICY}
    )
    assert merged[0]["rotation_policy_source"] == "data_plane"


def test_merge_rotation_policies_keeps_a_data_plane_only_key():
    """A key the management list missed must not be dropped from the inventory.

    Prowler's `keys_dict[name]` lookup silently discards it, which would understate
    the key count. Here it is added, with no policy attached if there was none.
    """
    kr = _load("key_vault_key_rotation")
    merged = kr.merge_rotation_policies([], {"orphan-key": None, "rotating": DATA_PLANE_ROTATION_POLICY})
    assert [k["name"] for k in merged] == ["orphan-key", "rotating"]
    assert merged[0]["rotation_policy"] is None
    assert merged[1]["rotation_enabled"] is True


def test_data_plane_inaccessible_is_recognized_by_the_whole_class_hierarchy():
    """Prowler catches HttpResponseError; every subclass must read the same way.

    Matched by walking the exception's class NAMES so the predicate needs no
    azure-core import — and so a 403 (HttpResponseError), a key with no policy
    (ResourceNotFoundError) and a 401 (ClientAuthenticationError) all land on the
    per-vault status rather than on the exit code. A TRANSPORT failure must NOT:
    "the vault is unreachable" is a broken run, not a posture.
    """
    kr = _load("key_vault_key_rotation")

    class HttpResponseError(Exception):
        pass

    class ResourceNotFoundError(HttpResponseError):
        pass

    class ServiceRequestError(Exception):
        pass

    assert kr.is_data_plane_inaccessible(HttpResponseError("(Forbidden) no keys/list")) is True
    assert kr.is_data_plane_inaccessible(ResourceNotFoundError("(KeyNotFound) no policy")) is True
    assert kr.is_data_plane_inaccessible(ServiceRequestError("getaddrinfo failed")) is False
    assert kr.is_data_plane_inaccessible(RuntimeError("something else")) is False


def test_vault_data_plane_uri_prefers_the_arm_supplied_uri():
    """Prowler hardcodes .vault.azure.net; the sovereign clouds use another suffix."""
    kr = _load("key_vault_key_rotation")
    assert (
        kr.vault_data_plane_uri({"name": "kv", "vault_uri": "https://kv.vault.usgovcloudapi.net/"})
        == "https://kv.vault.usgovcloudapi.net/"
    )
    # Fallback is Prowler's exact form.
    assert kr.vault_data_plane_uri({"name": "kv"}) == "https://kv.vault.azure.net/"
    assert kr.vault_data_plane_uri({}) is None


def test_key_rotation_summary_measures_only_keys_whose_policy_was_readable():
    """A key nobody could ask about must not drag the percentage down.

    Otherwise the number measures the collector's permissions rather than the
    tenant's key management — the unreadable keys are reported as their own count
    instead.
    """
    kr = _load("key_vault_key_rotation")

    rotating = kr.key_record(MANAGEMENT_KEY, kr.SOURCE_MANAGEMENT_PLANE)
    rotating = kr.merge_rotation_policies([rotating], {"storage-cmk": DATA_PLANE_ROTATION_POLICY})
    open_vault = kr.vault_record(
        {
            "id": VAULT_ID,
            "name": "kv-pf-hardened",
            "vault_uri": "https://kv-pf-hardened.vault.azure.net/",
            "enable_rbac_authorization": True,
            "data_plane_status": kr.DATA_PLANE_ACCESSIBLE,
            "keys": rotating,
            "secrets": [kr.secret_record({"name": "db-password", "expires": None})],
        }
    )
    closed_vault = kr.vault_record(
        {
            "id": VAULT_ID_DEFAULT,
            "name": "kv-pf-default",
            "data_plane_status": kr.DATA_PLANE_INACCESSIBLE,
            "data_plane_message": "(Forbidden) caller is not authorized",
            "keys": [kr.key_record({"name": "unseen", "expires": EPOCH_EXPIRES})],
            "secrets": [],
        }
    )

    summary = kr.summarize([open_vault, closed_vault])
    assert summary["total_key_vaults"] == 2
    assert summary["data_plane_accessible_vaults"] == 1
    assert summary["data_plane_inaccessible_vaults"] == 1
    assert summary["total_keys"] == 2
    assert summary["keys_with_readable_rotation_policy"] == 1
    assert summary["keys_with_rotation_enabled"] == 1
    # 1 of 1 READABLE key rotates — not 1 of 2, which would penalize the fetcher's
    # own lack of any answer for the other vault's key.
    assert summary["rotation_enabled_percentage"] == 100
    assert summary["keys_with_expiration"] == 2
    assert summary["key_expiration_percentage"] == 100
    assert summary["total_secrets"] == 1
    assert summary["secrets_with_expiration"] == 0
    assert summary["secret_expiration_percentage"] == 0


def test_key_rotation_summary_empty_subscription():
    kr = _load("key_vault_key_rotation")
    summary = kr.summarize([])
    assert summary["total_key_vaults"] == 0
    assert summary["rotation_enabled_percentage"] == 0
    assert summary["secret_expiration_percentage"] == 0


def test_vault_record_defaults_the_data_plane_status():
    """A vault whose data plane was never reached must say so, not imply access."""
    kr = _load("key_vault_key_rotation")
    rec = kr.vault_record({"id": VAULT_ID, "name": "kv-pf-hardened"})
    assert rec["data_plane_status"] == "not_attempted"
    assert rec["data_plane_message"] is None
    assert rec["keys"] == []
    assert rec["secrets"] == []
    assert rec["resource_group"] == "rg-paramify-fetcher-test"


# --------------------------------------------------------------------------- #
# Diagnostic settings — the Activity Log export
# --------------------------------------------------------------------------- #

SETTING_ID = (
    f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Insights"
    "/diagnosticSettings/activity-log-to-la"
)

FULL_SETTING = {  # SYNTHETIC — project_diagnostic_setting()'s output shape
    "id": SETTING_ID,
    "name": "activity-log-to-la",
    "storage_account_id": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-logs"
        "/providers/Microsoft.Storage/storageAccounts/pflogs"
    ),
    "workspace_id": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-logs"
        "/providers/Microsoft.OperationalInsights/workspaces/pf-law"
    ),
    "event_hub_name": None,
    "event_hub_authorization_rule_id": None,
    "service_bus_rule_id": None,
    "marketplace_partner_id": None,
    "log_analytics_destination_type": "Dedicated",
    "logs": [
        {
            "category": "Administrative",
            "category_group": None,
            "enabled": True,
            "retention_policy": {"enabled": False, "days": 0},
        },
        {
            "category": "Security",
            "category_group": None,
            "enabled": True,
            "retention_policy": {"enabled": False, "days": 0},
        },
        {
            "category": "Alert",
            "category_group": None,
            "enabled": True,
            "retention_policy": {"enabled": True, "days": 365},
        },
        {
            "category": "Policy",
            "category_group": None,
            "enabled": True,
            "retention_policy": {"enabled": False, "days": 0},
        },
        {
            # Selected in the portal but switched off — must not count as covered.
            "category": "Autoscale",
            "category_group": None,
            "enabled": False,
            "retention_policy": {"enabled": None, "days": None},
        },
    ],
}

PARTIAL_SETTING = {  # SYNTHETIC — a storage-only export missing Security and Policy
    "id": SETTING_ID.replace("activity-log-to-la", "activity-log-to-storage"),
    "name": "activity-log-to-storage",
    "storage_account_id": (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-logs"
        "/providers/Microsoft.Storage/storageAccounts/pfarchive"
    ),
    "workspace_id": None,
    "event_hub_name": None,
    "event_hub_authorization_rule_id": None,
    "service_bus_rule_id": None,
    "marketplace_partner_id": None,
    "log_analytics_destination_type": None,
    "logs": [
        {
            "category": "Administrative",
            "category_group": None,
            "enabled": True,
            "retention_policy": {"enabled": None, "days": None},
        }
    ],
}


def test_project_diagnostic_setting_reads_the_flattened_sdk_attributes():
    """azure-mgmt-monitor 6.x is msrest and FLATTENS properties.* onto the model."""
    ds = _load("diagnostic_settings")
    setting = SimpleNamespace(
        id=SETTING_ID,
        name="activity-log-to-la",
        storage_account_id=FULL_SETTING["storage_account_id"],
        workspace_id=FULL_SETTING["workspace_id"],
        event_hub_name=None,
        event_hub_authorization_rule_id=None,
        service_bus_rule_id=None,
        marketplace_partner_id=None,
        log_analytics_destination_type="Dedicated",
        logs=[
            SimpleNamespace(
                category=log["category"],
                category_group=None,
                enabled=log["enabled"],
                retention_policy=SimpleNamespace(
                    enabled=log["retention_policy"]["enabled"],
                    days=log["retention_policy"]["days"],
                ),
            )
            for log in FULL_SETTING["logs"]
        ],
    )
    assert ds.project_diagnostic_setting(setting) == FULL_SETTING


def test_project_diagnostic_setting_falls_back_to_the_id_for_the_name():
    """Prowler derives the name from the id's last segment; both paths must work."""
    ds = _load("diagnostic_settings")
    projected = ds.project_diagnostic_setting(SimpleNamespace(id=SETTING_ID))
    assert projected["name"] == "activity-log-to-la"
    assert projected["logs"] == []
    assert projected["storage_account_id"] is None


def test_diagnostic_setting_record_decodes_destinations_and_categories():
    ds = _load("diagnostic_settings")
    rec = ds.diagnostic_setting_record(FULL_SETTING)
    assert rec["destinations"] == ["storage_account", "log_analytics_workspace"]
    assert rec["storage_account_name"] == "pflogs"
    assert rec["workspace_name"] == "pf-law"
    assert rec["enabled_log_categories"] == ["Administrative", "Alert", "Policy", "Security"]
    assert rec["captures_required_log_categories"] is True
    assert rec["missing_required_log_categories"] == []
    # A category selected but disabled is NOT captured.
    assert "Autoscale" not in rec["enabled_log_categories"]
    # An absent retention block reads as off/0, not as unknown.
    assert rec["logs"][4]["retention_policy"] == {"enabled": False, "days": 0}
    assert rec["logs"][2]["retention_policy"] == {"enabled": True, "days": 365}

    partial = ds.diagnostic_setting_record(PARTIAL_SETTING)
    assert partial["destinations"] == ["storage_account"]
    assert partial["captures_required_log_categories"] is False
    assert partial["missing_required_log_categories"] == ["Security", "Alert", "Policy"]


def test_diagnostic_setting_all_logs_group_covers_every_category():
    """category_group "allLogs" selects every category without naming any.

    Reading it as covering nothing would report a fully-logged subscription as
    unlogged — and "allLogs" is what the portal writes by default.
    """
    ds = _load("diagnostic_settings")
    rec = ds.diagnostic_setting_record(
        {
            "id": SETTING_ID,
            "name": "all-logs",
            "workspace_id": "/subscriptions/s/workspaces/w",
            "logs": [{"category": None, "category_group": "allLogs", "enabled": True}],
        }
    )
    assert rec["enabled_log_categories"] == []
    assert rec["enabled_log_category_groups"] == ["allLogs"]
    assert rec["captures_all_log_categories"] is True
    assert rec["captures_required_log_categories"] is True
    assert rec["missing_required_log_categories"] == []

    coverage = ds.category_coverage([rec])
    assert all(coverage.values())


def test_diagnostic_settings_summary_unions_coverage_across_settings():
    """Two partial settings can together cover the required categories.

    Coverage is the union — exporting Administrative to storage and Security to a
    workspace does capture both. Prowler's stricter "one setting carries all four"
    reading is reported separately.
    """
    ds = _load("diagnostic_settings")
    settings = [
        ds.diagnostic_setting_record(FULL_SETTING),
        ds.diagnostic_setting_record(PARTIAL_SETTING),
    ]
    summary = ds.summarize(settings)
    assert summary["total_diagnostic_settings"] == 2
    assert summary["activity_log_exported"] is True
    assert summary["settings_with_storage_account"] == 2
    assert summary["settings_with_log_analytics_workspace"] == 1
    assert summary["settings_with_event_hub"] == 0
    assert summary["all_required_log_categories_covered"] is True
    assert summary["required_log_category_percentage"] == 100
    assert summary["settings_capturing_required_categories"] == 1  # the full one only
    assert summary["log_category_coverage"]["ServiceHealth"] is False
    assert summary["settings_with_legacy_retention"] == 1


def test_diagnostic_settings_summary_when_the_activity_log_is_not_exported():
    """No setting at all: the Activity Log is kept 90 days and then discarded."""
    ds = _load("diagnostic_settings")
    summary = ds.summarize([])
    assert summary["total_diagnostic_settings"] == 0
    assert summary["activity_log_exported"] is False
    assert summary["all_required_log_categories_covered"] is False
    assert summary["required_log_category_percentage"] == 0
    assert set(summary["log_category_coverage"]) == set(ds.ACTIVITY_LOG_CATEGORIES)
    assert not any(summary["log_category_coverage"].values())


# --------------------------------------------------------------------------- #
# Activity log alerts — the inventory plus the derived coverage map
# --------------------------------------------------------------------------- #

ALERT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-alerts"
    "/providers/Microsoft.Insights/activityLogAlerts/nsg-write"
)

NSG_WRITE_ALERT = {  # SYNTHETIC — project_activity_log_alert()'s output shape
    "id": ALERT_ID,
    "name": "nsg-write",
    "location": "global",
    "enabled": True,
    "description": "NSG created or updated",
    "scopes": [f"/subscriptions/{SUBSCRIPTION}"],
    "condition": {
        "all_of": [
            {
                "field": "category",
                "equals": "Administrative",
                "contains_any": None,
                "any_of": [],
            },
            {
                "field": "operationName",
                "equals": "Microsoft.Network/networkSecurityGroups/write",
                "contains_any": None,
                "any_of": [],
            },
        ]
    },
    "action_groups": [f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-alerts/providers/Microsoft.Insights/actionGroups/secops"],
}


def test_project_activity_log_alert_reads_the_flattened_sdk_attributes():
    """The projection's output IS the fixture the transforms are tested against."""
    al = _load("activity_log_alerts")
    alert = SimpleNamespace(
        id=ALERT_ID,
        name="nsg-write",
        location="global",
        enabled=True,
        description="NSG created or updated",
        scopes=[f"/subscriptions/{SUBSCRIPTION}"],
        condition=SimpleNamespace(
            all_of=[
                SimpleNamespace(field="category", equals="Administrative"),
                SimpleNamespace(
                    field="operationName",
                    equals="Microsoft.Network/networkSecurityGroups/write",
                ),
            ]
        ),
        actions=SimpleNamespace(
            action_groups=[
                SimpleNamespace(
                    action_group_id=NSG_WRITE_ALERT["action_groups"][0],
                    webhook_properties={},
                )
            ]
        ),
    )
    assert al.project_activity_log_alert(alert) == NSG_WRITE_ALERT


def test_project_activity_log_alert_survives_an_alert_with_no_condition():
    """`condition` / `actions` are None on a rule the API returned bare."""
    al = _load("activity_log_alerts")
    projected = al.project_activity_log_alert(
        SimpleNamespace(id=ALERT_ID, name="bare")
    )  # must not raise
    assert projected["condition"] == {"all_of": []}
    assert projected["action_groups"] == []
    assert projected["enabled"] is None
    rec = al.alert_record(projected)
    assert rec["enabled"] is False
    assert rec["monitored_operations"] == []


def test_alert_operation_names_decodes_all_three_condition_forms():
    """Prowler reads only `equals`; `anyOf` and `containsAny` must count too.

    A portal-created alert listing several operations under one `anyOf` group would
    otherwise read as covering nothing, understating real coverage. Case folding
    matters for the same reason: ARM echoes back whatever case was written.
    """
    al = _load("activity_log_alerts")
    alert = {
        "enabled": True,
        "condition": {
            "all_of": [
                {
                    "field": "operationName",
                    "equals": "Microsoft.Network/networkSecurityGroups/write",
                },
                {
                    "field": "operationName",
                    "contains_any": ["MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE"],
                },
                {
                    "field": None,
                    "any_of": [
                        {
                            "field": "operationName",
                            "equals": "Microsoft.Sql/servers/firewallRules/delete",
                        },
                        {
                            "field": "operationName",
                            "contains_any": [
                                "Microsoft.Authorization/policyAssignments/write"
                            ],
                        },
                    ],
                },
            ]
        },
    }
    assert al.alert_operation_names(alert) == [
        "microsoft.authorization/policyassignments/write",
        "microsoft.network/networksecuritygroups/write",
        "microsoft.network/publicipaddresses/write",
        "microsoft.sql/servers/firewallrules/delete",
    ]


def test_disabled_alert_contributes_no_coverage():
    """`check_alert_rule` starts with `if alert_rule.enabled` — a disabled rule never fires."""
    al = _load("activity_log_alerts")
    rec = al.alert_record({**NSG_WRITE_ALERT, "enabled": False})
    assert rec["enabled"] is False
    assert rec["monitored_operations"] == []
    coverage = al.operation_coverage([rec])
    assert coverage["create_update_network_security_group"] is False


def test_service_health_alert_needs_both_conditions():
    """monitor_alert_service_health_exists wants category AND incidentType on one rule.

    A rule with only `category == ServiceHealth` also fires on planned maintenance
    and health advisories, which is not what the check asks for.
    """
    al = _load("activity_log_alerts")

    def _alert(conditions, enabled=True):
        return {"enabled": enabled, "condition": {"all_of": conditions}}

    both = _alert(
        [
            {"field": "category", "equals": "ServiceHealth"},
            {"field": "properties.incidentType", "equals": "Incident"},
        ]
    )
    category_only = _alert([{"field": "category", "equals": "ServiceHealth"}])

    assert al.is_service_health_alert(both) is True
    assert al.is_service_health_alert(category_only) is False
    assert al.alert_record(both)["service_health_alert"] is True
    # A disabled rule cannot satisfy it.
    assert al.alert_record({**both, "enabled": False})["service_health_alert"] is False


def test_delete_nsg_coverage_accepts_the_classic_namespace():
    """monitor_alert_delete_nsg passes on EITHER the ARM or the classic operation."""
    al = _load("activity_log_alerts")
    classic = al.alert_record(
        {
            "id": "a",
            "name": "classic-nsg-delete",
            "enabled": True,
            "condition": {
                "all_of": [
                    {
                        "field": "operationName",
                        "equals": "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
                    }
                ]
            },
        }
    )
    coverage = al.operation_coverage([classic])
    assert coverage["delete_network_security_group"] is True
    assert coverage["create_update_network_security_group"] is False


def test_activity_log_alerts_summary_reports_operation_coverage():
    al = _load("activity_log_alerts")
    alerts = [
        al.alert_record(NSG_WRITE_ALERT),
        al.alert_record(
            {
                "id": ALERT_ID.replace("nsg-write", "service-health"),
                "name": "service-health",
                "enabled": True,
                "condition": {
                    "all_of": [
                        {"field": "category", "equals": "ServiceHealth"},
                        {"field": "properties.incidentType", "equals": "Incident"},
                    ]
                },
                "action_groups": [],
            }
        ),
        al.alert_record({"id": "z", "name": "disabled-policy-delete", "enabled": False}),
    ]
    summary = al.summarize(alerts)
    assert summary["total_activity_log_alerts"] == 3
    assert summary["enabled_alerts"] == 2
    assert summary["disabled_alerts"] == 1
    assert summary["alerts_with_action_groups"] == 1
    assert summary["alerts_without_action_groups"] == 2
    assert summary["monitored_operations_total"] == len(al.MONITORED_OPERATIONS)
    assert summary["monitored_operations_covered"] == 1
    assert summary["monitored_operation_coverage"]["create_update_network_security_group"] is True
    assert summary["all_monitored_operations_covered"] is False
    assert "delete_network_security_group" in summary["uncovered_monitored_operations"]
    assert summary["service_health_alert_configured"] is True


def test_activity_log_alerts_summary_empty_subscription():
    al = _load("activity_log_alerts")
    summary = al.summarize([])
    assert summary["total_activity_log_alerts"] == 0
    assert summary["monitored_operations_covered"] == 0
    assert summary["monitored_operation_percentage"] == 0
    assert summary["service_health_alert_configured"] is False
    assert set(summary["monitored_operation_coverage"]) == set(al.MONITORED_OPERATIONS)


def test_monitored_operations_cover_every_prowler_alert_check():
    """The map must not silently lose an operation Prowler has a check for."""
    al = _load("activity_log_alerts")
    expected = {
        "Microsoft.Network/networkSecurityGroups/write",
        "Microsoft.Network/networkSecurityGroups/delete",
        "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
        "Microsoft.Network/publicIPAddresses/write",
        "Microsoft.Network/publicIPAddresses/delete",
        "Microsoft.Authorization/policyAssignments/write",
        "Microsoft.Authorization/policyAssignments/delete",
        "Microsoft.Sql/servers/firewallRules/write",
        "Microsoft.Sql/servers/firewallRules/delete",
        "Microsoft.Security/securitySolutions/write",
        "Microsoft.Security/securitySolutions/delete",
    }
    declared = {op for ops in al.MONITORED_OPERATIONS.values() for op in ops}
    assert expected <= declared


# --------------------------------------------------------------------------- #
# Backup / recovery status
# --------------------------------------------------------------------------- #

RS_VAULT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-backup"
    "/providers/Microsoft.RecoveryServices/vaults/rsv-paramify"
)
POLICY_ID = f"{RS_VAULT_ID}/backupPolicies/DailyPolicy"
ITEM_ID = f"{RS_VAULT_ID}/backupFabrics/Azure/protectionContainers/c1/protectedItems/vm-app"

VM_POLICY = {  # SYNTHETIC — project_backup_policy()'s output shape
    "id": POLICY_ID,
    "name": "DailyPolicy",
    "type": "Microsoft.RecoveryServices/vaults/backupPolicies",
    "location": None,
    "backup_management_type": "AzureIaasVM",
    "policy_type": "V2",
    "workload_type": None,
    "protected_items_count": 1,
    "time_zone": "UTC",
    "instant_rp_retention_range_in_days": 2,
    "schedule_policy": {
        "schedule_policy_type": "SimpleSchedulePolicyV2",
        "schedule_run_frequency": "Daily",
        "schedule_run_days": None,
        "schedule_run_times": ["2026-08-13T02:00:00Z"],
        "schedule_weekly_frequency": None,
    },
    "retention_policy": {
        "retention_policy_type": "LongTermRetentionPolicy",
        "retention_duration": {"count": None, "duration_type": None},
        "daily_schedule": {
            "retention_duration": {"count": 30, "duration_type": "Days"},
            "retention_times": ["2026-08-13T02:00:00Z"],
            "days_of_the_week": None,
            "months_of_year": None,
            "retention_schedule_format_type": None,
        },
        "weekly_schedule": {
            "retention_duration": {"count": 12, "duration_type": "Weeks"},
            "retention_times": ["2026-08-13T02:00:00Z"],
            "days_of_the_week": ["Sunday"],
            "months_of_year": None,
            "retention_schedule_format_type": None,
        },
        "monthly_schedule": None,
        "yearly_schedule": None,
    },
    "sub_protection_policies": [],
}

# A weekly-only policy: Prowler reads its daily retention as None and FAILS it,
# even though it keeps recovery points for 12 weeks.
WEEKLY_ONLY_POLICY = {
    **VM_POLICY,
    "id": POLICY_ID.replace("DailyPolicy", "WeeklyPolicy"),
    "name": "WeeklyPolicy",
    "retention_policy": {
        "retention_policy_type": "LongTermRetentionPolicy",
        "retention_duration": {"count": None, "duration_type": None},
        "daily_schedule": None,
        "weekly_schedule": {
            "retention_duration": {"count": 12, "duration_type": "Weeks"},
            "retention_times": [],
            "days_of_the_week": ["Sunday"],
            "months_of_year": None,
            "retention_schedule_format_type": None,
        },
        "monthly_schedule": None,
        "yearly_schedule": None,
    },
}

# A SAP HANA / SQL-in-VM policy: all retention lives in sub_protection_policy.
SUB_POLICY_POLICY = {
    **VM_POLICY,
    "id": POLICY_ID.replace("DailyPolicy", "HanaPolicy"),
    "name": "HanaPolicy",
    "backup_management_type": "AzureWorkload",
    "retention_policy": None,
    "sub_protection_policies": [
        {
            "policy_type": "Full",
            "schedule_policy": None,
            "retention_policy": {
                "retention_policy_type": "LongTermRetentionPolicy",
                "retention_duration": {"count": None, "duration_type": None},
                "daily_schedule": None,
                "weekly_schedule": None,
                "monthly_schedule": {
                    "retention_duration": {"count": 6, "duration_type": "Months"},
                    "retention_times": [],
                    "days_of_the_week": None,
                    "months_of_year": None,
                    "retention_schedule_format_type": "Weekly",
                },
                "yearly_schedule": None,
            },
        },
        {
            "policy_type": "Log",
            "schedule_policy": None,
            "retention_policy": {
                "retention_policy_type": "SimpleRetentionPolicy",
                "retention_duration": {"count": 15, "duration_type": "Days"},
                "daily_schedule": None,
                "weekly_schedule": None,
                "monthly_schedule": None,
                "yearly_schedule": None,
            },
        },
    ],
}

SHORT_POLICY = {  # 7 days — under the 30-day threshold
    **VM_POLICY,
    "id": POLICY_ID.replace("DailyPolicy", "ShortPolicy"),
    "name": "ShortPolicy",
    "retention_policy": {
        "retention_policy_type": "LongTermRetentionPolicy",
        "retention_duration": {"count": None, "duration_type": None},
        "daily_schedule": {
            "retention_duration": {"count": 7, "duration_type": "Days"},
            "retention_times": [],
            "days_of_the_week": None,
            "months_of_year": None,
            "retention_schedule_format_type": None,
        },
        "weekly_schedule": None,
        "monthly_schedule": None,
        "yearly_schedule": None,
    },
}

PROTECTED_VM = {  # SYNTHETIC — project_protected_item()'s output shape
    "id": ITEM_ID,
    "name": "vm-app",
    "protected_item_type": "Microsoft.Compute/virtualMachines",
    "backup_management_type": "AzureIaasVM",
    "workload_type": "VM",
    "container_name": "iaasvmcontainer;iaasvmcontainerv2;rg-app;vm-app",
    "friendly_name": "vm-app",
    "source_resource_id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm-app",
    "backup_policy_id": POLICY_ID,
    "backup_policy_name": "DailyPolicy",
    "protection_state": "Protected",
    "protection_status": "Healthy",
    "health_status": "Passed",
    "last_backup_status": "Completed",
    "last_backup_time": "2026-08-13T02:14:00Z",
    "last_recovery_point": "2026-08-13T02:20:00Z",
    "is_scheduled_for_deferred_delete": None,
    "is_archive_enabled": None,
    "soft_delete_retention_period_in_days": 14,
}


def test_project_backup_policy_reads_through_polymorphic_properties():
    """`ProtectionPolicyResource.properties` cannot be flattened — it is polymorphic."""
    rb = _load("backup_recovery_status")
    policy = SimpleNamespace(
        id=POLICY_ID,
        name="DailyPolicy",
        type="Microsoft.RecoveryServices/vaults/backupPolicies",
        location=None,
        properties=SimpleNamespace(
            backup_management_type="AzureIaasVM",
            policy_type="V2",
            protected_items_count=1,
            time_zone="UTC",
            instant_rp_retention_range_in_days=2,
            schedule_policy=SimpleNamespace(
                schedule_policy_type="SimpleSchedulePolicyV2",
                schedule_run_frequency="Daily",
                schedule_run_days=None,
                schedule_run_times=[datetime(2026, 8, 13, 2, tzinfo=timezone.utc)],
                schedule_weekly_frequency=None,
            ),
            retention_policy=SimpleNamespace(
                retention_policy_type="LongTermRetentionPolicy",
                daily_schedule=SimpleNamespace(
                    retention_duration=SimpleNamespace(count=30, duration_type="Days"),
                    retention_times=[datetime(2026, 8, 13, 2, tzinfo=timezone.utc)],
                ),
                weekly_schedule=SimpleNamespace(
                    retention_duration=SimpleNamespace(count=12, duration_type="Weeks"),
                    retention_times=[datetime(2026, 8, 13, 2, tzinfo=timezone.utc)],
                    days_of_the_week=["Sunday"],
                ),
                monthly_schedule=None,
                yearly_schedule=None,
            ),
        ),
    )
    assert rb.project_backup_policy(policy) == VM_POLICY


def test_project_protected_item_survives_the_base_class_without_health_fields():
    """`last_backup_status` lives on the workload SUBCLASSES, not on `ProtectedItem`."""
    rb = _load("backup_recovery_status")
    projected = rb.project_protected_item(
        SimpleNamespace(
            id=ITEM_ID,
            name="vm-app",
            properties=SimpleNamespace(
                protected_item_type="Microsoft.Compute/virtualMachines",
                workload_type="VM",
                policy_id=POLICY_ID,
            ),
        )
    )  # must not raise
    assert projected["last_backup_status"] is None
    assert projected["last_backup_time"] is None
    assert projected["protection_state"] is None
    assert projected["workload_type"] == "VM"


def test_backup_timestamps_are_normalized_to_the_category_format():
    """msrest hands ARM's iso-8601 fields over as datetimes; str() is not the format."""
    rb = _load("backup_recovery_status")
    assert rb._timestamp(datetime(2026, 8, 13, 2, 14, tzinfo=timezone.utc)) == (
        "2026-08-13T02:14:00Z"
    )
    assert rb._timestamp(datetime(2026, 8, 13, 2, 14)) == "2026-08-13T02:14:00Z"
    assert rb._timestamp("2026-08-13T02:14:00Z") == "2026-08-13T02:14:00Z"
    assert rb._timestamp(None) is None


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        ({"count": 30, "duration_type": "Days"}, 30),
        ({"count": 12, "duration_type": "Weeks"}, 84),
        ({"count": 6, "duration_type": "Months"}, 180),
        ({"count": 2, "duration_type": "Years"}, 730),
        ({"count": 5, "duration_type": "days"}, 5),          # case-insensitive
        ({"count": 5, "duration_type": "Invalid"}, None),    # ARM's own "unset"
        ({"count": None, "duration_type": "Days"}, None),
        ({}, None),
        (None, None),
        ({"count": "oops", "duration_type": "Days"}, None),  # must not raise
    ],
)
def test_retention_duration_days(duration, expected):
    rb = _load("backup_recovery_status")
    assert rb.retention_duration_days(duration) == expected


def test_max_retention_days_beats_prowlers_daily_only_reading():
    """A weekly-only policy keeps 84 days; Prowler's daily-only read calls it None.

    Both numbers are emitted: `daily_retention_days` for parity with a Prowler run,
    `max_retention_days` for the threshold, so a policy that genuinely retains long
    enough is not reported as having no retention.
    """
    rb = _load("backup_recovery_status")

    assert rb.daily_retention_days(VM_POLICY) == 30
    assert rb.max_retention_days(VM_POLICY) == 84  # the weekly schedule wins

    assert rb.daily_retention_days(WEEKLY_ONLY_POLICY) is None
    assert rb.max_retention_days(WEEKLY_ONLY_POLICY) == 84

    # All retention under sub_protection_policy: 6 months beats the 15-day log policy.
    assert rb.daily_retention_days(SUB_POLICY_POLICY) is None
    assert rb.max_retention_days(SUB_POLICY_POLICY) == 180

    # No retention readable at all — the finding, distinct from "0 days".
    assert rb.max_retention_days({"retention_policy": None}) is None


def test_backup_policy_record_states_the_threshold_it_was_judged_against():
    rb = _load("backup_recovery_status")
    rec = rb.backup_policy_record(VM_POLICY)
    assert rec["daily_retention_days"] == 30
    assert rec["max_retention_days"] == 84
    assert rec["retention_threshold_days"] == 30
    assert rec["meets_retention_threshold"] is True
    assert rec["schedule_policy"]["schedule_run_frequency"] == "Daily"

    short = rb.backup_policy_record(SHORT_POLICY)
    assert short["max_retention_days"] == 7
    assert short["meets_retention_threshold"] is False

    unreadable = rb.backup_policy_record({"id": "p", "name": "p", "retention_policy": None})
    assert unreadable["max_retention_days"] is None
    assert unreadable["meets_retention_threshold"] is False


def test_protected_item_record_joins_the_policy_that_governs_it():
    """ARM gives the item a policy_id and nothing else — the join carries retention."""
    rb = _load("backup_recovery_status")
    policies = {POLICY_ID: rb.backup_policy_record(VM_POLICY)}
    rec = rb.protected_item_record(PROTECTED_VM, policies)
    assert rec["backup_policy_name"] == "DailyPolicy"
    assert rec["policy_max_retention_days"] == 84
    assert rec["meets_retention_threshold"] is True
    assert rec["protected"] is True
    assert rec["last_backup_healthy"] is True
    assert rec["last_backup_time"] == "2026-08-13T02:14:00Z"
    # Coerced, not passed through: ARM omits these when never set.
    assert rec["is_scheduled_for_deferred_delete"] is False
    assert rec["is_archive_enabled"] is False

    # An item whose policy is not in the vault's policy list (deleted, or another
    # vault's) must still be emitted, just without retention.
    orphan = rb.protected_item_record({**PROTECTED_VM, "backup_policy_id": "gone"}, policies)
    assert orphan["policy_max_retention_days"] is None
    assert orphan["meets_retention_threshold"] is False

    failing = rb.protected_item_record(
        {**PROTECTED_VM, "protection_state": "ProtectionError", "last_backup_status": "Failed"},
        policies,
    )
    assert failing["protected"] is False
    assert failing["last_backup_healthy"] is False


def test_project_vault_reads_the_nested_security_and_redundancy_settings():
    rb = _load("backup_recovery_status")
    projected = rb.project_vault(
        SimpleNamespace(
            id=RS_VAULT_ID,
            name="rsv-paramify",
            location="eastus",
            type="Microsoft.RecoveryServices/vaults",
            sku=SimpleNamespace(name="RS0", tier="Standard"),
            properties=SimpleNamespace(
                provisioning_state="Succeeded",
                public_network_access="Enabled",
                backup_storage_version="V2",
                private_endpoint_state_for_backup="None",
                security_settings=SimpleNamespace(
                    soft_delete_settings=SimpleNamespace(
                        soft_delete_state="Enabled",
                        soft_delete_retention_period_in_days=14,
                    ),
                    immutability_settings=SimpleNamespace(state="Unlocked"),
                    multi_user_authorization="Enabled",
                ),
                redundancy_settings=SimpleNamespace(
                    cross_region_restore="Enabled",
                    standard_tier_storage_redundancy="GeoRedundant",
                ),
                encryption=SimpleNamespace(
                    infrastructure_encryption="Enabled",
                    key_vault_properties=SimpleNamespace(
                        key_uri="https://kv-pf-hardened.vault.azure.net/keys/backup-cmk"
                    ),
                ),
            ),
        )
    )
    assert projected["soft_delete_state"] == "Enabled"
    assert projected["soft_delete_retention_period_in_days"] == 14
    assert projected["immutability_state"] == "Unlocked"
    assert projected["cross_region_restore"] == "Enabled"
    assert projected["standard_tier_storage_redundancy"] == "GeoRedundant"
    assert projected["encryption_key_uri"].endswith("/keys/backup-cmk")
    assert projected["sku_tier"] == "Standard"

    bare = rb.project_vault(SimpleNamespace(id=RS_VAULT_ID, name="rsv"))  # must not raise
    assert bare["soft_delete_state"] is None
    assert bare["immutability_state"] is None
    assert bare["encryption_key_uri"] is None


@pytest.mark.parametrize(
    ("state", "expected"),
    [("Enabled", True), ("AlwaysON", True), ("Disabled", False), ("Invalid", False), (None, False)],
)
def test_vault_soft_delete_always_on_counts_as_enabled(state, expected):
    """"AlwaysON" is soft delete that cannot be turned off — the strongest state."""
    rb = _load("backup_recovery_status")
    rec = rb.vault_record({"id": RS_VAULT_ID, "name": "rsv", "soft_delete_state": state})
    assert rec["soft_delete_enabled"] is expected


@pytest.mark.parametrize(
    ("state", "expected"),
    [("Locked", True), ("Unlocked", True), ("Disabled", False), (None, False)],
)
def test_vault_immutability_states(state, expected):
    rb = _load("backup_recovery_status")
    rec = rb.vault_record({"id": RS_VAULT_ID, "name": "rsv", "immutability_state": state})
    assert rec["immutability_enabled"] is expected


def _vault_with(rb, policies, items, **overrides):
    policy_records = [rb.backup_policy_record(p) for p in policies]
    by_id = {p["id"]: p for p in policy_records}
    return rb.vault_record(
        {
            "id": RS_VAULT_ID,
            "name": "rsv-paramify",
            "location": "eastus",
            "soft_delete_state": "Enabled",
            "immutability_state": "Unlocked",
            "cross_region_restore": "Enabled",
            "backup_policies": policy_records,
            "backup_protected_items": [
                rb.protected_item_record(item, by_id) for item in items
            ],
            **overrides,
        }
    )


def test_backup_summary_expresses_retention_coverage_over_protected_items():
    """The headline is the fraction of PROTECTED ITEMS kept long enough.

    A vault can define a dozen policies and protect nothing; what matters for
    recovery planning is what is actually being backed up, and for how long.
    """
    rb = _load("backup_recovery_status")
    short_item = {
        **PROTECTED_VM,
        "id": ITEM_ID.replace("vm-app", "vm-scratch"),
        "name": "vm-scratch",
        "backup_policy_id": SHORT_POLICY["id"],
        "workload_type": "VM",
    }
    sql_item = {
        **PROTECTED_VM,
        "id": ITEM_ID.replace("vm-app", "sqldb"),
        "name": "sqldb",
        "backup_policy_id": SUB_POLICY_POLICY["id"],
        "workload_type": "SQLDataBase",
        "last_backup_status": "Failed",
        "protection_state": "ProtectionError",
    }
    vault = _vault_with(
        rb,
        [VM_POLICY, SHORT_POLICY, SUB_POLICY_POLICY],
        [PROTECTED_VM, short_item, sql_item],
    )
    empty_vault = rb.vault_record(
        {
            "id": RS_VAULT_ID.replace("rsv-paramify", "rsv-empty"),
            "name": "rsv-empty",
            "soft_delete_state": "Disabled",
        }
    )

    summary = rb.summarize([vault, empty_vault])
    assert summary["total_recovery_services_vaults"] == 2
    assert summary["vaults_with_protected_items"] == 1
    assert summary["vaults_without_protected_items"] == 1
    assert summary["soft_delete_enabled_vaults"] == 1
    assert summary["immutability_enabled_vaults"] == 1
    assert summary["cross_region_restore_vaults"] == 1
    assert summary["total_backup_policies"] == 3
    assert summary["policies_meeting_retention_threshold"] == 2  # not ShortPolicy
    assert summary["policies_without_readable_retention"] == 0
    assert summary["total_protected_items"] == 3
    assert summary["protected_items_with_policy"] == 3
    assert summary["protected_items_in_protected_state"] == 2
    assert summary["protected_items_with_healthy_last_backup"] == 2
    assert summary["retention_threshold_days"] == 30
    assert summary["protected_items_meeting_retention_threshold"] == 2
    assert summary["retention_threshold_percentage"] == 66
    assert summary["protected_items_by_workload_type"] == {"VM": 2, "SQLDataBase": 1}


def test_backup_summary_empty_subscription():
    rb = _load("backup_recovery_status")
    summary = rb.summarize([])
    assert summary["total_recovery_services_vaults"] == 0
    assert summary["total_protected_items"] == 0
    assert summary["retention_threshold_percentage"] == 0
    assert summary["retention_threshold_days"] == 30
    assert summary["protected_items_by_workload_type"] == {}


# --------------------------------------------------------------------------- #
# Contract wiring — every new fetcher.yaml agrees with its fetcher.py
# --------------------------------------------------------------------------- #

NEW_AZURE_FETCHERS = (
    "key_vault_configuration",
    "key_vault_key_rotation",
    "diagnostic_settings",
    "activity_log_alerts",
    "backup_recovery_status",
)


@pytest.mark.parametrize("short_name", NEW_AZURE_FETCHERS)
def test_fetcher_yaml_declares_the_ambient_credential_contract(short_name):
    import yaml

    spec = yaml.safe_load((AZURE_ROOT / short_name / "fetcher.yaml").read_text())
    assert spec["name"] == f"azure_{short_name}"
    assert spec["version"] == "0.1.0"
    assert spec["category"] == "azure"
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
    # No validators and no KSI declarations in this set.
    assert "validators" not in spec
    assert "ksis" not in spec


def test_evidence_set_reference_ids_are_unique_across_the_category():
    """A duplicate reference_id would make two fetchers get-or-create ONE evidence set."""
    import yaml

    reference_ids = {}
    for directory in sorted(AZURE_ROOT.iterdir()):
        spec_path = directory / "fetcher.yaml"
        if not spec_path.exists():
            continue
        spec = yaml.safe_load(spec_path.read_text())
        reference_id = (spec.get("evidence_set") or {}).get("reference_id")
        assert reference_id not in reference_ids, (
            f"{spec['name']} reuses {reference_id} from {reference_ids.get(reference_id)}"
        )
        reference_ids[reference_id] = spec["name"]
    assert len(reference_ids) >= len(NEW_AZURE_FETCHERS)


@pytest.mark.parametrize("short_name", NEW_AZURE_FETCHERS)
def test_fetcher_writes_evidence_and_a_status_file_when_it_cannot_resolve_a_target(
    short_name, tmp_path, monkeypatch
):
    """The failure path end-to-end for all five, with no Azure SDK involved.

    With no resolvable subscription and no credential, each fetcher must still write
    parseable evidence, exit non-zero, and leave a well-formed reason in
    $FETCHER_STATUS_FILE — otherwise `metadata.error` falls back to the tail of
    stderr and reports a harmless INFO line as the cause.
    """
    evidence_dir = tmp_path / short_name / "evidence"
    status_file = tmp_path / short_name / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    module = _load(short_name)
    # Force both auth steps to fail even where azure-* happens to be installed, so
    # this asserts the failure path rather than reaching the network.
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
    assert payload["results"]
    assert payload["summary"]

    status = json.loads(status_file.read_text())
    assert status["error"] and "\n" not in status["error"]
    common = _load_shared()
    assert status["code"] in common.STATUS_CODES
