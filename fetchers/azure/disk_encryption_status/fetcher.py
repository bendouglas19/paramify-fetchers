#!/usr/bin/env python3
"""
Azure managed disk encryption at rest — customer-managed keys and Azure Disk Encryption

For every managed disk in one subscription, reports which key encrypts it: the
platform key (Microsoft-managed, the default), a customer-managed key held in a
disk encryption set, or both (double encryption). Managed disks are ALWAYS
encrypted at rest, so "encrypted: true" can never fail — the fact that varies is
`encryption.type` and, for guest-level encryption, whether Azure Disk Encryption
(dm-crypt / BitLocker) is switched on via `encryption_settings_collection`.

Attached and unattached disks are reported and summarized SEPARATELY. That split
is why this is its own evidence set: an unattached disk still holds the data of
whatever VM it was detached from, nothing is watching it, and Prowler makes it a
distinct finding for exactly that reason
(vm_ensure_attached_disks_encrypted_with_cmk /
vm_ensure_unattached_disks_encrypted_with_cmk). Every record carries `attached`
plus the VM ids in `vms_attached`, and the summary breaks CMK coverage out three
ways: all disks, attached only, unattached only.

Field projections are ported from Prowler's
prowler/providers/azure/services/vm/vm_service.py `_get_disks()` (Apache-2.0),
which reads the same azure-mgmt-compute SDK, so the attribute paths transfer
directly. The CMK reading is the two checks named above, verbatim: a disk counts
as customer-managed when `encryption.type` is set and is not
"EncryptionAtRestWithPlatformKey".

Single-subscription per invocation; fanout across subscriptions happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_disk_encryption_status")

# encryption.type (the EncryptionType enum). "EncryptionAtRestWithPlatformKey" is
# the Microsoft-managed default; the other two involve a customer-managed key held
# in a disk encryption set, and "…PlatformAndCustomerKeys" is double encryption.
ENCRYPTION_PLATFORM_KEY = "encryptionatrestwithplatformkey"
ENCRYPTION_DOUBLE = "EncryptionAtRestWithPlatformAndCustomerKeys"

# network_access_policy values that keep the disk's export path off the Internet.
# "AllowAll" is the permissive default; a SAS URL can then be minted for the disk.
RESTRICTED_NETWORK_ACCESS_POLICIES = ("DenyAll", "AllowPrivate")


# --- projection: the only code here that touches an azure-mgmt model ---

def project_encryption_settings(element) -> dict:
    """Read one `EncryptionSettingsElement` — an Azure Disk Encryption key pair.

    Only the Key Vault *identity* is projected, never `disk_encryption_key.secret_url`
    or `key_encryption_key.key_url`. Those URLs address the BitLocker/dm-crypt key
    material itself; the control-relevant fact is which vault holds it and whether
    the volume key is itself wrapped by a KEK, so the URLs are deliberately left
    out of the evidence file.
    """
    disk_key = model_attr(element, "disk_encryption_key")
    key_encryption_key = model_attr(element, "key_encryption_key")
    return {
        "disk_encryption_key_vault_id": model_attr(
            model_attr(disk_key, "source_vault"), "id"
        ),
        "key_encryption_key_vault_id": model_attr(
            model_attr(key_encryption_key, "source_vault"), "id"
        ),
        "has_key_encryption_key": key_encryption_key is not None,
    }


def project_disk(disk) -> dict:
    """Read a `Disk` model's attributes into a flat snake_case dict.

    Attribute access is stable across the azure-mgmt generator styles; `as_dict()`
    is not (azure-mgmt-compute 38.x is on the `_model_base` runtime, whose
    `as_dict()` emits the camelCase wire shape with everything but id/name/location/
    sku/managedBy nested under "properties"). Confining the SDK to this one function
    keeps every transform below pure dict-in/dict-out — and testable with no azure-*
    package installed.

    `model_attr`'s enum unwrapping is load-bearing here: `encryption.type` is an
    `EncryptionType` member, and `str()` on one renders
    "EncryptionType.ENCRYPTION_AT_REST_WITH_CUSTOMER_KEY" rather than the wire value
    — which would invert the CMK comparison below and put an enum repr in the
    evidence. `os_type`, `disk_state`, `sku.name`, `network_access_policy` and
    `public_network_access` are all enums too.
    """
    encryption = model_attr(disk, "encryption")
    settings_collection = model_attr(disk, "encryption_settings_collection")
    sku = model_attr(disk, "sku")

    return {
        "id": model_attr(disk, "id"),
        "name": model_attr(disk, "name"),
        "location": model_attr(disk, "location"),
        # --- encryption at rest (platform key vs CMK vs double) ---
        "encryption_type": model_attr(encryption, "type"),
        "disk_encryption_set_id": model_attr(encryption, "disk_encryption_set_id"),
        # --- guest-level encryption: Azure Disk Encryption (dm-crypt / BitLocker) ---
        "encryption_settings_collection": {
            "enabled": model_attr(settings_collection, "enabled"),
            "encryption_settings_version": model_attr(
                settings_collection, "encryption_settings_version"
            ),
            "encryption_settings": [
                project_encryption_settings(element)
                for element in (model_attr(settings_collection, "encryption_settings") or [])
            ],
        },
        # --- what the disk is and who holds it ---
        "os_type": model_attr(disk, "os_type"),
        "disk_size_gb": model_attr(disk, "disk_size_gb"),
        "disk_state": model_attr(disk, "disk_state"),
        "sku_name": model_attr(sku, "name"),
        # Prowler's two sources for "which VMs is this attached to": managed_by is
        # the single owner, managed_by_extended the shared-disk owner list.
        "managed_by": model_attr(disk, "managed_by"),
        "managed_by_extended": model_attr(disk, "managed_by_extended"),
        # --- export exposure ---
        "network_access_policy": model_attr(disk, "network_access_policy"),
        "public_network_access": model_attr(disk, "public_network_access"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def is_customer_managed(encryption_type) -> bool:
    """Prowler's CMK condition, verbatim (as its inverse).

    vm_ensure_attached_disks_encrypted_with_cmk fails when `not encryption_type or
    encryption_type == "EncryptionAtRestWithPlatformKey"`, so a disk is
    customer-managed exactly when the type is present and is something else. Written
    as "not the platform key" rather than an allow-list of the two CMK values so a
    future encryption type is not silently reported as platform-managed.
    """
    if not encryption_type:
        return False
    return str(encryption_type).lower() != ENCRYPTION_PLATFORM_KEY


def encryption_settings_record(settings: dict) -> dict:
    """Normalize one projected Azure Disk Encryption key pair."""
    return {
        "disk_encryption_key_vault_id": settings.get("disk_encryption_key_vault_id"),
        "key_encryption_key_vault_id": settings.get("key_encryption_key_vault_id"),
        "has_key_encryption_key": bool(settings.get("has_key_encryption_key") or False),
    }


def disk_record(disk: dict) -> dict:
    """Normalize one projected managed disk into an evidence record.

    Takes `project_disk()`'s output. `vms_attached` is Prowler's construction:
    managed_by first, then any managed_by_extended entries (a shared disk attached
    to several VMs). `attached` is what the two Prowler checks branch on, so it is
    materialized rather than left for a reader to infer from an empty list.

    Optional booleans are coerced with `bool(x or False)`: Azure omits a false-y
    field rather than returning `false`, and a validator regex asserting `false`
    would not match `null`.
    """
    resource_id = disk.get("id")
    settings_collection = disk.get("encryption_settings_collection") or {}

    vms_attached = []
    if disk.get("managed_by"):
        vms_attached.append(disk["managed_by"])
    vms_attached.extend(disk.get("managed_by_extended") or [])

    encryption_type = disk.get("encryption_type")
    network_access_policy = disk.get("network_access_policy")

    return {
        "id": resource_id,
        "name": disk.get("name"),
        "location": disk.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        # --- encryption at rest (the evidence that actually varies) ---
        "encryption_type": encryption_type,
        "customer_managed_key": is_customer_managed(encryption_type),
        "double_encryption": str(encryption_type or "") == ENCRYPTION_DOUBLE,
        "disk_encryption_set_id": disk.get("disk_encryption_set_id"),
        # --- guest-level encryption (ADE / BitLocker) ---
        "azure_disk_encryption_enabled": bool(settings_collection.get("enabled") or False),
        "encryption_settings_version": settings_collection.get("encryption_settings_version"),
        "encryption_settings": [
            encryption_settings_record(element)
            for element in (settings_collection.get("encryption_settings") or [])
        ],
        # --- attachment (the reason this evidence set exists in two halves) ---
        "attached": bool(vms_attached),
        "vms_attached": vms_attached,
        "disk_state": disk.get("disk_state"),
        # --- what the disk is ---
        "os_type": disk.get("os_type"),
        "disk_size_gb": disk.get("disk_size_gb"),
        "sku_name": disk.get("sku_name"),
        # --- export exposure ---
        "network_access_policy": network_access_policy,
        "public_network_access": disk.get("public_network_access"),
        "network_access_restricted": network_access_policy in RESTRICTED_NETWORK_ACCESS_POLICIES,
    }


def _cmk_coverage(disks: list[dict], prefix: str = "") -> dict:
    """CMK counts + percentage for one slice of the disks, in storage's summary shape."""
    total = len(disks)
    cmk = sum(1 for d in disks if d["customer_managed_key"])
    return {
        f"{prefix}total_disks": total,
        f"{prefix}customer_managed_key_disks": cmk,
        f"{prefix}platform_managed_key_disks": total - cmk,
        f"{prefix}cmk_percentage": coverage_percentage(cmk, total),
    }


def summarize(disks: list[dict]) -> dict:
    """CMK coverage is the headline, computed three ways: all / attached / unattached.

    Managed disks are encrypted at rest unconditionally, so a generic "encrypted"
    percentage would be a constant 100 and prove nothing (the same reason
    storage_encryption_status reports CMK coverage instead). The attached /
    unattached split mirrors Prowler's two separate checks: an orphaned disk under a
    platform key is the finding operators most often miss.
    """
    attached = [d for d in disks if d["attached"]]
    unattached = [d for d in disks if not d["attached"]]
    return {
        **_cmk_coverage(disks),
        **_cmk_coverage(attached, "attached_"),
        **_cmk_coverage(unattached, "unattached_"),
        "double_encryption_disks": sum(1 for d in disks if d["double_encryption"]),
        "disk_encryption_set_disks": sum(1 for d in disks if d["disk_encryption_set_id"]),
        "azure_disk_encryption_disks": sum(
            1 for d in disks if d["azure_disk_encryption_enabled"]
        ),
        "network_access_restricted_disks": sum(
            1 for d in disks if d["network_access_restricted"]
        ),
        "os_disks": sum(1 for d in disks if d["os_type"]),
        "data_disks": sum(1 for d in disks if not d["os_type"]),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_disks(subscription_id, cred, collector: Collector) -> list[dict]:
    """One subscription-wide disks.list().

    The list response carries the whole encryption / attachment / export projection,
    so no per-disk GET is needed. `disks.list()` is the subscription-scoped variant
    (vs `list_by_resource_group`) and returns an ItemPaged, so the SDK follows
    nextLink itself.

    The SDK import lives inside the guarded factory so a missing azure-mgmt-compute
    is recorded as a failure (classified `internal_error`) and still writes evidence
    plus a status file, rather than aborting the process with a traceback.
    """

    def _client():
        from azure.mgmt.compute import ComputeManagementClient  # lazy

        return ComputeManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("compute.ComputeManagementClient (init)", _client)
    if client is None:
        return []

    disks = collector.guard(
        "compute.disks.list",
        lambda: [disk_record(project_disk(d)) for d in client.disks.list()],
        default=[],
    )
    return sorted(disks, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which
    # buries this fetcher's own lines and would dominate the runner's stderr tail.
    # Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    disks: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-disk result is legible: Azure returns
        # an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Compute"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Compute is not registered on subscription %s — no managed "
                "disks in use; reporting status not_registered",
                subscription_id,
            )
        disks = collect_disks(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "disks": disks,
            "provider_registration_status": registration,
        },
        summary={**summarize(disks), "provider_registration_status": registration},
    )

    filename = (
        f"azure_disk_encryption_status_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        logger.error(
            "Encountered %d Azure API failure(s) during collection", len(collector.failures)
        )
        write_status(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
