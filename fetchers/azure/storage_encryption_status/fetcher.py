#!/usr/bin/env python3
"""
KSI-SVC-03 / KSI-SVC-02 / KSI-SVC-06 / KSI-RPL-03: Azure Storage encryption at rest

For each storage account in one subscription, reports whether the account's
encryption key comes from Key Vault (customer-managed, CMK) or from the platform
(Microsoft-managed), plus the transit / network / key-rotation / soft-delete
posture around it. Azure Storage is ALWAYS encrypted at rest, so "encrypted:
true" can never fail — the fact that varies is `encryption.key_source` (CMK vs
Microsoft.Storage) and whether infrastructure (double) encryption is on.

Field projections are ported verbatim from Prowler's
prowler/providers/azure/services/storage/storage_service.py (Apache-2.0), which
reads the same azure-mgmt-storage SDK, so the attribute paths transfer directly.

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
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    dig,
    failure_reason,
    first,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    to_dict,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_storage_encryption_status")

# encryption.key_source. "Microsoft.Keyvault" means the account's encryption key
# is a customer-managed key held in Key Vault; "Microsoft.Storage" is the
# platform-managed default.
KEY_SOURCE_KEYVAULT = "microsoft.keyvault"

# Benign, per-account, expected: the account kind simply has no Blob (or File)
# endpoint (e.g. a FileStorage or BlockBlobStorage account). Prowler string-matches
# these and continues; they are NOT collection failures and must not push the
# fetcher to exit 1.
BENIGN_UNSUPPORTED_SERVICE = (
    "Blob is not supported for the account.",
    "File is not supported for the account.",
)


# --- pure transforms (operate on as_dict()-shaped dicts; unit-tested from fixtures) ---

def _prop(obj: dict, *names: str):
    """Read a field that azure-mgmt flattens out of the wire `properties` bag.

    `Model.as_dict()` hoists `properties.*` to top-level snake_case attributes;
    `serialize()` / raw REST keep them nested under "properties" in camelCase.
    Look top-level first, then inside "properties", so either shape reads.
    """
    val = first(obj, *names)
    if val is not None:
        return val
    nested = obj.get("properties") if isinstance(obj, dict) else None
    return first(nested, *names)


def _retention_policy(policy: dict | None) -> dict:
    """Normalize a {enabled, days} soft-delete policy, defaulting to off/0.

    Mirrors Prowler's `DeleteRetentionPolicy(enabled=... or False, days=... or 0)`:
    an absent or explicitly-null policy reads as disabled rather than unknown,
    because the API omits the block when the feature was never turned on.
    """
    policy = policy if isinstance(policy, dict) else {}
    return {
        "enabled": bool(first(policy, "enabled") or False),
        "days": int(first(policy, "days") or 0),
    }


def _semicolon_list(value) -> list:
    """Split a ";"-delimited SMB settings string ("AES-128-GCM;AES-256-GCM")."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    return str(value).rstrip(";").split(";")


def account_record(account: dict) -> dict:
    """Normalize one storage account into an evidence record.

    Every field below is Prowler's projection, with Prowler's defaults preserved:
    the API omits `allow_cross_tenant_replication` / `allow_shared_key_access` /
    `network_rule_set.bypass` / `network_rule_set.default_action` when they sit at
    their (permissive) service defaults, so absent must read as that default, not
    as None.
    """
    resource_id = first(account, "id")
    encryption = _prop(account, "encryption") or {}
    network_rule_set = _prop(account, "network_rule_set", "networkAcls") or {}
    key_policy = _prop(account, "key_policy", "keyPolicy") or {}
    sku = first(account, "sku") or {}

    key_source = first(encryption, "key_source", "keySource")
    key_expiration = first(key_policy, "key_expiration_period_in_days", "keyExpirationPeriodInDays")

    cross_tenant = _prop(account, "allow_cross_tenant_replication", "allowCrossTenantReplication")
    shared_key = _prop(account, "allow_shared_key_access", "allowSharedKeyAccess")
    entra_auth = _prop(account, "default_to_o_auth_authentication", "defaultToOAuthAuthentication")

    return {
        "id": resource_id,
        "name": first(account, "name"),
        "location": first(account, "location"),
        "resource_group": resource_group_from_id(resource_id),
        # --- encryption at rest (the evidence that actually varies) ---
        "encryption_type": key_source,
        "customer_managed_key": str(key_source or "").lower() == KEY_SOURCE_KEYVAULT,
        "infrastructure_encryption": first(
            encryption, "require_infrastructure_encryption", "requireInfrastructureEncryption"
        ),
        # --- encryption in transit ---
        "enable_https_traffic_only": bool(
            _prop(account, "enable_https_traffic_only", "supportsHttpsTrafficOnly") or False
        ),
        "minimum_tls_version": _prop(account, "minimum_tls_version", "minimumTlsVersion"),
        # --- network exposure ---
        "allow_blob_public_access": bool(
            _prop(account, "allow_blob_public_access", "allowBlobPublicAccess") or False
        ),
        "public_network_access": _prop(account, "public_network_access", "publicNetworkAccess"),
        "network_rule_set": {
            "bypass": first(network_rule_set, "bypass") or "AzureServices",
            "default_action": first(network_rule_set, "default_action", "defaultAction") or "Allow",
        },
        "private_endpoint_connections": [
            {
                "id": first(pec, "id"),
                "name": first(pec, "name"),
                "type": first(pec, "type"),
            }
            for pec in (
                _prop(account, "private_endpoint_connections", "privateEndpointConnections") or []
            )
        ],
        # --- key + identity management ---
        "key_expiration_period_in_days": int(key_expiration) if key_expiration is not None else None,
        "allow_shared_key_access": True if shared_key is None else bool(shared_key),
        "default_to_entra_authorization": False if entra_auth is None else bool(entra_auth),
        # --- durability / replication ---
        "replication_settings": first(sku, "name"),
        "allow_cross_tenant_replication": True if cross_tenant is None else bool(cross_tenant),
        # Filled in by the blob/file service enrichment; None means "not collected
        # for this account" (an account kind without that endpoint).
        "blob_properties": None,
        "file_service_properties": None,
    }


def blob_properties_record(properties: dict) -> dict:
    """Normalize blob_services.get_service_properties() — versioning + soft delete."""
    return {
        "id": first(properties, "id"),
        "name": first(properties, "name"),
        "type": first(properties, "type"),
        "default_service_version": _prop(
            properties, "default_service_version", "defaultServiceVersion"
        ),
        "container_delete_retention_policy": _retention_policy(
            _prop(properties, "container_delete_retention_policy", "containerDeleteRetentionPolicy")
        ),
        "versioning_enabled": bool(
            _prop(properties, "is_versioning_enabled", "isVersioningEnabled") or False
        ),
    }


def file_service_properties_record(properties: dict) -> dict:
    """Normalize file_services.get_service_properties() — share soft delete + SMB."""
    smb = (
        dig(_prop(properties, "protocol_settings", "protocolSettings") or {}, "smb")
        or {}
    )
    return {
        "id": first(properties, "id"),
        "name": first(properties, "name"),
        "type": first(properties, "type"),
        "share_delete_retention_policy": _retention_policy(
            _prop(properties, "share_delete_retention_policy", "shareDeleteRetentionPolicy")
        ),
        "smb_protocol_settings": {
            "channel_encryption": _semicolon_list(first(smb, "channel_encryption", "channelEncryption")),
            "supported_versions": _semicolon_list(first(smb, "versions")),
        },
    }


def summarize(accounts: list[dict]) -> dict:
    """CMK coverage is the headline, not an encrypted/total percentage.

    Azure Storage encrypts at rest unconditionally, so a generic "encrypted"
    percentage would be a constant 100 and prove nothing. What varies — and what a
    reviewer needs — is how many accounts hold a customer-managed key.
    """
    cmk = sum(1 for a in accounts if a["customer_managed_key"])
    total = len(accounts)
    return {
        "total_storage_accounts": total,
        "customer_managed_key_storage": cmk,
        "platform_managed_key_storage": total - cmk,
        "cmk_percentage": coverage_percentage(cmk, total),
        "infrastructure_encryption_accounts": sum(
            1 for a in accounts if a["infrastructure_encryption"]
        ),
        "https_only_accounts": sum(1 for a in accounts if a["enable_https_traffic_only"]),
        "minimum_tls_1_2_accounts": sum(
            1 for a in accounts if (a["minimum_tls_version"] or "") in ("TLS1_2", "TLS1_3")
        ),
        "public_blob_access_accounts": sum(1 for a in accounts if a["allow_blob_public_access"]),
        "shared_key_access_accounts": sum(1 for a in accounts if a["allow_shared_key_access"]),
        "private_endpoint_accounts": sum(
            1 for a in accounts if a["private_endpoint_connections"]
        ),
        "key_expiration_policy_accounts": sum(
            1 for a in accounts if a["key_expiration_period_in_days"] is not None
        ),
        "blob_versioning_accounts": sum(
            1 for a in accounts if dig(a, "blob_properties", "versioning_enabled")
        ),
        "container_soft_delete_accounts": sum(
            1
            for a in accounts
            if dig(a, "blob_properties", "container_delete_retention_policy", "enabled")
        ),
        "share_soft_delete_accounts": sum(
            1
            for a in accounts
            if dig(a, "file_service_properties", "share_delete_retention_policy", "enabled")
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def _is_benign_unsupported(exc: BaseException) -> bool:
    message = str(exc).strip()
    return any(marker in message for marker in BENIGN_UNSUPPORTED_SERVICE)


def collect_storage_accounts(subscription_id, cred, collector: Collector) -> list[dict]:
    """One storage_accounts.list() plus a blob/file service GET per account.

    The list response already carries the whole encryption / network / key-policy
    projection; only versioning and the soft-delete policies need the per-account
    service-properties GETs.
    """
    from azure.mgmt.storage import StorageManagementClient

    def _client():
        return StorageManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("storage.StorageManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [account_record(to_dict(a)) for a in client.storage_accounts.list()]

    accounts = collector.guard("storage.storage_accounts.list", _list, default=[])

    for account in accounts:
        group, name = account.get("resource_group"), account.get("name")
        if not group or not name:
            collector.record(
                "storage.blob_services.get_service_properties",
                RuntimeError(f"storage account {name!r} has no resource group in its id"),
            )
            continue
        account["blob_properties"] = _service_properties(
            collector,
            "storage.blob_services.get_service_properties",
            name,
            lambda: blob_properties_record(
                to_dict(client.blob_services.get_service_properties(group, name))
            ),
        )
        account["file_service_properties"] = _service_properties(
            collector,
            "storage.file_services.get_service_properties",
            name,
            lambda: file_service_properties_record(
                to_dict(client.file_services.get_service_properties(group, name))
            ),
        )

    return sorted(accounts, key=lambda r: r.get("id") or "")


def _service_properties(collector: Collector, operation: str, account_name: str, fn):
    """Run one service-properties GET, tolerating the benign "not supported" error.

    Not routed through Collector.guard because one specific message must NOT be
    recorded as an API failure: an account kind with no Blob/File endpoint answers
    "Blob is not supported for the account.", which is expected and would
    otherwise fail the whole run. Prowler skips it the same way.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if _is_benign_unsupported(exc):
            logger.warning(
                "%s: skipping %s — %s", operation, account_name, str(exc).strip().splitlines()[0]
            )
            return None
        collector.record(f"{operation} ({account_name})", exc)
        return None


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

    accounts: list[dict] = []
    if subscription_id and cred is not None:
        accounts = collect_storage_accounts(subscription_id, cred, collector)
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
        results={"storage_accounts": accounts},
        summary=summarize(accounts),
    )

    filename = (
        f"azure_storage_encryption_status_"
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
