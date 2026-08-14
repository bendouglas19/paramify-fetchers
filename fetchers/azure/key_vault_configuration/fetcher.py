#!/usr/bin/env python3
"""
KSI-SVC-04 / KSI-SVC-06 / KSI-IAM-04 / KSI-RPL-03: Azure Key Vault configuration

For each key vault in one subscription, reports which access model governs it
(Azure RBAC or the legacy vault access policies), whether it is recoverable (soft
delete + purge protection), how it is exposed to the network (public network
access, network ACL default action, private endpoint connections), and its SKU.

`enable_rbac_authorization` is the field to read first: it decides which of the
two authorization models applies, and Prowler splits its key/secret expiration
checks into RBAC and non-RBAC variants on exactly that basis
(keyvault_rbac_key_expiration_set vs keyvault_key_expiration_set_in_non_rbac). The
access policy entries are emitted alongside it — they are the model that governs
when RBAC is off, and Azure returns an empty list for an RBAC vault, so the same
field answers both readings without a second evidence set.

Field projections are ported from Prowler's
prowler/providers/azure/services/keyvault/keyvault_service.py (Apache-2.0), whose
`VaultProperties` projection this matches field for field; the SKU, network ACLs
and access policies are added here because Prowler's checks
(keyvault_access_only_through_private_endpoints, keyvault_private_endpoints) read
them from the raw model rather than through its own projection.

No key material, secret value or certificate is read: this fetcher only calls
vaults.list_by_subscription() on the MANAGEMENT plane and never opens a vault's
data plane. Access policies carry principal object ids and permission verbs, not
credentials.

Single-subscription per invocation; fanout across subscriptions happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from enum import Enum
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

logger = logging.getLogger("azure_key_vault_configuration")

# The two authorization models a vault can be under. Which one applies is decided
# by `enable_rbac_authorization`, and it changes how a reviewer must read the rest
# of the evidence: under RBAC the grants live in Azure role assignments (outside
# this evidence set), under access policies they are the `access_policies` list.
ACCESS_MODEL_RBAC = "rbac"
ACCESS_MODEL_ACCESS_POLICY = "access_policy"

# publicNetworkAccess is OMITTED by ARM when it was never restricted, and absent
# means Enabled — Prowler encodes the same default inline
# (`getattr(properties, "public_network_access", "Enabled") == "Disabled"`).
PUBLIC_NETWORK_ACCESS_DEFAULT = "Enabled"

# networkAcls.defaultAction when the whole block is absent. ARM omits networkAcls
# entirely on a vault that was never firewalled, and the service default is Allow.
NETWORK_ACL_DEFAULT_ACTION = "Allow"


# --- projection: the only code here that touches an azure-mgmt model ---

def properties_bag(model):
    """Return the model's `properties` sub-model, or the model itself.

    azure-mgmt-keyvault 14.x does NOT flatten `properties` onto the resource:
    `Vault` carries exactly {id, name, type, location, tags, properties} and
    `vault.tenant_id` is absent (verified against the installed SDK), which is why
    Prowler reads `keyvault.properties.tenant_id`. Older msrest-generated
    azure-mgmt-keyvault releases DO flatten it, and then there is no `properties`
    attribute at all. Returning the model itself in that case makes one projection
    correct on both, without the caller having to know which SDK it got.
    """
    bag = model_attr(model, "properties")
    return model if bag is None else bag


def _str_list(value) -> list:
    """Normalize a list-valued SDK field, unwrapping any `str` enum members.

    `model_attr` unwraps an enum it is handed directly, but permission verbs and
    IP rules arrive as LISTS of enums/models; an unwrapped member would put
    "KeyPermissions.GET" in the evidence on a `str()`-based renderer.
    """
    if not isinstance(value, list):
        return []
    return [item.value if isinstance(item, Enum) else item for item in value]


def _permission_verbs(permissions, *names) -> list:
    """Read one permission-verb list off an `AccessPolicyEntry.permissions` model.

    The `keys` verb list is spelled `keys_property` on azure-mgmt-keyvault 14.x:
    the model is Mapping-like, so the generator renamed the field to keep
    `.keys()` working. Reading `keys` there returns the BOUND METHOD — truthy, not
    a list, and it would render as "<bound method ...>" in the evidence. So the
    candidate spellings are tried in order and anything that is not a list is
    discarded rather than trusted.
    """
    for name in names:
        value = model_attr(permissions, name)
        if isinstance(value, list):
            return _str_list(value)
    return []


def project_access_policy(entry) -> dict:
    """Read one `AccessPolicyEntry` into a flat dict — principals and verbs only."""
    permissions = model_attr(entry, "permissions")
    return {
        "tenant_id": model_attr(entry, "tenant_id"),
        "object_id": model_attr(entry, "object_id"),
        "application_id": model_attr(entry, "application_id"),
        "permissions": {
            "keys": _permission_verbs(permissions, "keys_property", "keys"),
            "secrets": _permission_verbs(permissions, "secrets"),
            "certificates": _permission_verbs(permissions, "certificates"),
            "storage": _permission_verbs(permissions, "storage"),
        },
    }


def project_private_endpoint_connection(connection) -> dict:
    """Read one `PrivateEndpointConnectionItem` into a flat dict."""
    properties = properties_bag(connection)
    state = model_attr(properties, "private_link_service_connection_state")
    return {
        "id": model_attr(connection, "id"),
        "provisioning_state": model_attr(properties, "provisioning_state"),
        "connection_status": model_attr(state, "status"),
    }


def project_vault(vault) -> dict:
    """Read a `Vault` model's attributes into a flat snake_case dict.

    Values are the SDK's own, un-defaulted: `None` means "the API did not return
    this field", and `vault_record()` decides how an absence reads. Every nested
    model (`sku`, `network_acls`, an access policy's `permissions`) is routinely
    absent, hence `model_attr`'s None-tolerance at every hop.
    """
    properties = properties_bag(vault)
    sku = model_attr(properties, "sku")
    network_acls = model_attr(properties, "network_acls")

    return {
        "id": model_attr(vault, "id"),
        "name": model_attr(vault, "name"),
        "location": model_attr(vault, "location"),
        "type": model_attr(vault, "type"),
        # --- authorization model (decides how the rest reads) ---
        "tenant_id": model_attr(properties, "tenant_id"),
        "enable_rbac_authorization": model_attr(properties, "enable_rbac_authorization"),
        "access_policies": [
            project_access_policy(entry)
            for entry in (model_attr(properties, "access_policies") or [])
        ],
        # --- recoverability ---
        "enable_soft_delete": model_attr(properties, "enable_soft_delete"),
        "enable_purge_protection": model_attr(properties, "enable_purge_protection"),
        "soft_delete_retention_in_days": model_attr(properties, "soft_delete_retention_in_days"),
        # --- network exposure ---
        "public_network_access": model_attr(properties, "public_network_access"),
        "network_acls": {
            "bypass": model_attr(network_acls, "bypass"),
            "default_action": model_attr(network_acls, "default_action"),
            "ip_rules": [
                model_attr(rule, "value") for rule in (model_attr(network_acls, "ip_rules") or [])
            ],
            "virtual_network_rules": [
                model_attr(rule, "id")
                for rule in (model_attr(network_acls, "virtual_network_rules") or [])
            ],
        },
        "private_endpoint_connections": [
            project_private_endpoint_connection(connection)
            for connection in (model_attr(properties, "private_endpoint_connections") or [])
        ],
        # --- platform integration + SKU ---
        "sku": {
            "family": model_attr(sku, "family"),
            "name": model_attr(sku, "name"),
        },
        "vault_uri": model_attr(properties, "vault_uri"),
        "enabled_for_deployment": model_attr(properties, "enabled_for_deployment"),
        "enabled_for_disk_encryption": model_attr(properties, "enabled_for_disk_encryption"),
        "enabled_for_template_deployment": model_attr(
            properties, "enabled_for_template_deployment"
        ),
        "provisioning_state": model_attr(properties, "provisioning_state"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def vault_record(vault: dict) -> dict:
    """Normalize one projected vault into an evidence record.

    Optional booleans are COERCED, not passed through: ARM omits
    `enablePurgeProtection` / `enableRbacAuthorization` entirely when they were
    never turned on, so the raw value is None rather than False, and a validator
    regex asserting `false` would not match `null`. Absent means disabled here —
    there is no third state — and Prowler reads the same absences the same way
    (`getattr(properties, "enable_purge_protection", False)`).
    """
    resource_id = vault.get("id")
    network_acls = vault.get("network_acls") or {}

    rbac = bool(vault.get("enable_rbac_authorization") or False)
    soft_delete = bool(vault.get("enable_soft_delete") or False)
    purge_protection = bool(vault.get("enable_purge_protection") or False)
    public_access = vault.get("public_network_access") or PUBLIC_NETWORK_ACCESS_DEFAULT
    default_action = network_acls.get("default_action") or NETWORK_ACL_DEFAULT_ACTION
    policies = vault.get("access_policies") or []

    return {
        "id": resource_id,
        "name": vault.get("name"),
        "location": vault.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "tenant_id": vault.get("tenant_id"),
        # --- authorization model ---
        "rbac_authorization_enabled": rbac,
        # Derived so a reader never has to know that "RBAC on" makes the
        # access_policies list inapplicable rather than merely empty.
        "access_model": ACCESS_MODEL_RBAC if rbac else ACCESS_MODEL_ACCESS_POLICY,
        "access_policies": policies,
        "access_policy_count": len(policies),
        # --- recoverability (Prowler's keyvault_recoverable is the AND of the two) ---
        "soft_delete_enabled": soft_delete,
        "purge_protection_enabled": purge_protection,
        "recoverable": soft_delete and purge_protection,
        "soft_delete_retention_in_days": vault.get("soft_delete_retention_in_days"),
        # --- network exposure ---
        "public_network_access": public_access,
        "public_network_access_disabled": str(public_access).lower() == "disabled",
        "network_acls": {
            "bypass": network_acls.get("bypass") or "AzureServices",
            "default_action": default_action,
            "ip_rules": network_acls.get("ip_rules") or [],
            "virtual_network_rules": network_acls.get("virtual_network_rules") or [],
        },
        "network_acl_default_deny": str(default_action).lower() == "deny",
        "private_endpoint_connections": vault.get("private_endpoint_connections") or [],
        # --- platform integration + SKU ---
        "sku": vault.get("sku") or {"family": None, "name": None},
        "vault_uri": vault.get("vault_uri"),
        "enabled_for_deployment": bool(vault.get("enabled_for_deployment") or False),
        "enabled_for_disk_encryption": bool(vault.get("enabled_for_disk_encryption") or False),
        "enabled_for_template_deployment": bool(
            vault.get("enabled_for_template_deployment") or False
        ),
        "provisioning_state": vault.get("provisioning_state"),
    }


def summarize(vaults: list[dict]) -> dict:
    """RBAC adoption and recoverability are the headlines.

    Both are the fields a reviewer is actually asking about: which authorization
    model is in force, and whether a deleted vault (or key) can be recovered.
    """
    total = len(vaults)
    rbac = sum(1 for v in vaults if v["rbac_authorization_enabled"])
    recoverable = sum(1 for v in vaults if v["recoverable"])
    return {
        "total_key_vaults": total,
        "rbac_authorization_vaults": rbac,
        "access_policy_vaults": total - rbac,
        "rbac_authorization_percentage": coverage_percentage(rbac, total),
        "soft_delete_vaults": sum(1 for v in vaults if v["soft_delete_enabled"]),
        "purge_protection_vaults": sum(1 for v in vaults if v["purge_protection_enabled"]),
        "recoverable_vaults": recoverable,
        "recoverable_percentage": coverage_percentage(recoverable, total),
        "public_network_access_disabled_vaults": sum(
            1 for v in vaults if v["public_network_access_disabled"]
        ),
        "network_acl_default_deny_vaults": sum(1 for v in vaults if v["network_acl_default_deny"]),
        "private_endpoint_vaults": sum(1 for v in vaults if v["private_endpoint_connections"]),
        "premium_sku_vaults": sum(
            1 for v in vaults if str((v["sku"] or {}).get("name") or "").lower() == "premium"
        ),
        "total_access_policies": sum(v["access_policy_count"] for v in vaults),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_key_vaults(subscription_id, cred, collector: Collector) -> list[dict]:
    """One vaults.list_by_subscription() call — the whole projection is in it."""
    from azure.mgmt.keyvault import KeyVaultManagementClient

    def _client():
        return KeyVaultManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("keyvault.KeyVaultManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [vault_record(project_vault(v)) for v in client.vaults.list_by_subscription()]

    vaults = collector.guard("keyvault.vaults.list_by_subscription", _list, default=[])
    return sorted(vaults, key=lambda r: r.get("id") or "")


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

    vaults: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-vault result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.KeyVault"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.KeyVault is not registered on subscription %s — no key "
                "vaults in use; reporting status not_registered",
                subscription_id,
            )
        vaults = collect_key_vaults(subscription_id, cred, collector)
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
            "key_vaults": vaults,
            "provider_registration_status": registration,
        },
        summary={**summarize(vaults), "provider_registration_status": registration},
    )

    filename = (
        f"azure_key_vault_configuration_"
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
