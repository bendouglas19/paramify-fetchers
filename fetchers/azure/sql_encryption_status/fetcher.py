#!/usr/bin/env python3
"""
Azure SQL transparent data encryption (TDE) and its key source

For every Azure SQL logical server in one subscription, reports the server's
encryption protector — whether TDE is protected by a customer-managed key held in
Key Vault (`server_key_type: AzureKeyVault`) or by the platform's service-managed
key — and the per-database TDE state underneath it.

TDE is ON BY DEFAULT for every database created since 2017, so a generic
"encrypted / total" percentage would sit at a constant 100 and prove nothing. The
fact that actually varies is the KEY SOURCE, so the summary tracks CMK coverage
across servers, exactly as fetchers/azure/storage_encryption_status does for
storage accounts. Per-database TDE state is still collected, because a database
restored from an older backup or explicitly turned off can be unencrypted under
an otherwise CMK-protected server.

Field projections are ported from Prowler's
prowler/providers/azure/services/sqlserver/sqlserver_service.py (Apache-2.0),
which reads the same azure-mgmt-sql SDK. Two divergences from Prowler, both
verified against azure-mgmt-sql 4.0.0:

- Prowler reads the TDE state as `.status`; on 4.0.0 the field is `.state`
  (`LogicalDatabaseTransparentDataEncryption.properties.state`) and `.status` does
  not exist. Reading Prowler's spelling here would report every database's TDE as
  unknown.
- Prowler calls `transparent_data_encryptions.get(...,
  transparent_data_encryption_name="current")`; 4.0.0 renamed that parameter to
  `tde_name`, so the name is passed POSITIONALLY below and works on either.

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

logger = logging.getLogger("azure_sql_encryption_status")

# EncryptionProtector.server_key_type. "AzureKeyVault" means TDE is protected by a
# customer-managed key in Key Vault (BYOK); "ServiceManaged" is the platform-managed
# default. This is the one encryption field on Azure SQL that genuinely varies.
SERVER_KEY_TYPE_CMK = "azurekeyvault"

# TransparentDataEncryptionState. Azure returns "Enabled" / "Disabled".
TDE_ENABLED = "enabled"

# `master` exists on every logical server, is created and managed by Azure, and its
# TDE state is not customer-controlled. Prowler excludes it from both TDE checks, so
# the summary's user-database counts exclude it too — it stays in the evidence with
# `is_system_database: true` so a reader can see it was accounted for, not dropped.
SYSTEM_DATABASES = ("master",)


# --- projection: the only code here that touches an azure-mgmt model ---

def project_sql_server(server) -> dict:
    """Read a `Server` model's attributes into a flat snake_case dict.

    azure-mgmt-sql 4.0.0 is on the newer `_model_base` generator, which keeps a
    nested `properties` model but also forwards the flattened snake_case names to
    it — verified for this exact version, so `server.minimal_tls_version` resolves
    to `properties.minimalTlsVersion`. `as_dict()` would instead emit the camelCase
    wire shape nested under "properties", which is why nothing here uses it.
    """
    return {
        "id": model_attr(server, "id"),
        "name": model_attr(server, "name"),
        "type": model_attr(server, "type"),
        "location": model_attr(server, "location"),
        "version": model_attr(server, "version"),
        "state": model_attr(server, "state"),
        "fully_qualified_domain_name": model_attr(server, "fully_qualified_domain_name"),
    }


def project_encryption_protector(protector) -> dict:
    """Read an `EncryptionProtector` model into a flat dict — the CMK evidence.

    `server_key_name` is the Key Vault key the server is bound to (or
    "ServiceManaged" when it is not bound to one); `server_key_type` is the field
    the CMK determination is made from.
    """
    return {
        "id": model_attr(protector, "id"),
        "name": model_attr(protector, "name"),
        "type": model_attr(protector, "type"),
        "kind": model_attr(protector, "kind"),
        "server_key_name": model_attr(protector, "server_key_name"),
        "server_key_type": model_attr(protector, "server_key_type"),
        "uri": model_attr(protector, "uri"),
        "auto_rotation_enabled": model_attr(protector, "auto_rotation_enabled"),
    }


def project_database(database) -> dict:
    """Read a `Database` model into a flat dict."""
    return {
        "id": model_attr(database, "id"),
        "name": model_attr(database, "name"),
        "type": model_attr(database, "type"),
        "location": model_attr(database, "location"),
        "managed_by": model_attr(database, "managed_by"),
        "status": model_attr(database, "status"),
    }


def project_transparent_data_encryption(tde) -> dict:
    """Read a `LogicalDatabaseTransparentDataEncryption` model into a flat dict.

    `state` — NOT Prowler's `status`, which does not exist on azure-mgmt-sql 4.0.0
    (see the module docstring). The value is a `TransparentDataEncryptionState`
    enum; `model_attr` unwraps it to "Enabled" / "Disabled" so the comparison below
    is against a real wire string and not "TransparentDataEncryptionState.ENABLED".
    """
    return {
        "id": model_attr(tde, "id"),
        "name": model_attr(tde, "name"),
        "type": model_attr(tde, "type"),
        "state": model_attr(tde, "state"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def encryption_protector_record(protector: dict | None) -> dict | None:
    """Normalize a projected encryption protector; None stays None.

    None means the protector GET did not answer for this server (recorded as a
    failure by the caller) — deliberately distinct from a protector that answered
    "ServiceManaged", which is a real posture.
    """
    if not protector:
        return None
    return {
        "id": protector.get("id"),
        "name": protector.get("name"),
        "type": protector.get("type"),
        "kind": protector.get("kind"),
        "server_key_name": protector.get("server_key_name"),
        "server_key_type": protector.get("server_key_type"),
        "key_vault_key_uri": protector.get("uri"),
        # Azure omits autoRotationEnabled when it was never turned on, so absent
        # must read as False: a validator asserting `false` would not match `null`.
        "auto_rotation_enabled": bool(protector.get("auto_rotation_enabled") or False),
    }


def database_record(database: dict, tde: dict | None) -> dict:
    """Normalize one projected database plus its TDE state.

    `tde_state` is None when the TDE GET did not answer for this database. That is
    NOT read as "disabled" — an unknown state must stay unknown, or a collection
    gap would be published as a finding.
    """
    name = database.get("name") or ""
    state = (tde or {}).get("state")
    return {
        "id": database.get("id"),
        "name": database.get("name"),
        "type": database.get("type"),
        "location": database.get("location"),
        "managed_by": database.get("managed_by"),
        "status": database.get("status"),
        "is_system_database": name.lower() in SYSTEM_DATABASES,
        "tde_id": (tde or {}).get("id"),
        "tde_state": state,
        "tde_enabled": None if state is None else str(state).lower() == TDE_ENABLED,
    }


def server_record(server: dict, protector: dict | None, databases: list[dict]) -> dict:
    """Assemble one server's encryption evidence from its projected parts."""
    resource_id = server.get("id")
    protector_record = encryption_protector_record(protector)
    key_type = (protector_record or {}).get("server_key_type")
    user_databases = [d for d in databases if not d["is_system_database"]]

    return {
        "id": resource_id,
        "name": server.get("name"),
        "type": server.get("type"),
        "location": server.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "version": server.get("version"),
        "state": server.get("state"),
        "fully_qualified_domain_name": server.get("fully_qualified_domain_name"),
        # --- the encryption evidence that varies ---
        "encryption_protector": protector_record,
        "server_key_type": key_type,
        "customer_managed_key": str(key_type or "").lower() == SERVER_KEY_TYPE_CMK,
        # --- per-database TDE, excluding the Azure-managed `master` ---
        "databases": databases,
        "total_databases": len(databases),
        "total_user_databases": len(user_databases),
        "tde_enabled_user_databases": sum(1 for d in user_databases if d["tde_enabled"] is True),
        "tde_disabled_user_databases": sum(1 for d in user_databases if d["tde_enabled"] is False),
        # True only when every user database is confirmed encrypted. A server with
        # no user databases is not "fully encrypted" — there is nothing to encrypt —
        # so it reports None rather than a vacuous True.
        "all_user_databases_tde_enabled": (
            all(d["tde_enabled"] is True for d in user_databases) if user_databases else None
        ),
    }


def summarize(servers: list[dict]) -> dict:
    """CMK coverage is the headline, not an encrypted/total percentage.

    TDE is on by default on Azure SQL, so an "encrypted" percentage would be a
    constant 100. What varies — and what a reviewer needs — is how many servers
    protect TDE with a customer-managed Key Vault key, mirroring how
    storage_encryption_status reports `cmk_percentage`.
    """
    total = len(servers)
    cmk = sum(1 for s in servers if s["customer_managed_key"])
    user_databases = [d for s in servers for d in s["databases"] if not d["is_system_database"]]
    return {
        "total_sql_servers": total,
        "customer_managed_key_servers": cmk,
        "service_managed_key_servers": total - cmk,
        "cmk_percentage": coverage_percentage(cmk, total),
        "key_auto_rotation_servers": sum(
            1
            for s in servers
            if (s["encryption_protector"] or {}).get("auto_rotation_enabled")
        ),
        "total_databases": sum(s["total_databases"] for s in servers),
        "total_user_databases": len(user_databases),
        "tde_enabled_user_databases": sum(1 for d in user_databases if d["tde_enabled"] is True),
        "tde_disabled_user_databases": sum(1 for d in user_databases if d["tde_enabled"] is False),
        "tde_unknown_user_databases": sum(1 for d in user_databases if d["tde_enabled"] is None),
        "tde_percentage": coverage_percentage(
            sum(1 for d in user_databases if d["tde_enabled"] is True), len(user_databases)
        ),
        "servers_with_a_tde_disabled_user_database": sum(
            1 for s in servers if s["tde_disabled_user_databases"] > 0
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

# Markers for "this optional sub-resource was never configured", which Azure answers
# with a 404 rather than an empty body. Not a collection failure — the same
# convention as the AWS fetchers' not-enabled handling.
NOT_FOUND_TYPES = ("resourcenotfounderror",)
NOT_FOUND_MARKERS = ("(resourcenotfound)", "(404)", "was not found", "could not be found")


def is_not_found(exc: BaseException) -> bool:
    """Is this Azure's "that optional sub-resource does not exist" answer?

    LOCAL HELPER (duplicated in the sibling database fetchers) — azure_common is
    off-limits for concurrent-edit reasons; consolidate after merge.
    """
    if type(exc).__name__.lower() in NOT_FOUND_TYPES:
        return True
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return any(marker in message for marker in NOT_FOUND_MARKERS)


def _optional_get(collector: Collector, operation: str, fn):
    """Run one GET whose absence is evidence, not a failure.

    Returns None both when the resource genuinely does not exist (logged, NOT
    recorded) and when the call failed (recorded). The caller distinguishes them by
    checking `collector.ok` — for this fetcher's purposes both mean "no data", and
    only the second must fail the run.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_not_found(exc):
            logger.info("%s: not configured (404) — recording as absent", operation)
            return None
        collector.record(operation, exc)
        return None


def collect_sql_servers(subscription_id, cred, collector: Collector) -> list[dict]:
    """One servers.list(), then per server: 1 protector GET + databases + a TDE GET each.

    This is the deepest per-resource fan-out of any Azure service in the catalog.
    Every call is guarded individually so one inaccessible server does not blank out
    the rest of the subscription.
    """

    def _client():
        from azure.mgmt.sql import SqlManagementClient  # lazy

        return SqlManagementClient(credential=cred, subscription_id=subscription_id)

    # Guarded (not a bare import at function top level) so a missing azure-mgmt-sql
    # is recorded as internal_error and the evidence file is still written, rather
    # than raising past main() and leaving no evidence and no status file.
    client = collector.guard("sql.SqlManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [project_sql_server(s) for s in client.servers.list()]

    projected_servers = collector.guard("sql.servers.list", _list, default=[])

    servers: list[dict] = []
    for server in projected_servers:
        group, name = resource_group_from_id(server.get("id")), server.get("name")
        if not group or not name:
            collector.record(
                "sql.encryption_protectors.get",
                RuntimeError(f"SQL server {name!r} has no resource group in its id"),
            )
            continue

        protector = _optional_get(
            collector,
            f"sql.encryption_protectors.get ({name})",
            lambda: project_encryption_protector(
                # "current" is the only valid protector name (EncryptionProtectorName.CURRENT).
                client.encryption_protectors.get(group, name, "current")
            ),
        )
        databases = _collect_databases(client, collector, group, name)
        servers.append(server_record(server, protector, databases))

    return sorted(servers, key=lambda r: r.get("id") or "")


def _collect_databases(client, collector: Collector, group: str, server_name: str) -> list[dict]:
    """databases.list_by_server(), plus one TDE GET per database."""

    def _list():
        return [project_database(d) for d in client.databases.list_by_server(group, server_name)]

    projected = collector.guard(
        f"sql.databases.list_by_server ({server_name})", _list, default=[]
    )

    databases = []
    for database in projected:
        database_name = database.get("name")
        tde = None
        if database_name:
            tde = _optional_get(
                collector,
                f"sql.transparent_data_encryptions.get ({server_name}/{database_name})",
                # "current" passed POSITIONALLY: azure-mgmt-sql 4.0.0 renamed the
                # parameter from Prowler's `transparent_data_encryption_name` to
                # `tde_name`, and a positional argument works on either spelling.
                lambda: project_transparent_data_encryption(
                    client.transparent_data_encryptions.get(
                        group, server_name, database_name, "current"
                    )
                ),
            )
        databases.append(database_record(database, tde))

    return sorted(databases, key=lambda r: r.get("id") or "")


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

    servers: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-server result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider,
        # which would otherwise make "no SQL in this subscription" indistinguishable
        # from "Microsoft.Sql was never registered".
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Sql"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Sql is not registered on subscription %s — no Azure SQL "
                "in use; reporting status not_registered",
                subscription_id,
            )
        servers = collect_sql_servers(subscription_id, cred, collector)
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
            "sql_servers": servers,
            "provider_registration_status": registration,
        },
        summary={**summarize(servers), "provider_registration_status": registration},
    )

    filename = (
        f"azure_sql_encryption_status_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
