#!/usr/bin/env python3
"""
Azure Database for PostgreSQL flexible server security configuration

For every PostgreSQL flexible server in one subscription, reports the settings that
show transport encryption, authentication, audit logging and durability are
configured: `require_secure_transport`, Entra ID (Azure AD) authentication and the
administrators configured for it, the five logging / throttling server parameters,
every firewall rule, geo-redundant backup, and the high-availability mode.

**Server parameters are read BY NAME, not dumped.** Prowler issues one
`configurations.get(rg, server, "<parameter>")` per parameter it cares about rather
than `configurations.list_by_server()`, and this fetcher keeps that: a flexible
server exposes several HUNDRED parameters (most of them PostgreSQL engine tunables
like `work_mem` that say nothing about security posture), so listing them all would
bury the six that matter under kilobytes of noise and make the evidence file's diff
unreadable between runs. The MySQL sibling fetcher deliberately does the opposite —
see fetchers/azure/mysql_configuration, where Prowler lists everything.

Two of those parameters legitimately DO NOT EXIST on newer servers, and their
absence is evidence rather than a failure:

- `connection_throttle.enable` was removed in PostgreSQL 16, so Azure answers a 404
  (`ConfigurationNotExists`) on a PG16+ server.
- `logfiles.retention_days` only exists when server logs are enabled.

Field projections are ported from Prowler's
prowler/providers/azure/services/postgresql/postgresql_service.py (Apache-2.0),
which reads the same azure-mgmt-postgresqlflexibleservers SDK. Two divergences,
verified against azure-mgmt-postgresqlflexibleservers 2.0.0:

- Prowler calls `client.servers.list()`; 2.0.0 has no `list` — the
  subscription-wide lister is `servers.list_by_subscription()`. Both spellings are
  tried below so either SDK generation works.
- Prowler calls `client.administrators.list_by_server(...)`; 2.0.0 renamed that
  operation group to `administrators_microsoft_entra`. Both are tried.

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

logger = logging.getLogger("azure_postgresql_configuration")

# The server parameters read by name, mapping the evidence field to the PostgreSQL
# parameter's real name. Exactly Prowler's set; the dotted names are Azure's own
# spelling for parameters that are not bare PostgreSQL GUCs.
SERVER_PARAMETERS = {
    "require_secure_transport": "require_secure_transport",
    "log_checkpoints": "log_checkpoints",
    "log_connections": "log_connections",
    "log_disconnections": "log_disconnections",
    "connection_throttling": "connection_throttle.enable",
    "log_retention_days": "logfiles.retention_days",
}

# Parameters whose absence is expected on some server versions (see the module
# docstring) and must therefore not be recorded as a collection failure.
OPTIONAL_PARAMETERS = ("connection_throttling", "log_retention_days")

# Prowler uppercases every parameter value and compares against "ON", because
# PostgreSQL reports booleans as the lowercase strings "on" / "off" while Azure's
# portal shows them capitalized. Uppercasing at the boundary keeps one spelling in
# the evidence.
PARAMETER_ON = "ON"

# AuthConfig.active_directory_auth serializes as "Enabled" / "Disabled".
AUTH_ENABLED = "ENABLED"

# HighAvailability.mode is "Disabled", "ZoneRedundant" or "SameZone"; anything other
# than Disabled (or absent) means a standby replica exists.
HA_DISABLED = "disabled"

# Backup.geo_redundant_backup serializes as "Enabled" / "Disabled".
GEO_REDUNDANT_ENABLED = "enabled"

# Azure's "allow public access from any Azure service" pseudo-rule, which admits
# every Azure tenant's compute. Prowler's
# postgresql_flexible_server_allow_access_services_disabled matches exactly this.
AZURE_SERVICES_RULE = ("0.0.0.0", "0.0.0.0")
ENTIRE_INTERNET_RULE = ("0.0.0.0", "255.255.255.255")

# Prowler's postgresql_flexible_server_log_retention_days_greater_3 passes only when
# retention is strictly inside (3, 8) — Azure's own supported range for this
# parameter tops out at 7 days, so a larger value means the parameter was not
# actually applied.
LOG_RETENTION_MINIMUM_DAYS = 3
LOG_RETENTION_MAXIMUM_DAYS = 8


# --- projection: the only code here that touches an azure-mgmt model ---

def project_postgresql_server(server) -> dict:
    """Read a `Server` model's attributes into a flat snake_case dict.

    azure-mgmt-postgresqlflexibleservers 2.0.0 is still on the msrest generator,
    whose models flatten `properties.*` onto the model itself, so these names are
    the attribute names directly. Reading them by attribute rather than via
    `as_dict()` keeps this fetcher on the same footing as the `_model_base` ones,
    whose `as_dict()` emits the camelCase wire shape nested under "properties".
    """
    auth_config = model_attr(server, "auth_config")
    backup = model_attr(server, "backup")
    high_availability = model_attr(server, "high_availability")
    network = model_attr(server, "network")
    return {
        "id": model_attr(server, "id"),
        "name": model_attr(server, "name"),
        "type": model_attr(server, "type"),
        "location": model_attr(server, "location"),
        "version": model_attr(server, "version"),
        "state": model_attr(server, "state"),
        "fully_qualified_domain_name": model_attr(server, "fully_qualified_domain_name"),
        # --- authentication ---
        "active_directory_auth": model_attr(auth_config, "active_directory_auth"),
        "password_auth": model_attr(auth_config, "password_auth"),
        "auth_tenant_id": model_attr(auth_config, "tenant_id"),
        # --- network ---
        "public_network_access": model_attr(network, "public_network_access"),
        "delegated_subnet_resource_id": model_attr(network, "delegated_subnet_resource_id"),
        # --- durability ---
        "backup_retention_days": model_attr(backup, "backup_retention_days"),
        "geo_redundant_backup": model_attr(backup, "geo_redundant_backup"),
        "high_availability_mode": model_attr(high_availability, "mode"),
        "high_availability_state": model_attr(high_availability, "state"),
    }


def project_configuration(configuration) -> dict:
    """Read a `Configuration` (one server parameter) into a flat dict."""
    return {
        "id": model_attr(configuration, "id"),
        "name": model_attr(configuration, "name"),
        "value": model_attr(configuration, "value"),
        "default_value": model_attr(configuration, "default_value"),
        "source": model_attr(configuration, "source"),
    }


def project_firewall_rule(rule) -> dict:
    """Read a `FirewallRule` model into a flat dict."""
    return {
        "id": model_attr(rule, "id"),
        "name": model_attr(rule, "name"),
        "start_ip_address": model_attr(rule, "start_ip_address"),
        "end_ip_address": model_attr(rule, "end_ip_address"),
    }


def project_entra_admin(admin) -> dict:
    """Read an `AdministratorMicrosoftEntra` model into a flat dict."""
    return {
        "id": model_attr(admin, "id"),
        "name": model_attr(admin, "name"),
        "object_id": model_attr(admin, "object_id"),
        "principal_name": model_attr(admin, "principal_name"),
        "principal_type": model_attr(admin, "principal_type"),
        "tenant_id": model_attr(admin, "tenant_id"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def parameter_value(configuration: dict | None) -> str | None:
    """Uppercased value of one server parameter; None when it was not collected.

    Prowler's `.value.upper()`, made None-safe. None means "the parameter does not
    exist on this server or could not be read" — deliberately distinct from "OFF",
    because reporting an uncollected parameter as off would publish a collection gap
    as a finding.
    """
    if not configuration:
        return None
    value = configuration.get("value")
    return None if value is None else str(value).upper()


def firewall_rule_record(rule: dict) -> dict:
    """Normalize one projected firewall rule, flagging the two exposures."""
    addresses = (rule.get("start_ip_address"), rule.get("end_ip_address"))
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "start_ip_address": rule.get("start_ip_address"),
        "end_ip_address": rule.get("end_ip_address"),
        "allows_all_azure_services": addresses == AZURE_SERVICES_RULE,
        "allows_entire_internet": addresses == ENTIRE_INTERNET_RULE,
    }


def entra_admin_record(admin: dict) -> dict:
    """Normalize one projected Entra ID administrator."""
    return {
        "id": admin.get("id"),
        "name": admin.get("name"),
        "object_id": admin.get("object_id"),
        "principal_name": admin.get("principal_name"),
        "principal_type": admin.get("principal_type"),
        "tenant_id": admin.get("tenant_id"),
    }


def _log_retention_compliant(value: str | None) -> bool:
    """Prowler's window: strictly greater than 3 and strictly less than 8 days."""
    if value is None:
        return False
    try:
        days = int(value)
    except (TypeError, ValueError):
        return False
    return LOG_RETENTION_MINIMUM_DAYS < days < LOG_RETENTION_MAXIMUM_DAYS


def server_record(
    server: dict,
    parameters: dict[str, str | None],
    firewall_rules: list[dict],
    entra_admins: list[dict],
) -> dict:
    """Assemble one flexible server's configuration evidence."""
    resource_id = server.get("id")
    active_directory_auth = str(server.get("active_directory_auth") or "").upper()
    ha_mode = server.get("high_availability_mode")

    return {
        "id": resource_id,
        "name": server.get("name"),
        "type": server.get("type"),
        "location": server.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "version": server.get("version"),
        "state": server.get("state"),
        "fully_qualified_domain_name": server.get("fully_qualified_domain_name"),
        # --- transport encryption ---
        "require_secure_transport": parameters.get("require_secure_transport"),
        "require_secure_transport_enabled": (
            parameters.get("require_secure_transport") == PARAMETER_ON
        ),
        # --- authentication ---
        "active_directory_auth": server.get("active_directory_auth"),
        "active_directory_auth_enabled": active_directory_auth == AUTH_ENABLED,
        "password_auth": server.get("password_auth"),
        "auth_tenant_id": server.get("auth_tenant_id"),
        "entra_id_admins": entra_admins,
        "total_entra_id_admins": len(entra_admins),
        # Prowler's postgresql_flexible_server_entra_id_authentication_enabled needs
        # BOTH: Entra auth switched on and at least one administrator assigned to it.
        "entra_id_authentication_configured": bool(
            active_directory_auth == AUTH_ENABLED and entra_admins
        ),
        # --- audit logging / throttling (the by-name parameters) ---
        "log_checkpoints": parameters.get("log_checkpoints"),
        "log_checkpoints_enabled": parameters.get("log_checkpoints") == PARAMETER_ON,
        "log_connections": parameters.get("log_connections"),
        "log_connections_enabled": parameters.get("log_connections") == PARAMETER_ON,
        "log_disconnections": parameters.get("log_disconnections"),
        "log_disconnections_enabled": parameters.get("log_disconnections") == PARAMETER_ON,
        "connection_throttling": parameters.get("connection_throttling"),
        "connection_throttling_enabled": parameters.get("connection_throttling") == PARAMETER_ON,
        "log_retention_days": parameters.get("log_retention_days"),
        "log_retention_compliant": _log_retention_compliant(
            parameters.get("log_retention_days")
        ),
        # --- network ---
        "public_network_access": server.get("public_network_access"),
        "public_network_access_disabled": str(
            server.get("public_network_access") or ""
        ).lower() == "disabled",
        "delegated_subnet_resource_id": server.get("delegated_subnet_resource_id"),
        "firewall_rules": firewall_rules,
        "total_firewall_rules": len(firewall_rules),
        "allows_all_azure_services": any(r["allows_all_azure_services"] for r in firewall_rules),
        "allows_entire_internet": any(r["allows_entire_internet"] for r in firewall_rules),
        # --- durability ---
        "backup_retention_days": server.get("backup_retention_days"),
        "geo_redundant_backup": server.get("geo_redundant_backup"),
        "geo_redundant_backup_enabled": (
            str(server.get("geo_redundant_backup") or "").lower() == GEO_REDUNDANT_ENABLED
        ),
        "high_availability_mode": ha_mode,
        "high_availability_state": server.get("high_availability_state"),
        "high_availability_enabled": bool(
            ha_mode is not None and str(ha_mode).lower() != HA_DISABLED
        ),
    }


def summarize(servers: list[dict]) -> dict:
    """Transport encryption is the headline percentage; the rest are counts."""
    total = len(servers)
    secure_transport = sum(1 for s in servers if s["require_secure_transport_enabled"])
    return {
        "total_postgresql_servers": total,
        "require_secure_transport_servers": secure_transport,
        "require_secure_transport_percentage": coverage_percentage(secure_transport, total),
        "entra_id_authentication_servers": sum(
            1 for s in servers if s["active_directory_auth_enabled"]
        ),
        "entra_id_authentication_configured_servers": sum(
            1 for s in servers if s["entra_id_authentication_configured"]
        ),
        "total_entra_id_admins": sum(s["total_entra_id_admins"] for s in servers),
        "log_checkpoints_servers": sum(1 for s in servers if s["log_checkpoints_enabled"]),
        "log_connections_servers": sum(1 for s in servers if s["log_connections_enabled"]),
        "log_disconnections_servers": sum(1 for s in servers if s["log_disconnections_enabled"]),
        "connection_throttling_servers": sum(
            1 for s in servers if s["connection_throttling_enabled"]
        ),
        "log_retention_compliant_servers": sum(
            1 for s in servers if s["log_retention_compliant"]
        ),
        "public_network_access_disabled_servers": sum(
            1 for s in servers if s["public_network_access_disabled"]
        ),
        "servers_allowing_all_azure_services": sum(
            1 for s in servers if s["allows_all_azure_services"]
        ),
        "servers_allowing_entire_internet": sum(
            1 for s in servers if s["allows_entire_internet"]
        ),
        "total_firewall_rules": sum(s["total_firewall_rules"] for s in servers),
        "geo_redundant_backup_servers": sum(
            1 for s in servers if s["geo_redundant_backup_enabled"]
        ),
        "high_availability_servers": sum(1 for s in servers if s["high_availability_enabled"]),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

# Markers for "this parameter / sub-resource does not exist on this server", which
# Azure answers with a 404 rather than an empty body.
NOT_FOUND_TYPES = ("resourcenotfounderror",)
NOT_FOUND_MARKERS = (
    "(resourcenotfound)",
    "configurationnotexists",
    "(404)",
    "was not found",
    "could not be found",
)

# Azure's answer when Entra ID authentication was never switched on for a server:
# listing its administrators is rejected rather than returning an empty list. Prowler
# skips this exact phrase, and it must not fail the run.
ENTRA_AUTH_DISABLED_MARKER = "authentication is not enabled"


def is_not_found(exc: BaseException) -> bool:
    """Is this Azure's "that parameter / sub-resource does not exist" answer?

    LOCAL HELPER (duplicated in the sibling database fetchers) — azure_common is
    off-limits for concurrent-edit reasons; consolidate after merge.
    """
    if type(exc).__name__.lower() in NOT_FOUND_TYPES:
        return True
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return any(marker in message for marker in NOT_FOUND_MARKERS)


def is_entra_auth_disabled(exc: BaseException) -> bool:
    """Is this "Entra ID auth is off, so there are no administrators to list"?"""
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return ENTRA_AUTH_DISABLED_MARKER in message


def _operation_group(client, *names):
    """First operation group on `client` that exists, by name.

    LOCAL HELPER — azure-mgmt-postgresqlflexibleservers renamed both the
    subscription-wide server lister and the Entra administrators group between the
    generation Prowler pins and 2.0.0 (see the module docstring). Trying both keeps
    one fetcher working across either, instead of failing with an AttributeError that
    would classify as a generic partial_failure.
    """
    for name in names:
        group = getattr(client, name, None)
        if group is not None:
            return group
    return None


def _collect_parameters(client, collector: Collector, group, server_name) -> dict:
    """One configurations.get() per parameter in SERVER_PARAMETERS.

    By name rather than list_by_server() — see the module docstring for why. An
    absent OPTIONAL_PARAMETERS entry is logged and left None; an absent required one
    is recorded, because it means the read failed rather than the parameter being
    retired.
    """
    parameters: dict[str, str | None] = {}
    for field, parameter_name in SERVER_PARAMETERS.items():
        operation = f"postgresql.configurations.get ({server_name}/{parameter_name})"
        try:
            configuration = project_configuration(
                client.configurations.get(group, server_name, parameter_name)
            )
            parameters[field] = parameter_value(configuration)
        except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
            parameters[field] = None
            if field in OPTIONAL_PARAMETERS and is_not_found(exc):
                logger.info(
                    "%s: parameter does not exist on this server version — recording as absent",
                    operation,
                )
                continue
            collector.record(operation, exc)
    return parameters


def _collect_entra_admins(client, collector: Collector, group, server_name) -> list[dict]:
    """Entra ID administrators, tolerating "Entra auth is not enabled"."""
    admins_group = _operation_group(client, "administrators_microsoft_entra", "administrators")
    operation = f"postgresql.administrators_microsoft_entra.list_by_server ({server_name})"
    if admins_group is None:
        collector.record(
            operation,
            RuntimeError(
                "azure-mgmt-postgresqlflexibleservers exposes neither "
                "`administrators_microsoft_entra` nor `administrators`"
            ),
        )
        return []
    try:
        return sorted(
            (
                entra_admin_record(project_entra_admin(a))
                for a in admins_group.list_by_server(group, server_name)
            ),
            key=lambda r: r.get("object_id") or "",
        )
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_entra_auth_disabled(exc) or is_not_found(exc):
            logger.info(
                "%s: Entra ID authentication is not enabled — no administrators to list",
                operation,
            )
            return []
        collector.record(operation, exc)
        return []


def collect_postgresql_servers(subscription_id, cred, collector: Collector) -> list[dict]:
    """One servers list, then per server: 6 parameter GETs + firewall + Entra admins."""

    def _client():
        # Lazy import: the pure transforms above must stay importable with no
        # azure-mgmt-postgresqlflexibleservers installed (that is what lets the
        # fixture tests run without the SDK).
        from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient

        return PostgreSQLManagementClient(credential=cred, subscription_id=subscription_id)

    # Guarded (not a bare import at function top level) so a missing
    # azure-mgmt-postgresqlflexibleservers is recorded as internal_error and the
    # evidence file is still written.
    client = collector.guard("postgresql.PostgreSQLManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        servers_group = client.servers
        # 2.0.0 dropped `list` in favor of `list_by_subscription`; Prowler pins a
        # generation that still has `list`.
        lister = None
        for name in ("list", "list_by_subscription"):
            lister = getattr(servers_group, name, None)
            if lister is not None:
                break
        if lister is None:
            raise RuntimeError(
                "azure-mgmt-postgresqlflexibleservers exposes neither servers.list "
                "nor servers.list_by_subscription"
            )
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [project_postgresql_server(s) for s in lister()]

    projected_servers = collector.guard(
        "postgresql.servers.list_by_subscription", _list, default=[]
    )

    servers: list[dict] = []
    for server in projected_servers:
        group, name = resource_group_from_id(server.get("id")), server.get("name")
        if not group or not name:
            collector.record(
                "postgresql.configurations.get",
                RuntimeError(f"PostgreSQL server {name!r} has no resource group in its id"),
            )
            continue

        parameters = _collect_parameters(client, collector, group, name)
        rules = collector.guard(
            f"postgresql.firewall_rules.list_by_server ({name})",
            lambda: [
                firewall_rule_record(project_firewall_rule(r))
                for r in client.firewall_rules.list_by_server(group, name)
            ],
            default=[],
        )
        admins = _collect_entra_admins(client, collector, group, name)
        servers.append(
            server_record(
                server, parameters, sorted(rules, key=lambda r: r.get("name") or ""), admins
            )
        )

    return sorted(servers, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which
    # buries this fetcher's own lines and would dominate the runner's stderr tail.
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
        # Asked BEFORE the list call: Azure returns an empty list rather than an
        # error for an unregistered provider, so without this "0 servers" reads
        # identically whether PostgreSQL is unused or Microsoft.DBforPostgreSQL was
        # never registered.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.DBforPostgreSQL"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.DBforPostgreSQL is not registered on subscription %s — no "
                "PostgreSQL in use; reporting status not_registered",
                subscription_id,
            )
        servers = collect_postgresql_servers(subscription_id, cred, collector)
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
            "postgresql_servers": servers,
            "provider_registration_status": registration,
        },
        summary={**summarize(servers), "provider_registration_status": registration},
    )

    filename = (
        f"azure_postgresql_configuration_"
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
