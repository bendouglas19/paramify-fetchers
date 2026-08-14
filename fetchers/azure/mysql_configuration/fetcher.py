#!/usr/bin/env python3
"""
Azure Database for MySQL flexible server security configuration

For every MySQL flexible server in one subscription, reports the engine version, the
full server-parameter set, and the security posture derived from it:
`require_secure_transport`, the accepted `tls_version` list, whether the audit log is
on and whether it records connection events, plus geo-redundant backup and the
high-availability mode from the server model itself.

**Every server parameter is listed, not read by name.** Prowler calls
`configurations.list_by_server()` here and reads the parameters it needs out of the
result, which is the OPPOSITE of what it does for PostgreSQL
(fetchers/azure/postgresql_configuration issues one `configurations.get()` per
parameter). Both behaviors are kept deliberately. The difference is not arbitrary:
MySQL's audit configuration is spread across several parameters whose relevance
depends on each other's values (`audit_log_enabled` gates `audit_log_events`, which
is a comma-separated event-class list), and a reviewer checking "was auditing
configured correctly" needs the whole set rather than the six fields someone decided
mattered. Only `name: value` is kept per parameter — the SDK also returns each
parameter's `description` and `allowed_values`, which are static engine documentation
identical on every server, not tenant state, and would multiply the payload size.

Field projections are ported from Prowler's
prowler/providers/azure/services/mysql/mysql_service.py (Apache-2.0), which reads the
same azure-mgmt-rdbms `mysql_flexibleservers` SDK.

Single-subscription per invocation; fanout across subscriptions happens at the runner
layer (see fetcher.yaml: supports_targets: true).
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

logger = logging.getLogger("azure_mysql_configuration")

# The parameters read out of the full configuration set. Listed here for the record;
# the evidence keeps every parameter, so adding a field is a transform change only.
PARAMETER_REQUIRE_SECURE_TRANSPORT = "require_secure_transport"
PARAMETER_TLS_VERSION = "tls_version"
PARAMETER_AUDIT_LOG_ENABLED = "audit_log_enabled"
PARAMETER_AUDIT_LOG_EVENTS = "audit_log_events"

# MySQL reports boolean parameters as "ON" / "OFF"; Prowler lowercases and compares
# to "on".
PARAMETER_ON = "on"

# tls_version is a COMMA-SEPARATED list of every accepted version, not a floor — so
# "TLSv1.2,TLSv1.3" is compliant but "TLSv1,TLSv1.2" is not, because the weak version
# is still accepted. Prowler fails the server if either deprecated version appears.
DEPRECATED_TLS_VERSIONS = ("TLSv1", "TLSv1.0", "TLSv1.1")

# audit_log_events is a comma-separated list of event classes. "CONNECTION" is the
# class that records who connected, which is what an access-audit control needs.
AUDIT_EVENT_CONNECTION = "connection"

# HighAvailability.mode is "Disabled", "ZoneRedundant" or "SameZone".
HA_DISABLED = "disabled"

# Backup.geo_redundant_backup serializes as "Enabled" / "Disabled".
GEO_REDUNDANT_ENABLED = "enabled"


# --- projection: the only code here that touches an azure-mgmt model ---

def project_mysql_server(server) -> dict:
    """Read a `Server` model's attributes into a flat snake_case dict.

    azure-mgmt-rdbms 10.1.1 is on the msrest generator, whose models flatten
    `properties.*` onto the model itself, so these are the attribute names directly.
    `backup`, `high_availability` and `network` are nested models that are absent on
    a server that never configured them, hence the None-tolerant hops.
    """
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
    """Read one `Configuration` (server parameter) into a flat dict.

    `description` and `allowed_values` are deliberately NOT read: they are static
    engine documentation, identical across every server, and would dominate a payload
    that carries a few hundred parameters per server.
    """
    return {
        "id": model_attr(configuration, "id"),
        "name": model_attr(configuration, "name"),
        "value": model_attr(configuration, "value"),
        "source": model_attr(configuration, "source"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def configuration_map(configurations: list[dict]) -> dict[str, str | None]:
    """Collapse the projected parameter list into a {name: value} map.

    A map, not a list, because that is how every reader uses it (look up one
    parameter by name) and because it makes the evidence file's diff between runs
    show exactly which parameter changed.
    """
    return {
        c["name"]: c.get("value")
        for c in configurations
        if c.get("name")
    }


def _parameter_is_on(parameters: dict, name: str) -> bool:
    """Is this parameter present and set to "ON"? Prowler's lowercased compare."""
    value = parameters.get(name)
    return value is not None and str(value).strip().lower() == PARAMETER_ON


def _tls_versions(value) -> list[str]:
    """Split the comma-separated tls_version list into its accepted versions."""
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _audit_log_events(value) -> list[str]:
    """Split the comma-separated audit_log_events list into its event classes."""
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def server_record(server: dict, configurations: list[dict]) -> dict:
    """Assemble one flexible server's configuration evidence."""
    resource_id = server.get("id")
    parameters = configuration_map(configurations)
    tls_versions = _tls_versions(parameters.get(PARAMETER_TLS_VERSION))
    audit_events = _audit_log_events(parameters.get(PARAMETER_AUDIT_LOG_EVENTS))
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
        "require_secure_transport": parameters.get(PARAMETER_REQUIRE_SECURE_TRANSPORT),
        "require_secure_transport_enabled": _parameter_is_on(
            parameters, PARAMETER_REQUIRE_SECURE_TRANSPORT
        ),
        "tls_version": parameters.get(PARAMETER_TLS_VERSION),
        "tls_versions_accepted": tls_versions,
        # A deprecated version still being ACCEPTED is the finding — the parameter is
        # a list of allowed versions, not a minimum.
        "tls_version_compliant": bool(
            tls_versions and not any(v in DEPRECATED_TLS_VERSIONS for v in tls_versions)
        ),
        # --- audit logging ---
        "audit_log_enabled": parameters.get(PARAMETER_AUDIT_LOG_ENABLED),
        "audit_log_enabled_state": _parameter_is_on(parameters, PARAMETER_AUDIT_LOG_ENABLED),
        "audit_log_events": parameters.get(PARAMETER_AUDIT_LOG_EVENTS),
        "audit_log_event_classes": audit_events,
        "audit_log_connection_events": any(
            event.lower() == AUDIT_EVENT_CONNECTION for event in audit_events
        ),
        # --- network ---
        "public_network_access": server.get("public_network_access"),
        "public_network_access_disabled": str(
            server.get("public_network_access") or ""
        ).lower() == "disabled",
        "delegated_subnet_resource_id": server.get("delegated_subnet_resource_id"),
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
        # --- the full parameter set (see the module docstring) ---
        "configurations": parameters,
        "total_configuration_parameters": len(parameters),
    }


def summarize(servers: list[dict]) -> dict:
    """Transport encryption is the headline percentage; the rest are counts."""
    total = len(servers)
    secure_transport = sum(1 for s in servers if s["require_secure_transport_enabled"])
    return {
        "total_mysql_servers": total,
        "require_secure_transport_servers": secure_transport,
        "require_secure_transport_percentage": coverage_percentage(secure_transport, total),
        "tls_version_compliant_servers": sum(1 for s in servers if s["tls_version_compliant"]),
        "audit_log_enabled_servers": sum(1 for s in servers if s["audit_log_enabled_state"]),
        "audit_log_connection_event_servers": sum(
            1 for s in servers if s["audit_log_connection_events"]
        ),
        "public_network_access_disabled_servers": sum(
            1 for s in servers if s["public_network_access_disabled"]
        ),
        "geo_redundant_backup_servers": sum(
            1 for s in servers if s["geo_redundant_backup_enabled"]
        ),
        "high_availability_servers": sum(1 for s in servers if s["high_availability_enabled"]),
        "total_configuration_parameters": sum(
            s["total_configuration_parameters"] for s in servers
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_mysql_servers(subscription_id, cred, collector: Collector) -> list[dict]:
    """One servers.list(), then one configurations.list_by_server() per server."""

    def _client():
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient  # lazy

        return MySQLManagementClient(credential=cred, subscription_id=subscription_id)

    # Guarded (not a bare import at function top level) so a missing azure-mgmt-rdbms
    # is recorded as internal_error and the evidence file is still written.
    client = collector.guard("mysql.MySQLManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [project_mysql_server(s) for s in client.servers.list()]

    projected_servers = collector.guard("mysql.servers.list", _list, default=[])

    servers: list[dict] = []
    for server in projected_servers:
        group, name = resource_group_from_id(server.get("id")), server.get("name")
        if not group or not name:
            collector.record(
                "mysql.configurations.list_by_server",
                RuntimeError(f"MySQL server {name!r} has no resource group in its id"),
            )
            continue

        configurations = collector.guard(
            f"mysql.configurations.list_by_server ({name})",
            lambda: [
                project_configuration(c)
                for c in client.configurations.list_by_server(group, name)
            ],
            default=[],
        )
        servers.append(server_record(server, configurations))

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
        # identically whether MySQL is unused or Microsoft.DBforMySQL was never
        # registered.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.DBforMySQL"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.DBforMySQL is not registered on subscription %s — no MySQL "
                "in use; reporting status not_registered",
                subscription_id,
            )
        servers = collect_mysql_servers(subscription_id, cred, collector)
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
            "mysql_servers": servers,
            "provider_registration_status": registration,
        },
        summary={**summarize(servers), "provider_registration_status": registration},
    )

    filename = (
        f"azure_mysql_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
