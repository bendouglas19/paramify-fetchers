#!/usr/bin/env python3
"""
GCP Cloud SQL Network & Authentication Configuration

For each Cloud SQL instance in one project, reports the boundary posture: whether
the instance has a public IP at all, which authorized networks reach it
(0.0.0.0/0 being the finding), whether SSL/TLS is required and at what minimum
version, how private connectivity is wired (VPC peering, Private Service Connect,
the private path for Google Cloud services), and the per-engine database flags
that decide connection logging and cross-database authentication.

Ported from Prowler's GCP Cloud SQL service (prowler/providers/gcp/services/
cloudsql/cloudsql_service.py, Apache-2.0) and its 24 checks. Prowler's Instance
projects name/version/region/ip_addresses/public_ip/authorized_networks/
require_ssl/ssl_mode/automated_backups/flags/availability_type/instance_type/
cmek_key_name; the network half of that (plus the ipConfiguration fields its
checks read indirectly) is what this fetcher evidences. The backup and
availability half is a separate evidence set (gcp_cloud_sql_backup_configuration),
and CMEK belongs to gcp_cloud_sql_encryption_status. All three read the same
`instances.list` response — one API call per fetcher, no extra calls.

Uses the official Google API Python client (discovery: sqladmin v1beta4), like
its sibling gcp_cloud_sql_encryption_status: Cloud SQL Admin has no stable
dedicated GAPIC client, so the category's "prefer GAPIC" rule does not apply
here. instances.list already returns full instance resources (REST/camelCase
dicts), which the pure transforms below consume directly.

Three deliberate departures from the Prowler original:
- **SSL enforcement reads `requireSsl` when `sslMode` is unset.** Prowler defaults
  an absent sslMode to ALLOW_UNENCRYPTED_AND_ENCRYPTED, which reports an instance
  using only the legacy requireSsl toggle as not requiring SSL. Here an absent or
  SSL_MODE_UNSPECIFIED sslMode falls back to requireSsl, and both raw fields are
  in the evidence so the reader can see which one answered.
- **`private_ip_only` means "private address, no public one".** Prowler's
  private-IP check fails on any address whose type is not PRIVATE, which includes
  the OUTGOING address every instance has.
- **Database flags are reported, not judged.** Prowler runs one check per flag per
  engine; this reports every flag the instance actually sets, plus the
  engine-relevant security flags with their value or None when unset, so the
  compliance judgment stays out of the collector.

Instance IP *addresses* are deliberately not copied — the posture fact is whether
a public address exists, not what it is (the same reasoning the GKE fetcher
applies to its control-plane endpoints).

Single-project per invocation; fanout across projects happens at the runner
layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    build_payload,
    coverage_percentage,
    credentials,
    dig_any,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    write_status,
)

logger = logging.getLogger("gcp_cloud_sql_network_configuration")

# The authorized-network value that whitelists the whole internet — Prowler's
# cloudsql_instance_public_access, and the single most load-bearing fact here.
_OPEN_TO_INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# sslMode values that force an encrypted connection. ALLOW_UNENCRYPTED_AND_ENCRYPTED
# does not; SSL_MODE_UNSPECIFIED (or an absent field) defers to requireSsl.
_SSL_ENFORCING_MODES = frozenset({"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"})

# The database flags that carry a security decision, per engine, keyed by a
# normalized name mapped to the exact flag name the API uses. SQL Server's flag
# names contain SPACES ("cross db ownership chaining") — that is the literal the
# API returns and the literal Prowler matches on, so it is what we look up.
_POSTGRES_SECURITY_FLAGS = {
    "log_checkpoints": "log_checkpoints",
    "log_connections": "log_connections",
    "log_disconnections": "log_disconnections",
    "log_min_messages": "log_min_messages",
    "log_min_duration_statement": "log_min_duration_statement",
    "log_min_error_statement": "log_min_error_statement",
    "log_error_verbosity": "log_error_verbosity",
    "log_statement": "log_statement",
    "cloudsql_enable_pgaudit": "cloudsql.enable_pgaudit",
    "ssl_min_protocol_version": "ssl_min_protocol_version",
}
_MYSQL_SECURITY_FLAGS = {
    "local_infile": "local_infile",
    "skip_show_database": "skip_show_database",
    "tls_version": "tls_version",
}
_SQLSERVER_SECURITY_FLAGS = {
    "cross_db_ownership_chaining": "cross db ownership chaining",
    "contained_database_authentication": "contained database authentication",
    "external_scripts_enabled": "external scripts enabled",
    "remote_access": "remote access",
    "user_connections": "user connections",
    "user_options": "user options",
    "trace_flag_3625": "3625",
}
_ENGINE_SECURITY_FLAGS = {
    "POSTGRES": _POSTGRES_SECURITY_FLAGS,
    "MYSQL": _MYSQL_SECURITY_FLAGS,
    "SQLSERVER": _SQLSERVER_SECURITY_FLAGS,
}

# The flag each engine uses to pin a minimum TLS version. Cloud SQL has no
# ipConfiguration field for it — it is a database flag, and a different one per
# engine, so both spellings are looked up in order.
_MIN_TLS_FLAGS = ("tls_version", "ssl_min_protocol_version")


# --- pure transforms (operate on REST-style dicts; unit-tested from fixtures) ---

def engine_family(database_version) -> str:
    """POSTGRES / MYSQL / SQLSERVER from a databaseVersion like POSTGRES_15.

    The engine decides which database flags mean anything, so it is projected
    explicitly rather than left for a reader to parse out of the version string.
    """
    version = str(database_version or "").upper()
    for family in _ENGINE_SECURITY_FLAGS:
        if version.startswith(family):
            return family
    return "OTHER"


def flag_map(flags) -> dict:
    """settings.databaseFlags[] → {flag name: value}, keyed by the API's own name."""
    result = {}
    for flag in flags or []:
        name = dig_any(flag, "name")
        if name:
            result[str(name)] = dig_any(flag, "value")
    return result


def ssl_enforced(ssl_mode, require_ssl) -> bool:
    """Whether the instance refuses unencrypted connections.

    sslMode is the modern field and answers on its own. SSL_MODE_UNSPECIFIED (or
    no sslMode at all, on an instance never updated since the field was added)
    defers to the legacy requireSsl boolean — see the module docstring for why
    this differs from Prowler.
    """
    mode = str(ssl_mode or "").upper()
    if mode in _SSL_ENFORCING_MODES:
        return True
    if mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED":
        return False
    return bool(require_ssl)


def min_tls_version(flags: dict):
    """The pinned minimum TLS version, or None when the engine's flag is unset."""
    for name in _MIN_TLS_FLAGS:
        if name in flags:
            return flags[name]
    return None


def authorized_network_record(network: dict) -> dict:
    """One authorized-network entry: the CIDR, its label, and any expiry."""
    value = dig_any(network, "value")
    return {
        "name": dig_any(network, "name") or None,
        "value": value,
        "expiration_time": dig_any(network, "expiration_time") or None,
        "open_to_internet": value in _OPEN_TO_INTERNET_CIDRS,
    }


def instance_record(inst: dict) -> dict:
    """Normalize one Cloud SQL instance resource into a network-posture record."""
    settings = dig_any(inst, "settings") or {}
    ip_config = dig_any(settings, "ip_configuration") or {}
    psc_config = dig_any(ip_config, "psc_config") or {}

    ip_types = sorted(
        {
            str(dig_any(addr, "type") or "")
            for addr in (dig_any(inst, "ip_addresses") or [])
            if dig_any(addr, "type")
        }
    )
    public_ip = "PRIMARY" in ip_types
    private_ip = "PRIVATE" in ip_types

    networks = sorted(
        (authorized_network_record(n) for n in (dig_any(ip_config, "authorized_networks") or [])),
        key=lambda n: (n["value"] or "", n["name"] or ""),
    )
    open_networks = [n["value"] for n in networks if n["open_to_internet"]]

    flags = flag_map(dig_any(settings, "database_flags"))
    engine = engine_family(dig_any(inst, "database_version"))
    relevant = _ENGINE_SECURITY_FLAGS.get(engine, {})
    # Value when the instance sets the flag, None when it does not — an unset flag
    # is the finding for most of these, so it has to be visible, not missing.
    security_flags = {norm: flags.get(api_name) for norm, api_name in relevant.items()}

    ssl_mode = dig_any(ip_config, "ssl_mode") or None
    require_ssl = dig_any(ip_config, "require_ssl")

    return {
        "name": dig_any(inst, "name"),
        "region": dig_any(inst, "region"),
        "database_version": dig_any(inst, "database_version"),
        "engine": engine,
        "state": dig_any(inst, "state"),
        "instance_type": dig_any(inst, "instance_type") or None,
        # --- network exposure ---
        # The addresses themselves are deliberately not copied; the posture fact is
        # whether a public one exists.
        "ip_address_types": ip_types,
        "public_ip": public_ip,
        "private_ip": private_ip,
        "private_ip_only": private_ip and not public_ip,
        "public_ip_enabled": bool(dig_any(ip_config, "ipv4_enabled")),
        "authorized_networks": networks,
        "authorized_network_count": len(networks),
        "open_to_internet": bool(open_networks),
        "open_authorized_networks": open_networks,
        # --- private connectivity ---
        "private_network": dig_any(ip_config, "private_network") or None,
        "allocated_ip_range": dig_any(ip_config, "allocated_ip_range") or None,
        "private_path_for_google_cloud_services": bool(
            dig_any(ip_config, "enable_private_path_for_google_cloud_services")
        ),
        "psc_enabled": bool(dig_any(psc_config, "psc_enabled")),
        "psc_allowed_consumer_projects": sorted(
            dig_any(psc_config, "allowed_consumer_projects") or []
        ),
        # --- transport security ---
        "ssl_mode": ssl_mode,
        "require_ssl": bool(require_ssl),
        "ssl_required": ssl_enforced(ssl_mode, require_ssl),
        "min_tls_version": min_tls_version(flags),
        "server_ca_mode": dig_any(ip_config, "server_ca_mode") or None,
        # --- database flags ---
        "database_flags": flags,
        "database_flag_count": len(flags),
        "security_flags": security_flags,
        "unset_security_flags": sorted(k for k, v in security_flags.items() if v is None),
    }


def summarize(instances: list[dict], *, api_readable: bool = True) -> dict:
    ssl_required = sum(1 for i in instances if i["ssl_required"])
    private_only = sum(1 for i in instances if i["private_ip_only"])
    engines: dict[str, int] = {}
    for inst in instances:
        engines[inst["engine"]] = engines.get(inst["engine"], 0) + 1
    return {
        # False when sqladmin.googleapis.com is not enabled on this project
        # (recorded in metadata.skipped_calls) — distinguishing "no Cloud SQL
        # instances" from "could not look".
        "cloud_sql_api_readable": api_readable,
        "total_instances": len(instances),
        "instances_by_engine": engines,
        "public_ip_instances": sum(1 for i in instances if i["public_ip"]),
        "private_ip_only_instances": private_only,
        "private_ip_only_percentage": coverage_percentage(private_only, len(instances)),
        "ssl_required_instances": ssl_required,
        "ssl_required_percentage": coverage_percentage(ssl_required, len(instances)),
        "instances_with_min_tls_version": sum(
            1 for i in instances if i["min_tls_version"] is not None
        ),
        # The finding: an authorized network of 0.0.0.0/0 reaches the instance
        # from anywhere on the internet.
        "instances_open_to_internet": sum(1 for i in instances if i["open_to_internet"]),
        "instances_with_authorized_networks": sum(
            1 for i in instances if i["authorized_network_count"]
        ),
        "private_network_instances": sum(1 for i in instances if i["private_network"]),
        "private_path_instances": sum(
            1 for i in instances if i["private_path_for_google_cloud_services"]
        ),
        "psc_instances": sum(1 for i in instances if i["psc_enabled"]),
        "instances_with_unset_security_flags": sum(
            1 for i in instances if i["unset_security_flags"]
        ),
    }


# --- collection (lazy google imports; not exercised by the fixture tests) ---

def collect_instances(project, creds, collector: Collector) -> list[dict] | None:
    """Every Cloud SQL instance in the project, or None when it could not list."""
    from googleapiclient.discovery import build

    def _list():
        service = build("sqladmin", "v1beta4", credentials=creds, cache_discovery=False)
        items, page_token = [], None
        while True:
            resp = service.instances().list(project=project, pageToken=page_token).execute()
            items.extend(resp.get("items", []) or [])
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return [instance_record(i) for i in items]

    # A project that has never run Cloud SQL has sqladmin.googleapis.com disabled
    # and the call 403s rather than returning an empty list — evidence, not a
    # failure (the same call the GKE fetcher makes about the Container API).
    records = collector.guard("sqladmin.instances.list", _list, tolerate=service_disabled)
    if records is None:
        return None
    return sorted(records, key=lambda r: r.get("name") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    instances: list[dict] | None = None
    if project and creds is not None:
        instances = collect_instances(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"instances": instances or []},
        summary=summarize(instances or [], api_readable=instances is not None),
    )

    filename = (
        f"gcp_cloud_sql_network_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        # Reported before any success log line: the runner takes the TAIL of
        # stderr as metadata.error when the status file is empty, so an "Evidence
        # saved" INFO line last would become the reported failure reason.
        reason, code = collector.failure_report()
        logger.error("%s", reason)
        write_status(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
