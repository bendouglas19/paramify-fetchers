#!/usr/bin/env python3
"""
GCP Cloud SQL Backup & High Availability Configuration

The recovery-planning evidence for Cloud SQL: for each instance in one project,
whether automated backups run and in which window, whether point-in-time recovery
is on (binary logging on MySQL, the PITR toggle elsewhere), how many backups and
how many days of transaction log are retained, and whether the instance is
regional (a standby in a second zone, automatic failover) or zonal.

Ported from Prowler's GCP Cloud SQL service (prowler/providers/gcp/services/
cloudsql/cloudsql_service.py, Apache-2.0), whose Instance projects
automated_backups (settings.backupConfiguration.enabled), availability_type and
instance_type — the fields behind cloudsql_instance_automated_backups and
cloudsql_instance_high_availability_enabled. Prowler stops at those two booleans;
the same `instances.list` response also carries the retention counts, the backup
window, the transaction-log retention and the replica topology, which is what
turns "backups are on" into recovery evidence. No extra API calls.

Sibling fetchers reading the same one response: gcp_cloud_sql_network_configuration
(boundary posture) and gcp_cloud_sql_encryption_status (CMEK).

Uses the official Google API Python client (discovery: sqladmin v1beta4) — Cloud
SQL Admin has no stable dedicated GAPIC client, so the category's "prefer GAPIC"
rule does not apply here.

Two deliberate departures from the Prowler original:
- **PITR is read per engine.** MySQL signals point-in-time recovery through
  `binaryLogEnabled`, PostgreSQL and SQL Server through
  `pointInTimeRecoveryEnabled`. Prowler reads neither; a fetcher that read only
  one would report every instance on the other engine as unprotected. Both raw
  fields stay in the evidence next to the derived answer.
- **High availability is scoped to primaries.** A read replica has no
  availabilityType of its own — it inherits from its primary — so the HA
  percentage is over primary instances only (Prowler's check skips replicas the
  same way, by filtering instanceType).

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

logger = logging.getLogger("gcp_cloud_sql_backup_configuration")

# The instanceType that identifies a primary. Read replicas (READ_REPLICA_INSTANCE)
# and the legacy first-generation type inherit availability from their primary.
_PRIMARY_INSTANCE_TYPE = "CLOUD_SQL_INSTANCE"

# availabilityType that provisions a standby in a second zone with automatic
# failover. ZONAL (the default) has neither.
_REGIONAL_AVAILABILITY = "REGIONAL"


# --- pure transforms (operate on REST-style dicts; unit-tested from fixtures) ---

def is_mysql(database_version) -> bool:
    """MySQL is the engine whose PITR signal is binaryLogEnabled, not the toggle."""
    return "MYSQL" in str(database_version or "").upper()


def point_in_time_recovery(backup: dict, database_version) -> bool:
    """Whether the instance can be restored to an arbitrary moment.

    Engine-specific by design — see the module docstring. Reads the field that
    actually governs the engine in question rather than OR-ing the two, so a MySQL
    instance cannot look protected because of a field MySQL does not use.
    """
    if is_mysql(database_version):
        return bool(dig_any(backup, "binary_log_enabled"))
    return bool(dig_any(backup, "point_in_time_recovery_enabled"))


def instance_record(inst: dict) -> dict:
    """Normalize one Cloud SQL instance resource into a recovery-posture record."""
    settings = dig_any(inst, "settings") or {}
    backup = dig_any(settings, "backup_configuration") or {}
    retention = dig_any(backup, "backup_retention_settings") or {}
    failover_replica = dig_any(inst, "failover_replica") or {}

    database_version = dig_any(inst, "database_version")
    instance_type = dig_any(inst, "instance_type") or None
    availability_type = dig_any(settings, "availability_type") or None
    replica_names = sorted(dig_any(inst, "replica_names") or [])

    return {
        "name": dig_any(inst, "name"),
        "region": dig_any(inst, "region"),
        "database_version": database_version,
        "state": dig_any(inst, "state"),
        "instance_type": instance_type,
        "is_primary": instance_type == _PRIMARY_INSTANCE_TYPE,
        "master_instance_name": dig_any(inst, "master_instance_name") or None,
        "create_time": dig_any(inst, "create_time") or None,
        # --- automated backups ---
        "backup_enabled": bool(dig_any(backup, "enabled")),
        # HH:MM UTC — the start of the daily backup window.
        "backup_start_time": dig_any(backup, "start_time") or None,
        "backup_location": dig_any(backup, "location") or None,
        "retained_backup_count": dig_any(retention, "retained_backups"),
        "retention_unit": dig_any(retention, "retention_unit") or None,
        # --- point-in-time recovery ---
        "point_in_time_recovery_enabled": point_in_time_recovery(backup, database_version),
        # Both raw fields kept so the engine-specific derivation above is auditable.
        "pitr_toggle_enabled": bool(dig_any(backup, "point_in_time_recovery_enabled")),
        "binary_log_enabled": bool(dig_any(backup, "binary_log_enabled")),
        "transaction_log_retention_days": dig_any(backup, "transaction_log_retention_days"),
        "transactional_log_storage_state": dig_any(
            backup, "transactional_log_storage_state"
        ) or None,
        # --- high availability / topology ---
        "availability_type": availability_type,
        "high_availability": availability_type == _REGIONAL_AVAILABILITY,
        "zone": dig_any(inst, "gce_zone") or None,
        "secondary_zone": dig_any(inst, "secondary_gce_zone") or None,
        "failover_replica_name": dig_any(failover_replica, "name") or None,
        "failover_replica_available": bool(dig_any(failover_replica, "available")),
        "read_replica_names": replica_names,
        "read_replica_count": len(replica_names),
        # Not a backup, but the control that stops a recovery plan being defeated
        # by a delete.
        "deletion_protection_enabled": bool(dig_any(settings, "deletion_protection_enabled")),
    }


def summarize(instances: list[dict], *, api_readable: bool = True) -> dict:
    # HA is a property of a primary; replicas inherit it, so including them would
    # dilute the percentage with instances that cannot be configured either way.
    primaries = [i for i in instances if i["is_primary"]]
    backed_up = sum(1 for i in instances if i["backup_enabled"])
    pitr = sum(1 for i in instances if i["point_in_time_recovery_enabled"])
    regional = sum(1 for i in primaries if i["high_availability"])

    retained = [
        i["retained_backup_count"] for i in instances if i["retained_backup_count"] is not None
    ]
    log_days = [
        i["transaction_log_retention_days"]
        for i in instances
        if i["transaction_log_retention_days"] is not None
    ]
    return {
        # False when sqladmin.googleapis.com is not enabled on this project
        # (recorded in metadata.skipped_calls) — distinguishing "no Cloud SQL
        # instances" from "could not look".
        "cloud_sql_api_readable": api_readable,
        "total_instances": len(instances),
        "primary_instances": len(primaries),
        "read_replica_instances": len(instances) - len(primaries),
        "backup_enabled_instances": backed_up,
        "backup_enabled_percentage": coverage_percentage(backed_up, len(instances)),
        "point_in_time_recovery_instances": pitr,
        "point_in_time_recovery_percentage": coverage_percentage(pitr, len(instances)),
        "high_availability_instances": regional,
        "high_availability_percentage": coverage_percentage(regional, len(primaries)),
        "zonal_primary_instances": len(primaries) - regional,
        "instances_with_failover_replica": sum(
            1 for i in instances if i["failover_replica_name"]
        ),
        "instances_with_read_replicas": sum(1 for i in instances if i["read_replica_count"]),
        "deletion_protection_instances": sum(
            1 for i in instances if i["deletion_protection_enabled"]
        ),
        # The weakest link, not the average: a recovery plan is bounded by its
        # shortest retention.
        "minimum_retained_backup_count": min(retained) if retained else None,
        "maximum_retained_backup_count": max(retained) if retained else None,
        "minimum_transaction_log_retention_days": min(log_days) if log_days else None,
        "maximum_transaction_log_retention_days": max(log_days) if log_days else None,
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
        f"gcp_cloud_sql_backup_configuration_{sanitize_for_filename(project or 'unknown')}.json"
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
