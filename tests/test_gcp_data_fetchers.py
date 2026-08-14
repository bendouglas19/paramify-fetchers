"""Fixture-based tests for the GCP data-platform fetchers.

Covers `gcp_cloud_sql_network_configuration`, `gcp_cloud_sql_backup_configuration`,
`gcp_bigquery_dataset_configuration` and `gcp_secret_manager_configuration` — the
sibling of tests/test_gcp_encryption_fetchers.py and
tests/test_gcp_platform_fetchers.py for the managed data stores and the secret
store.

Like those modules, these exercise each fetcher's PURE transform functions (no
live API calls, no credentials, no google client libraries — the heavy google
imports live inside each fetcher's collect_*() and are never triggered here), plus
an end-to-end run with deliberately-broken credentials.

**Every fixture here is SYNTHETIC.** These four fetchers have had no live-tenant
run, so the fixtures are hand-built from the API's documented resource shapes.
Each set covers a hardened resource and a default/exposed one, because the whole
point is the fields that differ between them — and one fixture per fetcher is
written in the *other* key spelling (snake_case where the API emits camelCase, and
the reverse) to prove the transforms tolerate either.

Three behaviors get their own tests because they are deliberate departures from
the Prowler checks these are ported from, and a future edit could silently undo
them:
- Cloud SQL SSL enforcement falls back to the legacy `requireSsl` when `sslMode`
  is unset (Prowler reports such an instance as not requiring SSL).
- Cloud SQL point-in-time recovery is read per engine (`binaryLogEnabled` on
  MySQL).
- BigQuery public access is matched exactly per ACL entry, so an ordinary account
  named `allusers-admin@example.com` is not a public grant.

And one because it is a hard constraint rather than a projection choice: the
Secret Manager fetcher must never emit a secret's value.

Run: pytest tests/test_gcp_data_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GCP_ROOT = REPO_ROOT / "fetchers" / "gcp"

STATUS_CODES = {
    "auth_failed",
    "not_authorized",
    "target_unreachable",
    "rate_limited",
    "bad_config",
    "partial_failure",
    "internal_error",
}

DATA_FETCHERS = [
    "cloud_sql_network_configuration",
    "cloud_sql_backup_configuration",
    "bigquery_dataset_configuration",
    "secret_manager_configuration",
]

# A fixed "now" so rotation / expiry arithmetic is not a function of the clock.
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GCP_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"gcp_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Cloud SQL network configuration — sqladmin instances.list resources
# --------------------------------------------------------------------------- #

HARDENED_POSTGRES = {  # private IP only, SSL enforced, every audit flag set
    "name": "pf-sql-postgres",
    "region": "us-central1",
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "ipAddresses": [
        {"type": "PRIVATE", "ipAddress": "10.1.2.3"},
        # Every instance has an OUTGOING address, private or not.
        {"type": "OUTGOING", "ipAddress": "34.1.2.3"},
    ],
    "settings": {
        "ipConfiguration": {
            "ipv4Enabled": False,
            "sslMode": "ENCRYPTED_ONLY",
            "privateNetwork": "projects/example-prod/global/networks/prod-vpc",
            "allocatedIpRange": "google-managed-services-prod-vpc",
            "enablePrivatePathForGoogleCloudServices": True,
            "authorizedNetworks": [],
            "serverCaMode": "GOOGLE_MANAGED_INTERNAL_CA",
        },
        "databaseFlags": [
            {"name": "log_checkpoints", "value": "on"},
            {"name": "log_connections", "value": "on"},
            {"name": "log_disconnections", "value": "on"},
            {"name": "log_min_messages", "value": "ERROR"},
            {"name": "log_min_duration_statement", "value": "-1"},
            {"name": "log_min_error_statement", "value": "ERROR"},
            {"name": "log_error_verbosity", "value": "DEFAULT"},
            {"name": "log_statement", "value": "ddl"},
            {"name": "cloudsql.enable_pgaudit", "value": "on"},
            {"name": "ssl_min_protocol_version", "value": "TLSv1.3"},
        ],
    },
}
EXPOSED_MYSQL = {  # public IP, whitelists the internet, no SSL requirement
    "name": "pf-sql-mysql",
    "region": "us-east1",
    "databaseVersion": "MYSQL_8_0",
    "state": "RUNNABLE",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.9.9.9"}],
    "settings": {
        "ipConfiguration": {
            "ipv4Enabled": True,
            "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
            "requireSsl": False,
            "authorizedNetworks": [
                {"name": "office", "value": "203.0.113.4/32"},
                {"name": "everywhere", "value": "0.0.0.0/0"},
            ],
        },
        "databaseFlags": [{"name": "local_infile", "value": "on"}],
    },
}
SQLSERVER_SNAKE = {  # snake_case spelling; SQL Server flag names contain SPACES
    "name": "pf-sql-mssql",
    "region": "us-central1",
    "database_version": "SQLSERVER_2019_STANDARD",
    "state": "RUNNABLE",
    "instance_type": "CLOUD_SQL_INSTANCE",
    "ip_addresses": [{"type": "PRIVATE", "ip_address": "10.4.5.6"}],
    "settings": {
        "ip_configuration": {
            "ipv4_enabled": False,
            "ssl_mode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
            "authorized_networks": [],
        },
        "database_flags": [
            {"name": "cross db ownership chaining", "value": "on"},
            {"name": "contained database authentication", "value": "off"},
            {"name": "3625", "value": "on"},
        ],
    },
}
LEGACY_REQUIRE_SSL = {  # no sslMode at all — only the legacy requireSsl toggle
    "name": "pf-sql-legacy",
    "region": "us-central1",
    "databaseVersion": "POSTGRES_11",
    "state": "RUNNABLE",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.2.2.2"}],
    "settings": {"ipConfiguration": {"ipv4Enabled": True, "requireSsl": True}},
}


def _net_records():
    net = _load("cloud_sql_network_configuration")
    return net, [
        net.instance_record(HARDENED_POSTGRES),
        net.instance_record(EXPOSED_MYSQL),
        net.instance_record(SQLSERVER_SNAKE),
        net.instance_record(LEGACY_REQUIRE_SSL),
    ]


def test_sql_network_private_instance_is_not_public_despite_outgoing_address():
    """The OUTGOING address every instance has must not read as a public IP."""
    _net, (hardened, *_rest) = _net_records()
    assert hardened["ip_address_types"] == ["OUTGOING", "PRIVATE"]
    assert hardened["public_ip"] is False
    assert hardened["private_ip"] is True
    assert hardened["private_ip_only"] is True
    assert hardened["public_ip_enabled"] is False
    assert hardened["private_network"].endswith("networks/prod-vpc")
    assert hardened["private_path_for_google_cloud_services"] is True
    assert hardened["psc_enabled"] is False


def test_sql_network_hardened_instance_enforces_ssl_and_sets_every_flag():
    _net, (hardened, *_rest) = _net_records()
    assert hardened["engine"] == "POSTGRES"
    assert hardened["ssl_mode"] == "ENCRYPTED_ONLY"
    assert hardened["ssl_required"] is True
    # Cloud SQL has no ipConfiguration field for this — it is a database flag.
    assert hardened["min_tls_version"] == "TLSv1.3"
    assert hardened["unset_security_flags"] == []
    assert hardened["database_flag_count"] == 10
    assert hardened["security_flags"]["log_min_messages"] == "ERROR"
    assert hardened["security_flags"]["cloudsql_enable_pgaudit"] == "on"
    assert hardened["open_to_internet"] is False
    assert hardened["authorized_network_count"] == 0


def test_sql_network_open_authorized_network_is_the_finding():
    _net, (_hardened, exposed, *_rest) = _net_records()
    assert exposed["public_ip"] is True
    assert exposed["private_ip_only"] is False
    assert exposed["open_to_internet"] is True
    assert exposed["open_authorized_networks"] == ["0.0.0.0/0"]
    assert exposed["authorized_network_count"] == 2
    # Sorted by CIDR, so the open one is deterministic in the payload.
    assert exposed["authorized_networks"][0]["open_to_internet"] is True
    assert exposed["authorized_networks"][1]["value"] == "203.0.113.4/32"
    assert exposed["authorized_networks"][1]["open_to_internet"] is False
    assert exposed["ssl_required"] is False
    assert exposed["min_tls_version"] is None


def test_sql_network_engine_scopes_which_flags_are_reported():
    """A MySQL instance is never judged on PostgreSQL flags, and vice versa."""
    _net, (hardened, exposed, mssql, _legacy) = _net_records()
    assert exposed["engine"] == "MYSQL"
    assert set(exposed["security_flags"]) == {"local_infile", "skip_show_database", "tls_version"}
    assert exposed["security_flags"]["local_infile"] == "on"
    assert exposed["unset_security_flags"] == ["skip_show_database", "tls_version"]
    assert "log_connections" not in exposed["security_flags"]

    # snake_case fixture, and the SQL Server flag names the API actually uses.
    assert mssql["engine"] == "SQLSERVER"
    assert mssql["ssl_required"] is True
    assert mssql["security_flags"]["cross_db_ownership_chaining"] == "on"
    assert mssql["security_flags"]["contained_database_authentication"] == "off"
    assert mssql["security_flags"]["trace_flag_3625"] == "on"
    assert mssql["database_flags"]["cross db ownership chaining"] == "on"
    assert mssql["unset_security_flags"] == [
        "external_scripts_enabled",
        "remote_access",
        "user_connections",
        "user_options",
    ]
    assert hardened["engine"] == "POSTGRES"


def test_sql_network_legacy_require_ssl_still_counts_as_ssl_required():
    """The documented departure from Prowler, which defaults an absent sslMode."""
    net, (*_rest, legacy) = _net_records()
    assert legacy["ssl_mode"] is None
    assert legacy["require_ssl"] is True
    assert legacy["ssl_required"] is True
    # And the reverse: an explicit permissive mode wins over a stale requireSsl.
    assert net.ssl_enforced("ALLOW_UNENCRYPTED_AND_ENCRYPTED", True) is False
    assert net.ssl_enforced(None, False) is False


def test_sql_network_instance_ip_addresses_are_not_copied():
    """The posture fact is that a public address exists, not what it is."""
    _net, records = _net_records()
    blob = json.dumps(records)
    for address in ("10.1.2.3", "34.1.2.3", "34.9.9.9", "10.4.5.6", "34.2.2.2"):
        assert address not in blob


def test_sql_network_summary():
    net, records = _net_records()
    summary = net.summarize(records)
    assert summary["cloud_sql_api_readable"] is True
    assert summary["total_instances"] == 4
    assert summary["instances_by_engine"] == {"POSTGRES": 2, "MYSQL": 1, "SQLSERVER": 1}
    assert summary["public_ip_instances"] == 2
    assert summary["private_ip_only_instances"] == 2
    assert summary["private_ip_only_percentage"] == 50
    assert summary["ssl_required_instances"] == 3
    assert summary["ssl_required_percentage"] == 75
    assert summary["instances_with_min_tls_version"] == 1
    assert summary["instances_open_to_internet"] == 1
    assert summary["instances_with_authorized_networks"] == 1
    assert summary["private_network_instances"] == 1
    assert summary["private_path_instances"] == 1
    assert summary["psc_instances"] == 0
    assert summary["instances_with_unset_security_flags"] == 3


def test_sql_network_summary_reports_a_disabled_api_as_unreadable():
    """An empty result must not look the same as "the API is off"."""
    net, _records = _net_records()
    summary = net.summarize([], api_readable=False)
    assert summary["cloud_sql_api_readable"] is False
    assert summary["total_instances"] == 0
    assert summary["ssl_required_percentage"] == 0


# --------------------------------------------------------------------------- #
# Cloud SQL backup configuration — the same instances.list resources
# --------------------------------------------------------------------------- #

BACKED_UP_POSTGRES = {
    "name": "pf-sql-postgres",
    "region": "us-central1",
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "createTime": "2025-11-02T18:04:11.123Z",
    "gceZone": "us-central1-a",
    "secondaryGceZone": "us-central1-b",
    "failoverReplica": {"name": "pf-sql-postgres-failover", "available": True},
    "replicaNames": ["pf-sql-postgres-replica"],
    "settings": {
        "availabilityType": "REGIONAL",
        "deletionProtectionEnabled": True,
        "backupConfiguration": {
            "enabled": True,
            "startTime": "03:00",
            "location": "us",
            "pointInTimeRecoveryEnabled": True,
            "transactionLogRetentionDays": 7,
            "transactionalLogStorageState": "CLOUD_STORAGE",
            "backupRetentionSettings": {"retainedBackups": 14, "retentionUnit": "COUNT"},
        },
    },
}
MYSQL_BINLOG_SNAKE = {  # snake_case; MySQL signals PITR through binaryLogEnabled
    "name": "pf-sql-mysql",
    "region": "us-east1",
    "database_version": "MYSQL_8_0",
    "state": "RUNNABLE",
    "instance_type": "CLOUD_SQL_INSTANCE",
    "settings": {
        "availability_type": "ZONAL",
        "backup_configuration": {
            "enabled": True,
            "start_time": "23:00",
            "binary_log_enabled": True,
            "transaction_log_retention_days": 3,
            "backup_retention_settings": {"retained_backups": 7, "retention_unit": "COUNT"},
        },
    },
}
READ_REPLICA = {
    "name": "pf-sql-postgres-replica",
    "region": "us-central1",
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "instanceType": "READ_REPLICA_INSTANCE",
    "masterInstanceName": "example-prod:pf-sql-postgres",
    "settings": {"availabilityType": "ZONAL", "backupConfiguration": {"enabled": False}},
}
NO_BACKUP_ZONAL = {
    "name": "pf-sql-scratch",
    "region": "us-west1",
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "settings": {"availabilityType": "ZONAL", "backupConfiguration": {"enabled": False}},
}


def _backup_records():
    backup = _load("cloud_sql_backup_configuration")
    return backup, [
        backup.instance_record(BACKED_UP_POSTGRES),
        backup.instance_record(MYSQL_BINLOG_SNAKE),
        backup.instance_record(READ_REPLICA),
        backup.instance_record(NO_BACKUP_ZONAL),
    ]


def test_sql_backup_full_recovery_posture():
    _backup, (postgres, *_rest) = _backup_records()
    assert postgres["is_primary"] is True
    assert postgres["backup_enabled"] is True
    assert postgres["backup_start_time"] == "03:00"
    assert postgres["backup_location"] == "us"
    assert postgres["retained_backup_count"] == 14
    assert postgres["retention_unit"] == "COUNT"
    assert postgres["transaction_log_retention_days"] == 7
    assert postgres["point_in_time_recovery_enabled"] is True
    assert postgres["high_availability"] is True
    assert postgres["availability_type"] == "REGIONAL"
    assert postgres["secondary_zone"] == "us-central1-b"
    assert postgres["failover_replica_name"] == "pf-sql-postgres-failover"
    assert postgres["failover_replica_available"] is True
    assert postgres["read_replica_count"] == 1
    assert postgres["deletion_protection_enabled"] is True


def test_sql_backup_point_in_time_recovery_is_read_per_engine():
    """MySQL uses binaryLogEnabled; the PITR toggle it never sets stays visible."""
    _backup, (postgres, mysql, *_rest) = _backup_records()
    assert mysql["point_in_time_recovery_enabled"] is True
    assert mysql["binary_log_enabled"] is True
    assert mysql["pitr_toggle_enabled"] is False       # raw field, kept for audit
    assert mysql["high_availability"] is False
    # PostgreSQL is the mirror image: the toggle answers, binary logging is off.
    assert postgres["pitr_toggle_enabled"] is True
    assert postgres["binary_log_enabled"] is False


def test_sql_backup_read_replica_is_not_a_primary():
    _backup, (*_rest, replica, no_backup) = _backup_records()
    assert replica["is_primary"] is False
    assert replica["master_instance_name"] == "example-prod:pf-sql-postgres"
    assert replica["backup_enabled"] is False
    assert no_backup["is_primary"] is True
    assert no_backup["backup_enabled"] is False
    assert no_backup["point_in_time_recovery_enabled"] is False
    assert no_backup["retained_backup_count"] is None


def test_sql_backup_summary_scopes_high_availability_to_primaries():
    backup, records = _backup_records()
    summary = backup.summarize(records)
    assert summary["cloud_sql_api_readable"] is True
    assert summary["total_instances"] == 4
    assert summary["primary_instances"] == 3
    assert summary["read_replica_instances"] == 1
    assert summary["backup_enabled_instances"] == 2
    assert summary["backup_enabled_percentage"] == 50
    assert summary["point_in_time_recovery_instances"] == 2
    assert summary["point_in_time_recovery_percentage"] == 50
    # 1 of 3 PRIMARIES, not 1 of 4 instances — a replica cannot be configured
    # either way.
    assert summary["high_availability_instances"] == 1
    assert summary["high_availability_percentage"] == 33
    assert summary["zonal_primary_instances"] == 2
    assert summary["instances_with_failover_replica"] == 1
    assert summary["instances_with_read_replicas"] == 1
    assert summary["deletion_protection_instances"] == 1
    # The weakest link, not the average.
    assert summary["minimum_retained_backup_count"] == 7
    assert summary["maximum_retained_backup_count"] == 14
    assert summary["minimum_transaction_log_retention_days"] == 3
    assert summary["maximum_transaction_log_retention_days"] == 7


def test_sql_backup_summary_on_an_empty_project():
    backup, _records = _backup_records()
    summary = backup.summarize([], api_readable=False)
    assert summary["cloud_sql_api_readable"] is False
    assert summary["high_availability_percentage"] == 0
    assert summary["minimum_retained_backup_count"] is None


# --------------------------------------------------------------------------- #
# BigQuery datasets — Dataset.to_api_repr() (REST camelCase)
# --------------------------------------------------------------------------- #

CMEK_DATASET = {
    "id": "example-prod:analytics_secure",
    "datasetReference": {"projectId": "example-prod", "datasetId": "analytics_secure"},
    "location": "US",
    "friendlyName": "Secure analytics",
    "labels": {"owner": "data-platform"},
    "creationTime": "1730000000000",
    "lastModifiedTime": "1740000000000",
    "defaultEncryptionConfiguration": {
        "kmsKeyName": "projects/example-prod/locations/us/keyRings/bq/cryptoKeys/analytics"
    },
    "defaultTableExpirationMs": "5184000000",       # 60 days
    "maxTimeTravelHours": "168",
    "access": [
        {"role": "OWNER", "specialGroup": "projectOwners"},
        {"role": "WRITER", "userByEmail": "data-eng@example.com"},
        {"role": "READER", "groupByEmail": "analysts@example.com"},
    ],
}
PUBLIC_DATASET = {
    "id": "example-prod:public_share",
    "datasetReference": {"projectId": "example-prod", "datasetId": "public_share"},
    "location": "us-central1",
    "access": [
        {"role": "READER", "specialGroup": "allAuthenticatedUsers"},
        {"role": "READER", "iamMember": "allUsers"},
        # The account Prowler's substring grep would misread as a public grant.
        {"role": "OWNER", "userByEmail": "allusers-admin@example.com"},
    ],
}
DOMAIN_DATASET = {
    "id": "example-prod:partner_feed",
    "datasetReference": {"projectId": "example-prod", "datasetId": "partner_feed"},
    "location": "EU",
    "access": [
        {"role": "READER", "domain": "example.com"},
        {
            "view": {
                "projectId": "example-prod",
                "datasetId": "analytics_secure",
                "tableId": "shared_view",
            }
        },
    ],
}


def _bq_records():
    bq = _load("bigquery_dataset_configuration")
    return bq, [
        bq.dataset_record(CMEK_DATASET),
        bq.dataset_record(PUBLIC_DATASET),
        bq.dataset_record(DOMAIN_DATASET),
    ]


def test_bigquery_cmek_detected_by_presence():
    _bq, (cmek, public, _domain) = _bq_records()
    assert cmek["name"] == "analytics_secure"
    assert cmek["project"] == "example-prod"
    assert cmek["location"] == "US"
    assert cmek["cmek"] is True
    assert cmek["kms_key_name"].endswith("cryptoKeys/analytics")
    assert cmek["labels"] == {"owner": "data-platform"}
    # Google-managed: the whole defaultEncryptionConfiguration block is absent.
    assert public["cmek"] is False
    assert public["kms_key_name"] is None


def test_bigquery_default_table_expiration_is_reported_in_days():
    _bq, (cmek, public, _domain) = _bq_records()
    assert cmek["default_table_expiration_ms"] == "5184000000"
    assert cmek["default_table_expiration_days"] == 60
    assert cmek["has_default_table_expiration"] is True
    assert cmek["max_time_travel_hours"] == "168"
    assert public["has_default_table_expiration"] is False
    assert public["default_table_expiration_days"] is None


def test_bigquery_public_acl_entries_are_named():
    _bq, (_cmek, public, _domain) = _bq_records()
    assert public["publicly_accessible"] is True
    assert [e["principal"] for e in public["public_access_entries"]] == [
        "allAuthenticatedUsers",
        "allUsers",
    ]
    assert [e["principal_type"] for e in public["public_access_entries"]] == [
        "specialGroup",
        "iamMember",
    ]
    assert public["access_entry_count"] == 3


def test_bigquery_public_access_is_matched_exactly_not_grepped():
    """The documented departure: allusers-admin@example.com is not allUsers."""
    bq, (_cmek, public, _domain) = _bq_records()
    assert bq.is_public_principal("allUsers") is True
    assert bq.is_public_principal("allAuthenticatedUsers") is True
    assert bq.is_public_principal("allusers-admin@example.com") is False
    assert bq.is_public_principal("user:allAuthenticatedUsers") is True
    assert bq.is_public_principal(None) is False

    # Prowler stringifies the whole ACL and greps, so this dataset's OWNER entry
    # would make it public a second time over. Here only the two real public
    # entries are flagged, and the account is not even named.
    assert len(public["public_access_entries"]) == 2
    owner = bq.access_entry_record({"role": "OWNER", "userByEmail": "allusers-admin@example.com"})
    assert owner["public"] is False
    assert owner["principal_type"] == "userByEmail"
    assert owner["principal"] is None


def test_bigquery_human_identities_are_counted_not_enumerated():
    _bq, (cmek, public, _domain) = _bq_records()
    # projectOwners is a special group, not a person — safe to name.
    assert [e["principal"] for e in cmek["access_entries"]] == ["projectOwners"]
    assert cmek["access_entry_counts_by_principal_type"] == {
        "specialGroup": 1,
        "userByEmail": 1,
        "groupByEmail": 1,
    }
    assert cmek["access_roles"] == ["OWNER", "READER", "WRITER"]
    blob = json.dumps([cmek, public])
    assert "data-eng@example.com" not in blob
    assert "analysts@example.com" not in blob
    assert "allusers-admin@example.com" not in blob


def test_bigquery_domain_and_authorized_view_entries():
    _bq, (_cmek, _public, domain) = _bq_records()
    assert domain["domain_access"] == ["example.com"]
    assert domain["publicly_accessible"] is False
    assert domain["access_entry_counts_by_principal_type"] == {"domain": 1, "view": 1}
    view = next(e for e in domain["access_entries"] if e["principal_type"] == "view")
    assert view["principal"] == "example-prod.analytics_secure.shared_view"
    assert view["role"] is None          # authorized views carry no role
    # An authorized view is a resource reference, never a public principal.
    assert view["public"] is False


def test_bigquery_summary_expresses_cmek_coverage_and_public_datasets():
    bq, records = _bq_records()
    summary = bq.summarize(records)
    assert summary["bigquery_api_readable"] is True
    assert summary["total_datasets"] == 3
    assert summary["cmek_datasets"] == 1
    assert summary["google_managed_datasets"] == 2
    assert summary["cmek_percentage"] == 33
    assert len(summary["distinct_kms_keys"]) == 1
    assert summary["publicly_accessible_datasets"] == 1
    # Counted independently — one dataset grants both principals.
    assert summary["datasets_with_all_users"] == 1
    assert summary["datasets_with_all_authenticated_users"] == 1
    assert summary["non_public_dataset_percentage"] == 66
    assert summary["datasets_with_domain_access"] == 1
    assert summary["datasets_with_default_table_expiration"] == 1
    assert summary["locations"] == ["EU", "US", "us-central1"]


def test_bigquery_summary_reports_a_disabled_api_as_unreadable():
    bq, _records = _bq_records()
    summary = bq.summarize([], api_readable=False)
    assert summary["bigquery_api_readable"] is False
    assert summary["cmek_percentage"] == 0
    assert summary["locations"] == []


# --------------------------------------------------------------------------- #
# Secret Manager — Secret.to_dict() / SecretVersion.to_dict() (snake_case)
# --------------------------------------------------------------------------- #

HARDENED_SECRET = {
    "name": "projects/example-prod/secrets/db-password",
    "create_time": "2026-01-04T10:00:00Z",
    "labels": {"owner": "platform", "rotation": "managed"},
    "replication": {
        "user_managed": {
            "replicas": [
                {
                    "location": "us-central1",
                    "customer_managed_encryption": {
                        "kms_key_name": "projects/example-prod/locations/us-central1/keyRings/secrets/cryptoKeys/sm"
                    },
                },
                {
                    "location": "us-east1",
                    "customer_managed_encryption": {
                        "kms_key_name": "projects/example-prod/locations/us-east1/keyRings/secrets/cryptoKeys/sm"
                    },
                },
            ]
        }
    },
    "rotation": {"rotation_period": "2592000s", "next_rotation_time": "2026-09-01T00:00:00Z"},
    "topics": [{"name": "projects/example-prod/topics/secret-rotation"}],
    "version_destroy_ttl": "86400s",
}
HARDENED_VERSIONS = [
    {
        "name": "projects/example-prod/secrets/db-password/versions/1",
        "state": "DESTROYED",
        "create_time": "2026-01-04T10:00:00Z",
        "destroy_time": "2026-05-04T10:00:00Z",
    },
    {
        "name": "projects/example-prod/secrets/db-password/versions/2",
        "state": "ENABLED",
        "create_time": "2026-05-04T10:00:00Z",
        "customer_managed_encryption": {
            "kms_key_version_name": "projects/example-prod/locations/us-central1/keyRings/secrets/cryptoKeys/sm/cryptoKeyVersions/3"
        },
    },
]
HARDENED_BINDINGS = [
    {
        "role": "roles/secretmanager.secretAccessor",
        "members": ["serviceAccount:api@example-prod.iam.gserviceaccount.com"],
    }
]

PUBLIC_SECRET = {  # camelCase spelling, automatic replication, no CMEK, expiring
    "name": "projects/example-prod/secrets/legacy-api-key",
    "createTime": "2024-02-01T00:00:00Z",
    "replication": {"automatic": {}},
    "expireTime": "2026-03-01T00:00:00Z",
}
PUBLIC_VERSIONS = [
    {
        "name": "projects/example-prod/secrets/legacy-api-key/versions/1",
        "state": "ENABLED",
        "createTime": "2024-02-01T00:00:00Z",
    }
]
PUBLIC_BINDINGS = [
    {
        "role": "roles/secretmanager.secretAccessor",
        "members": ["allUsers", "user:dev@example.com"],
    }
]

OVERDUE_SECRET = {  # rotation configured but the schedule has passed; mixed CMEK
    "name": "projects/example-prod/secrets/signing-key",
    "create_time": "2025-01-01T00:00:00Z",
    "replication": {
        "user_managed": {
            "replicas": [
                {
                    "location": "us-central1",
                    "customer_managed_encryption": {
                        "kms_key_name": "projects/example-prod/locations/us-central1/keyRings/secrets/cryptoKeys/sm"
                    },
                },
                {"location": "europe-west1"},
            ]
        }
    },
    "rotation": {"rotation_period": "31536000s", "next_rotation_time": "2026-02-01T00:00:00Z"},
}
OVERDUE_VERSIONS = [
    {
        "name": "projects/example-prod/secrets/signing-key/versions/1",
        "state": "DISABLED",
        "create_time": "2025-01-01T00:00:00Z",
    }
]


def _secret_records():
    sm = _load("secret_manager_configuration")
    return sm, [
        sm.secret_record(HARDENED_SECRET, HARDENED_VERSIONS, HARDENED_BINDINGS, NOW),
        sm.secret_record(PUBLIC_SECRET, PUBLIC_VERSIONS, PUBLIC_BINDINGS, NOW),
        sm.secret_record(OVERDUE_SECRET, OVERDUE_VERSIONS, [], NOW),
    ]


def test_secret_user_managed_replication_with_cmek_on_every_replica():
    _sm, (hardened, *_rest) = _secret_records()
    assert hardened["name"] == "db-password"
    assert hardened["location"] == "global"
    assert hardened["replication_policy"] == "user_managed"
    assert hardened["replica_locations"] == ["us-central1", "us-east1"]
    assert hardened["replica_count"] == 2
    assert hardened["cmek"] is True
    assert hardened["replicas_with_cmek"] == 2
    assert len(hardened["kms_key_names"]) == 2
    assert hardened["labels"] == {"owner": "platform", "rotation": "managed"}


def test_secret_cmek_requires_every_replica_to_have_a_key():
    """One Google-managed replica makes the secret Google-managed where it counts."""
    _sm, (*_rest, overdue) = _secret_records()
    assert overdue["replica_count"] == 2
    assert overdue["replicas_with_cmek"] == 1
    assert overdue["cmek"] is False
    assert overdue["replicas"][0]["location"] == "europe-west1"
    assert overdue["replicas"][0]["cmek"] is False


def test_secret_rotation_period_and_overdue_schedule():
    _sm, (hardened, default, overdue) = _secret_records()
    assert hardened["rotation_configured"] is True
    assert hardened["rotation_period"] == "2592000s"
    assert hardened["rotation_period_days"] == 30
    assert hardened["rotation_overdue"] is False
    assert hardened["notification_topic_count"] == 1
    assert hardened["version_destroy_ttl"] == "86400s"

    # Configured but not firing — "configured" alone would look healthy.
    assert overdue["rotation_period_days"] == 365
    assert overdue["rotation_overdue"] is True

    assert default["rotation_configured"] is False
    assert default["rotation_period_days"] is None
    assert default["rotation_overdue"] is False


def test_secret_automatic_replication_and_expiry_camel_case():
    _sm, (_hardened, default, _overdue) = _secret_records()
    assert default["replication_policy"] == "automatic"
    assert default["replica_count"] == 1
    assert default["replica_locations"] == []       # Google picks the regions
    assert default["cmek"] is False
    assert default["create_time"] == "2024-02-01T00:00:00Z"
    assert default["has_expiry"] is True
    assert default["expired"] is True               # relative to the fixed NOW


def test_secret_version_states_are_counted_and_payloads_never_appear():
    _sm, (hardened, _default, overdue) = _secret_records()
    assert hardened["version_count"] == 2
    assert hardened["version_states"] == {
        "ENABLED": 1,
        "DISABLED": 0,
        "DESTROYED": 1,
        "STATE_UNSPECIFIED": 0,
    }
    assert hardened["enabled_version_count"] == 1
    assert hardened["latest_enabled_version_create_time"] == "2026-05-04T10:00:00Z"
    assert [v["id"] for v in hardened["versions"]] == ["1", "2"]
    assert hardened["versions"][1]["kms_key_version"].endswith("cryptoKeyVersions/3")
    assert overdue["enabled_version_count"] == 0

    # The hard constraint: a version record carries state and timestamps only.
    assert set(hardened["versions"][0]) == {
        "id",
        "state",
        "create_time",
        "destroy_time",
        "scheduled_destroy_time",
        "kms_key_version",
    }


def _code_identifiers(path: Path) -> set[str]:
    """Identifiers and non-docstring string literals in a module's executable code.

    AST-based on purpose: this fetcher's docstrings name AccessSecretVersion
    precisely in order to say it is never called, so a grep over the file text
    cannot tell the promise apart from the breach.
    """
    tree = ast.parse(path.read_text())
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            found.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value not in docstrings:
                found.add(node.value)
    return {name.lower() for name in found}


def test_secret_manager_fetcher_never_calls_access_secret_version():
    """The one call that returns a secret's value must not be reachable at all."""
    identifiers = _code_identifiers(GCP_ROOT / "secret_manager_configuration" / "fetcher.py")
    for forbidden in (
        "access_secret_version",
        "accesssecretversion",
        "secret_data",
        "secretdata",
        "client_specified_payload_checksum",
    ):
        offenders = sorted(i for i in identifiers if forbidden in i)
        assert not offenders, f"{forbidden!r} reachable from the fetcher's code: {offenders}"
    # The three read calls it IS allowed to make.
    assert "list_secrets" in identifiers
    assert "list_secret_versions" in identifiers
    assert "get_iam_policy" in identifiers


def test_secret_records_carry_no_payload_shaped_field():
    """Belt and braces on the record shape, not just on the call the fetcher makes."""
    _sm, records = _secret_records()
    blob = json.dumps(records).lower()
    for forbidden in ("payload", "secret_data", "checksum", "secretdata"):
        assert forbidden not in blob


def test_secret_public_binding_is_the_finding_and_people_are_counted():
    _sm, (hardened, default, _overdue) = _secret_records()
    assert default["publicly_accessible"] is True
    assert default["public_access_members"] == ["allUsers"]
    binding = default["iam_policy_bindings"][0]
    assert binding["role"] == "roles/secretmanager.secretAccessor"
    assert binding["member_count"] == 2
    assert binding["public_members"] == ["allUsers"]
    assert binding["service_account_members"] == []
    assert binding["other_member_count"] == 1
    assert binding["personal_member_count"] == 1
    assert "dev@example.com" not in json.dumps(default)

    assert hardened["publicly_accessible"] is False
    assert hardened["iam_policy_bindings"][0]["service_account_members"] == [
        "serviceAccount:api@example-prod.iam.gserviceaccount.com"
    ]


def test_secret_helpers():
    sm, _records = _secret_records()
    assert sm.parse_duration_seconds("7776000s") == 7776000
    assert sm.parse_duration_seconds("600") == 600
    assert sm.parse_duration_seconds(None) is None
    assert sm.parse_duration_seconds("not-a-duration") is None
    assert sm.secret_location("projects/p/secrets/x") == "global"
    assert sm.secret_location("projects/p/locations/us-east1/secrets/x") == "us-east1"
    assert sm.is_public_member("allAuthenticatedUsers") is True
    assert sm.is_public_member("serviceAccount:allusers@example.iam.gserviceaccount.com") is False


def test_secret_summary():
    sm, records = _secret_records()
    summary = sm.summarize(records)
    assert summary["secret_manager_api_readable"] is True
    assert summary["total_secrets"] == 3
    assert summary["secrets_with_rotation"] == 2
    assert summary["rotation_percentage"] == 66
    assert summary["max_rotation_period_days"] == 90
    assert summary["secrets_rotating_within_max_period"] == 1
    assert summary["secrets_with_overdue_rotation"] == 1
    assert summary["longest_rotation_period_days"] == 365
    assert summary["cmek_secrets"] == 1
    assert summary["google_managed_secrets"] == 2
    assert summary["cmek_percentage"] == 33
    assert summary["automatic_replication_secrets"] == 1
    assert summary["user_managed_replication_secrets"] == 2
    assert summary["replica_locations"] == ["europe-west1", "us-central1", "us-east1"]
    assert summary["publicly_accessible_secrets"] == 1
    assert summary["non_public_secret_percentage"] == 66
    assert summary["secrets_with_expiry"] == 1
    assert summary["secrets_with_no_enabled_version"] == 1
    assert summary["total_versions"] == 4
    assert summary["enabled_versions"] == 2
    assert summary["disabled_versions"] == 1
    assert summary["destroyed_versions"] == 1


def test_secret_summary_reports_a_disabled_api_as_unreadable():
    sm, _records = _secret_records()
    summary = sm.summarize([], api_readable=False)
    assert summary["secret_manager_api_readable"] is False
    assert summary["rotation_percentage"] == 0
    assert summary["replica_locations"] == []


# --------------------------------------------------------------------------- #
# End to end with broken credentials. Offline: GOOGLE_APPLICATION_CREDENTIALS
# points at a file that does not exist, so ADC resolution fails before any
# network call. (Deliberately a local copy of the harness in
# test_gcp_encryption_fetchers.py / test_gcp_platform_fetchers.py — each test
# module stands alone, and the repo has no tests/conftest.py to share it through.)
# --------------------------------------------------------------------------- #

def run_with_broken_credentials(short_name: str, tmp_path: Path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    status_file = tmp_path / "status.json"
    env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TZ")},
        "PYTHONUNBUFFERED": "1",
        "EVIDENCE_DIR": str(evidence_dir),
        "FETCHER_STATUS_FILE": str(status_file),
        "GOOGLE_CLOUD_PROJECT": "paramify-not-a-real-project",
        "GCP_ENVIRONMENT": "pytest",
        "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "no-such-adc.json"),
        "CLOUDSDK_CONFIG": str(tmp_path / "no-such-gcloud-config"),
    }
    proc = subprocess.run(
        [sys.executable, str(GCP_ROOT / short_name / "fetcher.py")],
        env=env, capture_output=True, text=True, timeout=300,
    )
    return proc, evidence_dir, status_file


@pytest.mark.parametrize("short_name", DATA_FETCHERS)
def test_broken_credentials_fail_loudly_and_explain_themselves(short_name, tmp_path):
    pytest.importorskip("dotenv")
    proc, evidence_dir, status_file = run_with_broken_credentials(short_name, tmp_path)

    assert proc.returncode != 0, "unusable credentials must not look like success"

    evidence_files = list(evidence_dir.glob("*.json"))
    assert len(evidence_files) == 1, f"expected one evidence file, got {evidence_files}"
    payload = json.loads(evidence_files[0].read_text())
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"]

    assert status_file.exists(), "no failure reason reported to $FETCHER_STATUS_FILE"
    body = json.loads(status_file.read_text())
    assert set(body) <= {"error", "code"}
    assert isinstance(body["error"], str) and body["error"].strip()
    assert "\n" not in body["error"]
    assert body["code"] in STATUS_CODES
    assert "google.auth.default" in body["error"], f"unexpected reason: {body['error']}"

    # The issue #24 regression: the reason must not be the success message, which
    # is what the runner would have taken from the tail of stderr.
    assert "Evidence saved" not in body["error"]
    assert "Evidence saved" not in proc.stderr.strip().splitlines()[-1]
