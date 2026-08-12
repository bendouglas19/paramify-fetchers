"""Fixture-based tests for the GCP encryption-at-rest fetchers.

These exercise each fetcher's PURE transform functions against fixture responses
(no live API calls, no credentials, no google client libraries needed — the
heavy google imports live inside each fetcher's collect_*() and are never
triggered here). The fixtures are the shapes captured from the throwaway test
project (project-instructions/gcp-test-environment-setup.md → gcp-api-samples/),
plus a small number of clearly-labelled SYNTHETIC entries for the "green" cases
the test project did not create (a CMEK Cloud SQL instance, an HSM key).

The whole point of these fetchers: on GCP everything is encrypted at rest by
default, so the only meaningful signal is CMEK vs Google-managed and the key's
configuration. Each test asserts that distinction, not "encrypted: true".

Run: pytest tests/test_gcp_encryption_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GCP_ROOT = REPO_ROOT / "fetchers" / "gcp"


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GCP_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"gcp_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Persistent disks (+ snapshots) — gcp-api-samples/disks.json, snapshots.json
# --------------------------------------------------------------------------- #

CMEK_DISK = {  # gcp-api-samples/disks.json[0]
    "name": "cmek-disk",
    "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
    "type": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/diskTypes/pd-standard",
    "status": "READY",
    "sizeGb": "10",
    "diskEncryptionKey": {
        "kmsKeyName": "projects/p/locations/us-central1/keyRings/paramify-test-ring/cryptoKeys/rotating-key/cryptoKeyVersions/1"
    },
}
DEFAULT_DISK = {  # gcp-api-samples/disks.json[1] — NO diskEncryptionKey block at all
    "name": "default-disk",
    "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
    "type": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/diskTypes/pd-standard",
    "status": "READY",
    "sizeGb": "10",
}
CMEK_SNAP = {  # gcp-api-samples/snapshots.json[0]
    "name": "cmek-snap",
    "sourceDisk": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/disks/cmek-disk",
    "status": "READY",
    "diskSizeGb": "10",
    "storageLocations": ["us"],
    "snapshotEncryptionKey": {
        "kmsKeyName": "projects/p/locations/us-central1/keyRings/paramify-test-ring/cryptoKeys/rotating-key/cryptoKeyVersions/1"
    },
}
DEFAULT_SNAP = {  # gcp-api-samples/snapshots.json[1] — NO snapshotEncryptionKey
    "name": "default-snap",
    "sourceDisk": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/disks/default-disk",
    "status": "READY",
    "diskSizeGb": "10",
    "storageLocations": ["us"],
}


def test_disk_cmek_detected_by_presence():
    pd = _load("persistent_disk_encryption_status")
    rec = pd.disk_record(CMEK_DISK)
    assert rec["cmek"] is True
    assert rec["kms_key_name"].endswith("cryptoKeys/rotating-key/cryptoKeyVersions/1")
    assert rec["zone"] == "us-central1-a"          # basename of the full URL
    assert rec["type"] == "pd-standard"


def test_disk_google_managed_when_key_absent():
    pd = _load("persistent_disk_encryption_status")
    rec = pd.disk_record(DEFAULT_DISK)
    assert rec["cmek"] is False
    assert rec["kms_key_name"] is None


def test_snapshot_cmek_and_default():
    pd = _load("persistent_disk_encryption_status")
    assert pd.snapshot_record(CMEK_SNAP)["cmek"] is True
    assert pd.snapshot_record(CMEK_SNAP)["source_disk"] == "cmek-disk"
    assert pd.snapshot_record(DEFAULT_SNAP)["cmek"] is False


def test_disk_summary_counts_and_percentage():
    pd = _load("persistent_disk_encryption_status")
    disks = [pd.disk_record(CMEK_DISK), pd.disk_record(DEFAULT_DISK)]
    snaps = [pd.snapshot_record(CMEK_SNAP), pd.snapshot_record(DEFAULT_SNAP)]
    summary = pd.summarize(disks, snaps)
    assert summary["total_disks"] == 2
    assert summary["cmek_disks"] == 1
    assert summary["cmek_disk_percentage"] == 50
    assert summary["cmek_snapshots"] == 1


# --------------------------------------------------------------------------- #
# Cloud Storage — real GCS JSON API shape (nested, camelCase) AND the flattened
# `gcloud storage buckets describe` shape (gcp-api-samples/bucket-*.json)
# --------------------------------------------------------------------------- #

CMEK_BUCKET_REST = {  # real storage API resource (bucket._properties)
    "name": "pf-test-cmek-23684",
    "location": "US-CENTRAL1",
    "locationType": "region",
    "encryption": {
        "defaultKmsKeyName": "projects/p/locations/us-central1/keyRings/paramify-test-ring/cryptoKeys/rotating-key"
    },
    "iamConfiguration": {
        "uniformBucketLevelAccess": {"enabled": True},
        "publicAccessPrevention": "inherited",
    },
    "versioning": {"enabled": True},
    "retentionPolicy": {"retentionPeriod": "2592000"},
}
DEFAULT_BUCKET_GCLOUD = {  # gcp-api-samples/bucket-default.json (gcloud snake_case)
    "name": "pf-test-default-25252",
    "location": "US-CENTRAL1",
    "location_type": "region",
    "public_access_prevention": "inherited",
    "uniform_bucket_level_access": True,
}


def test_bucket_cmek_real_api_shape():
    st = _load("cloud_storage_encryption_status")
    rec = st.bucket_record(CMEK_BUCKET_REST)
    assert rec["cmek"] is True
    assert rec["kms_key_name"].endswith("cryptoKeys/rotating-key")
    assert rec["uniform_bucket_level_access"] is True
    assert rec["versioning_enabled"] is True
    assert rec["has_retention_policy"] is True


def test_bucket_google_managed_gcloud_shape():
    st = _load("cloud_storage_encryption_status")
    rec = st.bucket_record(DEFAULT_BUCKET_GCLOUD)
    assert rec["cmek"] is False              # transform tolerates snake_case gcloud output
    assert rec["kms_key_name"] is None
    assert rec["uniform_bucket_level_access"] is True
    assert rec["versioning_enabled"] is False
    assert rec["has_retention_policy"] is False


def test_bucket_summary():
    st = _load("cloud_storage_encryption_status")
    buckets = [st.bucket_record(CMEK_BUCKET_REST), st.bucket_record(DEFAULT_BUCKET_GCLOUD)]
    summary = st.summarize(buckets)
    assert summary["total_buckets"] == 2
    assert summary["cmek_buckets"] == 1
    assert summary["cmek_percentage"] == 50
    assert summary["versioned_buckets"] == 1


# --------------------------------------------------------------------------- #
# Cloud SQL — gcp-api-samples/sql-describe.json (Google-managed) + SYNTHETIC CMEK
# --------------------------------------------------------------------------- #

GOOGLE_MANAGED_SQL = {  # gcp-api-samples/sql-describe.json (no diskEncryptionConfiguration)
    "name": "pf-test-sql",
    "region": "us-central1",
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "settings": {
        "backupConfiguration": {
            "enabled": True,
            "startTime": "03:00",
            "backupRetentionSettings": {"retainedBackups": 7, "retentionUnit": "COUNT"},
            "pointInTimeRecoveryEnabled": True,
        }
    },
}
CMEK_SQL = {  # SYNTHETIC — the test project's Cloud SQL uses the Google-managed
    "name": "pf-test-sql-cmek",  # default (its service agent can't hold a key until
    "region": "us-central1",     # the instance exists). This is the CMEK shape.
    "databaseVersion": "POSTGRES_15",
    "state": "RUNNABLE",
    "diskEncryptionConfiguration": {
        "kmsKeyName": "projects/p/locations/us-central1/keyRings/paramify-test-ring/cryptoKeys/rotating-key"
    },
    "diskEncryptionStatus": {
        "kmsKeyVersionName": "projects/p/locations/us-central1/keyRings/paramify-test-ring/cryptoKeys/rotating-key/cryptoKeyVersions/1"
    },
    "settings": {"backupConfiguration": {"enabled": False}},
}


def test_sql_google_managed():
    sql = _load("cloud_sql_encryption_status")
    rec = sql.instance_record(GOOGLE_MANAGED_SQL)
    assert rec["cmek"] is False
    assert rec["kms_key_name"] is None
    assert rec["backup_enabled"] is True
    assert rec["backup_retained_count"] == 7
    assert rec["point_in_time_recovery_enabled"] is True


def test_sql_cmek_synthetic():
    sql = _load("cloud_sql_encryption_status")
    rec = sql.instance_record(CMEK_SQL)
    assert rec["cmek"] is True
    assert rec["kms_key_name"].endswith("cryptoKeys/rotating-key")
    assert rec["backup_enabled"] is False


def test_sql_summary():
    sql = _load("cloud_sql_encryption_status")
    instances = [sql.instance_record(GOOGLE_MANAGED_SQL), sql.instance_record(CMEK_SQL)]
    summary = sql.summarize(instances)
    assert summary["total_instances"] == 2
    assert summary["cmek_instances"] == 1
    assert summary["cmek_percentage"] == 50
    assert summary["backup_enabled_instances"] == 1

# NB: the Cloud KMS fetcher and its tests (tests/test_gcp_kms_key_rotation.py) are
# held out of the first commit until KMS has one green live-tenant re-run.
