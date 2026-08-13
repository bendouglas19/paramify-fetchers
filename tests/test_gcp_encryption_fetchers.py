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

The last two sections cover the failure path instead of the data: the shared
`write_status()` / `Collector.failure_report()` helpers, and an end-to-end run of
each fetcher with deliberately-broken credentials, which must exit non-zero AND
report why through $FETCHER_STATUS_FILE.

Run: pytest tests/test_gcp_encryption_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GCP_ROOT = REPO_ROOT / "fetchers" / "gcp"

# The categories docs/fetcher_contract.md § Output allows in the status file.
STATUS_CODES = {
    "auth_failed",
    "not_authorized",
    "target_unreachable",
    "rate_limited",
    "bad_config",
    "partial_failure",
    "internal_error",
}

ENCRYPTION_FETCHERS = [
    "persistent_disk_encryption_status",
    "cloud_storage_encryption_status",
    "cloud_sql_encryption_status",
]


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GCP_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"gcp_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_shared():
    """Load fetchers/gcp/_shared/gcp_common.py the same way."""
    path = GCP_ROOT / "_shared" / "gcp_common.py"
    spec = importlib.util.spec_from_file_location("gcp_common_under_test", path)
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


# --------------------------------------------------------------------------- #
# The failure channel — gcp_common.write_status / Collector.failure_report
#
# A non-zero exit says a collection failed; these say WHY. Without them the
# runner falls back to the tail of stderr, and the last line these fetchers log
# is "Evidence saved to ..." — a failed run reporting a success message as its
# cause (issue #24). See docs/fetcher_contract.md § Output.
# --------------------------------------------------------------------------- #

def _collector_with(*failures):
    """A Collector carrying pre-recorded failures, no API calls involved."""
    common = _load_shared()
    collector = common.Collector(logging.getLogger("test_gcp_failure_report"))
    for operation, exc in failures:
        collector.record(operation, exc)
    return common, collector


def test_write_status_is_a_no_op_when_the_runner_did_not_ask(monkeypatch, tmp_path):
    """Running a fetcher by hand must behave exactly as it did before."""
    common = _load_shared()
    monkeypatch.delenv("FETCHER_STATUS_FILE", raising=False)
    common.write_status("something broke", "internal_error")
    assert list(tmp_path.iterdir()) == []


def test_write_status_writes_the_documented_shape(monkeypatch, tmp_path):
    common = _load_shared()
    status = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))

    common.write_status("Cloud Storage API read timeout after 30s", "target_unreachable")

    body = json.loads(status.read_text())
    assert body == {
        "error": "Cloud Storage API read timeout after 30s",
        "code": "target_unreachable",
    }


def test_write_status_omits_code_and_collapses_multiline_errors(monkeypatch, tmp_path):
    """`error` is one line — google API errors routinely span several."""
    common = _load_shared()
    status = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))

    common.write_status("403 PermissionDenied\n  on storage.buckets.list\n\n")

    body = json.loads(status.read_text())
    assert body == {"error": "403 PermissionDenied on storage.buckets.list"}
    assert "\n" not in body["error"]


def test_failure_report_names_the_unanimous_cause():
    """Expired ADC takes down every call — "auth_failed" beats "partial_failure"."""
    _common, collector = _collector_with(
        ("storage.buckets.list", RuntimeError("RefreshError: invalid_grant: Token expired")),
        ("compute.disks.aggregatedList", RuntimeError("RefreshError: invalid_grant: Token expired")),
    )
    reason, code = collector.failure_report()
    assert code == "auth_failed"
    assert reason.startswith("2 GCP API calls failed:")
    assert "storage.buckets.list" in reason
    assert "\n" not in reason


def test_failure_report_distinguishes_permission_from_auth():
    _common, collector = _collector_with(
        ("storage.buckets.list", RuntimeError("403 PermissionDenied: caller does not have permission")),
    )
    reason, code = collector.failure_report()
    assert code == "not_authorized"
    assert reason.startswith("1 GCP API call failed:")


def test_failure_report_falls_back_to_partial_failure_when_causes_disagree():
    _common, collector = _collector_with(
        ("storage.buckets.list", RuntimeError("403 PermissionDenied")),
        ("compute.disks.aggregatedList", RuntimeError("Quota exceeded for reads")),
    )
    _reason, code = collector.failure_report()
    assert code == "partial_failure"


def test_failure_report_bounds_the_reason_line():
    """Many failures collapse to a bounded summary, not a wall of text.

    The leading count carries the total; only the first few are spelled out, and
    the whole ledger is in the payload's api_failures either way.
    """
    _common, collector = _collector_with(
        *[(f"api.call.{i}", RuntimeError("x" * 500)) for i in range(9)]
    )
    reason, _code = collector.failure_report()
    assert reason.startswith("9 GCP API calls failed:")
    assert "api.call.0" in reason and "api.call.8" not in reason
    assert len(reason) <= 800


def test_tolerated_failures_do_not_fail_the_collection():
    """An API that was never enabled on the project is evidence, not a failure."""
    common = _load_shared()
    collector = common.Collector(logging.getLogger("test_gcp_tolerate"))

    def _boom():
        raise RuntimeError(
            "403 Kubernetes Engine API has not been used in project 1234 before "
            "or it is disabled [SERVICE_DISABLED]"
        )

    result = collector.guard("container.clusters.list", _boom, tolerate=common.service_disabled)

    assert result is None
    assert collector.ok is True
    assert collector.failures == []
    assert collector.skipped[0]["operation"] == "container.clusters.list"


def test_skipped_calls_key_is_absent_when_nothing_was_skipped():
    """Keeps the payloads of fetchers that never tolerate anything byte-identical."""
    common = _load_shared()
    collector = common.Collector(logging.getLogger("test_gcp_payload"))
    payload = common.build_payload(
        project="p", project_source="target", collector=collector, results={}, summary={}
    )
    assert "skipped_calls" not in payload["metadata"]


# --------------------------------------------------------------------------- #
# End to end with broken credentials: exit non-zero, still write evidence, and
# report the reason. Offline — GOOGLE_APPLICATION_CREDENTIALS points at a file
# that does not exist, so ADC resolution fails before any network call.
# --------------------------------------------------------------------------- #

def run_with_broken_credentials(short_name: str, tmp_path: Path):
    """Invoke a fetcher exactly as the runner does. Returns (proc, evidence_dir, status)."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    status_file = tmp_path / "status.json"
    env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TZ")},
        "PYTHONUNBUFFERED": "1",
        "EVIDENCE_DIR": str(evidence_dir),
        "FETCHER_STATUS_FILE": str(status_file),
        # An explicit project keeps ADC from being asked for one, so the only
        # failure is the credential itself.
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


@pytest.mark.parametrize("short_name", ENCRYPTION_FETCHERS)
def test_broken_credentials_fail_loudly_and_explain_themselves(short_name, tmp_path):
    pytest.importorskip("dotenv")
    proc, evidence_dir, status_file = run_with_broken_credentials(short_name, tmp_path)

    assert proc.returncode != 0, "unusable credentials must not look like success"

    evidence_files = list(evidence_dir.glob("*.json"))
    assert len(evidence_files) == 1, f"expected one evidence file, got {evidence_files}"
    payload = json.loads(evidence_files[0].read_text())
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"], "the failure must be in the payload too"

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
