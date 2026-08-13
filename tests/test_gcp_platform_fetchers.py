"""Fixture-based tests for the GCP platform-posture fetchers.

Covers `gcp_gke_cluster_configuration`, `gcp_cloud_logging_configuration` and
`gcp_iam_service_accounts` — the sibling of tests/test_gcp_encryption_fetchers.py
for the fetchers that are not about encryption at rest.

Like that module, these exercise each fetcher's PURE transform functions (no live
API calls, no credentials, no google client libraries — the heavy google imports
live inside each fetcher's collect_*() and are never triggered here), plus an
end-to-end run with deliberately-broken credentials.

**Every fixture here is SYNTHETIC.** The encryption fetchers' fixtures were
captured from a live throwaway project; these three have had no live-tenant run
(see fetchers/gcp/README.md § Status), so the fixtures are hand-built from the
API's documented resource shapes. Each pair covers a hardened resource and a
default/unhardened one, because the whole point is the fields that differ between
them — and one fixture in each pair is written in the REST camelCase spelling to
prove the transforms tolerate either (GAPIC to_dict emits snake_case).

Run: pytest tests/test_gcp_platform_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

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

PLATFORM_FETCHERS = [
    "gke_cluster_configuration",
    "cloud_logging_configuration",
    "iam_service_accounts",
]


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GCP_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"gcp_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# GKE — container_v1 Cluster.to_dict() shape (snake_case) and the REST camelCase
# spelling of the same resource
# --------------------------------------------------------------------------- #

HARDENED_CLUSTER = {  # SYNTHETIC — the posture a hardened cluster reports
    "name": "prod-euw1",
    "id": "b9e1f0c2",
    "location": "europe-west1",
    "locations": ["europe-west1-c", "europe-west1-b"],
    "status": "RUNNING",
    "initial_cluster_version": "1.30.5-gke.1443001",
    "current_master_version": "1.30.5-gke.1443001",
    "current_node_count": 6,
    "release_channel": {"channel": "REGULAR"},
    "private_cluster_config": {
        "enable_private_nodes": True,
        "enable_private_endpoint": True,
        "master_ipv4_cidr_block": "172.16.0.0/28",
        "private_endpoint": "10.0.0.2",
        "public_endpoint": "",
    },
    "master_authorized_networks_config": {
        "enabled": True,
        "cidr_blocks": [{"cidr_block": "10.0.0.0/8", "display_name": "vpn"}],
    },
    "network_policy": {"enabled": True, "provider": "CALICO"},
    "network_config": {
        "datapath_provider": "ADVANCED_DATAPATH",
        "enable_intra_node_visibility": True,
    },
    "legacy_abac": {"enabled": False},
    # master_auth also carries the control plane's client cert/key; the transform
    # must read only the flag, never the block.
    "master_auth": {
        "client_certificate_config": {"issue_client_certificate": False},
        "cluster_ca_certificate": "FIXTURE-NOT-A-REAL-CERT",
    },
    "workload_identity_config": {"workload_pool": "example-prod.svc.id.goog"},
    "shielded_nodes": {"enabled": True},
    "binary_authorization": {"enabled": True, "evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
    "logging_service": "logging.googleapis.com/kubernetes",
    "monitoring_service": "monitoring.googleapis.com/kubernetes",
    "logging_config": {
        "component_config": {"enable_components": ["WORKLOADS", "SYSTEM_COMPONENTS", "APISERVER"]}
    },
    "monitoring_config": {
        "component_config": {"enable_components": ["SYSTEM_COMPONENTS"]},
        "managed_prometheus_config": {"enabled": True},
    },
    "database_encryption": {
        "state": "ENCRYPTED",
        "key_name": "projects/p/locations/europe-west1/keyRings/gke/cryptoKeys/etcd",
    },
    "node_config": {"service_account": "gke-nodes@example-prod.iam.gserviceaccount.com"},
    "node_pools": [
        {
            "name": "workers",
            "version": "1.30.5-gke.1443001",
            "status": "RUNNING",
            "initial_node_count": 3,
            "locations": ["europe-west1-b", "europe-west1-c"],
            "autoscaling": {"enabled": True, "min_node_count": 3, "max_node_count": 9},
            "management": {"auto_upgrade": True, "auto_repair": True},
            "upgrade_settings": {"strategy": "SURGE", "max_surge": 1},
            "config": {
                "machine_type": "e2-standard-4",
                "image_type": "COS_CONTAINERD",
                "service_account": "gke-nodes@example-prod.iam.gserviceaccount.com",
                "boot_disk_kms_key": "projects/p/locations/europe-west1/keyRings/gke/cryptoKeys/nodes",
                "shielded_instance_config": {
                    "enable_secure_boot": True,
                    "enable_integrity_monitoring": True,
                },
                "workload_metadata_config": {"mode": "GKE_METADATA"},
                "metadata": {"disable-legacy-endpoints": "true"},
            },
        }
    ],
}

DEFAULT_CLUSTER_REST = {  # SYNTHETIC — REST camelCase, everything left at default
    "name": "dev-scratch",
    "id": "0af12c",
    "location": "us-central1-a",
    "status": "RUNNING",
    "currentMasterVersion": "1.29.7-gke.1104000",
    "currentNodeCount": 1,
    # No privateClusterConfig / networkPolicy / workloadIdentityConfig /
    # shieldedNodes blocks at all — the API omits them when unset.
    "legacyAbac": {"enabled": True},
    "masterAuth": {"clientCertificateConfig": {"issueClientCertificate": True}},
    "databaseEncryption": {"state": "DECRYPTED"},
    "loggingService": "logging.googleapis.com/kubernetes",
    "nodeConfig": {"serviceAccount": "default"},
    "nodePools": [
        {
            "name": "default-pool",
            "initialNodeCount": 1,
            "management": {"autoUpgrade": False, "autoRepair": False},
            "config": {
                "machineType": "e2-medium",
                "serviceAccount": "default",
                "metadata": {"disable-legacy-endpoints": "false"},
            },
        }
    ],
}


def test_gke_hardened_cluster_posture():
    gke = _load("gke_cluster_configuration")
    rec = gke.cluster_record(HARDENED_CLUSTER)
    assert rec["private_nodes"] is True
    assert rec["private_control_plane_endpoint"] is True
    assert rec["control_plane_endpoint_access"] == "private"
    assert rec["master_authorized_networks_enabled"] is True
    assert rec["master_authorized_network_count"] == 1
    assert rec["network_policy_enabled"] is True
    assert rec["dataplane_v2"] is True
    assert rec["legacy_abac_enabled"] is False
    assert rec["rbac_only_authorization"] is True
    assert rec["client_certificate_issued"] is False
    assert rec["workload_identity_enabled"] is True
    assert rec["shielded_nodes_enabled"] is True
    assert rec["binary_authorization_enabled"] is True
    assert rec["etcd_cmek"] is True
    assert rec["etcd_kms_key_name"].endswith("cryptoKeys/etcd")
    assert rec["release_channel"] == "REGULAR"
    assert rec["control_plane_logging_components"] == [
        "APISERVER", "SYSTEM_COMPONENTS", "WORKLOADS"
    ]
    assert rec["locations"] == ["europe-west1-b", "europe-west1-c"]  # sorted


def test_gke_never_copies_control_plane_credentials():
    """master_auth carries the client key — only the flag may reach the evidence."""
    gke = _load("gke_cluster_configuration")
    rec = gke.cluster_record(HARDENED_CLUSTER)
    assert "FIXTURE-NOT-A-REAL-CERT" not in json.dumps(rec)


def test_gke_default_cluster_in_rest_spelling():
    """camelCase input, and blocks the API omits entirely when a feature is off."""
    gke = _load("gke_cluster_configuration")
    rec = gke.cluster_record(DEFAULT_CLUSTER_REST)
    assert rec["private_nodes"] is False
    assert rec["control_plane_endpoint_access"] == "public"
    assert rec["network_policy_enabled"] is False
    assert rec["workload_identity_enabled"] is False
    assert rec["workload_identity_pool"] is None
    assert rec["shielded_nodes_enabled"] is False
    # The finding: legacy ABAC on means RBAC can be bypassed.
    assert rec["legacy_abac_enabled"] is True
    assert rec["rbac_only_authorization"] is False
    assert rec["client_certificate_issued"] is True
    assert rec["etcd_cmek"] is False
    assert rec["node_service_account"] == "default"


def test_gke_node_pool_record_both_spellings():
    gke = _load("gke_cluster_configuration")
    hardened = gke.cluster_record(HARDENED_CLUSTER)["node_pools"][0]
    assert hardened["auto_upgrade"] is True
    assert hardened["auto_repair"] is True
    assert hardened["boot_disk_cmek"] is True
    assert hardened["boot_disk_kms_key"].endswith("cryptoKeys/nodes")
    assert hardened["secure_boot"] is True
    assert hardened["integrity_monitoring"] is True
    assert hardened["workload_metadata_mode"] == "GKE_METADATA"
    assert hardened["legacy_endpoints_disabled"] is True
    assert hardened["uses_default_service_account"] is False

    default = gke.cluster_record(DEFAULT_CLUSTER_REST)["node_pools"][0]
    assert default["auto_upgrade"] is False
    assert default["auto_repair"] is False
    assert default["boot_disk_cmek"] is False
    assert default["boot_disk_kms_key"] is None
    assert default["secure_boot"] is False
    assert default["legacy_endpoints_disabled"] is False
    # Prowler's gke_cluster_no_default_service_account finding.
    assert default["uses_default_service_account"] is True


def test_gke_summary_counts_and_percentages():
    gke = _load("gke_cluster_configuration")
    clusters = [gke.cluster_record(HARDENED_CLUSTER), gke.cluster_record(DEFAULT_CLUSTER_REST)]
    summary = gke.summarize(clusters)
    assert summary["gke_api_readable"] is True
    assert summary["total_clusters"] == 2
    assert summary["private_node_clusters"] == 1
    assert summary["private_node_percentage"] == 50
    assert summary["workload_identity_clusters"] == 1
    assert summary["legacy_abac_clusters"] == 1
    assert summary["etcd_cmek_clusters"] == 1
    assert summary["total_node_pools"] == 2
    assert summary["auto_upgrade_node_pools"] == 1
    assert summary["auto_upgrade_percentage"] == 50
    assert summary["cmek_boot_disk_node_pools"] == 1
    assert summary["default_service_account_node_pools"] == 1


def test_gke_summary_marks_an_unreadable_api():
    """A project with the Container API disabled: no clusters, and it says why."""
    gke = _load("gke_cluster_configuration")
    summary = gke.summarize([], api_readable=False)
    assert summary["gke_api_readable"] is False
    assert summary["total_clusters"] == 0
    assert summary["private_node_percentage"] == 0


# --------------------------------------------------------------------------- #
# Cloud Logging — logging_v2 to_dict() shapes
# --------------------------------------------------------------------------- #

PROJECT_SINK_ALL = {  # SYNTHETIC — exports everything to a log bucket
    "name": "projects/example-prod/sinks/all-to-bucket",
    "destination": "logging.googleapis.com/projects/example-prod/locations/global/buckets/audit",
    "filter": "",
    "disabled": False,
    "writer_identity": "serviceAccount:p123@gcp-sa-logging.iam.gserviceaccount.com",
}
PROJECT_SINK_AUDIT_ONLY = {  # SYNTHETIC — REST camelCase, audit stream only
    "name": "projects/example-prod/sinks/audit-to-gcs",
    "destination": "storage.googleapis.com/example-prod-audit-archive",
    "filter": 'logName:"cloudaudit.googleapis.com%2Factivity" AND severity>=NOTICE',
    "includeChildren": False,
    "writerIdentity": "serviceAccount:p123@gcp-sa-logging.iam.gserviceaccount.com",
}
DISABLED_SINK = {  # SYNTHETIC — exports everything, but switched off
    "name": "projects/example-prod/sinks/paused",
    "destination": "pubsub.googleapis.com/projects/example-prod/topics/logs",
    "filter": "",
    "disabled": True,
}
ORG_SINK_AGGREGATED = {  # SYNTHETIC — the aggregated sink above the project
    "name": "org-everything",
    "destination": "logging.googleapis.com/projects/example-logs/locations/global/buckets/org",
    "filter": "",
    "include_children": True,
}

LOCKED_BUCKET = {  # SYNTHETIC — the tamper-resistant configuration
    "name": "projects/example-prod/locations/global/buckets/audit",
    "retention_days": 400,
    "locked": True,
    "lifecycle_state": "ACTIVE",
    "cmek_settings": {
        "kms_key_name": "projects/p/locations/global/keyRings/logs/cryptoKeys/audit"
    },
    "index_configs": [{"field_path": "jsonPayload.actor"}],
}
DEFAULT_BUCKET_REST = {  # SYNTHETIC — REST camelCase, defaults
    "name": "projects/example-prod/locations/us-central1/buckets/_Default",
    "retentionDays": 30,
    "lifecycleState": "ACTIVE",
}

ALERT_POLICY = {  # SYNTHETIC
    "name": "projects/example-prod/alertPolicies/1122334455",
    "display_name": "IAM policy changes",
    "enabled": True,
    "notification_channels": ["projects/example-prod/notificationChannels/1"],
    "conditions": [
        {
            "display_name": "log metric above zero",
            "condition_threshold": {
                "filter": 'metric.type="logging.googleapis.com/user/iam-policy-changes"',
                "comparison": "COMPARISON_GT",
            },
        }
    ],
}
ALERTED_METRIC = {  # SYNTHETIC — the metric that policy watches
    "name": "iam-policy-changes",
    "filter": 'protoPayload.methodName="SetIamPolicy"',
    "metric_descriptor": {"type": "logging.googleapis.com/user/iam-policy-changes"},
}
UNALERTED_METRIC = {  # SYNTHETIC — collected, but nothing fires on it
    "name": "bucket-permission-changes",
    "filter": 'resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"',
    "metricDescriptor": {"type": "logging.googleapis.com/user/bucket-permission-changes"},
    "bucketName": "projects/example-prod/locations/global/buckets/audit",
}

SETTINGS = {  # SYNTHETIC
    "name": "projects/example-prod/settings",
    "kms_key_name": "projects/p/locations/global/keyRings/logs/cryptoKeys/router",
    "kms_service_account_id": "service-p123@gcp-sa-logging.iam.gserviceaccount.com",
    "storage_location": "us-central1",
    "disable_default_sink": False,
}


def _logging_records():
    """(module, sinks, buckets, metrics, alert_policies, settings) from the fixtures."""
    log = _load("cloud_logging_configuration")
    policies = [log.alert_policy_record(ALERT_POLICY)]
    sinks = [
        log.sink_record(PROJECT_SINK_ALL),
        log.sink_record(PROJECT_SINK_AUDIT_ONLY),
        log.sink_record(DISABLED_SINK),
        log.sink_record(ORG_SINK_AGGREGATED, "organizations/123456789"),
    ]
    buckets = [log.bucket_record(LOCKED_BUCKET), log.bucket_record(DEFAULT_BUCKET_REST)]
    metrics = [
        log.metric_record(ALERTED_METRIC, policies),
        log.metric_record(UNALERTED_METRIC, policies),
    ]
    return log, sinks, buckets, metrics, policies, log.settings_record(SETTINGS)


def test_logging_sink_destination_and_coverage_facts():
    log, sinks, *_ = _logging_records()
    everything, audit, disabled, org = sinks

    assert everything["destination_type"] == "log_bucket"
    assert everything["exports_all_logs"] is True
    assert everything["filters_on_audit_logs"] is False
    assert everything["scope"] == "project"
    assert everything["name"] == "all-to-bucket"          # basename, not the path

    assert audit["destination_type"] == "cloud_storage"
    assert audit["exports_all_logs"] is False
    # URL-encoded stream name, camelCase input.
    assert audit["filters_on_audit_logs"] is True

    assert disabled["disabled"] is True
    assert org["scope"] == "organizations/123456789"
    assert org["include_children"] is True
    assert log.destination_type("bigquery.googleapis.com/projects/p/datasets/d") == "bigquery"
    assert log.destination_type(None) is None


def test_logging_all_logs_captured_needs_an_enabled_sink():
    log, sinks, *_ = _logging_records()
    assert log.project_captures_all_logs(sinks) is True

    # A disabled sink proves nothing, and an ancestor sink only covers the project
    # when include_children is set (Prowler's logging_sink_created rule).
    disabled_only = [s for s in sinks if s["disabled"]]
    assert log.project_captures_all_logs(disabled_only) is False

    narrow_org = dict(sinks[3], include_children=False, scope="organizations/1")
    assert log.project_captures_all_logs([narrow_org]) is False
    assert log.project_captures_all_logs([sinks[3]]) is True


def test_logging_bucket_retention_lock_and_cmek():
    log, _sinks, buckets, *_ = _logging_records()
    locked, default = buckets

    assert locked["name"] == "audit"
    assert locked["location"] == "global"
    assert locked["retention_days"] == 400
    assert locked["locked"] is True
    assert locked["cmek"] is True
    assert locked["kms_key_name"].endswith("cryptoKeys/audit")
    assert locked["index_config_count"] == 1

    assert default["name"] == "_Default"
    assert default["location"] == "us-central1"
    assert default["retention_days"] == 30
    assert default["locked"] is False
    assert default["cmek"] is False
    assert log.location_of("projects/p/buckets/x") is None


def test_logging_metric_is_linked_to_the_policy_that_alerts_on_it():
    log, _sinks, _buckets, metrics, _policies, _settings = _logging_records()
    alerted, unalerted = metrics
    assert alerted["alerted"] is True
    assert alerted["alerting_policies"] == ["IAM policy changes"]
    assert alerted["metric_type"].endswith("iam-policy-changes")
    assert unalerted["alerted"] is False
    assert unalerted["alerting_policies"] == []
    assert unalerted["bucket_name"].endswith("buckets/audit")   # camelCase input


def test_logging_alert_policy_unwraps_its_condition_filters():
    log, *_ = _logging_records()
    rec = log.alert_policy_record(ALERT_POLICY)
    assert rec["name"] == "1122334455"
    assert rec["enabled"] is True
    assert rec["condition_count"] == 1
    assert rec["notification_channel_count"] == 1
    assert rec["condition_filters"] == [
        'metric.type="logging.googleapis.com/user/iam-policy-changes"'
    ]

    mql = {
        "name": "projects/p/alertPolicies/9",
        "display_name": "MQL policy",
        "enabled": False,
        "conditions": [{"condition_monitoring_query_language": {"query": "fetch gce_instance"}}],
    }
    assert log.alert_policy_record(mql)["condition_filters"] == ["fetch gce_instance"]


def test_logging_summary():
    log, sinks, buckets, metrics, policies, settings = _logging_records()
    summary = log.summarize(sinks, buckets, metrics, policies, settings)
    assert summary["total_sinks"] == 4
    assert summary["project_sinks"] == 3
    assert summary["ancestor_sinks"] == 1
    assert summary["enabled_sinks"] == 3
    assert summary["sinks_exporting_all_logs"] == 3
    assert summary["sinks_filtering_audit_logs"] == 1
    assert summary["all_logs_captured_by_a_sink"] is True
    assert summary["total_log_buckets"] == 2
    assert summary["locked_log_buckets"] == 1
    assert summary["cmek_log_buckets"] == 1
    assert summary["cmek_log_bucket_percentage"] == 50
    assert summary["shortest_retention_days"] == 30
    assert summary["longest_retention_days"] == 400
    assert summary["log_router_cmek_key"].endswith("cryptoKeys/router")
    assert summary["total_log_metrics"] == 2
    assert summary["alerted_log_metrics"] == 1
    assert summary["enabled_alert_policies"] == 1


def test_logging_settings_record_tolerates_an_absent_response():
    """A failed settings.get leaves the block empty, not missing."""
    log = _load("cloud_logging_configuration")
    assert log.settings_record(None) == {
        "kms_key_name": None,
        "kms_service_account": None,
        "storage_location": None,
        "disable_default_sink": False,
    }


# --------------------------------------------------------------------------- #
# IAM service accounts — iam_admin_v1 to_dict() shapes
# --------------------------------------------------------------------------- #

NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)

STALE_USER_KEY = {  # SYNTHETIC — a downloaded key, 408 days old, never expires
    "name": "projects/example-prod/serviceAccounts/ci@example-prod.iam.gserviceaccount.com/keys/aa11",
    "key_type": "USER_MANAGED",
    "key_origin": "GOOGLE_PROVIDED",
    "key_algorithm": "KEY_ALG_RSA_2048",
    "valid_after_time": "2025-07-01T00:00:00Z",
    "valid_before_time": "9999-12-31T23:59:59Z",
    "disabled": False,
}
FRESH_USER_KEY = {  # SYNTHETIC — REST camelCase, rotated 10 days ago, 1-year life
    "name": "projects/example-prod/serviceAccounts/ci@example-prod.iam.gserviceaccount.com/keys/bb22",
    "keyType": "USER_MANAGED",
    "keyOrigin": "USER_PROVIDED",
    "keyAlgorithm": "KEY_ALG_RSA_2048",
    "validAfterTime": "2026-08-03T00:00:00Z",
    "validBeforeTime": "2027-08-03T00:00:00Z",
}
SYSTEM_KEY = {  # SYNTHETIC — Google rotates this one; not a finding
    "name": "projects/example-prod/serviceAccounts/app@example-prod.iam.gserviceaccount.com/keys/cc33",
    "key_type": "SYSTEM_MANAGED",
    "key_origin": "GOOGLE_PROVIDED",
    "key_algorithm": "KEY_ALG_RSA_2048",
    "valid_after_time": "2026-08-01T00:00:00Z",
    "valid_before_time": "2026-08-25T00:00:00Z",
}

CI_ACCOUNT = {  # SYNTHETIC
    "name": "projects/example-prod/serviceAccounts/ci@example-prod.iam.gserviceaccount.com",
    "email": "ci@example-prod.iam.gserviceaccount.com",
    "display_name": "CI deployer",
    "unique_id": "104729371625384756291",
    "disabled": False,
}
APP_ACCOUNT = {  # SYNTHETIC — no user-managed keys, uses Workload Identity
    "name": "projects/example-prod/serviceAccounts/app@example-prod.iam.gserviceaccount.com",
    "email": "app@example-prod.iam.gserviceaccount.com",
    "displayName": "App runtime",
    "uniqueId": "118829371625384756292",
}

PROJECT_BINDINGS = [  # SYNTHETIC — as policy_bindings() would return them
    {"role": "roles/editor", "members": ["serviceAccount:ci@example-prod.iam.gserviceaccount.com"]},
    {
        "role": "roles/iam.serviceAccountUser",
        "members": ["user:dev@example.com", "user:ops@example.com"],
    },
    {
        "role": "roles/storage.objectViewer",
        "members": ["serviceAccount:app@example-prod.iam.gserviceaccount.com"],
    },
]
CI_SA_BINDINGS = [  # SYNTHETIC — bindings ON the CI account: who can act as it
    {
        "role": "roles/iam.serviceAccountTokenCreator",
        "members": ["group:platform@example.com"],
    },
    {"role": "roles/iam.serviceAccountViewer", "members": ["user:auditor@example.com"]},
]


def _iam_records():
    iam = _load("iam_service_accounts")
    ci = iam.service_account_record(
        CI_ACCOUNT, [STALE_USER_KEY, FRESH_USER_KEY], CI_SA_BINDINGS, PROJECT_BINDINGS, NOW
    )
    app = iam.service_account_record(APP_ACCOUNT, [SYSTEM_KEY], [], PROJECT_BINDINGS, NOW)
    return iam, ci, app


def test_iam_key_record_ages_and_expiry():
    iam = _load("iam_service_accounts")
    stale = iam.key_record(STALE_USER_KEY, NOW)
    assert stale["id"] == "aa11"
    assert stale["user_managed"] is True
    assert stale["age_days"] == 408
    assert stale["never_expires"] is True
    assert stale["key_origin"] == "GOOGLE_PROVIDED"

    fresh = iam.key_record(FRESH_USER_KEY, NOW)      # camelCase input
    assert fresh["user_managed"] is True
    assert fresh["age_days"] == 10
    assert fresh["never_expires"] is False
    assert fresh["expires_in_days"] == 355

    system = iam.key_record(SYSTEM_KEY, NOW)
    assert system["user_managed"] is False           # Google rotates it — not a finding
    assert system["key_type"] == "SYSTEM_MANAGED"


def test_iam_key_record_tolerates_missing_timestamps():
    iam = _load("iam_service_accounts")
    rec = iam.key_record({"name": "projects/p/serviceAccounts/x/keys/dd44"}, NOW)
    assert rec["age_days"] is None
    assert rec["expires_in_days"] is None
    assert rec["never_expires"] is False
    assert iam.parse_timestamp("not-a-timestamp") is None


def test_iam_service_account_key_inventory_and_privileges():
    _iam, ci, app = _iam_records()

    assert ci["user_managed_key_count"] == 2
    assert ci["system_managed_key_count"] == 0
    assert ci["oldest_user_managed_key_age_days"] == 408
    assert ci["user_managed_keys_past_rotation_age"] == 1
    assert [k["id"] for k in ci["keys"]] == ["aa11", "bb22"]   # oldest first

    # Prowler's iam_sa_no_administrative_privileges: roles/editor is over-broad.
    assert ci["project_roles"] == ["roles/editor"]
    assert ci["primitive_project_roles"] == ["roles/editor"]
    assert ci["has_over_broad_project_role"] is True
    # Bindings on the account itself say who can act as it.
    assert ci["impersonation_members"] == ["group:platform@example.com"]
    assert ci["impersonable"] is True

    assert app["user_managed_key_count"] == 0
    assert app["system_managed_key_count"] == 1
    assert app["oldest_user_managed_key_age_days"] is None
    assert app["project_roles"] == ["roles/storage.objectViewer"]
    assert app["has_over_broad_project_role"] is False
    assert app["impersonable"] is False


def test_iam_over_broad_role_rule():
    iam = _load("iam_service_accounts")
    assert iam.is_over_broad_role("roles/owner") is True
    assert iam.is_over_broad_role("roles/editor") is True
    assert iam.is_over_broad_role("roles/storage.admin") is True
    assert iam.is_over_broad_role("roles/viewer") is False       # primitive, but read-only
    assert iam.is_over_broad_role("roles/storage.objectViewer") is False


def test_iam_project_binding_names_service_accounts_and_counts_people():
    iam = _load("iam_service_accounts")
    people = iam.project_binding_record(PROJECT_BINDINGS[1])
    assert people["role"] == "roles/iam.serviceAccountUser"
    assert people["member_count"] == 2
    assert people["service_account_members"] == []
    assert people["other_member_count"] == 2
    assert people["impersonation_role"] is True
    # A user inventory is a different evidence set — no human identities here.
    assert "dev@example.com" not in json.dumps(people)

    editor = iam.project_binding_record(PROJECT_BINDINGS[0])
    assert editor["service_account_members"] == [
        "serviceAccount:ci@example-prod.iam.gserviceaccount.com"
    ]
    assert editor["over_broad_role"] is True
    assert editor["primitive_role"] is True


def test_iam_summary():
    iam, ci, app = _iam_records()
    summary = iam.summarize([ci, app], PROJECT_BINDINGS)
    assert summary["total_service_accounts"] == 2
    assert summary["service_accounts_with_user_managed_keys"] == 1
    assert summary["service_accounts_without_user_managed_keys"] == 1
    assert summary["no_user_managed_key_percentage"] == 50
    assert summary["user_managed_key_count"] == 2
    assert summary["system_managed_key_count"] == 1
    assert summary["user_managed_keys_past_rotation_age"] == 1
    assert summary["rotation_age_days"] == 90
    assert summary["oldest_user_managed_key_age_days"] == 408
    assert summary["never_expiring_user_managed_keys"] == 1
    assert summary["service_accounts_with_over_broad_roles"] == 1
    assert summary["impersonable_service_accounts"] == 1
    assert summary["total_project_role_bindings"] == 3
    assert summary["over_broad_project_role_bindings"] == 1
    assert summary["project_wide_impersonation_bindings"] == 1


# --------------------------------------------------------------------------- #
# End to end with broken credentials. Offline: GOOGLE_APPLICATION_CREDENTIALS
# points at a file that does not exist, so ADC resolution fails before any
# network call. (Deliberately a local copy of the harness in
# test_gcp_encryption_fetchers.py — each test module stands alone, and the repo
# has no tests/conftest.py to share it through.)
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


@pytest.mark.parametrize("short_name", PLATFORM_FETCHERS)
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
