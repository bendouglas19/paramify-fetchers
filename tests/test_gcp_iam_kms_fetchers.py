"""Fixture-based tests for the GCP identity, key-management and DNS fetchers.

Covers `gcp_iam_policy_bindings`, `gcp_iam_custom_roles`,
`gcp_kms_key_configuration`, `gcp_dns_configuration` and
`gcp_api_keys_inventory` — the sibling of tests/test_gcp_encryption_fetchers.py
and tests/test_gcp_platform_fetchers.py for the fetchers about who can act and
what protects the crypto and the name service.

Like those modules, these exercise each fetcher's PURE transform functions (no
live API calls, no credentials, no google client libraries — the heavy google
imports live inside each fetcher's collect_*() and are never triggered here), plus
an end-to-end run with deliberately-broken credentials.

**Every fixture here is SYNTHETIC.** None of these five fetchers has had a
live-tenant run (see fetchers/gcp/README.md § Status), so the fixtures are
hand-built from each API's documented resource shapes. Each pair covers a hardened
resource and a default/unhardened one, because the whole point is the fields that
differ between them — and one fixture in each pair is written in the REST camelCase
spelling to prove the transforms tolerate either (GAPIC to_dict emits snake_case,
and the Cloud DNS discovery client only ever emits camelCase).

Two of these fetchers write identities into the evidence, so two tests assert the
inverse of the usual rule: `gcp_iam_policy_bindings` MUST enumerate members (it is
the project's access inventory, unlike its sibling `gcp_iam_service_accounts`,
which counts them), while `gcp_api_keys_inventory` must NEVER emit a key string.

Run: pytest tests/test_gcp_iam_kms_fetchers.py  (needs `pip install -e .`)
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

IDENTITY_FETCHERS = [
    "iam_policy_bindings",
    "iam_custom_roles",
    "kms_key_configuration",
    "dns_configuration",
    "api_keys_inventory",
]

NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GCP_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"gcp_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# IAM policy bindings — google.iam.v1.Policy read through policy_dicts()
# --------------------------------------------------------------------------- #

ORG_DOMAIN = "example.com"
POLICY_PROJECT = "example-prod"

# SYNTHETIC — a policy with one of every finding in it.
RAW_BINDINGS = [
    {
        # Primitive + write-capable, held by a human and by a service account.
        "role": "roles/owner",
        "members": [
            "user:founder@example.com",
            "serviceAccount:terraform@example-prod.iam.gserviceaccount.com",
        ],
        "condition": None,
    },
    {
        # The critical finding: a project role granted to the whole internet.
        "role": "roles/storage.objectViewer",
        "members": ["allUsers", "user:analyst@example.com"],
        "condition": None,
    },
    {
        # External contractor, a personal Google account, and a service account
        # owned by a different project.
        "role": "roles/logging.viewer",
        "members": [
            "user:contractor@partner.io",
            "user:someone@gmail.com",
            "serviceAccount:shared-ci@other-project.iam.gserviceaccount.com",
            "user:dev@eu.example.com",
        ],
        "condition": None,
    },
    {
        # Conditional binding: the role means less than its name suggests.
        "role": "roles/cloudkms.admin",
        "members": ["group:crypto@example.com"],
        "condition": {
            "title": "business hours only",
            "description": "weekdays",
            "expression": 'request.time.getHours("UTC") < 18',
        },
    },
    {
        # The same group also gets to USE the keys it administers — Prowler's
        # iam_role_kms_enforce_separation_of_duties.
        "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "members": [
            "group:crypto@example.com",
            "serviceAccount:service-123@gcp-sa-logging.iam.gserviceaccount.com",
        ],
        "condition": None,
    },
    {
        # A binding left pointing at a deleted identity.
        "role": "roles/viewer",
        "members": ["deleted:user:gone@example.com?uid=100000000000000000001"],
        "condition": None,
    },
]

RAW_AUDIT_CONFIGS = [
    {
        "service": "allServices",
        "audit_log_configs": [
            {"log_type": "ADMIN_READ", "exempted_members": []},
            {"log_type": "DATA_READ", "exempted_members": ["user:batch@example.com"]},
        ],
    },
    {
        "service": "storage.googleapis.com",
        "audit_log_configs": [{"log_type": "DATA_WRITE", "exempted_members": []}],
    },
]

PROJECT_DETAILS = {  # SYNTHETIC — resourcemanager_v3 Project.to_dict()
    "name": "projects/482910375610",
    "project_id": POLICY_PROJECT,
    "display_name": "Example Prod",
    "parent": "folders/778899",
    "state": "ACTIVE",
    "labels": {"tier": "prod", "owner": "platform"},
}


def _policy_records(org_domain: str | None = ORG_DOMAIN):
    iam = _load("iam_policy_bindings")
    bindings = sorted(
        (iam.binding_record(b, org_domain, POLICY_PROJECT) for b in RAW_BINDINGS),
        key=lambda b: b["role"],
    )
    principals = iam.principal_records(bindings, org_domain, POLICY_PROJECT)
    audit = sorted(
        (iam.audit_config_record(c) for c in RAW_AUDIT_CONFIGS),
        key=lambda c: c["service"] or "",
    )
    return iam, bindings, principals, audit


def test_bindings_member_typing_and_domains():
    iam = _load("iam_policy_bindings")
    assert iam.member_type("user:a@example.com") == "user"
    assert iam.member_type("group:g@example.com") == "group"
    assert iam.member_type("serviceAccount:x@p.iam.gserviceaccount.com") == "serviceAccount"
    assert iam.member_type("domain:example.com") == "domain"
    assert iam.member_type("allUsers") == "public"
    assert iam.member_type("allAuthenticatedUsers") == "public"
    assert iam.member_type("projectOwner:example-prod") == "projectOwner"
    # Workload identity federation principals carry no email at all.
    assert iam.member_type("principalSet://iam.googleapis.com/projects/1/x") == "principalSet"
    # A stale binding is worth seeing, but it is not a live grant.
    assert iam.member_type("deleted:user:gone@example.com?uid=1") == "deleted_user"
    assert iam.member_type("somethingNew:x@example.com") == "other"

    assert iam.member_domain("user:A@Example.COM") == "example.com"
    assert iam.member_domain("domain:example.com") == "example.com"
    assert iam.member_domain("deleted:user:gone@example.com?uid=1") == "example.com"
    assert iam.member_domain("allUsers") is None
    assert iam.member_domain("principalSet://iam.googleapis.com/projects/1/x") is None


def test_bindings_external_consumer_and_cross_project_rules():
    iam = _load("iam_policy_bindings")
    assert iam.is_external("user:contractor@partner.io", ORG_DOMAIN) is True
    # A subdomain of the org domain is still inside the org.
    assert iam.is_external("user:dev@eu.example.com", ORG_DOMAIN) is False
    assert iam.is_external("user:founder@example.com", ORG_DOMAIN) is False
    # Service accounts never live on the org domain — cross-project is their question.
    assert iam.is_external("serviceAccount:x@other-project.iam.gserviceaccount.com", ORG_DOMAIN) is False
    # With no org domain resolved, nothing is claimed either way.
    assert iam.is_external("user:contractor@partner.io", None) is False

    assert iam.is_consumer_account("user:someone@gmail.com") is True
    assert iam.is_consumer_account("user:founder@example.com") is False

    assert iam.is_cross_project_service_account(
        "serviceAccount:shared-ci@other-project.iam.gserviceaccount.com", POLICY_PROJECT
    ) is True
    assert iam.is_cross_project_service_account(
        "serviceAccount:terraform@example-prod.iam.gserviceaccount.com", POLICY_PROJECT
    ) is False
    # Google's own service agent exists because an API was enabled, not because
    # someone granted a foreign identity access.
    assert iam.is_cross_project_service_account(
        "serviceAccount:service-123@gcp-sa-logging.iam.gserviceaccount.com", POLICY_PROJECT
    ) is False
    assert iam.is_google_service_agent(
        "serviceAccount:service-123@gcp-sa-logging.iam.gserviceaccount.com"
    ) is True


def test_bindings_over_broad_role_rule_matches_the_service_account_fetcher():
    iam = _load("iam_policy_bindings")
    assert iam.is_over_broad_role("roles/owner") is True
    assert iam.is_over_broad_role("roles/editor") is True
    assert iam.is_over_broad_role("roles/cloudkms.admin") is True
    assert iam.is_over_broad_role("roles/viewer") is False
    assert iam.is_over_broad_role("roles/storage.objectViewer") is False


def test_binding_record_flags_public_primitive_and_conditional():
    _iam, bindings, _principals, _audit = _policy_records()
    by_role = {b["role"]: b for b in bindings}

    owner = by_role["roles/owner"]
    assert owner["primitive_role"] is True
    assert owner["over_broad_role"] is True
    assert owner["member_count"] == 2
    assert owner["member_types"] == {"serviceAccount": 1, "user": 1}
    # Prowler's iam_sa_no_administrative_privileges, at the binding level.
    assert owner["service_account_granted_over_broad_role"] is True

    public = by_role["roles/storage.objectViewer"]
    assert public["publicly_granted"] is True
    assert public["public_members"] == ["allUsers"]
    assert public["primitive_role"] is False

    outside = by_role["roles/logging.viewer"]
    assert outside["external_members"] == ["user:contractor@partner.io", "user:someone@gmail.com"]
    assert outside["consumer_account_members"] == ["user:someone@gmail.com"]
    assert outside["cross_project_service_account_members"] == [
        "serviceAccount:shared-ci@other-project.iam.gserviceaccount.com"
    ]

    conditional = by_role["roles/cloudkms.admin"]
    assert conditional["conditional"] is True
    assert conditional["condition"]["title"] == "business hours only"
    assert "request.time" in conditional["condition"]["expression"]
    assert by_role["roles/owner"]["condition"] is None


def test_binding_record_enumerates_members_on_purpose():
    """The inverse of gcp_iam_service_accounts' rule: here the inventory IS the point."""
    _iam, bindings, principals, _audit = _policy_records()
    blob = json.dumps({"bindings": bindings, "principals": principals})
    assert "user:founder@example.com" in blob
    assert "group:crypto@example.com" in blob


def test_principal_rollup_answers_separation_of_duties():
    _iam, _bindings, principals, _audit = _policy_records()
    by_member = {p["member"]: p for p in principals}

    crypto = by_member["group:crypto@example.com"]
    # Both halves of Prowler's KMS separation-of-duties pair, on one principal,
    # without the fetcher deciding which pairs conflict.
    assert crypto["roles"] == [
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    ]
    assert crypto["has_over_broad_role"] is True     # cloudkms.admin
    assert crypto["conditional_role_count"] == 1

    founder = by_member["user:founder@example.com"]
    assert founder["primitive_roles"] == ["roles/owner"]
    assert founder["external"] is False
    assert founder["domain"] == "example.com"

    contractor = by_member["user:contractor@partner.io"]
    assert contractor["external"] is True
    assert contractor["consumer_account"] is False

    everyone = by_member["allUsers"]
    assert everyone["public"] is True
    assert everyone["member_type"] == "public"
    assert everyone["domain"] is None

    terraform = by_member["serviceAccount:terraform@example-prod.iam.gserviceaccount.com"]
    assert terraform["service_account_project"] == "example-prod"
    assert terraform["cross_project_service_account"] is False

    stale = by_member["deleted:user:gone@example.com?uid=100000000000000000001"]
    assert stale["member_type"] == "deleted_user"


def test_audit_config_record_keeps_its_exempted_members():
    _iam, _bindings, _principals, audit = _policy_records()
    all_services, storage = audit
    assert all_services["service"] == "allServices"
    assert all_services["log_types"] == ["ADMIN_READ", "DATA_READ"]
    # An exempted member is an identity whose access is deliberately NOT logged.
    assert all_services["exempted_members"] == ["user:batch@example.com"]
    assert all_services["exempted_member_count"] == 1
    assert storage["log_types"] == ["DATA_WRITE"]
    assert storage["exempted_members"] == []


def test_policy_summary():
    iam, bindings, principals, audit = _policy_records()
    summary = iam.summarize(bindings, principals, audit, ORG_DOMAIN, "config")

    assert summary["total_bindings"] == 6
    assert summary["total_principals"] == 11
    assert summary["primitive_role_bindings"] == 2            # owner + viewer
    assert summary["non_primitive_binding_percentage"] == 66
    assert summary["owner_principals"] == 2
    assert summary["publicly_granted"] is True
    assert summary["public_bindings"] == 1
    assert summary["public_members"] == ["allUsers"]
    assert summary["service_account_bindings_with_over_broad_roles"] == 1
    assert summary["cross_project_service_account_principals"] == 1
    assert summary["deleted_principals"] == 1
    assert summary["external_members_evaluated"] is True
    assert summary["external_principals"] == 2                # partner.io + gmail.com
    assert summary["consumer_account_principals"] == 1
    assert summary["conditional_bindings"] == 1
    # Prowler's iam_audit_logs_enabled, plus the CIS 2.1 detail it doesn't check.
    assert summary["audit_logging_configured"] is True
    assert summary["audit_all_services_configured"] is True
    assert summary["audit_full_log_types_on_all_services"] is False   # DATA_WRITE missing
    assert summary["audit_exempted_member_count"] == 1


def test_policy_summary_says_when_external_was_not_evaluated():
    """No org domain means "not asked", which must not read as "none found"."""
    iam, bindings, principals, audit = _policy_records(org_domain=None)
    summary = iam.summarize(bindings, principals, audit, None, "unresolved")
    assert summary["external_members_evaluated"] is False
    assert summary["external_principals"] == 0
    assert summary["organization_domain"] is None
    assert summary["organization_domain_source"] == "unresolved"
    # The consumer-account finding does not depend on the org domain.
    assert summary["consumer_account_principals"] == 1


def test_project_record_reads_the_number_out_of_the_resource_name():
    iam = _load("iam_policy_bindings")
    rec = iam.project_record(PROJECT_DETAILS, POLICY_PROJECT)
    assert rec["project_number"] == "482910375610"
    assert rec["display_name"] == "Example Prod"
    assert rec["parent"] == "folders/778899"
    assert rec["labels"] == {"owner": "platform", "tier": "prod"}

    # A failed projects.get leaves the block present but empty, not missing.
    empty = iam.project_record(None, POLICY_PROJECT)
    assert empty["project_id"] == POLICY_PROJECT
    assert empty["project_number"] is None
    assert empty["labels"] is None


# --------------------------------------------------------------------------- #
# IAM custom roles — iam_admin_v1 Role.to_dict() shape
# --------------------------------------------------------------------------- #

ESCALATING_ROLE = {  # SYNTHETIC — a "deployer" role that is a path to any identity
    "name": "projects/example-prod/roles/appDeployer",
    "title": "App Deployer",
    "description": "Deploys the app",
    "stage": "GA",
    "included_permissions": [
        "iam.serviceAccounts.actAs",
        "run.services.create",
        "run.services.update",
        "resourcemanager.projects.setIamPolicy",
        "iam.roles.update",
        "iam.serviceAccountKeys.create",
        "storage.objects.get",
        "storage.objects.create",
    ],
}
READ_ONLY_ROLE_REST = {  # SYNTHETIC — camelCase-ish input, genuinely read-only
    "name": "projects/example-prod/roles/auditReader",
    "title": "Audit Reader",
    "included_permissions": [
        "logging.logEntries.list",
        "logging.logs.list",
        "storage.buckets.get",
        "storage.buckets.getIamPolicy",
        "compute.instances.list",
    ],
    # No `stage` field at all — the API omits it for an ALPHA role.
}
ORG_ROLE = {  # SYNTHETIC — defined above the project, bindable inside it
    "name": "organizations/778899/roles/orgBreakGlass",
    "title": "Break Glass",
    "stage": "DISABLED",
    "included_permissions": ["compute.instances.setMetadata", "compute.instances.get"],
    "deleted": False,
}


def _role_records():
    roles = _load("iam_custom_roles")
    return (
        roles,
        roles.role_record(ESCALATING_ROLE),
        roles.role_record(READ_ONLY_ROLE_REST),
        roles.role_record(ORG_ROLE, "organizations/778899"),
    )


def test_custom_role_permission_classification():
    roles = _load("iam_custom_roles")
    # Matched by suffix, because every service spells its own.
    assert roles.permission_escalation_category("resourcemanager.projects.setIamPolicy") == "set_iam_policy"
    assert roles.permission_escalation_category("cloudkms.cryptoKeys.setIamPolicy") == "set_iam_policy"
    assert roles.permission_escalation_category("iam.serviceAccounts.actAs") == "act_as_service_account"
    assert roles.permission_escalation_category("iam.serviceAccounts.signJwt") == "act_as_service_account"
    assert roles.permission_escalation_category("iam.roles.update") == "role_management"
    assert (
        roles.permission_escalation_category("iam.serviceAccountKeys.create")
        == "service_account_key_creation"
    )
    assert roles.permission_escalation_category("run.services.create") == "deployment_pivot"
    assert roles.permission_escalation_category("storage.objects.get") is None

    assert roles.permission_service("compute.instances.get") == "compute"
    assert roles.permission_verb("compute.instances.get") == "get"
    assert roles.is_read_only_permission("storage.buckets.getIamPolicy") is True
    assert roles.is_read_only_permission("storage.buckets.setIamPolicy") is False
    assert roles.is_read_only_permission("storage.objects.create") is False


def test_custom_role_record_escalation_and_shape():
    _roles, escalating, read_only, org = _role_records()

    assert escalating["role_id"] == "appDeployer"
    assert escalating["scope"] == "project"
    assert escalating["stage"] == "GA"
    assert escalating["permission_count"] == 8
    assert escalating["service_count"] == 4    # iam, run, resourcemanager, storage
    assert escalating["read_only"] is False
    assert escalating["grants_privilege_escalation"] is True
    assert escalating["privilege_escalation_categories"] == [
        "act_as_service_account",
        "deployment_pivot",
        "role_management",
        "service_account_key_creation",
        "set_iam_policy",
    ]
    assert escalating["grants_set_iam_policy"] is True
    assert escalating["grants_role_management"] is True
    # The classic path: run code as any identity the role can act as.
    assert escalating["grants_act_as_with_deployment_pivot"] is True
    assert escalating["privilege_escalation_by_category"]["deployment_pivot"] == [
        "run.services.create",
        "run.services.update",
    ]

    assert read_only["read_only"] is True
    assert read_only["mutating_permission_count"] == 0
    assert read_only["grants_privilege_escalation"] is False
    # An ALPHA role comes back with no stage field.
    assert read_only["stage"] == "ALPHA"
    assert read_only["disabled"] is False

    assert org["scope"] == "organizations/778899"
    assert org["stage"] == "DISABLED"
    # A DISABLED role contributes no permissions to any principal bound to it.
    assert org["disabled"] is True
    assert org["service_count"] == 1
    assert org["grants_privilege_escalation"] is True    # setMetadata is a pivot


def test_custom_role_summary():
    roles, escalating, read_only, org = _role_records()
    summary = roles.summarize([escalating, read_only, org], "organizations/778899", True)
    assert summary["total_custom_roles"] == 3
    assert summary["project_scoped_roles"] == 2
    assert summary["organization_scoped_roles"] == 1
    assert summary["organization_roles_readable"] is True
    assert summary["role_stages"] == {"ALPHA": 1, "DISABLED": 1, "GA": 1}
    assert summary["disabled_roles"] == 1
    assert summary["read_only_roles"] == 1
    assert summary["largest_role_permission_count"] == 8
    assert summary["roles_spanning_multiple_services"] == 2
    assert summary["roles_granting_privilege_escalation"] == 2
    assert summary["no_privilege_escalation_percentage"] == 33
    assert summary["roles_granting_set_iam_policy"] == 1
    assert summary["roles_granting_act_as_with_deployment_pivot"] == 1
    assert summary["privilege_escalation_category_counts"]["set_iam_policy"] == 1
    assert summary["privilege_escalation_category_counts"]["deployment_pivot"] == 2
    assert summary["total_distinct_permissions"] == 15


def test_custom_role_summary_marks_unreadable_organization_roles():
    """A 403 above the project must not read as "the org defines no custom roles"."""
    roles = _load("iam_custom_roles")
    summary = roles.summarize([], None, False)
    assert summary["organization_roles_readable"] is False
    assert summary["total_custom_roles"] == 0
    assert summary["no_privilege_escalation_percentage"] == 0


# --------------------------------------------------------------------------- #
# Cloud KMS — kms_v1 CryptoKey.to_dict() / KeyRing.to_dict() shapes
# --------------------------------------------------------------------------- #

ROTATED_KEY = {  # SYNTHETIC — the posture a well-managed HSM key reports
    "name": "projects/example-prod/locations/us-central1/keyRings/prod/cryptoKeys/db",
    "purpose": "ENCRYPT_DECRYPT",
    "create_time": "2025-02-01T00:00:00Z",
    "rotation_period": "7776000s",             # 90 days
    "next_rotation_time": "2026-10-01T00:00:00Z",
    "destroy_scheduled_duration": "2592000s",  # 30 days
    "version_template": {
        "protection_level": "HSM",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
    },
    "primary": {
        "name": ".../cryptoKeys/db/cryptoKeyVersions/7",
        "state": "ENABLED",
        "protection_level": "HSM",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
        "generate_time": "2026-07-03T00:00:00Z",
    },
}
PUBLIC_STALE_KEY = {  # SYNTHETIC — REST camelCase; never rotated, and world-usable
    "name": "projects/example-prod/locations/global/keyRings/legacy/cryptoKeys/shared",
    "purpose": "ENCRYPT_DECRYPT",
    "createTime": "2021-06-01T00:00:00Z",
    # No rotationPeriod / nextRotationTime at all.
    "destroyScheduledDuration": "86400s",      # the API floor: 24h
    "versionTemplate": {
        "protectionLevel": "SOFTWARE",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
    },
    "primary": {
        "name": ".../cryptoKeys/shared/cryptoKeyVersions/1",
        "state": "DISABLED",
        "protectionLevel": "SOFTWARE",
    },
}
ASYMMETRIC_KEY = {  # SYNTHETIC — cannot carry a rotation period by design
    "name": "projects/example-prod/locations/us-central1/keyRings/prod/cryptoKeys/signer",
    "purpose": "ASYMMETRIC_SIGN",
    "version_template": {
        "protection_level": "EXTERNAL",
        "algorithm": "EC_SIGN_P256_SHA256",
    },
    "primary": {"name": ".../cryptoKeyVersions/2", "state": "ENABLED"},
}

PUBLIC_BINDINGS = [
    {"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["allUsers"]},
]
SOD_BINDINGS = [
    {"role": "roles/cloudkms.admin", "members": ["group:crypto@example.com"]},
    {
        "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "members": ["group:crypto@example.com", "serviceAccount:db@example-prod.iam.gserviceaccount.com"],
    },
]

PROD_RING = {  # SYNTHETIC
    "name": "projects/example-prod/locations/us-central1/keyRings/prod",
    "create_time": "2025-01-15T00:00:00Z",
}
LEGACY_RING_REST = {  # SYNTHETIC — camelCase
    "name": "projects/example-prod/locations/global/keyRings/legacy",
    "createTime": "2021-05-01T00:00:00Z",
}


def test_kms_duration_parsing_in_every_shape_it_arrives_in():
    kms = _load("kms_key_configuration")
    assert kms.duration_days("7776000s") == 90
    assert kms.duration_days("2592000s") == 30
    # Prowler slices the trailing "s" by hand and crashes on the mapping form.
    assert kms.duration_days({"seconds": 2592000}) == 30
    assert kms.duration_days(86400) == 1
    assert kms.duration_days(None) is None
    assert kms.duration_days("not-a-duration") is None
    # Normalized back to the API's own spelling, whichever shape came in.
    assert kms.duration_text({"seconds": 7776000}) == "7776000s"
    assert kms.duration_text(None) is None
    assert kms.resource_segment(ROTATED_KEY["name"], "locations") == "us-central1"
    assert kms.resource_segment(ROTATED_KEY["name"], "keyRings") == "prod"
    assert kms.resource_segment(None, "locations") is None


def test_kms_rotated_key_meets_the_interval_on_both_halves():
    kms = _load("kms_key_configuration")
    rec = kms.crypto_key_record(ROTATED_KEY, SOD_BINDINGS, NOW)
    assert rec["key_id"] == "db"
    assert rec["key_ring"] == "prod"
    assert rec["location"] == "us-central1"
    assert rec["rotation_supported"] is True
    assert rec["rotation_enabled"] is True
    assert rec["rotation_period_days"] == 90
    assert rec["days_until_next_rotation"] == 49
    assert rec["rotation_period_within_max_days"] is True
    assert rec["next_rotation_within_max_days"] is True
    # Prowler's kms_key_rotation_max_90_days needs BOTH.
    assert rec["meets_rotation_interval"] is True
    assert rec["protection_level"] == "HSM"
    assert rec["hardware_backed"] is True
    assert rec["external_key"] is False
    assert rec["primary_version_id"] == "7"
    assert rec["primary_version_state"] == "ENABLED"
    assert rec["primary_version_enabled"] is True
    assert rec["destroy_scheduled_days"] == 30
    # Prowler's iam_role_kms_enforce_separation_of_duties, at the key.
    assert rec["separation_of_duties_violated"] is True
    assert rec["separation_of_duties_members"] == ["group:crypto@example.com"]
    assert rec["publicly_accessible"] is False


def test_kms_public_unrotated_key_in_rest_spelling():
    kms = _load("kms_key_configuration")
    rec = kms.crypto_key_record(PUBLIC_STALE_KEY, PUBLIC_BINDINGS, NOW)
    assert rec["rotation_enabled"] is False
    assert rec["rotation_period_days"] is None
    assert rec["days_until_next_rotation"] is None
    assert rec["meets_rotation_interval"] is False
    assert rec["protection_level"] == "SOFTWARE"
    assert rec["hardware_backed"] is False
    assert rec["primary_version_state"] == "DISABLED"
    assert rec["primary_version_enabled"] is False
    # The API floor — an accidental destroy is recoverable for one day.
    assert rec["destroy_scheduled_days"] == 1
    # The critical finding: the CMEK on everything referencing this key is moot.
    assert rec["publicly_accessible"] is True
    assert rec["public_members"] == ["allUsers"]
    assert rec["separation_of_duties_violated"] is False


def test_kms_asymmetric_key_cannot_rotate_on_a_schedule():
    """A missing rotation period on an asymmetric key is the API's design."""
    kms = _load("kms_key_configuration")
    rec = kms.crypto_key_record(ASYMMETRIC_KEY, [], NOW)
    assert rec["purpose"] == "ASYMMETRIC_SIGN"
    assert rec["rotation_supported"] is False
    assert rec["rotation_enabled"] is False
    assert rec["external_key"] is True
    assert rec["iam_bindings"] == []
    assert rec["iam_member_count"] == 0


def test_kms_key_ring_record_carries_its_own_policy():
    """A binding on the RING inherits to every key in it."""
    kms = _load("kms_key_configuration")
    keys = [kms.crypto_key_record(PUBLIC_STALE_KEY, [], NOW)]
    rec = kms.key_ring_record(LEGACY_RING_REST, keys, PUBLIC_BINDINGS)
    assert rec["key_ring_id"] == "legacy"
    assert rec["location"] == "global"
    assert rec["create_time"] == "2021-05-01T00:00:00Z"
    assert rec["crypto_key_count"] == 1
    assert rec["crypto_keys"] == ["shared"]
    assert rec["publicly_accessible"] is True


def test_kms_summary():
    kms = _load("kms_key_configuration")
    keys = [
        kms.crypto_key_record(ROTATED_KEY, SOD_BINDINGS, NOW),
        kms.crypto_key_record(PUBLIC_STALE_KEY, PUBLIC_BINDINGS, NOW),
        kms.crypto_key_record(ASYMMETRIC_KEY, [], NOW),
    ]
    rings = [
        kms.key_ring_record(PROD_RING, [keys[0], keys[2]], SOD_BINDINGS),
        kms.key_ring_record(LEGACY_RING_REST, [keys[1]], PUBLIC_BINDINGS),
    ]
    summary = kms.summarize(rings, keys, ["global", "us-central1"])

    assert summary["kms_api_readable"] is True
    assert summary["locations_scanned"] == 2
    assert summary["total_key_rings"] == 2
    assert summary["total_crypto_keys"] == 3
    assert summary["keys_by_purpose"] == {"ASYMMETRIC_SIGN": 1, "ENCRYPT_DECRYPT": 2}
    assert summary["keys_by_protection_level"] == {"EXTERNAL": 1, "HSM": 1, "SOFTWARE": 1}
    assert summary["hsm_keys"] == 1
    assert summary["external_keys"] == 1
    # Measured over the keys that CAN rotate on a schedule, not all of them.
    assert summary["rotation_eligible_keys"] == 2
    assert summary["keys_without_rotation_period"] == 1
    assert summary["keys_meeting_rotation_interval"] == 1
    assert summary["rotation_compliance_percentage"] == 50
    assert summary["shortest_rotation_period_days"] == 90
    assert summary["primary_version_states"] == {"DISABLED": 1, "ENABLED": 2}
    assert summary["keys_with_disabled_primary_version"] == 1
    assert summary["shortest_destroy_scheduled_days"] == 1
    assert summary["publicly_accessible"] is True
    assert summary["publicly_accessible_keys"] == 1
    assert summary["publicly_accessible_key_rings"] == 1
    assert summary["keys_violating_separation_of_duties"] == 1


def test_kms_summary_marks_an_unreadable_api():
    """A project with cloudkms disabled: no keys, and it says why."""
    kms = _load("kms_key_configuration")
    summary = kms.summarize([], [], [], api_readable=False)
    assert summary["kms_api_readable"] is False
    assert summary["total_crypto_keys"] == 0
    assert summary["rotation_compliance_percentage"] == 0
    assert summary["publicly_accessible"] is False


# --------------------------------------------------------------------------- #
# Cloud DNS — discovery (dns v1) camelCase shapes, plus one snake_case spelling
# --------------------------------------------------------------------------- #

SIGNED_ZONE = {  # SYNTHETIC — DNSSEC on with modern algorithms, queries logged
    "name": "example-com",
    "id": "3300112244",
    "dnsName": "example.com.",
    "description": "primary public zone",
    "creationTime": "2024-03-04T10:00:00.123Z",
    "visibility": "public",
    "nameServers": ["ns-cloud-a2.googledomains.com.", "ns-cloud-a1.googledomains.com."],
    "dnssecConfig": {
        "state": "on",
        "nonExistence": "nsec3",
        "defaultKeySpecs": [
            {"keyType": "keySigning", "algorithm": "rsasha256", "keyLength": 2048},
            {"keyType": "zoneSigning", "algorithm": "ecdsap256sha256", "keyLength": 256},
        ],
    },
    "cloudLoggingConfig": {"enableLogging": True},
}
WEAK_ZONE = {  # SYNTHETIC — DNSSEC "on" and cryptographically hollow
    "name": "legacy-example-com",
    "id": "3300112245",
    "dnsName": "legacy.example.com.",
    "visibility": "public",
    "dnssecConfig": {
        "state": "on",
        "defaultKeySpecs": [
            {"keyType": "keySigning", "algorithm": "rsasha1", "keyLength": 2048},
            {"keyType": "zoneSigning", "algorithm": "rsasha1", "keyLength": 1024},
        ],
    },
}
UNSIGNED_PUBLIC_ZONE = {  # SYNTHETIC — the plain finding
    "name": "marketing-example-com",
    "id": "3300112246",
    "dnsName": "marketing.example.com.",
    # No visibility field at all — the API omits it on a public zone.
    "dnssecConfig": {"state": "off"},
}
PRIVATE_ZONE_SNAKE = {  # SYNTHETIC — snake_case spelling; DNSSEC does not apply
    "name": "internal",
    "id": "3300112247",
    "dns_name": "internal.example.",
    "visibility": "private",
    "private_visibility_config": {
        "networks": [
            {"network_url": "https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc-prod"}
        ],
        "gke_clusters": [{"gke_cluster_name": "projects/p/locations/us-central1/clusters/prod"}],
    },
    "cloud_logging_config": {"enable_logging": True},
}
TRANSFER_ZONE = {  # SYNTHETIC — mid-migration between DNSSEC providers
    "name": "moving-example-com",
    "id": "3300112248",
    "visibility": "public",
    "dnssecConfig": {"state": "transfer", "defaultKeySpecs": []},
    "forwardingConfig": {"targetNameServers": [{"ipv4Address": "10.1.0.53"}]},
}

LOGGING_POLICY = {  # SYNTHETIC
    "name": "vpc-logging",
    "id": "5500223344",
    "description": "log all VPC DNS queries",
    "enableLogging": True,
    "enableInboundForwarding": False,
    "networks": [
        {"networkUrl": "https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc-prod"}
    ],
}
FORWARDING_POLICY = {  # SYNTHETIC — inbound forwarding on, nothing logged
    "name": "hybrid-inbound",
    "id": "5500223345",
    "enableInboundForwarding": True,
    "alternativeNameServerConfig": {"targetNameServers": [{"ipv4Address": "192.168.10.53"}]},
}


def _dns_records():
    dns = _load("dns_configuration")
    zones = [
        dns.zone_record(SIGNED_ZONE),
        dns.zone_record(WEAK_ZONE),
        dns.zone_record(UNSIGNED_PUBLIC_ZONE),
        dns.zone_record(PRIVATE_ZONE_SNAKE),
        dns.zone_record(TRANSFER_ZONE),
    ]
    policies = [dns.policy_record(LOGGING_POLICY), dns.policy_record(FORWARDING_POLICY)]
    return dns, zones, policies


def test_dns_signed_zone_facts():
    _dns, zones, _policies = _dns_records()
    signed = zones[0]
    assert signed["dns_name"] == "example.com."
    assert signed["visibility"] == "public"
    assert signed["public"] is True
    assert signed["dnssec_applicable"] is True
    assert signed["dnssec_state"] == "on"
    assert signed["dnssec_enabled"] is True
    assert signed["dnssec_non_existence"] == "nsec3"
    assert signed["key_signing_algorithms"] == ["rsasha256"]
    assert signed["zone_signing_algorithms"] == ["ecdsap256sha256"]
    assert signed["uses_weak_signing_algorithm"] is False
    assert signed["logging_enabled"] is True
    assert signed["name_servers"] == [
        "ns-cloud-a1.googledomains.com.",
        "ns-cloud-a2.googledomains.com.",
    ]


def test_dns_rsasha1_is_reported_per_key_type():
    """Prowler keeps its two RSASHA1 checks apart; either key type can be weak."""
    dns, zones, _policies = _dns_records()
    weak = zones[1]
    assert weak["dnssec_enabled"] is True
    assert weak["rsasha1_key_signing"] is True
    assert weak["rsasha1_zone_signing"] is True
    assert weak["uses_weak_signing_algorithm"] is True
    assert weak["key_specs"][0]["weak_algorithm"] is True

    key_only = dns.zone_record(
        {
            "name": "half-weak",
            "visibility": "public",
            "dnssecConfig": {
                "state": "on",
                "defaultKeySpecs": [
                    {"keyType": "keySigning", "algorithm": "rsasha1"},
                    {"keyType": "zoneSigning", "algorithm": "rsasha256"},
                ],
            },
        }
    )
    assert key_only["rsasha1_key_signing"] is True
    assert key_only["rsasha1_zone_signing"] is False


def test_dns_visibility_defaults_to_public_and_gates_dnssec():
    _dns, zones, _policies = _dns_records()
    unsigned, private = zones[2], zones[3]

    # No visibility field: guessing "private" would understate the exposure.
    assert unsigned["visibility"] == "public"
    assert unsigned["dnssec_enabled"] is False
    assert unsigned["dnssec_applicable"] is True
    assert unsigned["logging_enabled"] is False

    # snake_case input, and a private zone has no public path to protect.
    assert private["visibility"] == "private"
    assert private["public"] is False
    assert private["dnssec_applicable"] is False
    assert private["dnssec_state"] is None
    assert private["private_networks"] == ["vpc-prod"]
    assert private["private_gke_clusters"] == [
        "projects/p/locations/us-central1/clusters/prod"
    ]
    assert private["logging_enabled"] is True


def test_dns_transfer_state_survives():
    """Prowler flattens the state to `== "on"` and loses this one entirely."""
    _dns, zones, _policies = _dns_records()
    transfer = zones[4]
    assert transfer["dnssec_state"] == "transfer"
    assert transfer["dnssec_enabled"] is False
    assert transfer["forwarding_targets"] == ["10.1.0.53"]


def test_dns_policy_record():
    _dns, _zones, policies = _dns_records()
    logging_policy, forwarding = policies
    assert logging_policy["logging_enabled"] is True
    assert logging_policy["inbound_forwarding_enabled"] is False
    assert logging_policy["networks"] == ["vpc-prod"]
    assert forwarding["logging_enabled"] is False
    assert forwarding["inbound_forwarding_enabled"] is True
    assert forwarding["alternative_name_servers"] == ["192.168.10.53"]


def test_dns_summary():
    dns, zones, policies = _dns_records()
    summary = dns.summarize(zones, policies)
    assert summary["dns_api_readable"] is True
    assert summary["total_managed_zones"] == 5
    assert summary["public_zones"] == 4
    assert summary["private_zones"] == 1
    assert summary["dnssec_enabled_zones"] == 2
    assert summary["dnssec_transferring_zones"] == 1
    # Over the four PUBLIC zones, not all five.
    assert summary["dnssec_public_zone_percentage"] == 50
    assert summary["unsigned_public_zones"] == 2
    assert summary["zones_using_weak_signing_algorithm"] == 1
    assert summary["rsasha1_key_signing_zones"] == 1
    assert summary["rsasha1_zone_signing_zones"] == 1
    assert summary["key_signing_algorithms"] == {"rsasha1": 1, "rsasha256": 1}
    assert summary["logging_enabled_zones"] == 2
    assert summary["logging_enabled_zone_percentage"] == 40
    assert summary["forwarding_zones"] == 1
    assert summary["total_dns_policies"] == 2
    assert summary["logging_enabled_policies"] == 1
    assert summary["inbound_forwarding_policies"] == 1


def test_dns_summary_marks_an_unreadable_api():
    dns = _load("dns_configuration")
    summary = dns.summarize([], [], api_readable=False)
    assert summary["dns_api_readable"] is False
    assert summary["total_managed_zones"] == 0
    assert summary["dnssec_public_zone_percentage"] == 0


# --------------------------------------------------------------------------- #
# API keys — api_keys_v2 Key.to_dict() shape
# --------------------------------------------------------------------------- #

# A key string never reaches the evidence. The fixture carries one so the test can
# prove it: every field is projected by name, so even an API that started
# returning keyString from keys.list could not leak it.
FIXTURE_KEY_STRING = "AIza-FIXTURE-NOT-A-REAL-KEY-0000000000"

RESTRICTED_KEY = {  # SYNTHETIC — both axes restricted
    "name": "projects/482910375610/locations/global/keys/aa11bb22",
    "uid": "aa11bb22-3344-5566-7788-99aabbccddee",
    "display_name": "maps frontend",
    "key_string": FIXTURE_KEY_STRING,
    "create_time": "2026-06-10T09:00:00Z",
    "update_time": "2026-08-01T09:00:00Z",
    "restrictions": {
        "browser_key_restrictions": {
            "allowed_referrers": ["https://example.com/*", "https://www.example.com/*"]
        },
        "api_targets": [
            {"service": "maps-backend.googleapis.com", "methods": []},
            {"service": "places-backend.googleapis.com", "methods": ["GET*"]},
        ],
    },
}
UNRESTRICTED_KEY_REST = {  # SYNTHETIC — REST camelCase, no restrictions block
    "name": "projects/482910375610/locations/global/keys/cc33dd44",
    "uid": "cc33dd44-3344-5566-7788-99aabbccddee",
    "displayName": "legacy server key",
    "keyString": FIXTURE_KEY_STRING,
    "createTime": "2022-01-15T09:00:00Z",
    "updateTime": "2022-01-15T09:00:00Z",
}
WILDCARD_KEY = {  # SYNTHETIC — "restricted" in the console, unrestricted in fact
    "name": "projects/482910375610/locations/global/keys/ee55ff66",
    "uid": "ee55ff66-3344-5566-7788-99aabbccddee",
    "display_name": "everything key",
    "create_time": "2026-05-01T09:00:00Z",
    "update_time": "2026-05-02T09:00:00Z",
    "restrictions": {"api_targets": [{"service": "cloudapis.googleapis.com"}]},
}
SERVER_KEY = {  # SYNTHETIC — IP-restricted, but reachable by any API
    "name": "projects/482910375610/locations/global/keys/1122aabb",
    "uid": "1122aabb-3344-5566-7788-99aabbccddee",
    "display_name": "batch runner",
    "create_time": "2026-07-20T09:00:00Z",
    "update_time": "2026-07-20T09:00:00Z",
    "restrictions": {"server_key_restrictions": {"allowed_ips": ["203.0.113.7/32"]}},
}


def _key_records():
    keys = _load("api_keys_inventory")
    return keys, [
        keys.key_record(RESTRICTED_KEY, NOW),
        keys.key_record(UNRESTRICTED_KEY_REST, NOW),
        keys.key_record(WILDCARD_KEY, NOW),
        keys.key_record(SERVER_KEY, NOW),
    ]


def test_api_key_record_never_emits_key_material():
    """The one rule this evidence set cannot break."""
    _keys, records = _key_records()
    blob = json.dumps(records)
    assert FIXTURE_KEY_STRING not in blob
    assert "key_string" not in blob
    assert "keyString" not in blob
    assert all(r["key_material_collected"] is False for r in records)


def test_api_key_restriction_axes_are_unpacked():
    _keys, records = _key_records()
    restricted, unrestricted, wildcard, server = records

    assert restricted["display_name"] == "maps frontend"
    assert restricted["uid"].startswith("aa11bb22")
    assert restricted["api_restrictions_configured"] is True
    assert restricted["client_restrictions_configured"] is True
    assert restricted["fully_restricted"] is True
    assert restricted["unrestricted"] is False
    assert restricted["allowed_referrers"] == [
        "https://example.com/*",
        "https://www.example.com/*",
    ]
    assert restricted["api_target_services"] == [
        "maps-backend.googleapis.com",
        "places-backend.googleapis.com",
    ]
    # `methods` narrows a target to specific RPCs; empty means the whole service.
    assert [t["method_count"] for t in restricted["api_targets"]] == [0, 1]
    assert restricted["age_days"] == 63
    assert restricted["days_since_update"] == 11
    assert restricted["never_updated"] is False
    assert restricted["past_rotation_age"] is False

    # camelCase input, and no restrictions block at all.
    assert unrestricted["display_name"] == "legacy server key"
    assert unrestricted["unrestricted"] is True
    assert unrestricted["api_targets"] == []
    assert unrestricted["allowed_ips"] == []
    assert unrestricted["never_updated"] is True
    assert unrestricted["past_rotation_age"] is True
    assert unrestricted["age_days"] == 1670

    # Prowler's rule: the cloudapis wildcard restricts nothing.
    assert wildcard["targets_all_cloud_apis"] is True
    assert wildcard["api_restrictions_configured"] is False
    assert wildcard["unrestricted"] is True

    # One axis only: reachable from one IP, but against every enabled API.
    assert server["client_restrictions_configured"] is True
    assert server["api_restrictions_configured"] is False
    assert server["unrestricted"] is False
    assert server["fully_restricted"] is False
    assert server["allowed_ips"] == ["203.0.113.7/32"]


def test_api_key_record_tolerates_missing_timestamps():
    keys = _load("api_keys_inventory")
    rec = keys.key_record({"uid": "zz99", "display_name": "orphan"}, NOW)
    assert rec["age_days"] is None
    assert rec["days_since_update"] is None
    assert rec["never_updated"] is False
    assert rec["past_rotation_age"] is False
    assert rec["unrestricted"] is True
    assert keys.parse_timestamp("not-a-timestamp") is None


def test_api_keys_summary():
    keys, records = _key_records()
    summary = keys.summarize(records)
    assert summary["api_keys_api_readable"] is True
    assert summary["total_api_keys"] == 4
    assert summary["no_api_keys"] is False
    assert summary["unrestricted_keys"] == 2
    assert summary["api_restricted_keys"] == 1
    assert summary["client_restricted_keys"] == 2
    assert summary["fully_restricted_keys"] == 1
    assert summary["restricted_key_percentage"] == 50
    assert summary["keys_targeting_all_cloud_apis"] == 1
    # The 1670-day-old key and the 103-day-old wildcard key.
    assert summary["keys_past_rotation_age"] == 2
    assert summary["rotation_age_days"] == 90
    assert summary["oldest_key_age_days"] == 1670
    assert summary["keys_never_updated"] == 2
    assert summary["api_target_service_counts"] == {
        "cloudapis.googleapis.com": 1,
        "maps-backend.googleapis.com": 1,
        "places-backend.googleapis.com": 1,
    }
    assert summary["key_material_collected"] is False


def test_api_keys_summary_zero_keys_is_a_passing_posture():
    """Prowler's apikeys_key_exists: no API keys is the defensible answer."""
    keys = _load("api_keys_inventory")
    assert keys.summarize([])["no_api_keys"] is True
    # ...but only when the API was actually readable.
    assert keys.summarize([], api_readable=False)["no_api_keys"] is False


# --------------------------------------------------------------------------- #
# End to end with broken credentials. Offline: GOOGLE_APPLICATION_CREDENTIALS
# points at a file that does not exist, so ADC resolution fails before any
# network call. (Deliberately a local copy of the harness in
# test_gcp_platform_fetchers.py — each test module stands alone, and the repo
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


@pytest.mark.parametrize("short_name", IDENTITY_FETCHERS)
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
