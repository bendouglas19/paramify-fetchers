#!/usr/bin/env python3
"""
GCP IAM Custom Role Definitions

Every custom role defined for one project — and, when the organization is
readable, the custom roles defined above it that can be bound inside it. For each
role: its id, launch stage, deleted state, and the full list of permissions it
grants, classified so the permissions that let a holder escalate out of the role
are visible without reading 200 permission strings by eye.

A predefined role's contents are Google's problem. A CUSTOM role's contents are
the customer's, which makes this the only IAM surface where the definition itself
is the evidence: `roles/appOperator` tells a reviewer nothing, while
`iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` tells them the
role is a path to any identity in the project.

The escalation classes reported per role:
- **`set_iam_policy`** — any `*.setIamPolicy` permission. A holder can grant
  themselves (or anyone) any role on that resource, so the role's stated scope
  stops bounding it.
- **`act_as_service_account`** — `iam.serviceAccounts.actAs` and the token/blob/JWT
  signing permissions. A holder runs code as another identity, inheriting its
  roles.
- **`role_management`** — `iam.roles.create` / `.update` / `.delete` / `.undelete`.
  A holder rewrites the definition of the role they hold.
- **`service_account_key_creation`** — minting a downloadable private key for an
  identity, which then lives outside GCP's control (see the sibling
  gcp_iam_service_accounts evidence set for what those keys look like afterwards).
- **`deployment_pivot`** — create/update on a compute or build surface that runs
  code with an attached service account. Dangerous only when paired with actAs,
  which is why the pairing is reported per role rather than each half alone.

**Prowler is not the source here.** Its GCP provider has no custom-role service
and no custom-role check: prowler/providers/gcp/services/iam/ enumerates service
accounts, their keys, and workload identity pool providers, and its role-related
checks (iam_role_kms_enforce_separation_of_duties,
iam_role_sa_enforce_separation_of_duties) read project BINDINGS from
cloudresourcemanager, never role DEFINITIONS. The API offers
`iam.projects.roles.list` with `view=FULL`, which returns included_permissions;
everything below the role's id and title is therefore an extension beyond Prowler,
and the escalation classification is this fetcher's own — modelled on the
well-known GCP privilege-escalation paths, not ported from a Prowler check.

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
    access_denied,
    basename,
    build_payload,
    coverage_percentage,
    credentials,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    write_status,
)

logger = logging.getLogger("gcp_iam_custom_roles")

# GCP allows at most 10 levels of folders between a project and its organization.
_MAX_ANCESTRY_DEPTH = 10

# Any permission ending here lets its holder rewrite the IAM policy on that
# resource — including granting themselves a broader role. Matched by suffix
# because every GCP service spells its own (resourcemanager.projects.setIamPolicy,
# iam.serviceAccounts.setIamPolicy, cloudkms.cryptoKeys.setIamPolicy, ...).
_SET_IAM_POLICY_SUFFIX = ".setIamPolicy"

# Run code as another identity, or mint a credential for it.
_ACT_AS_PERMISSIONS = frozenset(
    {
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
    }
)

# Rewrite a role definition — including the definition of the role you hold.
_ROLE_MANAGEMENT_PERMISSIONS = frozenset(
    {
        "iam.roles.create",
        "iam.roles.delete",
        "iam.roles.undelete",
        "iam.roles.update",
    }
)

# Produce a downloadable private key, which then rotates only if someone
# remembers to rotate it.
_SERVICE_ACCOUNT_KEY_PERMISSIONS = frozenset(
    {
        "iam.serviceAccountKeys.create",
        "iam.serviceAccountKeys.update",
    }
)

# Create or update something that RUNS CODE with an attached service account.
# Escalation only in combination with actAs, so the two are reported separately
# and their coincidence is reported as its own fact.
_DEPLOYMENT_PIVOT_PERMISSIONS = frozenset(
    {
        "cloudbuild.builds.create",
        "cloudfunctions.functions.create",
        "cloudfunctions.functions.sourceCodeSet",
        "cloudfunctions.functions.update",
        "cloudscheduler.jobs.create",
        "composer.environments.create",
        "compute.instances.create",
        "compute.instances.setMetadata",
        "compute.instances.setServiceAccount",
        "dataflow.jobs.create",
        "dataproc.clusters.create",
        "deploymentmanager.deployments.create",
        "orgpolicy.policy.set",
        "run.services.create",
        "run.services.update",
    }
)

_ESCALATION_CATEGORIES = (
    "act_as_service_account",
    "deployment_pivot",
    "role_management",
    "service_account_key_creation",
    "set_iam_policy",
)

# The final segment of a permission that only ever reads. Anything else mutates
# state, which is what makes "is this custom role actually read-only?" answerable.
# getIamPolicy reads a policy; setIamPolicy is deliberately absent.
_READ_ONLY_VERBS = frozenset(
    {
        "aggregatedList",
        "get",
        "getIamPolicy",
        "list",
        "search",
        "testIamPermissions",
        "view",
        "watch",
    }
)


# --- pure transforms (operate on to_dict() output; unit-tested from fixtures) ---

def permission_escalation_category(permission: str) -> str | None:
    """Which escalation class a permission belongs to, or None for an ordinary one."""
    if permission.endswith(_SET_IAM_POLICY_SUFFIX):
        return "set_iam_policy"
    if permission in _ACT_AS_PERMISSIONS:
        return "act_as_service_account"
    if permission in _ROLE_MANAGEMENT_PERMISSIONS:
        return "role_management"
    if permission in _SERVICE_ACCOUNT_KEY_PERMISSIONS:
        return "service_account_key_creation"
    if permission in _DEPLOYMENT_PIVOT_PERMISSIONS:
        return "deployment_pivot"
    return None


def permission_service(permission: str) -> str | None:
    """The service a permission belongs to (`compute` in `compute.instances.get`).

    How many services a single custom role spans is the plainest measure of how
    focused it is: a role touching one service is scoped, a role touching twelve
    is a primitive role wearing a custom name.
    """
    service = (permission or "").split(".", 1)[0]
    return service or None


def permission_verb(permission: str) -> str | None:
    """The action a permission grants (`get` in `compute.instances.get`)."""
    parts = (permission or "").rsplit(".", 1)
    return parts[-1] if len(parts) == 2 and parts[-1] else None


def is_read_only_permission(permission: str) -> bool:
    return permission_verb(permission) in _READ_ONLY_VERBS


def role_record(role: dict, scope: str = "project") -> dict:
    """Normalize one custom role definition into an evidence record.

    `scope` is where the role is defined: "project", or the ancestor resource
    ("organizations/123"). An organization-level custom role is bindable inside
    the project, so it belongs in the project's evidence even though it isn't
    defined there.
    """
    permissions = sorted(set(role.get("included_permissions") or []))
    by_category: dict[str, list[str]] = {}
    for permission in permissions:
        category = permission_escalation_category(permission)
        if category:
            by_category.setdefault(category, []).append(permission)

    services = sorted({s for s in (permission_service(p) for p in permissions) if s})
    mutating = [p for p in permissions if not is_read_only_permission(p)]
    escalation = sorted({p for group in by_category.values() for p in group})

    return {
        "name": role.get("name") or None,
        "role_id": basename(role.get("name")),
        "scope": scope,
        "title": role.get("title") or None,
        "description": role.get("description") or None,
        # ALPHA-stage roles come back with no stage field at all (the API omits it),
        # so an absent stage is reported as ALPHA rather than as unknown.
        "stage": role.get("stage") or "ALPHA",
        # A DISABLED role contributes no permissions to any principal it is bound
        # to; a deleted one is in the 7-day undelete window.
        "disabled": (role.get("stage") or "") == "DISABLED",
        "deleted": bool(role.get("deleted")),
        "permission_count": len(permissions),
        "included_permissions": permissions,
        "services": services,
        "service_count": len(services),
        "mutating_permission_count": len(mutating),
        "read_only": bool(permissions) and not mutating,
        "privilege_escalation_permissions": escalation,
        "privilege_escalation_categories": sorted(by_category),
        "privilege_escalation_by_category": {k: v for k, v in sorted(by_category.items())},
        "grants_privilege_escalation": bool(escalation),
        # Spelled out individually because these are the three a reviewer looks
        # for by name, and because the actAs + deployment pairing is the classic
        # "run as any service account" path.
        "grants_set_iam_policy": "set_iam_policy" in by_category,
        "grants_act_as_service_account": "act_as_service_account" in by_category,
        "grants_role_management": "role_management" in by_category,
        "grants_act_as_with_deployment_pivot": (
            "act_as_service_account" in by_category and "deployment_pivot" in by_category
        ),
    }


def summarize(roles: list[dict], organization_scope: str | None, org_readable: bool) -> dict:
    stages: dict[str, int] = {}
    for role in roles:
        stages[role["stage"]] = stages.get(role["stage"], 0) + 1

    escalating = [r for r in roles if r["grants_privilege_escalation"]]
    permissions = {p for r in roles for p in r["included_permissions"]}
    counts = [r["permission_count"] for r in roles]

    summary = {
        "total_custom_roles": len(roles),
        "project_scoped_roles": sum(1 for r in roles if r["scope"] == "project"),
        "organization_scoped_roles": sum(1 for r in roles if r["scope"] != "project"),
        "organization_scope": organization_scope,
        # False means the organization's roles were not readable, so the inventory
        # covers the project's own custom roles only — not that there are none.
        "organization_roles_readable": org_readable,
        "role_stages": dict(sorted(stages.items())),
        "disabled_roles": sum(1 for r in roles if r["disabled"]),
        "deleted_roles": sum(1 for r in roles if r["deleted"]),
        "read_only_roles": sum(1 for r in roles if r["read_only"]),
        "total_distinct_permissions": len(permissions),
        "largest_role_permission_count": max(counts) if counts else 0,
        "roles_spanning_multiple_services": sum(1 for r in roles if r["service_count"] > 1),
        "roles_granting_privilege_escalation": len(escalating),
        # The posture to evidence: no custom role is a way out of its own scope.
        "no_privilege_escalation_percentage": coverage_percentage(
            len(roles) - len(escalating), len(roles)
        ),
        "roles_granting_set_iam_policy": sum(1 for r in roles if r["grants_set_iam_policy"]),
        "roles_granting_act_as_service_account": sum(
            1 for r in roles if r["grants_act_as_service_account"]
        ),
        "roles_granting_role_management": sum(1 for r in roles if r["grants_role_management"]),
        "roles_granting_act_as_with_deployment_pivot": sum(
            1 for r in roles if r["grants_act_as_with_deployment_pivot"]
        ),
    }
    summary["privilege_escalation_category_counts"] = {
        category: sum(1 for r in roles if category in r["privilege_escalation_categories"])
        for category in _ESCALATION_CATEGORIES
    }
    return summary


# --- collection (lazy google imports; not exercised by the fixture tests) ---

def _outside_project_scope(exc: BaseException) -> bool:
    """`guard(tolerate=...)` predicate for the reads above the project.

    Resolving the organization and listing its custom roles are not in a
    project-scoped read-only role's grant. The project's own custom roles are
    still complete evidence, so these are recorded as skipped rather than failing
    the collection.
    """
    return access_denied(exc) or service_disabled(exc)


def collect_roles(
    parent: str, creds, collector: Collector, scope: str, tolerate=None
) -> list[dict] | None:
    """Custom roles defined on `parent` (a project or an organization).

    `view=FULL` is required: the default BASIC view omits included_permissions,
    which is the entire point of this evidence set.

    Returns None — not [] — when the call did not happen, so "no custom roles
    here" and "couldn't look" stay distinguishable in the summary.
    """
    from google.cloud import iam_admin_v1

    def _list():
        client = iam_admin_v1.IAMClient(credentials=creds)
        # The GAPIC pager iterates every page; no manual page-token loop.
        return [
            role_record(
                iam_admin_v1.Role.to_dict(role, use_integers_for_enums=False), scope
            )
            for role in client.list_roles(
                request={"parent": parent, "view": iam_admin_v1.RoleView.FULL}
            )
        ]

    return collector.guard(
        f"iam.roles.list ({parent})", _list, default=None, tolerate=tolerate
    )


def collect_organization(project, creds, collector: Collector) -> str | None:
    """The organization the project sits under, walking up through any folders.

    Reading the resource hierarchy is outside a project-scoped role's grant, so a
    403 here is tolerated and the inventory covers project-level roles only.
    """
    from google.cloud import resourcemanager_v3

    def _parent_of_project():
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        return client.get_project(name=f"projects/{project}").parent or ""

    parent = collector.guard(
        "cloudresourcemanager.projects.get (ancestry)",
        _parent_of_project,
        default="",
        tolerate=_outside_project_scope,
    )

    depth = 0
    while parent and parent.startswith("folders/") and depth < _MAX_ANCESTRY_DEPTH:
        depth += 1

        def _parent_of_folder(folder=parent):
            client = resourcemanager_v3.FoldersClient(credentials=creds)
            return client.get_folder(name=folder).parent or ""

        parent = collector.guard(
            f"cloudresourcemanager.folders.get ({parent})",
            _parent_of_folder,
            default="",
            tolerate=_outside_project_scope,
        )

    return parent if parent and parent.startswith("organizations/") else None


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

    roles: list[dict] = []
    organization: str | None = None
    org_readable = False

    if project and creds is not None:
        roles = collect_roles(f"projects/{project}", creds, collector, "project") or []
        organization = collect_organization(project, creds, collector)
        if organization:
            org_roles = collect_roles(
                organization, creds, collector, organization, tolerate=_outside_project_scope
            )
            org_readable = org_roles is not None
            roles += org_roles or []
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    roles.sort(key=lambda r: (r["scope"], r["role_id"] or ""))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"custom_roles": roles},
        summary=summarize(roles, organization, org_readable),
    )

    filename = f"gcp_iam_custom_roles_{sanitize_for_filename(project or 'unknown')}.json"
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
