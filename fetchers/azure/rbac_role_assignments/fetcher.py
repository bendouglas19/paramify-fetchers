#!/usr/bin/env python3
"""
Azure RBAC role assignments on one subscription

Who holds what, where. Each role assignment is reported with its scope, the principal
it grants to, and the role definition it grants — with the role's NAME resolved, not
just its GUID, and flagged when it is one of the four built-in roles that confer
effectively unlimited control.

Two facts do the work here:

- **Which role.** `Owner`, `Contributor`, `User Access Administrator` and `Role Based
  Access Control Administrator` are the built-ins that either grant full control or
  let the holder grant themselves full control. The first two are the classic
  over-assignment; the last two are the privilege-escalation path, since a principal
  that can write role assignments can make itself an Owner.
- **At which scope.** The same role is a different fact at different scopes. Inherited
  from a management group it applies to every subscription beneath it; at the
  subscription it applies to everything in this one; at a resource group or a single
  resource it is bounded. `scope_level` names which, so a broad assignment cannot hide
  behind a long ARM id.

Field projections are ported from Prowler's
prowler/providers/azure/services/iam/iam_service.py (Apache-2.0)
`_get_role_assignments` and `_get_roles`, which read the same azure-mgmt-authorization
SDK and make the same two calls with the same `atScope()` filter. The four role GUIDs
are theirs verbatim, from prowler/providers/azure/config.py.

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
    basename,
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

logger = logging.getLogger("azure_rbac_role_assignments")

# Built-in role definition GUIDs, verbatim from Prowler's
# prowler/providers/azure/config.py. These are Azure-wide constants — the same GUID
# identifies the role in every tenant — which is why matching on them is safe where
# matching on a display name would not be.
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
USER_ACCESS_ADMINISTRATOR_ROLE_ID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"

# The four roles above, with the reason each one is over-broad. Kept as a mapping
# rather than a set so the evidence can say WHICH role was matched: "Owner" and
# "User Access Administrator" are over-broad for different reasons and a reviewer
# remediates them differently.
OVER_BROAD_BUILTIN_ROLES = {
    OWNER_ROLE_ID: "Owner",
    CONTRIBUTOR_ROLE_ID: "Contributor",
    USER_ACCESS_ADMINISTRATOR_ROLE_ID: "User Access Administrator",
    ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID: "Role Based Access Control Administrator",
}

# The subset that can grant access — the privilege-escalation path, distinct from
# merely holding broad access. Owner is in both: it can do anything AND delegate it.
ROLE_GRANTING_ROLES = frozenset(
    {
        OWNER_ROLE_ID,
        USER_ACCESS_ADMINISTRATOR_ROLE_ID,
        ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID,
    }
)

SCOPE_MANAGEMENT_GROUP = "management_group"
SCOPE_SUBSCRIPTION = "subscription"
SCOPE_RESOURCE_GROUP = "resource_group"
SCOPE_RESOURCE = "resource"
SCOPE_ROOT = "root"
SCOPE_UNKNOWN = "unknown"


# --- projections: the only code here that touches an azure-mgmt model ---

def project_role_assignment(assignment) -> dict:
    """Read a `RoleAssignment` model's attributes into a flat snake_case dict.

    Attribute access rather than `as_dict()`, per the category's pattern:
    azure-mgmt-authorization is a multi-API client and the generator style varies by
    the API version the profile selects, so `as_dict()`'s output shape is not fixed.
    Attribute names are.

    `created_on` / `updated_on` are datetimes; they are rendered with `str()` here so
    the evidence carries a stable string rather than depending on `json.dump`'s
    `default=str` fallback for the same conversion.
    """
    created_on = model_attr(assignment, "created_on")
    updated_on = model_attr(assignment, "updated_on")
    return {
        "id": model_attr(assignment, "id"),
        "name": model_attr(assignment, "name"),
        "scope": model_attr(assignment, "scope"),
        "principal_id": model_attr(assignment, "principal_id"),
        "principal_type": model_attr(assignment, "principal_type"),
        "role_definition_id": model_attr(assignment, "role_definition_id"),
        "description": model_attr(assignment, "description"),
        # An ABAC condition narrows what the role can actually touch, so an
        # over-broad role WITH a condition is a materially different finding.
        "condition": model_attr(assignment, "condition"),
        "condition_version": model_attr(assignment, "condition_version"),
        "created_on": str(created_on) if created_on is not None else None,
        "updated_on": str(updated_on) if updated_on is not None else None,
        "delegated_managed_identity_resource_id": model_attr(
            assignment, "delegated_managed_identity_resource_id"
        ),
    }


def project_role_definition(definition) -> dict:
    """Read a `RoleDefinition` model into the flat dict the name lookup needs.

    Only the identity fields: this fetcher resolves GUID -> name and role TYPE. The
    permission bodies are the rbac_custom_roles fetcher's evidence, and duplicating
    them here would put the same large arrays in two evidence sets.
    """
    return {
        "id": model_attr(definition, "id"),
        "name": model_attr(definition, "name"),
        "role_name": model_attr(definition, "role_name"),
        "role_type": model_attr(definition, "role_type"),
        "description": model_attr(definition, "description"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def role_definition_guid(role_definition_id: str | None) -> str | None:
    """The trailing GUID of a role definition's ARM id.

    Prowler does `role_definition_id.split("/")[-1]` for the same reason: the full id
    is scope-qualified (`/subscriptions/<sub>/providers/Microsoft.Authorization/
    roleDefinitions/<guid>`), so the SAME built-in role arrives under a different id
    depending on the scope it was read at, while the GUID is invariant. Comparing full
    ids against the constants above would therefore silently never match.
    """
    return basename(role_definition_id)


def scope_level(scope: str | None) -> str:
    """Classify an ARM scope by how much it covers.

    Ordered narrowest-test-first is not possible here — a resource scope CONTAINS the
    resource-group segment — so the tests run widest-first and the resource case is
    what is left: a scope with a resource group AND a provider path beyond it names a
    single resource.
    """
    if not scope:
        return SCOPE_UNKNOWN
    normalized = scope.rstrip("/") or "/"
    lowered = normalized.lower()
    if normalized == "/":
        # The tenant root scope. Rare, and the broadest assignment possible.
        return SCOPE_ROOT
    if "/providers/microsoft.management/managementgroups/" in lowered:
        return SCOPE_MANAGEMENT_GROUP
    if resource_group_from_id(normalized) and "/resourcegroups/" in lowered:
        # A resource group scope ends at the group; anything past it is one resource.
        tail = lowered.split("/resourcegroups/", 1)[1]
        return SCOPE_RESOURCE if "/providers/" in tail else SCOPE_RESOURCE_GROUP
    if lowered.startswith("/subscriptions/"):
        return SCOPE_SUBSCRIPTION
    return SCOPE_UNKNOWN


def assignment_record(assignment: dict, role_names: dict[str, dict]) -> dict:
    """Normalize one projected assignment, resolving its role definition.

    `role_names` maps a role definition GUID to its projected definition. The lookup
    is by GUID and not by full id for the reason in `role_definition_guid()` — and it
    can legitimately miss: an assignment inherited from a management group can
    reference a custom role defined ABOVE this subscription, which
    `role_definitions.list(scope=/subscriptions/<sub>)` does not return.
    `role_name_resolved` records whether the name is real or unknown, so an unresolved
    name is never mistaken for a role actually called "unknown".

    The over-broad determination reads the GUID, NOT the resolved name, so it holds
    even when the name lookup missed. (Prowler's iam_role_user_access_admin_restricted
    check compares the resolved NAME, which reports a clean pass for exactly the
    inherited assignments it could not resolve.)
    """
    scope = assignment.get("scope")
    guid = role_definition_guid(assignment.get("role_definition_id"))
    definition = role_names.get(str(guid).lower()) if guid else None
    over_broad = OVER_BROAD_BUILTIN_ROLES.get(str(guid).lower()) if guid else None
    level = scope_level(scope)

    return {
        "id": assignment.get("id"),
        "name": assignment.get("name"),
        # --- where ---
        "scope": scope,
        "scope_level": level,
        "at_subscription_scope": level == SCOPE_SUBSCRIPTION,
        # Inherited from above this subscription: it applies here but is not managed
        # here, so remediation lives in a different place.
        "inherited_from_above_subscription": level in (SCOPE_MANAGEMENT_GROUP, SCOPE_ROOT),
        "scope_resource_group": resource_group_from_id(scope),
        # --- who ---
        "principal_id": assignment.get("principal_id"),
        # Absent principalType means the assignment predates the field or the caller
        # could not expand it; left as None rather than guessed, since guessing "User"
        # would misreport a service principal.
        "principal_type": assignment.get("principal_type"),
        # --- what ---
        "role_definition_id": assignment.get("role_definition_id"),
        "role_definition_guid": guid,
        "role_name": (definition or {}).get("role_name"),
        "role_name_resolved": definition is not None,
        "role_type": (definition or {}).get("role_type"),
        "is_custom_role": str((definition or {}).get("role_type") or "") == "CustomRole",
        # --- the flags ---
        "is_over_broad_builtin": over_broad is not None,
        "over_broad_role": over_broad,
        "can_grant_roles": str(guid).lower() in ROLE_GRANTING_ROLES if guid else False,
        # --- narrowing / provenance ---
        "has_condition": bool(assignment.get("condition")),
        "condition": assignment.get("condition"),
        "condition_version": assignment.get("condition_version"),
        "description": assignment.get("description"),
        "created_on": assignment.get("created_on"),
        "updated_on": assignment.get("updated_on"),
    }


def summarize(assignments: list[dict]) -> dict:
    """Over-broad built-in assignments are the headline, distinct principals second.

    `distinct_principals_with_over_broad_roles` is reported next to the raw count
    because one service principal holding Contributor on four scopes is one identity
    to review, not four — and a large gap between the numbers usually means an
    automation account was granted per-scope instead of once.
    """
    over_broad = [a for a in assignments if a["is_over_broad_builtin"]]
    by_type: dict[str, int] = {}
    for assignment in assignments:
        key = assignment["principal_type"] or "Unknown"
        by_type[key] = by_type.get(key, 0) + 1

    def _count_role(role_id: str) -> int:
        return sum(1 for a in assignments if str(a["role_definition_guid"] or "").lower() == role_id)

    return {
        "total_role_assignments": len(assignments),
        "distinct_principals": len({a["principal_id"] for a in assignments if a["principal_id"]}),
        # --- the headline ---
        "over_broad_builtin_assignments": len(over_broad),
        "distinct_principals_with_over_broad_roles": len(
            {a["principal_id"] for a in over_broad if a["principal_id"]}
        ),
        "over_broad_percentage": coverage_percentage(len(over_broad), len(assignments)),
        "least_privilege_assignments": len(assignments) - len(over_broad),
        # --- per over-broad role ---
        "owner_assignments": _count_role(OWNER_ROLE_ID),
        "contributor_assignments": _count_role(CONTRIBUTOR_ROLE_ID),
        "user_access_administrator_assignments": _count_role(USER_ACCESS_ADMINISTRATOR_ROLE_ID),
        "rbac_administrator_assignments": _count_role(
            ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID
        ),
        # The escalation path: a principal that can write role assignments can make
        # itself an Owner, so this is broader than the Owner count alone.
        "role_granting_assignments": sum(1 for a in assignments if a["can_grant_roles"]),
        # --- by scope ---
        "assignments_at_root_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_ROOT
        ),
        "assignments_at_management_group_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_MANAGEMENT_GROUP
        ),
        "assignments_at_subscription_scope": sum(1 for a in assignments if a["at_subscription_scope"]),
        "assignments_at_resource_group_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_RESOURCE_GROUP
        ),
        "assignments_at_resource_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_RESOURCE
        ),
        "assignments_inherited_from_above_subscription": sum(
            1 for a in assignments if a["inherited_from_above_subscription"]
        ),
        # The worst combination: unlimited control over the whole subscription or more.
        "over_broad_at_subscription_scope_or_above": sum(
            1
            for a in over_broad
            if a["at_subscription_scope"] or a["inherited_from_above_subscription"]
        ),
        # --- by role kind and principal kind ---
        "custom_role_assignments": sum(1 for a in assignments if a["is_custom_role"]),
        "builtin_role_assignments": sum(
            1 for a in assignments if a["role_name_resolved"] and not a["is_custom_role"]
        ),
        "unresolved_role_definitions": sum(1 for a in assignments if not a["role_name_resolved"]),
        "assignments_by_principal_type": by_type,
        # An ABAC condition narrows a role's reach, so these are the assignments that
        # are broad on paper but constrained in practice.
        "assignments_with_conditions": sum(1 for a in assignments if a["has_condition"]),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_role_assignments(subscription_id, cred, collector: Collector) -> tuple[list[dict], dict]:
    """One role_definitions.list() to name the roles, one role_assignments.list().

    The definitions call comes first and is the reason the evidence carries role NAMES
    at all: an assignment references its role only by GUID, and a reviewer cannot read
    a list of GUIDs. Prowler builds the same lookup for the same reason.

    `filter="atScope()"` on the assignments call is Prowler's, and is a deliberate
    scoping choice rather than an incidental one: without it the call also returns
    every assignment made at every resource group and every individual resource in the
    subscription, which on a large subscription is tens of thousands of records that
    bury the subscription-wide grants this evidence is about. With it, the response is
    the assignments that apply at the subscription scope and above — the ones that
    reach everything.
    """
    from azure.mgmt.authorization import AuthorizationManagementClient

    def _client():
        return AuthorizationManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("authorization.AuthorizationManagementClient (init)", _client)
    if client is None:
        return [], {}

    scope = f"/subscriptions/{subscription_id}"

    def _list_definitions():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        definitions = {}
        for definition in client.role_definitions.list(scope=scope):
            projected = project_role_definition(definition)
            # Keyed by the invariant GUID, lower-cased — ARM is inconsistent about
            # GUID casing across API versions and a case-sensitive key would miss.
            guid = str(projected.get("name") or "").lower()
            if guid:
                definitions[guid] = projected
        return definitions

    role_names = collector.guard(
        "authorization.role_definitions.list", _list_definitions, default={}
    )

    def _list_assignments():
        return [
            assignment_record(project_role_assignment(a), role_names)
            for a in client.role_assignments.list_for_subscription(filter="atScope()")
        ]

    assignments = collector.guard(
        "authorization.role_assignments.list_for_subscription", _list_assignments, default=[]
    )
    logger.info(
        "Collected %d role assignment(s) against %d role definition(s)",
        len(assignments),
        len(role_names),
    )
    # Sorted by ARM id so a re-run against unchanged access is byte-stable.
    return sorted(assignments, key=lambda a: a.get("id") or ""), role_names


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which
    # buries this fetcher's own lines and would dominate the runner's stderr tail.
    # Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    assignments: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list calls, so a zero-assignment result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Authorization"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Authorization is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        assignments, _ = collect_role_assignments(subscription_id, cred, collector)
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
            "role_assignments": assignments,
            "provider_registration_status": registration,
            # Named in the evidence so a reader knows which GUIDs the flags were
            # decided by, without having to read this script.
            "over_broad_builtin_roles_checked": dict(sorted(OVER_BROAD_BUILTIN_ROLES.items())),
            "assignment_scope_filter": "atScope()",
        },
        summary={**summarize(assignments), "provider_registration_status": registration},
    )

    filename = (
        f"azure_rbac_role_assignments_"
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
