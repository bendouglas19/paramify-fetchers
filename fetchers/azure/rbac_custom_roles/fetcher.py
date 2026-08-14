#!/usr/bin/env python3
"""
Azure RBAC custom role definitions on one subscription

Every custom role defined in the subscription, with the scopes it may be assigned at
and the permissions it actually grants — flagged for wildcard actions and for the
specific permissions that let a holder escalate its own privileges.

Custom roles are where least privilege is either implemented or quietly abandoned. A
role named "Deployment Reader" that grants `*` is an Owner under another name, and no
role-assignment review will catch it, because the assignment looks like a narrow
custom role. Two determinations are made here:

- **Wildcard breadth.** `actions: ["*"]` over an assignable scope is Owner-equivalent.
  Prowler's iam_subscription_roles_owner_custom_not_created check tests exactly this.
- **Privilege escalation.** Any permission matching
  `Microsoft.Authorization/roleAssignments/write` lets the holder assign itself any
  role, including Owner — so such a role is effectively Owner regardless of what else
  it grants. `Microsoft.Authorization/roleDefinitions/write` is the same escalation one
  step removed: rewrite the role you already hold.

Wildcards are matched properly rather than compared literally. An Azure action
wildcard's `*` spans `/`, so `*/write`, `Microsoft.Authorization/*` and
`Microsoft.Authorization/roleAssignments/*` all confer roleAssignments/write, and a
literal string comparison finds none of them. `not_actions` is subtracted, because a
role granting `*` while denying `Microsoft.Authorization/*/write` genuinely cannot
escalate — reporting it as if it could would be a false positive on the most common
"broad but safe" pattern.

Field projections are ported from Prowler's
prowler/providers/azure/services/iam/iam_service.py (Apache-2.0) `_get_roles`, which
reads the same azure-mgmt-authorization SDK and splits custom from built-in roles the
same way. The wildcard and lock checks come from their
iam_subscription_roles_owner_custom_not_created and
iam_custom_role_has_permissions_to_administer_resource_locks checks.

Single-subscription per invocation; fanout across subscriptions happens at the runner
layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import re
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
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_rbac_custom_roles")

CUSTOM_ROLE = "CustomRole"

# The permission that IS privilege escalation: a principal that can write role
# assignments can assign itself Owner, so a custom role granting this is
# Owner-equivalent no matter how narrow the rest of it looks.
ROLE_ASSIGNMENT_WRITE = "Microsoft.Authorization/roleAssignments/write"

# The same escalation one step removed — rewrite the definition of a role you already
# hold, rather than granting yourself a new one.
ROLE_DEFINITION_WRITE = "Microsoft.Authorization/roleDefinitions/write"

# A deny assignment can be written to shield resources from other principals; writing
# them is an administrative power in its own right.
DENY_ASSIGNMENT_WRITE = "Microsoft.Authorization/denyAssignments/write"

# Every permission treated as a privilege-escalation path, with why. A mapping rather
# than a set so the evidence names WHICH one matched.
PRIVILEGE_ESCALATION_ACTIONS = {
    ROLE_ASSIGNMENT_WRITE: "can assign any role to any principal, including Owner",
    ROLE_DEFINITION_WRITE: "can rewrite the permissions of a role it already holds",
    DENY_ASSIGNMENT_WRITE: "can write deny assignments that shield resources from others",
}

# Prowler's iam_custom_role_has_permissions_to_administer_resource_locks: a role able
# to administer resource locks can remove the locks protecting production resources
# from deletion. Reported as its own fact rather than as escalation.
RESOURCE_LOCK_ACTION_PREFIX = "Microsoft.Authorization/locks/"

# The all-permissions wildcard. Prowler's iam_subscription_roles_owner_custom_not_created
# tests for exactly this literal in a custom role's actions.
WILDCARD_ACTION = "*"

# The tenant-root assignable scope: a role assignable at "/" may be granted anywhere
# in the tenant, which is broader than the subscription that defines it.
ROOT_SCOPE = "/"


# --- projections: the only code here that touches an azure-mgmt model ---

def project_permission(permission) -> dict:
    """Read a `Permission` model's four action lists into a flat dict.

    All four are read because they are not interchangeable. `actions` and `not_actions`
    govern the CONTROL plane (manage a storage account); `data_actions` and
    `not_data_actions` govern the DATA plane (read the blobs inside it). A role with
    `data_actions: ["*"]` can read every byte in the subscription while its `actions`
    list looks modest — omitting the data plane would miss that entirely.

    Each list is `or []` because the SDK leaves an unset action list as None rather
    than an empty list.
    """
    return {
        "actions": list(model_attr(permission, "actions") or []),
        "not_actions": list(model_attr(permission, "not_actions") or []),
        "data_actions": list(model_attr(permission, "data_actions") or []),
        "not_data_actions": list(model_attr(permission, "not_data_actions") or []),
    }


def project_role_definition(definition) -> dict:
    """Read a `RoleDefinition` model's attributes into a flat snake_case dict.

    `name` is the role's GUID and `role_name` is its display name — the SDK's naming
    is genuinely inverted relative to what a reader expects, and both are kept.

    `created_on` / `updated_on` are rendered with `str()` here so the evidence carries
    a stable string rather than depending on `json.dump`'s `default=str` for the same
    conversion.
    """
    created_on = model_attr(definition, "created_on")
    updated_on = model_attr(definition, "updated_on")
    return {
        "id": model_attr(definition, "id"),
        "name": model_attr(definition, "name"),
        "role_name": model_attr(definition, "role_name"),
        "role_type": model_attr(definition, "role_type"),
        "description": model_attr(definition, "description"),
        "assignable_scopes": list(model_attr(definition, "assignable_scopes") or []),
        "permissions": [
            project_permission(p) for p in (model_attr(definition, "permissions") or [])
        ],
        "created_on": str(created_on) if created_on is not None else None,
        "updated_on": str(updated_on) if updated_on is not None else None,
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def action_matches(pattern: str, action: str) -> bool:
    """Whether an Azure RBAC action `pattern` grants the concrete `action`.

    Azure's action wildcards are NOT path globs: `*` matches any sequence of
    characters INCLUDING `/`. So `*/write` grants `Microsoft.Authorization/
    roleAssignments/write`, and `Microsoft.Authorization/*` does too. This is the whole
    reason the escalation check cannot be a literal `in` test — Prowler's checks
    compare action strings directly and therefore see none of these forms.

    Matching is case-insensitive: ARM treats action strings that way, and roles
    authored by hand or by Terraform differ in casing constantly.
    """
    if not pattern or not action:
        return False
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, action, re.IGNORECASE) is not None


def grants_action(permission: dict, action: str, data_plane: bool = False) -> bool:
    """Whether one permission block grants `action` after `not_actions` is subtracted.

    An Azure permission is allow-list minus deny-list, and the deny side is what makes
    the common "grant `*`, deny the dangerous bits" pattern safe. Ignoring
    `not_actions` would report every such role as an escalation path — a false
    positive on the most widespread least-privilege idiom there is.

    A `not_actions` entry only subtracts what it actually covers, so the same wildcard
    semantics apply on both sides.
    """
    allow_key, deny_key = ("data_actions", "not_data_actions") if data_plane else (
        "actions",
        "not_actions",
    )
    allowed = any(action_matches(p, action) for p in (permission.get(allow_key) or []))
    if not allowed:
        return False
    return not any(action_matches(p, action) for p in (permission.get(deny_key) or []))


def role_grants_action(role: dict, action: str) -> bool:
    """Whether ANY of a role's permission blocks grants the CONTROL-plane `action`.

    Blocks are independent: Azure unions the allow lists across blocks and each block's
    `not_actions` subtracts only from its own. So a role is checked block by block, and
    one permissive block is enough — a `not_actions` in a different block does not
    rescue it.

    Deliberately control-plane only. `data_actions` is a separate permission space and
    cannot confer a management operation: a role with `data_actions: ["*"]` can read
    every blob in the subscription but cannot write a role assignment, and testing the
    data plane here would report exactly that role as an escalation path. Data-plane
    breadth is reported on its own, through `has_data_actions` and
    `wildcard_actions.data_plane`.
    """
    return any(grants_action(p, action) for p in (role.get("permissions") or []))


def _wildcard_actions(role: dict) -> dict:
    """The literal wildcard entries in a role, split by plane.

    The exact strings are reported, not just a boolean: `*` and `Microsoft.Compute/*`
    are both wildcards but the first is Owner-equivalent while the second is scoped to
    one provider, and a reviewer needs to see which they are looking at.
    """
    control, data = [], []
    for permission in role.get("permissions") or []:
        control.extend(a for a in (permission.get("actions") or []) if "*" in str(a))
        data.extend(a for a in (permission.get("data_actions") or []) if "*" in str(a))
    return {"control_plane": sorted(set(control)), "data_plane": sorted(set(data))}


def custom_role_record(role: dict) -> dict:
    """Normalize one projected custom role definition into an evidence record.

    `is_owner_equivalent` is Prowler's iam_subscription_roles_owner_custom_not_created
    condition — an assignable scope of the form `/...` AND an action of exactly `*` —
    with `not_actions` honored, so a role granting `*` while denying the write actions
    is not reported as an Owner.
    """
    assignable_scopes = list(role.get("assignable_scopes") or [])
    permissions = role.get("permissions") or []
    wildcards = _wildcard_actions(role)

    escalation = sorted(
        action for action in PRIVILEGE_ESCALATION_ACTIONS if role_grants_action(role, action)
    )
    # Prowler matches `^/.*` against each assignable scope — every real ARM scope
    # satisfies it, so the clause that actually decides the finding is the `*` action.
    has_bare_wildcard = any(
        WILDCARD_ACTION in (p.get("actions") or []) for p in permissions
    )
    # What separates Owner from Contributor is exactly one permission: both grant `*`,
    # and Contributor subtracts `Microsoft.Authorization/*/write`. So a custom role
    # granting `*` is Owner-equivalent when it can still write role assignments, and
    # Contributor-equivalent when its not_actions took that away.
    can_assign_roles = role_grants_action(role, ROLE_ASSIGNMENT_WRITE)

    return {
        "id": role.get("id"),
        # The SDK's naming is inverted: `name` is the GUID, `role_name` the label.
        "role_definition_guid": role.get("name"),
        "role_name": role.get("role_name"),
        "role_type": role.get("role_type"),
        "description": role.get("description"),
        # --- where it may be assigned ---
        "assignable_scopes": assignable_scopes,
        "has_root_assignable_scope": ROOT_SCOPE in [str(s).strip() for s in assignable_scopes],
        "assignable_scope_count": len(assignable_scopes),
        # --- what it grants ---
        "permissions": permissions,
        "action_count": sum(len(p.get("actions") or []) for p in permissions),
        "data_action_count": sum(len(p.get("data_actions") or []) for p in permissions),
        "has_data_actions": any(p.get("data_actions") for p in permissions),
        "has_not_actions": any(p.get("not_actions") or p.get("not_data_actions") for p in permissions),
        # --- wildcard breadth ---
        "wildcard_actions": wildcards,
        "has_wildcard_action": bool(wildcards["control_plane"] or wildcards["data_plane"]),
        "has_all_actions_wildcard": has_bare_wildcard,
        # Prowler's owner-equivalent test (iam_subscription_roles_owner_custom_not_created),
        # with not_actions honored so a Contributor-shaped role is not called an Owner.
        "is_owner_equivalent": has_bare_wildcard and can_assign_roles,
        "is_contributor_equivalent": has_bare_wildcard and not can_assign_roles,
        # --- privilege escalation ---
        "privilege_escalation_actions": escalation,
        "can_escalate_privileges": bool(escalation),
        "can_assign_roles": can_assign_roles,
        "can_write_role_definitions": role_grants_action(role, ROLE_DEFINITION_WRITE),
        # --- other administrative powers worth naming ---
        # Prowler's iam_custom_role_has_permissions_to_administer_resource_locks
        # matches the literal prefix `Microsoft.Authorization/locks/`; routing it
        # through the wildcard matcher instead also catches the `*` and
        # `Microsoft.Authorization/*` forms that grant the same power, and honors
        # not_actions.
        "can_administer_resource_locks": role_grants_action(
            role, f"{RESOURCE_LOCK_ACTION_PREFIX}delete"
        ),
        "created_on": role.get("created_on"),
        "updated_on": role.get("updated_on"),
    }


def summarize(custom_roles: list[dict], total_definitions: int) -> dict:
    """Escalation-capable custom roles are the headline.

    `total_role_definitions` and `builtin_role_definitions` are reported alongside so
    `custom_role_definitions: 0` is legible: a subscription with no custom roles at all
    is the least-privilege ideal, and it should not read the same as a failed call that
    returned nothing. A non-zero built-in count proves the list call worked.
    """
    escalating = [r for r in custom_roles if r["can_escalate_privileges"]]
    return {
        "total_role_definitions": total_definitions,
        "builtin_role_definitions": total_definitions - len(custom_roles),
        "custom_role_definitions": len(custom_roles),
        # --- the headline ---
        "custom_roles_with_privilege_escalation": len(escalating),
        "custom_roles_that_can_assign_roles": sum(1 for r in custom_roles if r["can_assign_roles"]),
        "custom_roles_that_can_write_role_definitions": sum(
            1 for r in custom_roles if r["can_write_role_definitions"]
        ),
        "custom_roles_with_escalation_names": sorted(
            r["role_name"] or "" for r in escalating
        ),
        # --- wildcard breadth ---
        "custom_roles_with_wildcard_actions": sum(
            1 for r in custom_roles if r["has_wildcard_action"]
        ),
        "custom_roles_with_all_actions_wildcard": sum(
            1 for r in custom_roles if r["has_all_actions_wildcard"]
        ),
        "owner_equivalent_custom_roles": sum(1 for r in custom_roles if r["is_owner_equivalent"]),
        "contributor_equivalent_custom_roles": sum(
            1 for r in custom_roles if r["is_contributor_equivalent"]
        ),
        # --- data plane and scope breadth ---
        "custom_roles_with_data_actions": sum(1 for r in custom_roles if r["has_data_actions"]),
        "custom_roles_with_root_assignable_scope": sum(
            1 for r in custom_roles if r["has_root_assignable_scope"]
        ),
        "custom_roles_with_not_actions": sum(1 for r in custom_roles if r["has_not_actions"]),
        "custom_roles_administering_resource_locks": sum(
            1 for r in custom_roles if r["can_administer_resource_locks"]
        ),
        # --- the positive form: neither wildcard-broad nor escalation-capable ---
        "least_privilege_custom_roles": sum(
            1
            for r in custom_roles
            if not r["has_wildcard_action"] and not r["can_escalate_privileges"]
        ),
        "least_privilege_percentage": coverage_percentage(
            sum(
                1
                for r in custom_roles
                if not r["has_wildcard_action"] and not r["can_escalate_privileges"]
            ),
            len(custom_roles),
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_custom_roles(subscription_id, cred, collector: Collector) -> tuple[list[dict], int]:
    """One role_definitions.list(), split into custom and built-in in Python.

    Listing everything and filtering here rather than passing
    `filter="type eq 'CustomRole'"` is Prowler's approach, and it buys the total and
    built-in counts for free in the same call — which is what makes
    "custom_role_definitions: 0" distinguishable from a call that returned nothing.

    The scope is the subscription. Custom roles defined at a management group above it
    and assignable here are NOT returned — see the fetcher.yaml note; that is a known
    limitation of a per-subscription read, not a failure.
    """
    from azure.mgmt.authorization import AuthorizationManagementClient

    def _client():
        return AuthorizationManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("authorization.AuthorizationManagementClient (init)", _client)
    if client is None:
        return [], 0

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        custom, total = [], 0
        for definition in client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
            projected = project_role_definition(definition)
            total += 1
            if str(projected.get("role_type") or "") == CUSTOM_ROLE:
                custom.append(custom_role_record(projected))
        return custom, total

    custom_roles, total = collector.guard(
        "authorization.role_definitions.list", _list, default=([], 0)
    )
    logger.info(
        "Collected %d custom role definition(s) out of %d total", len(custom_roles), total
    )
    # Sorted by ARM id so a re-run against unchanged roles is byte-stable.
    return sorted(custom_roles, key=lambda r: r.get("id") or ""), total


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

    custom_roles: list[dict] = []
    total_definitions = 0
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-role result is legible: Azure returns
        # an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Authorization"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Authorization is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        custom_roles, total_definitions = collect_custom_roles(subscription_id, cred, collector)
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
            "custom_roles": custom_roles,
            "provider_registration_status": registration,
            # Named in the evidence so a reader knows which permissions the escalation
            # flags were decided by, without having to read this script.
            "privilege_escalation_actions_checked": dict(
                sorted(PRIVILEGE_ESCALATION_ACTIONS.items())
            ),
        },
        summary={
            **summarize(custom_roles, total_definitions),
            "provider_registration_status": registration,
        },
    )

    filename = (
        f"azure_rbac_custom_roles_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
