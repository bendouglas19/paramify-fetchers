#!/usr/bin/env python3
"""
Azure Policy assignments — what governance is assigned to the subscription

For one subscription, reports every Azure Policy assignment in effect (its own and
the ones inherited from a management group): what is assigned, at which scope, with
which parameters, which scopes are excluded, whether it is ENFORCED or audit-only,
and — resolved from the referenced definition — the definition's human-readable
name and whether it is a built-in or a custom policy.

**What is ported and what is ours.** Prowler's
prowler/providers/azure/services/policy/policy_service.py (Apache-2.0) is very thin
here: it keeps `id`, `name` and `enforcement_mode`, and its single check
(policy_ensure_asc_enforcement_enabled) only asserts that the SecurityCenterBuiltIn
assignment's enforcement_mode is "Default". That is a small slice of a large
compliance surface, so this fetcher goes past it. Ported from Prowler: `id`, `name`,
`enforcement_mode`. Ours: `display_name`, `description`, `policy_definition_id`,
`scope`, `scope_kind`, `inherited_from_management_group`, `not_scopes`,
`parameters`, `enforced`, the identity/location of the assignment, the resolved
`policy_definition` block (display_name + policy_type BuiltIn/Custom/Static, and
whether the reference is a single definition or an initiative), and the whole
summary.

Definition resolution is best-effort by design. A management-group-scoped custom
definition is frequently unreadable with subscription-scoped Reader, and the
assignment record is already complete without it, so a failed lookup is reported as
`policy_definition.status: "unavailable"` with the reason and does NOT fail the run
or flip the exit code. Every other API call here is guarded normally.

`PolicyClient` has moved twice: it was re-exported at `azure.mgmt.resource`'s root
through 24.x (what Prowler imports), lives at `azure.mgmt.resource.policy` in the
split-out `azure-mgmt-resource-policy` distribution, and is absent from
azure-mgmt-resource 25.x/26.x entirely. The import below tries both surviving paths,
mirroring `azure_common.provider_registration_status`'s handling of the same churn
for `ResourceManagementClient`.

Single-subscription per invocation; fanout across subscriptions happens at the
runner layer (see fetcher.yaml: supports_targets: true).
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
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    dig,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_policy_assignments")

# enforcementMode. "Default" enforces the policy's effect (deny / deployIfNotExists
# actually act); "DoNotEnforce" is what the portal calls "Disabled" — the policy
# still evaluates and reports compliance but changes nothing. ARM omits the field
# when it sits at its "Default" service default, so absent reads as enforced.
ENFORCED_MODE = "default"

# The subscription-scope assignment Defender for Cloud creates, and the only
# assignment Prowler's one policy check looks at.
SECURITY_CENTER_BUILTIN_ASSIGNMENT = "SecurityCenterBuiltIn"

# policy_definition.status values.
RESOLVED = "resolved"
UNAVAILABLE = "unavailable"
UNSUPPORTED = "unsupported"

# The two things an assignment can point at: one definition, or an initiative
# (policy set) bundling many. Matched case-insensitively — ARM returns
# "/PROVIDERS/MICROSOFT.AUTHORIZATION/POLICYDEFINITIONS/..." in upper case for some
# management-group assignments (confirmed live).
DEFINITION_SEGMENT = "policydefinitions"
SET_DEFINITION_SEGMENT = "policysetdefinitions"
DEFINITION_KIND = "policy_definition"
SET_DEFINITION_KIND = "policy_set_definition"

# Where the referenced definition lives, which decides WHICH getter can read it.
BUILT_IN_SCOPE = "built_in"
SUBSCRIPTION_SCOPE = "subscription"
MANAGEMENT_GROUP_SCOPE = "management_group"
UNKNOWN_SCOPE = "unknown"


# --- projection: the only code here that touches an azure-mgmt model ---

def _parameter_values(parameters) -> dict:
    """Unwrap {name: ParameterValuesValue} into a plain {name: value} map.

    The SDK wraps every assignment parameter in a one-field model, so a raw
    projection would write `{"tagName": {}}` (the model's repr) into the evidence
    instead of the value. Assignment parameters are policy configuration — allowed
    locations, a required tag name, a Log Analytics workspace id — not credentials.
    """
    if not parameters:
        return {}
    values = {}
    for name, holder in parameters.items():
        value = model_attr(holder, "value")
        if value is None and hasattr(holder, "get"):
            value = holder.get("value")
        values[str(name)] = value
    return values


def project_policy_assignment(assignment) -> dict:
    """Read a `PolicyAssignment` model's attributes into a flat snake_case dict.

    Attribute access is stable across the azure-mgmt generator styles; `as_dict()`
    is not (this client is on the newer `model_base` runtime, whose `as_dict()`
    emits the camelCase wire shape nested under "properties"). `enforcement_mode` is
    an SDK `str` enum, which `model_attr` unwraps to "Default"/"DoNotEnforce" — left
    wrapped, `str()` would put "EnforcementMode.DEFAULT" in the evidence and the
    comparison below would silently stop matching.
    """
    identity = model_attr(assignment, "identity")
    return {
        "id": model_attr(assignment, "id"),
        "name": model_attr(assignment, "name"),
        "type": model_attr(assignment, "type"),
        "display_name": model_attr(assignment, "display_name"),
        "description": model_attr(assignment, "description"),
        "policy_definition_id": model_attr(assignment, "policy_definition_id"),
        "scope": model_attr(assignment, "scope"),
        "not_scopes": model_attr(assignment, "not_scopes"),
        "enforcement_mode": model_attr(assignment, "enforcement_mode"),
        "parameters": _parameter_values(model_attr(assignment, "parameters")),
        "location": model_attr(assignment, "location"),
        "identity_type": model_attr(identity, "type"),
    }


def project_policy_definition(definition) -> dict:
    """Read a `PolicyDefinition` / `PolicySetDefinition` into a flat dict.

    `policy_type` is an SDK `str` enum whose members are "BuiltIn", "Custom" and
    "Static"; `model_attr` unwraps it.
    """
    return {
        "display_name": model_attr(definition, "display_name"),
        "policy_type": model_attr(definition, "policy_type"),
        "description": model_attr(definition, "description"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def parse_definition_reference(definition_id) -> dict:
    """Work out what a `policyDefinitionId` points at and who can read it.

    The same field carries five shapes, and each needs a different getter:
      /providers/Microsoft.Authorization/policyDefinitions/<name>          built-in
      /providers/Microsoft.Authorization/policySetDefinitions/<name>       built-in initiative
      /subscriptions/<sub>/providers/.../policyDefinitions/<name>          subscription custom
      /providers/Microsoft.Management/managementGroups/<mg>/providers/...  MG custom
      (anything else)                                                     unknown

    Matched case-insensitively: ARM returns the whole path upper-cased for some
    management-group assignments (confirmed live).
    """
    segments = [s for s in str(definition_id or "").split("/") if s]
    lowered = [s.lower() for s in segments]

    kind, name = None, None
    for index, segment in enumerate(lowered):
        if segment in (DEFINITION_SEGMENT, SET_DEFINITION_SEGMENT) and index + 1 < len(segments):
            kind = DEFINITION_KIND if segment == DEFINITION_SEGMENT else SET_DEFINITION_KIND
            name = segments[index + 1]
            break

    scope_kind, management_group_id, subscription_id = UNKNOWN_SCOPE, None, None
    if lowered[:1] == ["subscriptions"] and len(segments) > 1:
        scope_kind, subscription_id = SUBSCRIPTION_SCOPE, segments[1]
    elif lowered[:3] == ["providers", "microsoft.management", "managementgroups"] and (
        len(segments) > 3
    ):
        scope_kind, management_group_id = MANAGEMENT_GROUP_SCOPE, segments[3]
    elif lowered[:2] == ["providers", "microsoft.authorization"]:
        scope_kind = BUILT_IN_SCOPE

    return {
        "kind": kind,
        "name": name,
        "source_scope": scope_kind,
        "management_group_id": management_group_id,
        "subscription_id": subscription_id,
    }


def scope_kind(scope) -> str:
    """Classify an assignment's own scope: subscription, resource group, MG, resource."""
    segments = [s.lower() for s in str(scope or "").split("/") if s]
    if segments[:1] == ["providers"] and segments[1:3] == ["microsoft.management", "managementgroups"]:
        return MANAGEMENT_GROUP_SCOPE
    if segments[:1] == ["subscriptions"]:
        if len(segments) == 2:
            return SUBSCRIPTION_SCOPE
        if len(segments) == 4 and segments[2] == "resourcegroups":
            return "resource_group"
        return "resource"
    return UNKNOWN_SCOPE


def definition_block(status: str, reference: dict, definition: dict | None, reason=None) -> dict:
    """The resolved-definition block, in one shape whether or not the lookup worked."""
    definition = definition or {}
    return {
        "status": status,
        "reason": " ".join(str(reason).split())[:200] if reason else None,
        "kind": reference.get("kind"),
        "name": reference.get("name"),
        "source_scope": reference.get("source_scope"),
        "display_name": definition.get("display_name"),
        "policy_type": definition.get("policy_type"),
    }


def assignment_record(assignment: dict) -> dict:
    """Normalize one projected policy assignment into an evidence record.

    `enforced` is the fact Prowler's one check asserts, made explicit as a boolean so
    a validator does not have to know that "Default" means enforcing and
    "DoNotEnforce" means audit-only. An absent enforcement_mode reads as enforced,
    because ARM omits the field at its service default.
    """
    scope = assignment.get("scope")
    mode = assignment.get("enforcement_mode")
    reference = parse_definition_reference(assignment.get("policy_definition_id"))
    kind = scope_kind(scope)
    return {
        "id": assignment.get("id"),
        "name": assignment.get("name"),
        "display_name": assignment.get("display_name"),
        "description": assignment.get("description"),
        "policy_definition_id": assignment.get("policy_definition_id"),
        "scope": scope,
        "scope_kind": kind,
        # An assignment made on a management group shows up in every subscription
        # under it; saying so keeps "we assigned this" separate from "this reached us".
        "inherited_from_management_group": kind == MANAGEMENT_GROUP_SCOPE,
        "not_scopes": list(assignment.get("not_scopes") or []),
        "excluded_scope_count": len(assignment.get("not_scopes") or []),
        "parameters": assignment.get("parameters") or {},
        "enforcement_mode": mode,
        "enforced": str(mode or ENFORCED_MODE).lower() == ENFORCED_MODE,
        "assignment_identity_type": assignment.get("identity_type"),
        "location": assignment.get("location"),
        # Filled in by the definition enrichment; the shape is always present so the
        # evidence never has to be read with two different layouts in mind.
        "policy_definition": definition_block(UNAVAILABLE, reference, None, "not resolved"),
    }


def summarize(assignments: list[dict]) -> dict:
    """Enforcement coverage plus what kind of governance is actually assigned."""
    total = len(assignments)
    enforced = sum(1 for a in assignments if a["enforced"])
    return {
        "total_policy_assignments": total,
        "enforced_assignments": enforced,
        "audit_only_assignments": total - enforced,
        "enforced_percentage": coverage_percentage(enforced, total),
        "initiative_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "kind") == SET_DEFINITION_KIND
        ),
        "single_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "kind") == DEFINITION_KIND
        ),
        "built_in_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "policy_type") == "BuiltIn"
        ),
        "custom_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "policy_type") == "Custom"
        ),
        "unresolved_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "status") != RESOLVED
        ),
        "subscription_scoped_assignments": sum(
            1 for a in assignments if a["scope_kind"] == SUBSCRIPTION_SCOPE
        ),
        "resource_group_scoped_assignments": sum(
            1 for a in assignments if a["scope_kind"] == "resource_group"
        ),
        "inherited_assignments": sum(
            1 for a in assignments if a["inherited_from_management_group"]
        ),
        "assignments_with_excluded_scopes": sum(
            1 for a in assignments if a["excluded_scope_count"] > 0
        ),
        "assignments_with_parameters": sum(1 for a in assignments if a["parameters"]),
        # Prowler's single policy check in one field: Defender for Cloud's own
        # subscription-scope assignment, and whether it is enforcing.
        "security_center_builtin_assigned": any(
            a["name"] == SECURITY_CENTER_BUILTIN_ASSIGNMENT for a in assignments
        ),
        "security_center_builtin_enforced": any(
            a["name"] == SECURITY_CENTER_BUILTIN_ASSIGNMENT and a["enforced"]
            for a in assignments
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def policy_client(cred, subscription_id):
    """Build a PolicyClient, tolerating the class's two remaining import paths.

    `azure.mgmt.resource.policy` is where the split-out `azure-mgmt-resource-policy`
    distribution puts it (and where azure-mgmt-resource <= 24.x also had it); the
    root re-export only existed through 24.x. azure-mgmt-resource 25.x and 26.x ship
    neither — they contain only `resources` — so this fetcher needs
    `azure-mgmt-resource-policy` installed alongside a modern azure-mgmt-resource.
    """
    try:
        from azure.mgmt.resource.policy import PolicyClient  # lazy
    except ImportError:  # pragma: no cover - depends on installed SDK version
        from azure.mgmt.resource import PolicyClient  # lazy

    return PolicyClient(credential=cred, subscription_id=subscription_id)


def _lookup_definition(client, reference: dict, subscription_id):
    """Read the referenced definition, or say why it could not be read.

    Returns (projected_definition | None, status, reason). Deliberately NOT routed
    through `Collector.guard`: the assignment evidence is complete without the
    definition's display name, and a management-group-scoped definition is routinely
    unreadable with subscription-scoped Reader. Failing the whole run over an
    enrichment lookup would turn a normal permission boundary into a red run.
    """
    kind, name, scope = reference.get("kind"), reference.get("name"), reference.get("source_scope")
    if not kind or not name:
        return None, UNSUPPORTED, "policy_definition_id is not a recognized definition reference"

    operations = (
        client.policy_definitions if kind == DEFINITION_KIND else client.policy_set_definitions
    )
    if scope == BUILT_IN_SCOPE:
        getter = lambda: operations.get_built_in(name)  # noqa: E731
    elif scope == MANAGEMENT_GROUP_SCOPE:
        getter = lambda: operations.get_at_management_group(  # noqa: E731
            reference["management_group_id"], name
        )
    elif scope == SUBSCRIPTION_SCOPE:
        if reference.get("subscription_id") != subscription_id:
            # The client is bound to one subscription; a definition custom to a
            # different one is not reachable from here.
            return (
                None,
                UNSUPPORTED,
                f"definition is custom to subscription {reference.get('subscription_id')}",
            )
        getter = lambda: operations.get(name)  # noqa: E731
    else:
        return None, UNSUPPORTED, "definition reference scope not recognized"

    try:
        return project_policy_definition(getter()), RESOLVED, None
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        logger.warning(
            "policy.%s lookup failed for %s (%s) — reporting the assignment without "
            "the definition's display name: %s",
            "policy_definitions" if kind == DEFINITION_KIND else "policy_set_definitions",
            name,
            scope,
            " ".join(str(exc).split())[:200],
        )
        return None, UNAVAILABLE, exc


def collect_policy_assignments(subscription_id, cred, collector: Collector) -> list[dict]:
    """One policy_assignments.list(), then one cached definition GET per definition.

    `list()` at subscription scope returns the subscription's own assignments AND the
    ones it inherits from its management groups, which is what "in effect here" means.
    Definition lookups are cached by definition id, so an initiative assigned five
    times costs one GET.
    """
    client = collector.guard("policy.PolicyClient (init)", lambda: policy_client(cred, subscription_id))
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            assignment_record(project_policy_assignment(assignment))
            for assignment in client.policy_assignments.list()
        ]

    assignments = collector.guard("policy.policy_assignments.list", _list, default=[])

    cache: dict[str, dict] = {}
    for assignment in assignments:
        definition_id = assignment.get("policy_definition_id") or ""
        if definition_id not in cache:
            reference = parse_definition_reference(definition_id)
            definition, status, reason = _lookup_definition(client, reference, subscription_id)
            cache[definition_id] = definition_block(status, reference, definition, reason)
        assignment["policy_definition"] = cache[definition_id]

    return sorted(assignments, key=lambda r: r.get("id") or "")


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
        # Microsoft.Authorization is registered on every subscription in practice, but
        # the field is collected for the same reason the other Azure fetchers collect
        # it: a zero-assignment result then reads as "no governance assigned" rather
        # than "the provider is not there".
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Authorization"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Authorization is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        assignments = collect_policy_assignments(subscription_id, cred, collector)
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
            "policy_assignments": assignments,
            "provider_registration_status": registration,
        },
        summary={**summarize(assignments), "provider_registration_status": registration},
    )

    filename = (
        f"azure_policy_assignments_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
