#!/usr/bin/env python3
"""
GitLab Compliance Framework Status

Reads (and optionally reconciles) a GitLab compliance framework for one project
via the GraphQL API: framework definition, requirement/control coverage, and
per-control pass/fail. Templates live in framework_jsons/.

Single-target per invocation; fanout across projects happens at the runner
layer (see fetcher.yaml: supports_targets: true). Default is read-only;
GITLAB_COMPLIANCE_SYNC=true creates/updates the framework and applies it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

logger = logging.getLogger("gitlab_compliance_framework")

SCRIPT_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = SCRIPT_DIR / "framework_jsons"

BUNDLED_TEMPLATES = {
    "fedramp_20x": "fedramp_20x.json",
    "fedramp_high_r5": "fedramp_high_r5.json",
    "nist_800-53_r5": "nist_800-53_r5.json",
    "nist_csf_2": "nist_csf_2.json",
    "soc2": "soc2.json",
}

Q_PROJECT = """
query($p: ID!) {
  project(fullPath: $p) {
    id
    fullPath
    name
    group { id fullPath }
    complianceFrameworks(first: 50) {
      nodes { id name }
    }
  }
}
"""

Q_GROUP_FRAMEWORKS = """
query($g: ID!, $after: String) {
  group(fullPath: $g) {
    id
    fullPath
    parent { fullPath }
    complianceFrameworks(first: 50, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id name description color
        complianceRequirements(first: 100) {
          nodes {
            id name description
            complianceRequirementsControls(first: 20) {
              nodes { id name controlType expression }
            }
          }
        }
        projects(first: 100) {
          nodes { id fullPath }
        }
      }
    }
  }
}
"""

Q_COVERAGE = """
query($g: ID!) {
  group(fullPath: $g) {
    complianceRequirementCoverage { passed failed pending }
    complianceRequirementControlCoverage { passed failed pending }
  }
}
"""

Q_CONTROL_STATUS = """
query($p: ID!, $after: String) {
  project(fullPath: $p) {
    complianceControlStatus(first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        status
        complianceRequirementsControl {
          name
          complianceRequirement { name }
        }
      }
    }
  }
}
"""

Q_REQUIREMENT_STATUS = """
query($p: ID!, $after: String) {
  project(fullPath: $p) {
    complianceRequirementStatuses(first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        passCount failCount pendingCount
        complianceRequirement { name }
        complianceFramework { name }
      }
    }
  }
}
"""

M_CREATE_FW = """
mutation($ns: ID!, $p: ComplianceFrameworkInput!) {
  createComplianceFramework(input: {namespacePath: $ns, params: $p}) {
    errors
    framework { id name }
  }
}
"""

M_CREATE_REQ = """
mutation(
  $fw: ComplianceManagementFrameworkID!,
  $p: ComplianceRequirementInput!,
  $c: [ComplianceRequirementsControlInput!]
) {
  createComplianceRequirement(
    input: {complianceFrameworkId: $fw, params: $p, controls: $c}
  ) {
    errors
    requirement {
      id name
      complianceRequirementsControls { nodes { name } }
    }
  }
}
"""

M_UPDATE_REQ = """
mutation(
  $id: ComplianceManagementComplianceFrameworkComplianceRequirementID!,
  $p: ComplianceRequirementInput!,
  $c: [ComplianceRequirementsControlInput!]
) {
  updateComplianceRequirement(input: {id: $id, params: $p, controls: $c}) {
    errors
    requirement {
      id name
      complianceRequirementsControls { nodes { name } }
    }
  }
}
"""

M_APPLY = """
mutation($proj: ProjectID!, $ids: [ComplianceManagementFrameworkID!]!) {
  projectUpdateComplianceFrameworks(
    input: {projectId: $proj, complianceFrameworkIds: $ids}
  ) {
    errors
    project { id }
  }
}
"""


class TransportError(Exception):
    """HTTP/network failure talking to GitLab GraphQL."""

    def __init__(self, message: str, code: str = "target_unreachable"):
        super().__init__(message)
        self.code = code


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the envelope's metadata.error.

    Without it the runner falls back to the tail of stderr — which on the way out
    is the "Evidence saved" line. See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("true", "1", "yes", "on")


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def requirement_key(name: str) -> str:
    """Prefix before the first colon — KSI-CMT-LMC, AC-5, or the whole name."""
    if ":" in name:
        return name.split(":", 1)[0].strip()
    return name


def parse_expression(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def graphql_messages(body: dict) -> List[str]:
    return [e.get("message", str(e)) for e in (body.get("errors") or []) if e]


def mutation_errors(payload: Optional[dict], field: str, body: dict) -> List[str]:
    nested = ((payload or {}).get(field) or {}).get("errors") or []
    return [str(e) for e in nested] + graphql_messages(body)


def resolve_template_path(value: str) -> Path:
    key = value.strip()
    if key in BUNDLED_TEMPLATES:
        path = TEMPLATES_DIR / BUNDLED_TEMPLATES[key]
    elif (TEMPLATES_DIR / key).is_file():
        path = TEMPLATES_DIR / key
    else:
        path = Path(key)
    if not path.is_file():
        bundled = ", ".join(sorted(BUNDLED_TEMPLATES))
        raise RuntimeError(
            f"Unknown compliance template {key!r}. Bundled keys: {bundled}"
        )
    return path


def load_template(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Template is not valid JSON: {path}: {e}") from e
    if not isinstance(data, dict) or not data.get("name"):
        raise RuntimeError(f"Template {path} must be an object with a name")
    if not isinstance(data.get("requirements"), list):
        data["requirements"] = []
    return data


def template_controls_input(requirement: dict) -> List[dict]:
    controls = []
    for control in requirement.get("controls") or []:
        expr = control.get("expression")
        if not isinstance(expr, str):
            expr = json.dumps(expr, separators=(",", ":"))
        controls.append({
            "name": control.get("name"),
            "controlType": control.get("controlType") or control.get("control_type") or "internal",
            "expression": expr,
        })
    return controls


class GitLabGraphQL:
    def __init__(self, gitlab_url: str, api_token: str):
        self.endpoint = f"{gitlab_url.rstrip('/')}/api/graphql"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

    def execute(self, query: str, variables: Optional[dict] = None) -> dict:
        try:
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json={"query": query, "variables": variables or {}},
                timeout=60,
            )
        except requests.exceptions.RequestException as e:
            raise TransportError(f"GraphQL transport error: {e}") from e
        if response.status_code == 401:
            raise TransportError(
                f"API Error: 401 {response.text}", code="auth_failed"
            )
        if response.status_code == 403:
            raise TransportError(
                f"API Error: 403 {response.text}", code="not_authorized"
            )
        if response.status_code >= 400:
            raise TransportError(
                f"API Error: {response.status_code} {response.text}"
            )
        try:
            return response.json()
        except ValueError as e:
            raise TransportError(f"GraphQL returned non-JSON: {e}") from e

    def data(self, query: str, variables: Optional[dict] = None) -> Tuple[dict, List[str]]:
        body = self.execute(query, variables)
        return (body.get("data") or {}), graphql_messages(body)


def paginate_nodes(
    client: GitLabGraphQL,
    query: str,
    variables: dict,
    path: List[str],
) -> Tuple[List[dict], List[str]]:
    nodes: List[dict] = []
    errors: List[str] = []
    after: Optional[str] = None
    while True:
        data, msgs = client.data(query, {**variables, "after": after})
        errors.extend(msgs)
        cursor: Any = data
        for key in path:
            cursor = (cursor or {}).get(key) if isinstance(cursor, dict) else None
        if not isinstance(cursor, dict):
            break
        nodes.extend(cursor.get("nodes") or [])
        page = cursor.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        after = page.get("endCursor")
        if not after:
            break
    return nodes, errors


def find_framework(
    client: GitLabGraphQL,
    start_group: Optional[str],
    framework_name: str,
) -> Tuple[Optional[str], Optional[dict], List[str]]:
    """Walk the group and its parents until a framework with this name appears."""
    errors: List[str] = []
    group_path = start_group
    seen: set[str] = set()
    while group_path and group_path not in seen:
        seen.add(group_path)
        nodes, msgs = paginate_nodes(
            client, Q_GROUP_FRAMEWORKS, {"g": group_path},
            ["group", "complianceFrameworks"],
        )
        errors.extend(msgs)
        match = next((n for n in nodes if n.get("name") == framework_name), None)
        if match:
            return group_path, match, errors
        data, parent_msgs = client.data(Q_GROUP_FRAMEWORKS, {"g": group_path, "after": None})
        errors.extend(parent_msgs)
        parent = ((data.get("group") or {}).get("parent") or {}).get("fullPath")
        group_path = parent
    return None, None, errors


def apply_sync(
    client: GitLabGraphQL,
    group_path: str,
    project_id_gid: str,
    project_framework_ids: List[str],
    framework: Optional[dict],
    template: dict,
    framework_name: str,
) -> Tuple[Optional[dict], List[dict], List[str]]:
    """Create/update the framework from the template and apply it to the project."""
    actions: List[dict] = []
    errors: List[str] = []

    if framework is None:
        params = {
            "name": template.get("name"),
            "description": template.get("description") or "",
            "color": template.get("color") or "#6699cc",
        }
        body = client.execute(M_CREATE_FW, {"ns": group_path, "p": params})
        payload = body.get("data") or {}
        fw_err = mutation_errors(payload, "createComplianceFramework", body)
        fw_id = ((payload.get("createComplianceFramework") or {}).get("framework") or {}).get("id")
        if not fw_id:
            actions.append({"action": "create_framework", "ok": False, "errors": fw_err})
            errors.extend(fw_err)
            return None, actions, errors
        actions.append({"action": "create_framework", "ok": True, "id": fw_id})
        framework = {
            "id": fw_id,
            "name": framework_name,
            "complianceRequirements": {"nodes": []},
            "projects": {"nodes": []},
        }

    fw_id = framework.get("id") or ""
    existing_reqs = {
        r.get("name"): r
        for r in (framework.get("complianceRequirements") or {}).get("nodes") or []
        if r.get("name")
    }

    for req in template.get("requirements") or []:
        name = req.get("name") or ""
        controls = template_controls_input(req)
        wanted = sorted(c["name"] for c in controls if c.get("name"))
        params = {"name": name, "description": req.get("description") or ""}
        existing = existing_reqs.get(name)

        if existing is None:
            body = client.execute(M_CREATE_REQ, {"fw": fw_id, "p": params, "c": controls})
            payload = body.get("data") or {}
            created = [
                n.get("name")
                for n in (
                    ((payload.get("createComplianceRequirement") or {}).get("requirement") or {})
                    .get("complianceRequirementsControls") or {}
                ).get("nodes") or []
                if n.get("name")
            ]
            err = mutation_errors(payload, "createComplianceRequirement", body)
            got = sorted(created)
            actions.append({
                "action": "create_requirement",
                "requirement": name,
                "wanted": wanted,
                "created": got,
                "ok": wanted == got and not err,
                "errors": err,
            })
            errors.extend(err)
        else:
            have = sorted(
                n.get("name")
                for n in (existing.get("complianceRequirementsControls") or {}).get("nodes") or []
                if n.get("name")
            )
            if have != wanted:
                body = client.execute(
                    M_UPDATE_REQ,
                    {"id": existing.get("id"), "p": params, "c": controls},
                )
                payload = body.get("data") or {}
                now = [
                    n.get("name")
                    for n in (
                        ((payload.get("updateComplianceRequirement") or {}).get("requirement") or {})
                        .get("complianceRequirementsControls") or {}
                    ).get("nodes") or []
                    if n.get("name")
                ]
                err = mutation_errors(payload, "updateComplianceRequirement", body)
                got = sorted(now)
                actions.append({
                    "action": "update_requirement",
                    "requirement": name,
                    "had": have,
                    "wanted": wanted,
                    "now": got,
                    "ok": wanted == got and not err,
                    "errors": err,
                })
                errors.extend(err)

    if fw_id and fw_id not in project_framework_ids:
        ids = list(dict.fromkeys(project_framework_ids + [fw_id]))
        body = client.execute(M_APPLY, {"proj": project_id_gid, "ids": ids})
        payload = body.get("data") or {}
        err = mutation_errors(payload, "projectUpdateComplianceFrameworks", body)
        actions.append({
            "action": "apply_framework_to_project",
            "ok": len(err) == 0,
            "errors": err,
        })
        errors.extend(err)

    return framework, actions, errors


def assemble_artifact(
    *,
    gitlab_url: str,
    project_path: str,
    project_gid: Optional[str],
    group_path: Optional[str],
    template_path: Path,
    framework_name: str,
    sync_enabled: bool,
    sync_actions: List[dict],
    framework: Optional[dict],
    project_framework_names: List[str],
    coverage: dict,
    coverage_errors: List[str],
    control_nodes: List[dict],
    requirement_nodes: List[dict],
    control_errors: List[str],
    generated_at: str,
) -> dict:
    reqs = (framework or {}).get("complianceRequirements", {}).get("nodes") or []
    ctl_map = {
        ((n.get("complianceRequirementsControl") or {}).get("name")): n.get("status")
        for n in control_nodes
        if (n.get("complianceRequirementsControl") or {}).get("name")
    }
    req_map = {
        ((n.get("complianceRequirement") or {}).get("name")): n
        for n in requirement_nodes
        if (n.get("complianceRequirement") or {}).get("name")
    }

    requirements = []
    control_status: Dict[str, str] = {}
    ksi_status: Dict[str, str] = {}
    failing_controls = 0
    pending_controls = 0
    unavailable_controls = 0

    for req in reqs:
        name = req.get("name") or ""
        key = requirement_key(name)
        controls_out = []
        for ctl in (req.get("complianceRequirementsControls") or {}).get("nodes") or []:
            ctl_name = ctl.get("name") or ""
            status = ctl_map.get(ctl_name) or "UNAVAILABLE"
            if status == "FAIL":
                failing_controls += 1
            elif status == "PENDING":
                pending_controls += 1
            elif status == "UNAVAILABLE":
                unavailable_controls += 1
            control_status[ctl_name] = status
            controls_out.append({
                "name": ctl_name,
                "control_type": ctl.get("controlType"),
                "expression": parse_expression(ctl.get("expression")),
                "status": status,
            })
        req_status = req_map.get(name) or {}
        fail_count = req_status.get("failCount")
        if fail_count is None:
            ksi_value = "UNAVAILABLE"
        elif fail_count == 0:
            ksi_value = "PASS"
        else:
            ksi_value = "FAIL"
        ksi_status[key] = ksi_value
        method_count = len(controls_out)
        requirements.append({
            "ksi": key,
            "name": name,
            "description": req.get("description"),
            "method_count": method_count,
            "meets_class_c": method_count >= 2,
            "meets_class_d": method_count >= 4,
            "pass_count": req_status.get("passCount"),
            "fail_count": fail_count,
            "pending_count": req_status.get("pendingCount"),
            "controls": controls_out,
        })

    applied = framework_name in project_framework_names
    failed_sync = sum(1 for a in sync_actions if a.get("ok") is False)
    control_count = sum(r["method_count"] for r in requirements)

    return {
        "evidence": "GitLab Compliance Framework Status",
        "generated_at": generated_at,
        "gitlab": {
            "url": gitlab_url,
            "group": group_path,
            "project": project_path,
            "project_id": project_gid,
        },
        "template": {
            "file": template_path.name,
            "framework_name": framework_name,
        },
        "sync": {
            "enabled": sync_enabled,
            "actions": sync_actions,
            "drift_detected": any(a.get("action") != "create_framework" for a in sync_actions),
            "sync_failed_action_count": failed_sync,
        },
        "framework": {
            "found": framework is not None,
            "id": (framework or {}).get("id"),
            "name": (framework or {}).get("name") or framework_name,
            "applied_to_project": applied,
            "requirement_count": len(requirements),
            "control_count": control_count,
            "project_count": len(((framework or {}).get("projects") or {}).get("nodes") or []),
        },
        "coverage": {
            "requirements": coverage.get("complianceRequirementCoverage"),
            "controls": coverage.get("complianceRequirementControlCoverage"),
            "errors": coverage_errors,
        },
        "requirements": requirements,
        "control_status": control_status,
        "ksi_status": ksi_status,
        "status_api": {
            "available": len(control_errors) == 0,
            "errors": control_errors,
        },
        "summary": {
            "framework_found": framework is not None,
            "applied_to_project": applied,
            "sync_enabled": sync_enabled,
            "sync_failed_action_count": failed_sync,
            "requirement_count": len(requirements),
            "control_count": control_count,
            "failing_control_count": failing_controls,
            "pending_control_count": pending_controls,
            "unavailable_control_count": unavailable_controls,
            "status_api_available": len(control_errors) == 0,
        },
    }


def collect(
    gitlab_url: str,
    api_token: str,
    project_path: str,
    template_path: Path,
    template: dict,
    framework_name: str,
    sync_enabled: bool,
) -> dict:
    generated_at = current_timestamp()
    base = {
        "project_id": project_path,
        "retrieved_at": generated_at,
    }
    try:
        client = GitLabGraphQL(gitlab_url, api_token)
        project_data, project_errors = client.data(Q_PROJECT, {"p": project_path})
        project = project_data.get("project")
        if not project:
            reason = "; ".join(project_errors) or f"cannot resolve project {project_path}"
            lower = reason.lower()
            code = "not_authorized" if "permission" in lower else "target_unreachable"
            return {**base, "status": "error", "code": code, "message": reason}

        project_gid = project.get("id")
        group_path = (project.get("group") or {}).get("fullPath")
        project_frameworks = (project.get("complianceFrameworks") or {}).get("nodes") or []
        project_framework_ids = [n["id"] for n in project_frameworks if n.get("id")]
        project_framework_names = [n["name"] for n in project_frameworks if n.get("name")]

        owner_group, framework, fw_errors = find_framework(client, group_path, framework_name)
        sync_actions: List[dict] = []
        sync_errors: List[str] = []

        if sync_enabled:
            sync_group = owner_group or group_path
            if not sync_group:
                return {
                    **base,
                    "status": "error",
                    "code": "bad_config",
                    "message": (
                        f"Project {project_path} has no parent group; "
                        "compliance frameworks cannot be synced onto a personal namespace"
                    ),
                }
            framework, sync_actions, sync_errors = apply_sync(
                client, sync_group, project_gid, project_framework_ids,
                framework, template, framework_name,
            )
            owner_group, framework, reread_errors = find_framework(
                client, sync_group, framework_name,
            )
            fw_errors = list(fw_errors) + reread_errors
            project_data, project_errors = client.data(Q_PROJECT, {"p": project_path})
            project = project_data.get("project") or project
            project_frameworks = (project.get("complianceFrameworks") or {}).get("nodes") or []
            project_framework_names = [n["name"] for n in project_frameworks if n.get("name")]

        coverage: dict = {}
        coverage_errors: List[str] = []
        if owner_group or group_path:
            cov_data, coverage_errors = client.data(
                Q_COVERAGE, {"g": owner_group or group_path},
            )
            coverage = (cov_data.get("group") or {})

        control_nodes, control_errors = paginate_nodes(
            client, Q_CONTROL_STATUS, {"p": project_path},
            ["project", "complianceControlStatus"],
        )
        req_nodes, req_errors = paginate_nodes(
            client, Q_REQUIREMENT_STATUS, {"p": project_path},
            ["project", "complianceRequirementStatuses"],
        )
        status_errors = control_errors + req_errors

        artifact = assemble_artifact(
            gitlab_url=gitlab_url,
            project_path=project_path,
            project_gid=project_gid,
            group_path=owner_group or group_path,
            template_path=template_path,
            framework_name=framework_name,
            sync_enabled=sync_enabled,
            sync_actions=sync_actions,
            framework=framework,
            project_framework_names=project_framework_names,
            coverage=coverage,
            coverage_errors=coverage_errors,
            control_nodes=control_nodes,
            requirement_nodes=req_nodes,
            control_errors=status_errors,
            generated_at=generated_at,
        )
        artifact["graphql_errors"] = project_errors + fw_errors + sync_errors

        failed_sync = artifact["summary"]["sync_failed_action_count"]
        if sync_enabled and failed_sync:
            artifact["status"] = "error"
            artifact["code"] = "partial_failure"
            artifact["message"] = f"{failed_sync} sync action(s) failed"
            return artifact
        if sync_enabled and not artifact["framework"]["found"]:
            artifact["status"] = "error"
            artifact["code"] = "partial_failure"
            artifact["message"] = (
                f'framework "{framework_name}" not found in group '
                f"{owner_group or group_path} after sync"
            )
            return artifact

        artifact["status"] = "success"
        return artifact
    except TransportError as e:
        return {
            **base,
            "status": "error",
            "code": e.code,
            "message": str(e),
        }
    except Exception as e:
        return {
            **base,
            "status": "error",
            "code": "internal_error",
            "message": str(e),
        }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        gitlab_url = get_env("GITLAB_URL")
        api_token = get_env("GITLAB_API_TOKEN")
        project_id = get_env("GITLAB_PROJECT_ID")
        template_path = resolve_template_path(
            os.environ.get("GITLAB_COMPLIANCE_TEMPLATE", "fedramp_20x")
        )
        template = load_template(template_path)
    except RuntimeError as e:
        logger.error("%s", e)
        report_failure(str(e), "bad_config")
        return 1

    framework_name = (
        os.environ.get("GITLAB_COMPLIANCE_FRAMEWORK_NAME", "").strip()
        or template["name"]
    )
    sync_enabled = env_flag("GITLAB_COMPLIANCE_SYNC", "false")

    result = collect(
        gitlab_url, api_token, project_id,
        template_path, template, framework_name, sync_enabled,
    )

    parts = project_id.split("/")
    result_with_metadata = {
        "metadata": {
            "project_id": project_id,
            "project_name": parts[-1],
            "project_group": parts[0] if len(parts) > 1 else "unknown",
            "gitlab_url": gitlab_url,
            "template": template_path.name,
            "framework_name": framework_name,
            "sync": sync_enabled,
            "scan_timestamp": current_timestamp(),
        },
        **result,
    }

    output_path = output_dir / f"gitlab_compliance_framework_{sanitize_for_filename(project_id)}.json"
    with open(output_path, "w") as f:
        json.dump(result_with_metadata, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    if result.get("status") != "success":
        reason = result.get("message", "unknown error")
        logger.error("collection failed: %s", reason)
        report_failure(reason, result.get("code"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
