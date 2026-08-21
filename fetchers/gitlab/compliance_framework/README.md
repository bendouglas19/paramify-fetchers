# gitlab_compliance_framework

Records a GitLab compliance framework's definition and per-project
requirement/control status via the GraphQL API. Optionally reconciles a
committed template onto the group first (off by default).

Default template is **FedRAMP 20x Key Security Indicators**. Bundled
alternatives: FedRAMP High, NIST 800-53 Rev. 5, NIST CSF 2.0, SOC 2.

## Fanout-capable

Single-target per invocation; the runner fans out across projects via
`supports_targets: true`. See [`docs/run_manifest_reference.md`](../../../docs/run_manifest_reference.md).

```bash
GITLAB_URL=https://gitlab.example.com \
GITLAB_API_TOKEN=glpat-... \
GITLAB_PROJECT_ID=group/project \
python fetchers/gitlab/compliance_framework/fetcher.py
```

## Required env vars

| Var | Source | Notes |
|-----|--------|-------|
| `GITLAB_URL` | `target_schema.url` | Instance base URL, no trailing slash |
| `GITLAB_API_TOKEN` | per-target secret | See token scopes below |
| `GITLAB_PROJECT_ID` | `target_schema.project_id` | Project path, e.g. `group/project` |
| `GITLAB_COMPLIANCE_TEMPLATE` | `target_schema.template` | Default `fedramp_20x` |
| `GITLAB_COMPLIANCE_FRAMEWORK_NAME` | `target_schema.framework_name` | Optional; defaults to the template's `name` |
| `GITLAB_COMPLIANCE_SYNC` | `target_schema.sync` | Default `false` (read-only) |
| `EVIDENCE_DIR` | runner-set | Output directory (defaults to `./evidence`) |

### Token scopes

Compliance frameworks live on the **group**, not the project. A project access
token usually cannot query `group.complianceFrameworks`. Use a **group access
token** or a PAT that can see the parent group.

| Mode | Scopes | Role |
|------|--------|------|
| Read-only (default) | `read_api` | Reporter or higher on the group |
| Sync (`GITLAB_COMPLIANCE_SYNC=true`) | `api` | Owner on the group |

This fetcher talks to `/api/graphql`, not the REST API the other GitLab
fetchers use.

### Templates

Bundled files in [`framework_jsons/`](framework_jsons/):

| Key | File | GitLab framework name |
|-----|------|-----------------------|
| `fedramp_20x` (default) | `fedramp_20x.json` | FedRAMP 20x Key Security Indicators |
| `fedramp_high_r5` | `fedramp_high_r5.json` | FedRAMP High |
| `nist_800-53_r5` | `nist_800-53_r5.json` | NIST 800-53 Revision 5 |
| `nist_csf_2` | `nist_csf_2.json` | NIST CSF 2.0 |
| `soc2` | `soc2.json` | SOC 2 |

`GITLAB_COMPLIANCE_TEMPLATE` accepts the key, the filename, or a path to any
GitLab-importer JSON (the UI export shape: `name`, `description`, `color`,
`requirements[].controls[]` with `expression` as an object).

## What sync does

Off by default. When `GITLAB_COMPLIANCE_SYNC=true`, idempotent reconciliation
against the template, in this order:

1. Create the framework if the group (or an ancestor) does not have one by that name.
2. Per template requirement: create it when absent; update it when its control set has drifted; leave it untouched when it already matches.
3. Apply the framework to the target project, preserving any frameworks already applied.
4. Re-read post-sync state so the artifact reflects reality, not intent.

Every action is recorded in `sync.actions[]` with `wanted` vs `created`/`now`,
so a control GitLab silently drops shows up as `ok: false` rather than
vanishing:

```json
{
  "action": "create_requirement",
  "requirement": "KSI-SCR-MON: Monitoring Supply Chain Risk",
  "wanted": ["scanner_container_scanning_running", "scanner_dep_scanning_running", "package_hunter_no_findings_untriaged"],
  "created": ["scanner_container_scanning_running", "scanner_dep_scanning_running"],
  "ok": false,
  "errors": []
}
```

`expression` is passed to GraphQL as a JSON **string**, not an object — the
mutation API differs from the UI importer here.

A failed sync action still writes the evidence file, then exits non-zero
(`partial_failure`).

## Output

`<EVIDENCE_DIR>/gitlab_compliance_framework_<sanitized_project_id>.json`

```
metadata            { project_id, project_name, project_group, gitlab_url,
                      template, framework_name, sync, scan_timestamp }
status              "success" | "error"
evidence            "GitLab Compliance Framework Status"
generated_at        RFC3339 UTC
gitlab              { url, group, project, project_id }
template            { file, framework_name }
sync                { enabled, actions[], drift_detected, sync_failed_action_count }
framework           { found, id, name, applied_to_project,
                      requirement_count, control_count, project_count }
coverage            { requirements{passed,failed,pending},
                      controls{passed,failed,pending}, errors[] }
requirements[]      { ksi, name, description, method_count,
                      meets_class_c, meets_class_d,
                      pass_count, fail_count, pending_count,
                      controls[]{ name, control_type, expression, status } }
control_status      { "<control_name>": "PASS" | "FAIL" | "PENDING" | "UNAVAILABLE" }
ksi_status          { "<requirement prefix>": "PASS" | "FAIL" | "UNAVAILABLE" }
status_api          { available, errors[] }
summary             { framework_found, applied_to_project, sync_failed_action_count,
                      failing_control_count, ... }
```

`control_status` and `ksi_status` are flat maps so a validator can assert one
control or one KSI with a single regex. `ksi` is the prefix before the first
colon (`KSI-CMT-LMC`, `AC-5`, `CC3.2 - COSO Principle 7`).

## Tier behaviour

On Premium, the per-project control status query is rejected. The fetcher
records that in `status_api` and fills every status with `"UNAVAILABLE"`
rather than failing the run — so the same fetcher works before and after an
Ultimate upgrade. Available on Premium regardless: the framework definition,
sync actions, and the group `coverage` counters.

Practical consequence for validators: assert on `framework`, `sync`,
`coverage`, and `method_count` / `meets_class_*` today. Add `control_status`
and `ksi_status` assertions when the Status tab lights up.

## Validator patterns

Shipped as `validators:` on `fetcher.yaml`. Written against the raw artifact
text. Test with Node, not Python — Paramify's engine is JavaScript regex.

**A specific control passes** (branch protection on the target project):

```
regex:  "default_branch_protected":\s*"PASS"
```

**A specific KSI / requirement prefix passes:**

```
regex:  "KSI-CMT-RVP":\s*"PASS"
```

**Framework is applied to this project:**

```
regex:  "applied_to_project":\s*true
```

**No sync action failed:**

```
regex:  "sync_failed_action_count":\s*0
```

**No control is FAIL:**

```
regex:  "failing_control_count":\s*0
```

When Paramify stores the artifact, newlines become literal `\n`. The patterns
above only ever match within a single key/value pair.

## Exit codes

- `0` — collected successfully. A missing framework (`framework.found: false`)
  or an Ultimate-only status API (`status_api.available: false`) is still
  success: both are facts about the instance.
- `1` — required env var / unknown template, auth/transport failure, or sync
  did not fully apply. The evidence file is still written on the network path.

## Known v0.x interim behavior

- Reads env vars directly via `os.environ` (replaced by the framework's secret resolver later).
- Reads `EVIDENCE_DIR` from env (replaced by the runner passing an output path later).
- Output filename includes the sanitized project id — this logic moves to the runner when output templating is formalized.
