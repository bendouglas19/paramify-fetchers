# GCP

GCP fetchers pull configuration evidence from your GCP projects using the
official Google Cloud client libraries. All fetchers are **read-only** and
authenticate with **Application Default Credentials (ADC)** — there is no static
API token or service-account key file to hand over.

Encryption at rest:

| Fetcher | Evidence | GCP API |
|---------|----------|---------|
| `gcp_persistent_disk_encryption_status` | Persistent disks + snapshots: CMEK vs Google-managed | `compute.disks.aggregatedList`, `compute.snapshots.list` |
| `gcp_cloud_storage_encryption_status` | Buckets: CMEK vs Google-managed + data-protection posture | `storage.buckets.list` |
| `gcp_cloud_sql_encryption_status` | Cloud SQL: CMEK vs Google-managed + backup config | `sqladmin.instances.list` |
| `gcp_kms_key_configuration` | KMS key rings and keys across every location: purpose, protection level (SOFTWARE/HSM/EXTERNAL), rotation period vs the 90-day interval, primary version state, IAM on key and ring | `cloudkms.{locations,keyRings,cryptoKeys}.list` |
| `gcp_bigquery_dataset_configuration` | Datasets: default CMEK, ACL with public grants named per entry, default table expiration, location | `bigquery.datasets.{list,get}` |
| `gcp_secret_manager_configuration` | Secrets: replication policy, per-replica CMEK, rotation schedule and whether overdue, expiry, version state counts, who can read | `secretmanager.secrets.{list,getIamPolicy}`, `versions.list` |

Platform posture:

| Fetcher | Evidence | GCP API |
|---------|----------|---------|
| `gcp_gke_cluster_configuration` | GKE clusters: private nodes/endpoint, network policy, legacy ABAC, Workload Identity, shielded nodes, etcd CMEK, release channel, per node pool auto-upgrade/repair + boot-disk CMEK | `container.clusters.list` |
| `gcp_cloud_logging_configuration` | Log sinks (destination, filter, include_children), log buckets (retention, locked, CMEK), log-router settings, log metrics paired with alert policies | `logging.{sinks,buckets,settings,metrics}`, `monitoring.alertPolicies.list`, `cloudresourcemanager.{projects,folders}.get` |
| `gcp_compute_instance_configuration` | Instances: Shielded VM, Confidential Computing, OS Login + 2FA, serial port, IP forwarding, attached service account and scopes, public IP, deletion protection | `compute.instances.aggregatedList`, `compute.projects.get` |
| `gcp_vpc_network_configuration` | Networks: subnet mode, routing mode, peerings, whether the auto-created `default` network survives; subnets with Private Google Access and flow-log settings | `compute.{networks,subnetworks}.list` |
| `gcp_firewall_rules` | Rules: direction, allow/deny protocol and port ranges, source/destination ranges, target tags and service accounts, priority, logging — derives internet-to-admin-port exposure | `compute.firewalls.list` |
| `gcp_load_balancer_tls_configuration` | HTTPS/SSL proxies and their SSL policies: minimum TLS version, profile, resolved ciphers, and the effective floor for a proxy running Google's permissive default | `compute.target{Https,Ssl}Proxies.list`, `compute.sslPolicies.list` |
| `gcp_dns_configuration` | Managed zones: DNSSEC state and KSK/ZSK algorithms, visibility, query logging, private/forwarding/peering topology, plus DNS policies | `dns.{managedZones,policies}.list` |
| `gcp_cloud_sql_network_configuration` | Cloud SQL boundary: public IP presence, authorized networks, SSL/TLS requirement and minimum version, private connectivity, per-engine security flags | `sqladmin.instances.list` |
| `gcp_cloud_sql_backup_configuration` | Cloud SQL recovery: automated backups and window, per-engine PITR, retention counts and transaction-log days, regional vs zonal, replicas, deletion protection | `sqladmin.instances.list` |

Identity and access:

| Fetcher | Evidence | GCP API |
|---------|----------|---------|
| `gcp_iam_service_accounts` | Service accounts: user- vs system-managed keys with age/expiry, project roles (primitive/admin), who can impersonate each account | `iam.serviceAccounts.{list,keys.list,getIamPolicy}`, `cloudresourcemanager.projects.getIamPolicy` |
| `gcp_iam_policy_bindings` | The project policy read by role and by principal: primitive roles, service accounts with admin grants, `allUsers`/`allAuthenticatedUsers`, out-of-domain and cross-project members, conditional bindings, plus audit configs and their exemptions | `cloudresourcemanager.projects.getIamPolicy` (policy version 3) |
| `gcp_iam_custom_roles` | Project (and readable org) custom roles: launch stage, deleted state, full permission list classified into escalation paths — `*.setIamPolicy`, `serviceAccounts.actAs`, token signing, `roles.update`, key creation | `iam.{projects,organizations}.roles.list` |
| `gcp_api_keys_inventory` | API keys: creation and update time, age against the 90-day interval, API-service restrictions (flagging the `cloudapis.googleapis.com` wildcard) and referrer/IP/app restrictions. No key string is read | `apikeys.projects.locations.keys.list` |

> **Status:** all 19 fetchers have been run against a live project and exit 0.
> The CMEK-vs-Google-managed contrast that the validators depend on is confirmed
> for Cloud Storage, persistent disks, BigQuery, Secret Manager and Cloud SQL, as
> are the finding paths for open firewall rules, weak TLS proxies, default
> service accounts, privilege-escalating custom roles, never-expiring
> service-account keys and unrestricted API keys.
>
> Two caveats remain. **The least-privilege permission list below is still
> unverified** — the live run used an owner-level account, not the custom role,
> so treat the table as a best determination and reconcile it against a real
> least-privilege run (any 403 is a permission to add). And a few fields have
> only ever returned their negative case, because the test project has no
> positive one to report: GKE private nodes, private control plane, master
> authorized networks, Binary Authorization, etcd CMEK and boot-disk CMEK, plus
> Cloud SQL minimum TLS version and database security flags.

## The one thing to get right

On GCP, **persistent disks, Cloud Storage, and Cloud SQL are all encrypted at
rest by default** with Google-managed keys. A validator asking "is it encrypted:
true?" can never fail — worthless evidence. These fetchers instead capture what
actually varies: **CMEK vs Google-managed** (`kms_key_name` present or not),
**which key**, **rotation**, **location**, and **protection level**. Write
validators against those fields — see [`DRAFT_VALIDATORS.md`](DRAFT_VALIDATORS.md).

The same rule shapes the posture fetchers: they report the fields that differ
between a hardened and a default configuration (legacy ABAC on/off, a locked log
bucket, a user-managed key's age), not facts that are true of every project.

## Prerequisites

1. **Enable the APIs** in each project you collect from:
   ```bash
   gcloud services enable \
     compute.googleapis.com \
     storage.googleapis.com \
     sqladmin.googleapis.com \
     cloudkms.googleapis.com \
     container.googleapis.com \
     logging.googleapis.com \
     monitoring.googleapis.com \
     iam.googleapis.com \
     cloudresourcemanager.googleapis.com
   ```
   `container.googleapis.com` is the exception you can skip: a project that runs
   no GKE records "API not enabled" as evidence (`metadata.skipped_calls`,
   `summary.gke_api_readable: false`) and still exits 0, because GCP answers a
   never-enabled service with a 403 rather than an empty list.
2. **Python deps.** The top-level `requirements.txt` carries every client the
   category needs — `pip install -r requirements.txt` is enough. Cloud SQL Admin
   and Cloud DNS have no stable GAPIC client, so they go through the discovery
   client (`google-api-python-client`); `google-auth` comes transitively. One
   name to watch: the Secret Manager distribution is hyphenated
   (`google-cloud-secret-manager`) while its import is
   `google.cloud.secretmanager`, so `pip install google-cloud-secretmanager`
   fails with "no matching distribution".

## Credential setup (ADC — no key files)

We deliberately do **not** use exported service-account JSON keys
(`GOOGLE_APPLICATION_CREDENTIALS`). Use one of the two ADC paths:

### Option A: Local workstation — `gcloud` ADC
```bash
gcloud auth application-default login
gcloud auth application-default print-access-token   # should print a token
```
This writes the well-known ADC file under `~/.config/gcloud/`. The runner
inherits `HOME`, so the client libraries find it automatically. `CLOUDSDK_CONFIG`
relocates that file if you keep the gcloud config elsewhere.

> Note: `gcloud auth login` (Option in the env-setup guide) and `gcloud auth
> application-default login` are **separate** credentials — `gcloud` uses one,
> the client libraries use the other. Forgetting the second is the usual cause of
> "works in gcloud, 403s in Python."

### Option B: In-cluster — GKE Workload Identity (recommended)
Bind a Kubernetes service account to a GCP service account with the read-only
role below. The client libraries reach the GKE metadata server automatically —
**nothing to wire**, no env var, no key file.

## Required read-only permissions (least privilege)

Per the brief, use a **custom role**, not `roles/viewer`. Only these permissions
are needed:

| Permission | Used by |
|------------|---------|
| `compute.disks.list` | persistent disks |
| `compute.snapshots.list` | snapshots |
| `storage.buckets.list` | Cloud Storage |
| `storage.buckets.get` | Cloud Storage (bucket metadata; include if `list` alone under-populates the encryption block) |
| `cloudsql.instances.list` | Cloud SQL |
| `cloudkms.keyRings.list` | KMS |
| `cloudkms.cryptoKeys.list` | KMS |
| `cloudkms.locations.list` | KMS (enumerate locations) — ⚠ **verify; if denied, set `GCP_KMS_LOCATIONS` to skip enumeration (see note below)** |
| `container.clusters.list` | GKE clusters |
| `logging.sinks.list` | log sinks |
| `logging.buckets.list` | log buckets |
| `logging.settings.get` | log-router CMEK / storage location |
| `logging.logMetrics.list` | log-based metrics |
| `monitoring.alertPolicies.list` | alert policies paired with those metrics |
| `iam.serviceAccounts.list` | service accounts |
| `iam.serviceAccountKeys.list` | their keys (metadata only — never key material) |
| `iam.serviceAccounts.getIamPolicy` | who can impersonate each service account |
| `resourcemanager.projects.getIamPolicy` | project role bindings |
| `resourcemanager.projects.get` | the project's ancestry (for org/folder sinks) |

The posture rows are **unverified against a live least-privilege run** — see the
status note at the top. Two of them are also optional by design: the ancestry
walk (`resourcemanager.projects.get`, `resourcemanager.folders.get`) and the
ancestor sink listing are tolerated when denied, so a project-scoped role
collects project-level logging evidence and records the gap in
`metadata.skipped_calls` rather than failing.

Create the role and bind it (project-level; repeat per project or set at the org):

```bash
cat > paramify-evidence-role.yaml <<'YAML'
title: "Paramify Evidence Reader (encryption at rest)"
description: "Read-only access for Paramify encryption-at-rest fetchers."
stage: "GA"
includedPermissions:
  - compute.disks.list
  - compute.snapshots.list
  - storage.buckets.list
  - storage.buckets.get
  - cloudsql.instances.list
  - cloudkms.keyRings.list
  - cloudkms.cryptoKeys.list
  - cloudkms.locations.list        # ⚠ verify — remove if unrecognized (see note)
  # Platform posture — ⚠ not yet confirmed against a live run
  - container.clusters.list
  - logging.sinks.list
  - logging.buckets.list
  - logging.settings.get
  - logging.logMetrics.list
  - monitoring.alertPolicies.list
  - iam.serviceAccounts.list
  - iam.serviceAccountKeys.list
  - iam.serviceAccounts.getIamPolicy
  - resourcemanager.projects.get
  - resourcemanager.projects.getIamPolicy
YAML

gcloud iam roles create paramifyEvidenceReader \
  --project="$PROJECT_ID" --file=paramify-evidence-role.yaml

# Bind to the service account the fetchers run as (Workload Identity SA or dev SA)
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:evidence-reader@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="projects/$PROJECT_ID/roles/paramifyEvidenceReader"
```

> **⚠ Verify the permission list by testing it.** This list is my best
> determination from the API calls each fetcher makes; I could not confirm every
> permission string against a live least-privilege run. The honest way (from the
> env-setup guide): create the role, grant it to a service account, run the
> fetchers under it, and treat any **403** as a permission to add and any unused
> permission as one to remove. In particular, confirm whether KMS location
> enumeration needs `cloudkms.locations.list` — if that string is rejected or the
> enumeration still 403s, either set `GCP_KMS_LOCATIONS` (comma-separated, e.g.
> `us-central1,us`) so the fetcher skips `locations.list` and scans only those
> locations, or grant the predefined `roles/cloudkms.viewer` as the safe fallback.
>
> Broad predefined fallbacks (looser than least privilege) if you need to unblock
> a demo fast: `roles/compute.viewer`, `roles/cloudsql.viewer`,
> `roles/cloudkms.viewer`, and `roles/storage.admin` (there is no narrow
> bucket-metadata read role). For the posture fetchers the nearest predefined
> roles are `roles/container.clusterViewer`, `roles/logging.admin` (the read-only
> logging roles do not all cover `settings.get`), `roles/monitoring.viewer` and
> `roles/iam.securityReviewer` — each still to be confirmed against a real run.
> Prefer the custom role for the actual package.

## Wiring into a manifest

GCP fetchers declare **no secrets** — ADC flows through the credential chain, not
the manifest. Fanout is per project; `environment` labels each project's evidence.

```bash
paramify manifest add gcp_kms_key_configuration
paramify manifest add-target gcp_kms_key_configuration project=my-prod-project environment=prod
paramify validate manifest.yaml
paramify run manifest.yaml
```

Five ready-to-edit manifests, split by theme rather than by wiring — merge them
into one run if you prefer:

- [`examples/gcp_data_at_rest.yaml`](../../examples/gcp_data_at_rest.yaml) — the
  encryption-at-rest fetchers.
- [`examples/gcp_platform_posture.yaml`](../../examples/gcp_platform_posture.yaml)
  — GKE cluster configuration, Cloud Logging configuration, IAM service accounts.
- [`examples/gcp_compute_posture.yaml`](../../examples/gcp_compute_posture.yaml)
  — instances, firewall rules, VPC networks, load-balancer TLS.
- [`examples/gcp_data_platform.yaml`](../../examples/gcp_data_platform.yaml)
  — BigQuery, Secret Manager, Cloud SQL network and backup configuration.
- [`examples/gcp_identity_and_keys.yaml`](../../examples/gcp_identity_and_keys.yaml)
  — IAM policy bindings, custom roles, KMS keys, DNS, API keys.

## Per-fetcher env vars

| Var | Purpose | Declared in |
|-----|---------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Project to collect from (optional — falls back to the ADC default project) | `target_schema.project` |
| `GCP_ENVIRONMENT` | Environment label (prod / preprod) written into the evidence metadata | `target_schema.environment` |
| `EVIDENCE_DIR` | Output directory (defaults to `./evidence`) | runner-set |
| `FETCHER_STATUS_FILE` | Where a failing fetcher writes its reason (`{error, code}`) | runner-set |
| `CLOUDSDK_CONFIG` | Optional: relocate the gcloud/ADC config dir | platform `passthrough_env` |

## Output & failure semantics

- One envelope per target (`aggregation: per_target`); the file name carries a
  sanitized project id.
- Output is **deterministic** — resource lists are sorted by a stable id and the
  JSON is written with sorted keys, so re-runs are byte-stable and regex
  validators stay quiet.
- **Partial failure never looks like success.** Any failed API call is recorded
  in `payload.metadata.api_failures`, sets `payload.metadata.partial_failure:
  true`, and exits non-zero — so the runner marks that target's envelope
  `status: failed`. One inaccessible project of five does not silently exit 0.
- **A failing run says why.** On the way out it writes a one-line reason and a
  category to `$FETCHER_STATUS_FILE` (`{"error": "...", "code":
  "auth_failed"}`), which the runner masks for secrets and puts in the envelope's
  `metadata.error` — the field Paramify shows whoever is triaging. Codes come from
  the contract's fixed set; `gcp_common.Collector.failure_report()` picks the
  unanimous cause (expired ADC ⇒ `auth_failed`) or `partial_failure` when the
  causes disagree. The exit code stays binary. Writing is a no-op when the env var
  is unset, so running a fetcher by hand is unchanged.
- **"Not enabled" is evidence, not failure.** A call that fails because the API
  was never enabled on the project, or because a read above the project (the
  org/folder ancestry) is outside the granted role, is recorded in
  `payload.metadata.skipped_calls` and does **not** fail the run. That key is
  absent entirely when nothing was skipped.
- `environment` lives in `payload.metadata.environment`. The runner-built
  envelope schema has no `environment` field, so it is carried in the payload
  (alongside `project`) rather than the envelope wrapper — see the note in
  `DRAFT_NARRATIVES.md` / the handoff summary.
