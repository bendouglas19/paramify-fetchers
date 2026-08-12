# GCP

GCP fetchers pull encryption-at-rest evidence from your GCP projects using the
official Google Cloud client libraries. All fetchers are **read-only** and
authenticate with **Application Default Credentials (ADC)** — there is no static
API token or service-account key file to hand over.

| Fetcher | Evidence | GCP API |
|---------|----------|---------|
| `gcp_persistent_disk_encryption_status` | Persistent disks + snapshots: CMEK vs Google-managed | `compute.disks.aggregatedList`, `compute.snapshots.list` |
| `gcp_cloud_storage_encryption_status` | Buckets: CMEK vs Google-managed + data-protection posture | `storage.buckets.list` |
| `gcp_cloud_sql_encryption_status` | Cloud SQL: CMEK vs Google-managed + backup config | `sqladmin.instances.list` |
| `gcp_kms_key_rotation` | KMS keys: rotation, algorithm, protection level (SOFTWARE/HSM), location | `cloudkms.{locations,keyRings,cryptoKeys}.list` |

> **Status:** the first three fetchers are verified against a live project and
> ship now. `gcp_kms_key_rotation` is written and unit-tested but **held back
> until one green live-tenant re-run** (its first run hit a `list_locations` bug,
> since fixed); the rows/sections referencing it below apply once it ships.

## The one thing to get right

On GCP, **persistent disks, Cloud Storage, and Cloud SQL are all encrypted at
rest by default** with Google-managed keys. A validator asking "is it encrypted:
true?" can never fail — worthless evidence. These fetchers instead capture what
actually varies: **CMEK vs Google-managed** (`kms_key_name` present or not),
**which key**, **rotation**, **location**, and **protection level**. Write
validators against those fields — see [`DRAFT_VALIDATORS.md`](DRAFT_VALIDATORS.md).

## Prerequisites

1. **Enable the APIs** in each project you collect from:
   ```bash
   gcloud services enable \
     compute.googleapis.com \
     storage.googleapis.com \
     sqladmin.googleapis.com \
     cloudkms.googleapis.com
   ```
2. **Python deps** (already in the top-level `requirements.txt`):
   `google-cloud-compute`, `google-cloud-storage`, `google-cloud-kms`,
   `google-api-python-client`. `google-auth` comes transitively.

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
> bucket-metadata read role). Prefer the custom role for the actual package.

## Wiring into a manifest

GCP fetchers declare **no secrets** — ADC flows through the credential chain, not
the manifest. Fanout is per project; `environment` labels each project's evidence.

```bash
paramify manifest add gcp_kms_key_rotation
paramify manifest add-target gcp_kms_key_rotation project=my-prod-project environment=prod
paramify validate manifest.yaml
paramify run manifest.yaml
```

A ready-to-edit manifest for the three shipping fetchers (with the KMS entry
commented out until it is verified) is at
[`examples/gcp_data_at_rest.yaml`](../../examples/gcp_data_at_rest.yaml).

## Per-fetcher env vars

| Var | Purpose | Declared in |
|-----|---------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Project to collect from (optional — falls back to the ADC default project) | `target_schema.project` |
| `GCP_ENVIRONMENT` | Environment label (prod / preprod) written into the evidence metadata | `target_schema.environment` |
| `EVIDENCE_DIR` | Output directory (defaults to `./evidence`) | runner-set |
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
- `environment` lives in `payload.metadata.environment`. The runner-built
  envelope schema has no `environment` field, so it is carried in the payload
  (alongside `project`) rather than the envelope wrapper — see the note in
  `DRAFT_NARRATIVES.md` / the handoff summary.
