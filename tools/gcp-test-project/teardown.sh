#!/usr/bin/env bash
#
# Remove what seed.sh created, in dependency order.
#
#   ./teardown.sh --project my-proj            # everything
#   ./teardown.sh --project my-proj --tier2    # only the billable Cloud SQL + GKE
#
# Two things cannot be fully undone, and neither is a bug in this script:
#
#   * KMS key rings and crypto keys are permanent. GCP has no delete verb for
#     them — the most you can do is destroy their key versions, which is what
#     this script does. They keep costing nothing once no versions are enabled.
#   * Custom roles and log buckets soft-delete with a 7-day purge window, so
#     re-running seed.sh inside that window hits "already exists" on them.
#
# Deleting the whole project is therefore the only complete cleanup:
#   gcloud projects delete PROJECT_ID
#
set -uo pipefail   # deliberately no -e: teardown continues past missing resources

PROJECT_ID=""
REGION="us-central1"
ZONE="us-central1-a"
PREFIX="paramify"
TIER2_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT_ID="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --zone) ZONE="$2"; shift 2 ;;
    --tier2) TIER2_ONLY=true; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$PROJECT_ID" ]] || { echo "--project is required" >&2; exit 2; }

G() { gcloud --project="$PROJECT_ID" --quiet "$@"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
del() {  # del <label> <cmd...>
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  gone  $what"; else echo "  skip  $what"; fi
}

KR="projects/$PROJECT_ID/locations/$REGION/keyRings/$PREFIX-test"

step "Billable tier 2 (GKE, Cloud SQL)"
del "gke $PREFIX-gke" G container clusters delete "$PREFIX-gke" --zone="$ZONE"
G sql instances patch "$PREFIX-sql" --no-deletion-protection >/dev/null 2>&1
del "cloud sql $PREFIX-sql" G sql instances delete "$PREFIX-sql"

if $TIER2_ONLY; then
  printf '\n\033[1m==> Tier 2 removed; tier 1 left in place\033[0m\n'
  exit 0
fi

step "Compute instances"
G compute instances update "$PREFIX-hardened" --zone="$ZONE" --no-deletion-protection >/dev/null 2>&1
del "instance $PREFIX-hardened" G compute instances delete "$PREFIX-hardened" --zone="$ZONE"
del "instance $PREFIX-default"  G compute instances delete "$PREFIX-default"  --zone="$ZONE"

# Front end first: a proxy pins the url map, which pins the backend service.
step "Load balancer front end"
del "proxy $PREFIX-proxy-modern"   G compute target-https-proxies delete "$PREFIX-proxy-modern"
del "proxy $PREFIX-proxy-nopolicy" G compute target-https-proxies delete "$PREFIX-proxy-nopolicy"
del "url map $PREFIX-urlmap"       G compute url-maps delete "$PREFIX-urlmap"
del "backend $PREFIX-backend"      G compute backend-services delete "$PREFIX-backend" --global
del "cert $PREFIX-cert"            G compute ssl-certificates delete "$PREFIX-cert" --global
del "ssl policy $PREFIX-modern"     G compute ssl-policies delete "$PREFIX-modern"
del "ssl policy $PREFIX-permissive" G compute ssl-policies delete "$PREFIX-permissive"

step "Disks and snapshots"
del "snapshot snap-default" G compute snapshots delete snap-default
del "disk pd-cmek"    G compute disks delete pd-cmek    --zone="$ZONE"
del "disk pd-default" G compute disks delete pd-default --zone="$ZONE"

# DNS policies reference the VPC, so they have to go before the network.
step "Cloud DNS"
del "dns policy $PREFIX-dns-policy" G dns policies delete "$PREFIX-dns-policy"
G dns managed-zones update "$PREFIX-public" --dnssec-state=off >/dev/null 2>&1
del "zone $PREFIX-public"  G dns managed-zones delete "$PREFIX-public"
del "zone $PREFIX-private" G dns managed-zones delete "$PREFIX-private"

step "Firewall rules, subnets, network"
for r in "$PREFIX-allow-ssh-world" "$PREFIX-allow-internal" "$PREFIX-deny-smtp-egress"; do
  del "fw $r" G compute firewall-rules delete "$r"
done
del "subnet $PREFIX-subnet" G compute networks subnets delete "$PREFIX-subnet" --region="$REGION"
del "subnet $PREFIX-nolog"  G compute networks subnets delete "$PREFIX-nolog"  --region="$REGION"
del "network $PREFIX-vpc"   G compute networks delete "$PREFIX-vpc"

step "Logging and monitoring"
del "metric ${PREFIX}_iam_changes" G logging metrics delete "${PREFIX}_iam_changes"
del "sink $PREFIX-sink"            G logging sinks delete "$PREFIX-sink"
del "log bucket $PREFIX-retained"  G logging buckets delete "$PREFIX-retained" --location=global
POLICY="$(G alpha monitoring policies list --filter="displayName:'$PREFIX IAM changes'" --format='value(name)' 2>/dev/null | head -1)"
[[ -n "$POLICY" ]] && del "alert policy" G alpha monitoring policies delete "$POLICY"

step "Secrets and Pub/Sub"
del "secret $PREFIX-auto" G secrets delete "$PREFIX-auto"
del "secret $PREFIX-cmek" G secrets delete "$PREFIX-cmek"
del "topic $PREFIX-secret-rotation" G pubsub topics delete "$PREFIX-secret-rotation"

step "BigQuery"
del "dataset ${PREFIX}_cmek"  bq --project_id="$PROJECT_ID" rm -r -f -d "${PROJECT_ID}:${PREFIX}_cmek"
del "dataset ${PREFIX}_plain" bq --project_id="$PROJECT_ID" rm -r -f -d "${PROJECT_ID}:${PREFIX}_plain"

# API keys are live bearer credentials — delete them by resource id, and never
# print the key strings while looking them up.
step "API keys"
for name in "$PREFIX-unrestricted" "$PREFIX-restricted"; do
  KEY="$(G services api-keys list --filter="displayName='$name'" --format='value(name)' 2>/dev/null | head -1)"
  if [[ -n "$KEY" ]]; then del "api key $name" G services api-keys delete "$KEY"; else echo "  skip  api key $name"; fi
done

step "Buckets (contents included)"
for b in "$PROJECT_ID-cmek" "$PROJECT_ID-plain" "$PROJECT_ID-logs"; do
  del "bucket $b" G storage rm --recursive "gs://$b"
done

step "IAM"
del "binding roles/viewer" G projects remove-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$PREFIX-stale-key@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/viewer
del "sa $PREFIX-stale-key"       G iam service-accounts delete "$PREFIX-stale-key@$PROJECT_ID.iam.gserviceaccount.com"
del "sa $PREFIX-evidence-reader" G iam service-accounts delete "$PREFIX-evidence-reader@$PROJECT_ID.iam.gserviceaccount.com"
del "role paramifyEvidenceReader" G iam roles delete paramifyEvidenceReader --project="$PROJECT_ID"
del "role paramifyEscalator"      G iam roles delete paramifyEscalator      --project="$PROJECT_ID"

# Key rings and keys survive; destroying their versions is the whole cleanup.
step "KMS key versions (rings and keys are permanent)"
for k in disk-key bucket-key secret-key bq-key sql-key no-rotation-key; do
  for v in $(G kms keys versions list --key="$k" --keyring="$PREFIX-test" --location="$REGION" \
               --filter='state:ENABLED' --format='value(name)' 2>/dev/null); do
    del "destroy $k version ${v##*/}" G kms keys versions destroy "${v##*/}" \
      --key="$k" --keyring="$PREFIX-test" --location="$REGION"
  done
done
for v in $(G kms keys versions list --key=multi-region-key --keyring="$PREFIX-multi" --location=us \
             --filter='state:ENABLED' --format='value(name)' 2>/dev/null); do
  del "destroy multi-region-key version ${v##*/}" G kms keys versions destroy "${v##*/}" \
    --key=multi-region-key --keyring="$PREFIX-multi" --location=us
done

printf '\n\033[1m==> Teardown complete\033[0m\n'
echo "KMS rings/keys remain (GCP has no delete verb for them) — their versions are destroyed."
echo "For a truly clean slate: gcloud projects delete $PROJECT_ID"
