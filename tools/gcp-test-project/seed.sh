#!/usr/bin/env bash
#
# Seed a throwaway GCP project with resources that make every fetcher under
# fetchers/gcp/ produce non-trivial evidence.
#
# The point is contrast. A brand-new project has no resources, so every fetcher
# returns an empty list and exits 0 — which proves ADC and the API plumbing work
# and nothing else. GCP also encrypts disks, buckets, Cloud SQL and BigQuery at
# rest by default, so "encrypted: true" is worthless evidence. This script
# therefore creates resources in PAIRS: one CMEK-encrypted and one Google-managed,
# one with flow logs and one without, one TLS proxy with a policy and one running
# Google's permissive default. That contrast is what the validators key on.
#
#   ./seed.sh --project my-proj --tier1        # cheap; pennies/day
#   ./seed.sh --project my-proj --tier2        # Cloud SQL + GKE; tear down after
#   ./seed.sh --project my-proj --all
#
# Deliberately-weak resources: some fetchers exist to surface a misconfiguration,
# so the fixture has to contain one. The weak resources created by default are
# NOT actually reachable — the 0.0.0.0/0 SSH rule targets a network tag no
# instance carries, and the permissive TLS proxy has no forwarding rule, so
# neither has a live path from the internet. The two that WOULD be genuinely
# exposed — a public BigQuery ACL and a Cloud SQL instance authorized from
# 0.0.0.0/0 — are behind --include-exposed and are off by default.
#
set -euo pipefail

PROJECT_ID=""
REGION="us-central1"
ZONE="us-central1-a"
TIER1=false
TIER2=false
INCLUDE_EXPOSED=false
PREFIX="paramify"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT_ID="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --zone) ZONE="$2"; shift 2 ;;
    --tier1) TIER1=true; shift ;;
    --tier2) TIER2=true; shift ;;
    --all) TIER1=true; TIER2=true; shift ;;
    --include-exposed) INCLUDE_EXPOSED=true; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$PROJECT_ID" ]] || { echo "--project is required" >&2; exit 2; }
$TIER1 || $TIER2 || { echo "pick --tier1, --tier2 or --all" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

G() { gcloud --project="$PROJECT_ID" --quiet "$@"; }

# Every create is best-effort: re-running the script must not abort on the first
# resource that already exists. Failures are counted and printed at the end
# rather than killing the run, because a single unavailable API should not stop
# the other eighteen fetchers from getting a fixture.
FAILED=()
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
try() {
  local what="$1"; shift
  # Both streams, because bq reports its errors on stdout rather than stderr —
  # capturing only stderr makes every bq failure look like a silent one.
  if "$@" >"$WORK/err" 2>&1; then
    echo "  ok    $what"
  else
    # Each API words "it's already there" differently: Cloud Storage returns a
    # 409 "you already own it", bq says "Already Exists", the GAPIC services say
    # "alreadyExists". Missing one makes a clean re-run look like a failed one.
    # bq also hard-wraps its message mid-token, so the newlines are flattened
    # before matching.
    if tr '\n' ' ' <"$WORK/err" \
       | grep -qiE 'already exists|alreadyExists|already own it|duplicate|HTTPError 409|error 409'; then
      echo "  exists $what"
    else
      echo "  FAIL  $what"
      sed 's/^/          /' "$WORK/err" | head -4
      FAILED+=("$what")
    fi
  fi
}

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
KR="projects/$PROJECT_ID/locations/$REGION/keyRings/$PREFIX-test"
echo "project $PROJECT_ID ($PROJECT_NUMBER)  region $REGION  zone $ZONE"

# ---------------------------------------------------------------- APIs --------
step "Enabling APIs (slow on a new project — 1-2 min)"
G services enable \
  compute.googleapis.com storage.googleapis.com sqladmin.googleapis.com \
  cloudkms.googleapis.com container.googleapis.com logging.googleapis.com \
  monitoring.googleapis.com iam.googleapis.com cloudresourcemanager.googleapis.com \
  bigquery.googleapis.com secretmanager.googleapis.com dns.googleapis.com \
  apikeys.googleapis.com pubsub.googleapis.com iamcredentials.googleapis.com
echo "  ok    core APIs"

# Service agents are created lazily. CMEK on a managed service fails with an
# opaque permission error until the service's own agent can use the key, so the
# agents have to exist before the grants below.
for svc in secretmanager.googleapis.com sqladmin.googleapis.com container.googleapis.com; do
  try "service identity $svc" G beta services identity create --service="$svc"
done

if $TIER1; then

# ----------------------------------------------------------------- KMS --------
# gcp_kms_key_configuration. Two locations so the fetcher's locations.list
# enumeration has more than one hit to walk; a key with no rotation schedule
# next to one on the 90-day interval so "rotation configured" actually varies.
step "KMS key rings and keys"
try "keyring $PREFIX-test ($REGION)" G kms keyrings create "$PREFIX-test" --location="$REGION"
try "keyring $PREFIX-multi (us)"     G kms keyrings create "$PREFIX-multi" --location=us

for k in disk-key bucket-key secret-key bq-key sql-key; do
  try "key $k (rotating 90d)" G kms keys create "$k" \
    --keyring="$PREFIX-test" --location="$REGION" --purpose=encryption \
    --rotation-period=90d --next-rotation-time="$(date -u -v+90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '+90 days' '+%Y-%m-%dT%H:%M:%SZ')"
done
try "key no-rotation-key (finding)" G kms keys create no-rotation-key \
  --keyring="$PREFIX-test" --location="$REGION" --purpose=encryption
try "key multi-region-key (us)" G kms keys create multi-region-key \
  --keyring="$PREFIX-multi" --location=us --purpose=encryption

grant_key() {  # grant_key <key> <service-agent-email>
  G kms keys add-iam-policy-binding "$1" --keyring="$PREFIX-test" --location="$REGION" \
    --member="serviceAccount:$2" --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
}
step "Granting each service agent use of its key"

# Cloud Storage and BigQuery are the two exceptions to `services identity
# create` — each exposes its encryption agent through its own command, and
# calling that command is what brings the agent into existence. Granting a key
# to the constructed email before that call fails with "Service account ... does
# not exist", which then surfaces one step later as an opaque 403 on the key.
GCS_AGENT="$(G storage service-agent 2>/dev/null | tr -d '[:space:]')"
[[ -n "$GCS_AGENT" ]] || GCS_AGENT="service-${PROJECT_NUMBER}@gs-project-accounts.iam.gserviceaccount.com"
BQ_AGENT="$(bq --project_id="$PROJECT_ID" --format=prettyjson show --encryption_service_account 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ServiceAccountID",""))' 2>/dev/null)"
[[ -n "$BQ_AGENT" ]] || BQ_AGENT="bq-${PROJECT_NUMBER}@bigquery-encryption.iam.gserviceaccount.com"
echo "  agent storage  $GCS_AGENT"
echo "  agent bigquery $BQ_AGENT"

try "compute agent -> disk-key"   grant_key disk-key   "service-${PROJECT_NUMBER}@compute-system.iam.gserviceaccount.com"
try "storage agent -> bucket-key" grant_key bucket-key "$GCS_AGENT"
try "bigquery agent -> bq-key"    grant_key bq-key     "$BQ_AGENT"
try "secretmgr agent -> secret-key" grant_key secret-key "service-${PROJECT_NUMBER}@gcp-sa-secretmanager.iam.gserviceaccount.com"
try "cloudsql agent -> sql-key"   grant_key sql-key    "service-${PROJECT_NUMBER}@gcp-sa-cloud-sql.iam.gserviceaccount.com"

# A key grant is not readable by the granting service the instant it returns.
# Creating a CMEK bucket immediately after tends to 403; a short pause is far
# cheaper than debugging that as a permissions problem.
echo "  ...waiting 30s for the key grants to propagate"
sleep 30

# --------------------------------------------------------------- Storage ------
# gcp_cloud_storage_encryption_status. The -cmek/-plain pair is the whole point:
# both report encrypted, only one reports a kms_key_name.
step "Cloud Storage buckets"
try "bucket $PROJECT_ID-cmek (CMEK, UBLA, PAP)" G storage buckets create "gs://$PROJECT_ID-cmek" \
  --location="$REGION" --uniform-bucket-level-access --public-access-prevention \
  --default-encryption-key="$KR/cryptoKeys/bucket-key"
try "bucket $PROJECT_ID-cmek versioning" G storage buckets update "gs://$PROJECT_ID-cmek" --versioning
try "bucket $PROJECT_ID-plain (Google-managed)" G storage buckets create "gs://$PROJECT_ID-plain" --location="$REGION"
try "bucket $PROJECT_ID-logs (sink target)" G storage buckets create "gs://$PROJECT_ID-logs" --location="$REGION"

# ----------------------------------------------------------------- Disks ------
# gcp_persistent_disk_encryption_status, incl. the snapshot path.
step "Persistent disks and a snapshot"
try "disk pd-cmek"    G compute disks create pd-cmek --size=10GB --zone="$ZONE" --kms-key="$KR/cryptoKeys/disk-key"
try "disk pd-default" G compute disks create pd-default --size=10GB --zone="$ZONE"
try "snapshot snap-default" G compute snapshots create snap-default --source-disk=pd-default --source-disk-zone="$ZONE"

# ------------------------------------------------------- VPC / firewall -------
# gcp_vpc_network_configuration reports whether the auto-created `default`
# network still exists, so we add a custom-mode VPC alongside it rather than
# deleting it. One subnet logs flows, one does not.
step "VPC, subnets, firewall rules"
try "network $PREFIX-vpc (custom mode)" G compute networks create "$PREFIX-vpc" --subnet-mode=custom
try "subnet $PREFIX-subnet (flow logs on)" G compute networks subnets create "$PREFIX-subnet" \
  --network="$PREFIX-vpc" --region="$REGION" --range=10.10.0.0/24 \
  --enable-flow-logs --enable-private-ip-google-access \
  --logging-aggregation-interval=interval-5-sec --logging-flow-sampling=0.5 --logging-metadata=include-all
try "subnet $PREFIX-nolog (flow logs off)" G compute networks subnets create "$PREFIX-nolog" \
  --network="$PREFIX-vpc" --region="$REGION" --range=10.20.0.0/24

# Targeted at a tag no instance carries: the rule is real evidence for
# gcp_firewall_rules' internet-to-admin-port derivation, but reaches nothing.
try "fw allow-ssh-world (finding, unreachable)" G compute firewall-rules create "$PREFIX-allow-ssh-world" \
  --network="$PREFIX-vpc" --allow=tcp:22 --source-ranges=0.0.0.0/0 --target-tags=no-such-instance-tag
try "fw allow-internal (logging on)" G compute firewall-rules create "$PREFIX-allow-internal" \
  --network="$PREFIX-vpc" --allow=tcp:0-65535,udp:0-65535,icmp --source-ranges=10.10.0.0/24 --enable-logging
try "fw deny-smtp-egress" G compute firewall-rules create "$PREFIX-deny-smtp-egress" \
  --network="$PREFIX-vpc" --direction=EGRESS --action=DENY --rules=tcp:25 \
  --destination-ranges=0.0.0.0/0 --priority=900

# ------------------------------------------------------------------ IAM -------
# gcp_iam_service_accounts' headline finding is the user-managed key that never
# rotates, and the only way to have one is to create one. The private key is
# written to a temp dir and shredded immediately — the fetcher reads key
# METADATA (age, type, expiry) and never the material, so nothing needs to keep it.
step "Service accounts, keys, custom roles, bindings"
try "sa $PREFIX-evidence-reader" G iam service-accounts create "$PREFIX-evidence-reader" \
  --display-name="Paramify evidence reader"
try "sa $PREFIX-stale-key" G iam service-accounts create "$PREFIX-stale-key" \
  --display-name="Has a user-managed key (fixture)"
# Key creation has no natural identity to collide on, so it succeeds every time
# and a second run silently doubles the fixture. Guard on the existing count, or
# the evidence reports key growth that came from re-running this script.
EXISTING_KEYS="$(G iam service-accounts keys list \
  --iam-account="$PREFIX-stale-key@$PROJECT_ID.iam.gserviceaccount.com" \
  --managed-by=user --format='value(name)' 2>/dev/null | grep -c . || true)"
if [[ "${EXISTING_KEYS:-0}" -gt 0 ]]; then
  echo "  exists user-managed key on $PREFIX-stale-key ($EXISTING_KEYS)"
else
  try "user-managed key on $PREFIX-stale-key" G iam service-accounts keys create "$WORK/sa-key.json" \
    --iam-account="$PREFIX-stale-key@$PROJECT_ID.iam.gserviceaccount.com"
fi
rm -f "$WORK/sa-key.json"

cat >"$WORK/reader-role.yaml" <<'YAML'
title: "Paramify Evidence Reader"
description: "Read-only access for the Paramify GCP fetchers."
stage: "GA"
includedPermissions:
  - compute.disks.list
  - compute.snapshots.list
  - storage.buckets.list
  - storage.buckets.get
  - cloudsql.instances.list
  - cloudkms.keyRings.list
  - cloudkms.cryptoKeys.list
  - container.clusters.list
  - logging.sinks.list
  - logging.buckets.list
  - logging.logMetrics.list
  - monitoring.alertPolicies.list
  - iam.serviceAccounts.list
  - iam.serviceAccountKeys.list
  - resourcemanager.projects.get
  - resourcemanager.projects.getIamPolicy
YAML
try "custom role paramifyEvidenceReader" G iam roles create paramifyEvidenceReader \
  --project="$PROJECT_ID" --file="$WORK/reader-role.yaml"

# Exercises gcp_iam_custom_roles' escalation-path classification: setIamPolicy,
# actAs and key creation are each a different escape hatch out of the role.
try "custom role paramifyEscalator (finding)" G iam roles create paramifyEscalator \
  --project="$PROJECT_ID" --stage=GA --title="Escalation paths (fixture)" \
  --permissions=resourcemanager.projects.setIamPolicy,iam.serviceAccounts.actAs,iam.serviceAccountKeys.create,iam.roles.update

# A primitive role held by a service account — what gcp_iam_policy_bindings flags.
try "bind roles/viewer to $PREFIX-stale-key (finding)" G projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$PREFIX-stale-key@$PROJECT_ID.iam.gserviceaccount.com" --role=roles/viewer

# gcp_iam_policy_bindings also reads auditConfigs, which have no gcloud verb —
# they can only be set by rewriting the whole policy.
step "Audit config on the project IAM policy"
if G projects get-iam-policy "$PROJECT_ID" --format=json >"$WORK/policy.json" 2>/dev/null; then
  python3 - "$WORK/policy.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
p["auditConfigs"] = [{
    "service": "allServices",
    "auditLogConfigs": [
        {"logType": "ADMIN_READ"},
        {"logType": "DATA_READ", "exemptedMembers": []},
        {"logType": "DATA_WRITE"},
    ],
}]
json.dump(p, open(sys.argv[1], "w"))
PY
  try "set audit config (allServices)" G projects set-iam-policy "$PROJECT_ID" "$WORK/policy.json"
else
  echo "  skip  audit config (could not read policy)"
fi

# -------------------------------------------------------- Secret Manager ------
step "Secret Manager secrets"
try "topic $PREFIX-secret-rotation" G pubsub topics create "$PREFIX-secret-rotation"
try "secretmgr agent -> topic publisher" G pubsub topics add-iam-policy-binding "$PREFIX-secret-rotation" \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-secretmanager.iam.gserviceaccount.com" \
  --role=roles/pubsub.publisher
printf 'fixture-value-not-a-real-secret' >"$WORK/secret.txt"
try "secret $PREFIX-auto (automatic replication)" G secrets create "$PREFIX-auto" \
  --data-file="$WORK/secret.txt" --replication-policy=automatic
# --kms-key-name is rejected for user-managed replication: gcloud only accepts a
# per-replica key through a policy file, because each replica carries its own.
cat >"$WORK/replication.json" <<JSON
{
  "userManaged": {
    "replicas": [
      {
        "location": "$REGION",
        "customerManagedEncryption": { "kmsKeyName": "$KR/cryptoKeys/secret-key" }
      }
    ]
  }
}
JSON
try "secret $PREFIX-cmek (user-managed + CMEK)" G secrets create "$PREFIX-cmek" \
  --data-file="$WORK/secret.txt" --replication-policy-file="$WORK/replication.json"
try "rotation schedule on $PREFIX-auto" G secrets update "$PREFIX-auto" \
  --next-rotation-time="$(date -u -v+30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ')" \
  --rotation-period=2592000s --add-topics="projects/$PROJECT_ID/topics/$PREFIX-secret-rotation"
rm -f "$WORK/secret.txt"

# -------------------------------------------------------------- BigQuery ------
step "BigQuery datasets"
try "dataset ${PREFIX}_cmek" bq --project_id="$PROJECT_ID" --location="$REGION" mk --dataset \
  --default_kms_key="$KR/cryptoKeys/bq-key" "${PROJECT_ID}:${PREFIX}_cmek"
try "dataset ${PREFIX}_plain (1h table expiry)" bq --project_id="$PROJECT_ID" --location="$REGION" mk --dataset \
  --default_table_expiration=3600 "${PROJECT_ID}:${PREFIX}_plain"

# ------------------------------------------------------------- Cloud DNS ------
# Both zone names are under reserved/undelegated domains, so the public zone is
# authoritative for nothing — it exists purely as a DNSSEC fixture.
step "Cloud DNS zones and policy"
try "zone $PREFIX-public (DNSSEC on)" G dns managed-zones create "$PREFIX-public" \
  --dns-name="$PREFIX-fixture.example.com." --description="DNSSEC fixture" \
  --dnssec-state=on --visibility=public
try "zone $PREFIX-private" G dns managed-zones create "$PREFIX-private" \
  --dns-name="internal.$PREFIX.test." --description="private fixture" \
  --visibility=private --networks="$PREFIX-vpc"
try "dns policy $PREFIX-dns-policy (logging on)" G dns policies create "$PREFIX-dns-policy" \
  --networks="$PREFIX-vpc" --enable-logging --description="query logging fixture"

# -------------------------------------------------------------- API keys ------
# These are live bearer credentials. Output is suppressed so no key string is
# ever written to a terminal, a log or a file; teardown.sh deletes them.
# Display names are not unique either, so these need the same guard as the SA key.
step "API keys (key strings suppressed)"
api_key_absent() {
  [[ -z "$(G services api-keys list --filter="displayName='$1'" --format='value(name)' 2>/dev/null | head -1)" ]]
}
if api_key_absent "$PREFIX-unrestricted"; then
  try "api key $PREFIX-unrestricted (finding)" G services api-keys create --display-name="$PREFIX-unrestricted"
else
  echo "  exists api key $PREFIX-unrestricted"
fi
if api_key_absent "$PREFIX-restricted"; then
  try "api key $PREFIX-restricted" G services api-keys create --display-name="$PREFIX-restricted" \
    --api-target=service=storage.googleapis.com
else
  echo "  exists api key $PREFIX-restricted"
fi

# --------------------------------------------------------------- Logging ------
# NOTE: log buckets are deliberately NOT locked. Locking is irreversible and
# blocks deletion until the retention period expires — a locked 400-day bucket
# would outlive the test project.
step "Log sink, log bucket, log metric, alert policy"
try "log bucket $PREFIX-retained (400d, unlocked)" G logging buckets create "$PREFIX-retained" \
  --location=global --retention-days=400 --description="retention fixture"
try "sink $PREFIX-sink" G logging sinks create "$PREFIX-sink" \
  "storage.googleapis.com/$PROJECT_ID-logs" --log-filter='severity>=WARNING'
try "metric ${PREFIX}_iam_changes" G logging metrics create "${PREFIX}_iam_changes" \
  --description="IAM policy changes (fixture)" \
  --log-filter='protoPayload.methodName="SetIamPolicy"'

cat >"$WORK/alert.yaml" <<YAML
displayName: "$PREFIX IAM changes (fixture)"
combiner: OR
conditions:
  - displayName: "IAM policy change rate"
    conditionThreshold:
      filter: 'metric.type="logging.googleapis.com/user/${PREFIX}_iam_changes" AND resource.type="global"'
      comparison: COMPARISON_GT
      thresholdValue: 0
      duration: 0s
      aggregations:
        - alignmentPeriod: 300s
          perSeriesAligner: ALIGN_COUNT
YAML
try "alert policy on ${PREFIX}_iam_changes" G alpha monitoring policies create --policy-from-file="$WORK/alert.yaml"

# ------------------------------------------------------- LB / TLS policy ------
# gcp_load_balancer_tls_configuration's headline finding is a proxy with NO ssl
# policy, which silently runs Google's TLS 1.0 COMPATIBLE default — so we build
# one of each. No forwarding rule is created, so nothing gets a public IP and
# nothing is billed for traffic.
step "SSL policies and target HTTPS proxies"
try "ssl policy $PREFIX-modern (1.2/MODERN)" G compute ssl-policies create "$PREFIX-modern" \
  --profile=MODERN --min-tls-version=1.2
try "ssl policy $PREFIX-permissive (1.0/COMPATIBLE)" G compute ssl-policies create "$PREFIX-permissive" \
  --profile=COMPATIBLE --min-tls-version=1.0
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
  -days 365 -nodes -subj "/CN=$PREFIX-fixture.example.com" >/dev/null 2>&1
try "self-signed cert $PREFIX-cert" G compute ssl-certificates create "$PREFIX-cert" \
  --certificate="$WORK/tls.crt" --private-key="$WORK/tls.key" --global
rm -f "$WORK/tls.key" "$WORK/tls.crt"
try "backend service $PREFIX-backend" G compute backend-services create "$PREFIX-backend" \
  --global --protocol=HTTP --load-balancing-scheme=EXTERNAL_MANAGED
try "url map $PREFIX-urlmap" G compute url-maps create "$PREFIX-urlmap" --default-service="$PREFIX-backend"
try "proxy $PREFIX-proxy-modern (policy attached)" G compute target-https-proxies create "$PREFIX-proxy-modern" \
  --url-map="$PREFIX-urlmap" --ssl-certificates="$PREFIX-cert" --ssl-policy="$PREFIX-modern"
try "proxy $PREFIX-proxy-nopolicy (finding)" G compute target-https-proxies create "$PREFIX-proxy-nopolicy" \
  --url-map="$PREFIX-urlmap" --ssl-certificates="$PREFIX-cert"

# ------------------------------------------------------- Compute instances ----
# e2-micro in us-central1 is Always Free eligible. The pair contrasts a hardened
# instance (Shielded VM, OS Login, blocked project keys, dedicated SA, no public
# IP) against the classic finding: the default compute SA with cloud-platform.
step "Compute instances"
try "instance $PREFIX-hardened" G compute instances create "$PREFIX-hardened" \
  --zone="$ZONE" --machine-type=e2-micro --subnet="$PREFIX-subnet" --no-address \
  --image-family=debian-12 --image-project=debian-cloud \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --service-account="$PREFIX-evidence-reader@$PROJECT_ID.iam.gserviceaccount.com" \
  --scopes=https://www.googleapis.com/auth/devstorage.read_only \
  --metadata=block-project-ssh-keys=TRUE,enable-oslogin=TRUE \
  --deletion-protection
try "instance $PREFIX-default (finding)" G compute instances create "$PREFIX-default" \
  --zone="$ZONE" --machine-type=e2-micro --subnet="$PREFIX-nolog" --no-address \
  --image-family=debian-12 --image-project=debian-cloud --scopes=cloud-platform

if $INCLUDE_EXPOSED; then
  step "Exposed fixtures (--include-exposed)"
  try "public ACL on ${PREFIX}_plain" bq --project_id="$PROJECT_ID" add-iam-policy-binding \
    --member=allUsers --role=roles/bigquery.dataViewer "${PROJECT_ID}:${PREFIX}_plain"
fi

fi  # TIER1

# ------------------------------------------------------------- TIER 2 ---------
if $TIER2; then
step "TIER 2 — Cloud SQL and GKE (billable; run teardown.sh when done)"

# Cloud SQL takes ~10 minutes to create. CMEK requires the key to live in the
# same region as the instance, which is why sql-key is in $REGION above.
SQL_ARGS=(
  --database-version=MYSQL_8_0 --tier=db-f1-micro --region="$REGION"
  --storage-size=10 --storage-type=HDD
  --backup --backup-start-time=03:00 --enable-bin-log
  --retained-backups-count=7 --retained-transaction-log-days=3
  --availability-type=zonal
  --require-ssl
  --disk-encryption-key="$KR/cryptoKeys/sql-key"
)
$INCLUDE_EXPOSED && SQL_ARGS+=(--authorized-networks=0.0.0.0/0)
try "cloud sql $PREFIX-sql (~10 min)" G sql instances create "$PREFIX-sql" "${SQL_ARGS[@]}"

# One zonal Standard cluster: the control-plane fee is covered by GKE's own free
# tier, so the only real cost is the single node. Workload Identity and shielded
# nodes on, network policy on, legacy ABAC off.
try "gke cluster $PREFIX-gke (~7 min)" G container clusters create "$PREFIX-gke" \
  --zone="$ZONE" --num-nodes=1 --machine-type=e2-small --disk-size=32 \
  --network="$PREFIX-vpc" --subnetwork="$PREFIX-subnet" \
  --workload-pool="$PROJECT_ID.svc.id.goog" --shielded-secure-boot --shielded-integrity-monitoring \
  --enable-network-policy --no-enable-legacy-authorization \
  --enable-autoupgrade --enable-autorepair --release-channel=regular \
  --enable-ip-alias --no-enable-basic-auth --no-issue-client-certificate
fi

# ---------------------------------------------------------------- Summary -----
printf '\n\033[1m==> Done\033[0m\n'
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "${#FAILED[@]} step(s) failed:"
  printf '  - %s\n' "${FAILED[@]}"
  echo
  echo "A failure here is usually a not-yet-propagated API or service agent."
  echo "Re-running the script is safe — existing resources are skipped."
else
  echo "All steps succeeded."
fi
echo
echo "Next: paramify run manifests/gcp.yaml"
