#!/bin/bash
# Collects the S3 destinations GuardDuty exports its findings to: the bucket ARN,
# its derived bucket name / key prefix, the KMS key ARN, and publishing status.
#
# No detectors is valid evidence that GuardDuty is not enabled. Detectors with no
# publishing destination is valid evidence that findings are not exported to S3.
# Neither is a collection failure — only real API errors are.
#
# Output: $EVIDENCE_DIR/aws_guard_duty_publishing_destinations_<target>.json
# Optional env (else the CLI's ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI's own credential chain. A manifest target
# may set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout);
# when unset, the CLI uses the ambient identity/region. The helper sets PROFILE
# and REGION (for metadata) and provides aws_target_id (for the filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename (profile+region, or "ambient") so fanout runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_guard_duty_publishing_destinations_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_gd_pub_dest.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_gd_pub_dest_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_guard_duty_publishing_destinations %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_guard_duty_publishing_destinations %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"detectors": [], "publishing_destinations": [], "destination_arns": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

# S3 bucket ARNs are `arn:PARTITION:s3:::BUCKET[/KEY_PREFIX]`. Take the ARN verbatim
# from the API and PARSE the parts out of it — never reconstruct it — so GovCloud
# (arn:aws-us-gov) and commercial (arn:aws) both come out right.
_PARSE_ARN_JQ='
def parse_s3_arn:
  if . == null or . == "" then
    {partition: null, bucket_name: null, key_prefix: null}
  else
    (split(":")) as $p
    | (if ($p | length) >= 6 then ($p[5:] | join(":")) else "" end) as $res
    | ($res | split("/")) as $r
    | {
        partition: (if ($p | length) > 1 and $p[1] != "" then $p[1] else null end),
        bucket_name: (if ($r | length) > 0 and $r[0] != "" then $r[0] else null end),
        key_prefix: (if ($r | length) > 1 then ($r[1:] | join("/")) else null end)
      }
  end;
'

# --- data collection ---

# Get detector IDs. GuardDuty not enabled is valid evidence, not a failure — and it
# surfaces two ways depending on the account: an empty DetectorIds list (exit 0), OR
# a SubscriptionRequiredException (the account/region was never subscribed, so the
# call errors). Treat both as "not enabled"; only OTHER API errors (AccessDenied,
# throttling, …) are real collection failures.
_LIST_ERR="$(mktemp -t aws_gd_pub_dest_list.XXXXXX)"
detectors=$(aws guardduty list-detectors --query 'DetectorIds[*]' --output json 2>"$_LIST_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if grep -q 'SubscriptionRequiredException' "$_LIST_ERR"; then
        log_info "GuardDuty not enabled in ${REGION:-ambient region} (SubscriptionRequiredException) — recording as not enabled"
    else
        echo "aws guardduty list-detectors failed (exit=$ec): $(tr '\n' ' ' < "$_LIST_ERR")" >> "$_FAILURE_LOG"
    fi
    detectors='[]'
fi
rm -f "$_LIST_ERR"
if [ -z "$detectors" ] || ! echo "$detectors" | jq . >/dev/null 2>&1; then
    detectors='[]'
fi

jq --argjson detectors "$detectors" '.results.detectors = ($detectors // [])' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# Walk detectors -> destinations. Process substitution (not a pipe) so the loop runs
# in THIS shell and can mutate destinations_json / the counters below.
destinations_json='[]'

while read -r detector_id; do
    [ -z "$detector_id" ] && continue

    dest_list=$(aws guardduty list-publishing-destinations \
                    --detector-id "$detector_id" \
                    --query 'Destinations[*]' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$dest_list" ] || ! echo "$dest_list" | jq . >/dev/null 2>&1; then
        echo "aws guardduty list-publishing-destinations ($detector_id) failed (exit=$ec)" >> "$_FAILURE_LOG"
        continue
    fi

    if [ "$(echo "$dest_list" | jq 'length')" -eq 0 ]; then
        log_info "Detector $detector_id has no publishing destinations (findings not exported to S3)"
        continue
    fi

    while read -r destination_id; do
        [ -z "$destination_id" ] && continue

        detail=$(aws guardduty describe-publishing-destination \
                     --detector-id "$detector_id" \
                     --destination-id "$destination_id" --output json 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ] || [ -z "$detail" ] || ! echo "$detail" | jq . >/dev/null 2>&1; then
            echo "aws guardduty describe-publishing-destination ($detector_id/$destination_id) failed (exit=$ec)" >> "$_FAILURE_LOG"
            continue
        fi

        entry=$(echo "$detail" | jq --arg detector_id "$detector_id" "$_PARSE_ARN_JQ"'
            (.DestinationProperties.DestinationArn // null) as $dest_arn
            | ($dest_arn | parse_s3_arn) as $parts
            | {
                detector_id: $detector_id,
                destination_id: (.DestinationId // null),
                destination_type: (.DestinationType // null),
                status: (.Status // null),
                publishing_failure_start_timestamp: (.PublishingFailureStartTimestamp // null),
                destination_arn: $dest_arn,
                partition: $parts.partition,
                bucket_name: $parts.bucket_name,
                key_prefix: $parts.key_prefix,
                kms_key_arn: (.DestinationProperties.KmsKeyArn // null)
              }')
        if [ -z "$entry" ] || ! echo "$entry" | jq . >/dev/null 2>&1; then
            echo "failed to parse describe-publishing-destination ($detector_id/$destination_id)" >> "$_FAILURE_LOG"
            continue
        fi

        destinations_json=$(echo "$destinations_json" | jq --argjson e "$entry" '. + [$e]')
    done < <(echo "$dest_list" | jq -r '.[].DestinationId // empty')
done < <(echo "$detectors" | jq -r '.[]')

if [ "$(echo "$detectors" | jq 'length')" -eq 0 ]; then
    log_info "No GuardDuty detectors found (GuardDuty not enabled in ${REGION:-ambient region})"
fi

# Count collection failures BEFORE building the summary. A partial failure means the
# destination list is incomplete, so the summary must not report HEALTHY over it — the
# exit code alone isn't enough, since the payload gets read on its own.
failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}

# Summary + the flat ARN list consumers use as the S3 endpoint.
summary_json=$(jq -n \
    --argjson detectors "$detectors" \
    --argjson dests "$destinations_json" \
    --argjson failures "$failure_count" \
    '($dests | map(select(.status == "PUBLISHING")) | length) as $publishing
     | (
         (if $failures > 0 then ["collection_incomplete"] else [] end)
         + (if ($detectors | length) > 0 and ($dests | length) == 0
            then ["no_publishing_destination"] else [] end)
         + (if ($dests | length) > 0 and $publishing < ($dests | length)
            then ["destination_not_publishing"] else [] end)
         + (if ($dests | map(select(.kms_key_arn == null)) | length) > 0
            then ["destination_not_kms_encrypted"] else [] end)
       ) as $issues
     | {
         detector_count: ($detectors | length),
         destination_count: ($dests | length),
         s3_destination_count: ($dests | map(select(.destination_type == "S3")) | length),
         publishing_count: $publishing,
         encrypted_destination_count: ($dests | map(select(.kms_key_arn != null)) | length),
         collection_failure_count: $failures,
         # Derived FROM $issues so health and issues can never disagree. No detectors is
         # NOT_ENABLED (a distinct fact from "enabled but misconfigured"), not a failure —
         # but an INCOMPLETE collection never reads HEALTHY, whatever the partial data says.
         health_status: (
           if $failures > 0 then "REQUIRES_ATTENTION"
           elif ($detectors | length) == 0 then "NOT_ENABLED"
           elif ($issues | length) > 0 then "REQUIRES_ATTENTION"
           else "HEALTHY" end
         ),
         issues: $issues
       }')

jq --argjson dests "$destinations_json" --argjson summary "$summary_json" \
   '.results.publishing_destinations = $dests
    | .results.destination_arns = ($dests | map(.destination_arn) | map(select(. != null)) | unique)
    | .results.summary = $summary' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

if [ "$failure_count" -gt 0 ]; then
    log_error "Encountered $failure_count AWS API failures during collection"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
