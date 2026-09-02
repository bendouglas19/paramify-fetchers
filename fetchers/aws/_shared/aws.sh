#!/usr/bin/env bash
# Shared helpers for the AWS fetchers (SOURCED, not executed).
#
# Credential + region resolution is the AWS CLI's job, via its own provider
# chain. The runner sets AWS_PROFILE / AWS_DEFAULT_REGION from a manifest target
# when one is given; when a target omits them — or there are no targets at all —
# they stay unset and the CLI uses the AMBIENT identity/region ("collect where
# deployed"). So fetchers do NOT pass --profile/--region; they just run `aws ...`
# and let the CLI read the env vars (or fall through to IRSA / instance role /
# SSO / ~/.aws). A profile-bearing target still scopes the run for fanout.
#
# Usage in a fetcher.sh:
#   source "$(dirname "$0")/../_shared/aws.sh"
#   _TARGET_ID="$(aws_target_id)"

# Failure reporting. Re-exported, NOT reimplemented (docs/fetcher_contract.md
# § Output): every AWS fetcher already sources this file, so sourcing the shared
# helper here gives all 80 `report_failure` without a per-fetcher source line.
# BASH_SOURCE[0] is this file, so the path holds whatever the caller's cwd is.
source "$(dirname "${BASH_SOURCE[0]}")/../../_lib/status.sh"

# Recorded in evidence metadata only (the CLI reads the env itself). Empty is a
# valid value = ambient.
PROFILE="${AWS_PROFILE:-}"
REGION="${AWS_DEFAULT_REGION:-}"

# aws_target_id [REGION] — id for unique output filenames across a fanout: the
# profile when set, else "ambient", with the region appended only when passed.
# Regional fetchers pass "$REGION"; global fetchers (IAM, Route53, S3 naming)
# pass nothing so their filename stays account/profile-scoped. Account
# attribution always lives in the evidence metadata (account_id from
# `aws sts get-caller-identity`), so an ambient run is still traceable.
aws_target_id() {
  local id="${PROFILE:-ambient}"
  [ -n "${1:-}" ] && id="${id}_${1}"
  printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_'
}

# aws_service_unavailable <stderr-file> — true (exit 0) when the captured AWS CLI
# error means the service is simply NOT IN USE for this account. That is valid
# evidence ("not enabled / not subscribed / not applicable"), NOT a collection
# failure, so the caller should record a not-enabled result and exit 0 rather than
# logging a failure. Covers: service not subscribed / not opted-in, Security Hub /
# Macie not enabled, account not a member of an Organization, Resource Explorer /
# resource not found, and the generic "needs a subscription for the service"
# message. Use it ONLY at a fetcher's primary enablement / top-level list call to
# decide not-enabled (exit 0) vs. a real failure (exit 1). Genuine AccessDenied
# (without the subscription message), throttling, and endpoint errors are NOT
# matched here and stay real failures.
aws_service_unavailable() {
  [ -s "${1:-/dev/null}" ] || return 1
  grep -qiE 'SubscriptionRequiredException|OptInRequired|needs a subscription for the service|InvalidAccessException|AWSOrganizationsNotInUseException|not a member of an organization|is not enabled|ResourceNotFoundException' "$1"
}

# aws_text_list <output> — echoes an AWS CLI `--output text` list back UNLESS it is
# the empty-list sentinel the CLI prints for an absent/null field (the literal
# "None", or whitespace only). Prevents the classic bug where
# `for x in $(aws ... --query 'Items[].Id' --output text)` iterates once over the
# string "None" and then fails a per-item call. Usage:
#   for x in $(aws_text_list "$ids"); do ...
aws_text_list() {
  case "$1" in
    None|"") return 0 ;;
    *) printf '%s' "$1" ;;
  esac
}
