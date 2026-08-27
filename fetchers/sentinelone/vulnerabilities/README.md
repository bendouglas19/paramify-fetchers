# sentinelone_vulnerabilities

Collects vulnerability findings from SentinelOne Singularity's Application Risk /
Vulnerability Management module (`GET /web/api/v2.1/application-management/risks`)
as source evidence for FedRAMP 20x CR26 **VER-RPT-VDT** (vulnerability detail)
reporting.

## What it speaks to

VER-RPT-VDT, with the reporting window stamped for VER-RPT-PER. Facts only —
severity, CVSS scores, and status are reported verbatim as SentinelOne returns
them. No pass/fail, compliance status, PAIN/N-rating, or risk interpretation is
computed here; per `docs/design.md` that judgment is Paramify-side. This section
is informational, not authoritative.

## API contract — core shape verified, two items open

SentinelOne publishes its API reference only from an authenticated tenant console
(`/api-doc/overview`), so this fetcher was built against the shape used by
Elastic's `sentinel_one` integration (`application_risk` data stream) and the
endpoint list in the Qualys SentinelOne EDR connector, then confirmed by a live
run.

**Verified 2026-08-19** against a `us-east-1` tenant — 12,694 records over 13
cursor pages, empty failure ledger, `status: success`. The endpoint path, the
`ApiToken` auth scheme, `limit`/`cursor` params, `pagination.nextCursor`
pagination, and the flat record shape all behave as documented. Grouping was
lossless: 12,694 records in, 12,694 affected-endpoint rows out.

**The field set is not uniform across tenants.** That tenant returned **23 of
the 33** documented fields. Absent: `exploitCodeMaturity`, `remediationLevel`,
`reportConfidence`, `riskScore`, `nvdBaseScore`, `nvdCvssVersion`,
`mitigationStatus`, `mitigationStatusChangeTime`, `mitigationStatusChangedBy`,
`mitigationStatusReason`. That reads as a **licensing tier** difference — the
CVSS temporal triad and the mitigation-workflow family look like full
Singularity VM / Ranger Insights features rather than base Application Risk.
Confirm with your SentinelOne rep, because it directly costs FedRAMP fields.
Those fields keep their null slots rather than being removed, so a higher-tier
tenant populates them with no code change.

Still open:

1. **Scope params — untested.** The verifying run was unscoped. Only `siteIds`
   is sent; `accountIds` and `groupIds` are unconfirmed.
2. **Risk-accepted enum values — untested, and a zero proves nothing.** In the
   verifying run `markType`/`markedBy`/`markedDate`/`reason` were present but
   **0% populated** and `status` was 100% `Detected`, so
   `records_excluded_risk_accepted` was 0 for lack of any marked record — not
   because the matcher agreed with the console. Re-check once someone actually
   marks a vulnerability.

Settled by that run: the local-windowing decision (detections spanned
2024-09-06 to 2026-08-18, `daysDetected` up to 712, and only 2,286 of 4,730
vulnerabilities fell inside a 30-day window — a server-side date filter would
have dropped 52% of the report, biased toward the most overdue findings), and
the absence of every field in the "does not expose" list below.

## Required env vars

| Var | Purpose |
|-----|---------|
| `SENTINELONE_API_TOKEN` | Console API token. Needs the **Application Risk** permission (`Applications -> viewRisks`). |
| `SENTINELONE_API_URL` | Console base URL, no trailing slash. Required. Declared as a **secret** to match the category convention shared by every SentinelOne fetcher (see `fetchers/sentinelone/README.md`). Works with **any** host: commercial (`https://usea1-019.sentinelone.net`) or **GovCloud / FedRAMP** (`https://usgovwe1-901.s1gov.net` — the `s1gov.net` domain). |
| `SENTINELONE_REPORTING_PERIOD_DAYS` | Optional, default `30`. Derives `report_period.start`/`end`. |
| `SENTINELONE_SCOPE_IDS` | Optional. Comma-separated Site IDs, sent as `siteIds`. |
| `SENTINELONE_INCLUDE_ACCEPTED` | Optional, default `false`. `true` collects the risk-accepted set (VER-RPT-AVI) instead of excluding it. |
| `EVIDENCE_DIR` | Output directory (defaults to `./evidence`). |

## How to run

The fetcher reads secrets from `os.environ`. Any mechanism that populates the
process environment works — `.env`, `export`, AWS Secrets Manager, HashiCorp
Vault, K8s secret env mounts, CI provider secret blocks. `.env` is not
privileged.

```bash
.venv/bin/paramify run examples/sentinelone_vulnerabilities.yaml
```

## Output

Writes `sentinelone_vulnerabilities.json` to `EVIDENCE_DIR`. Top level:

| Key | Contents |
|---|---|
| `status` | `success` \| `partial` \| `error` — collection status, not compliance status |
| `report_period` | `start` / `end` (ISO8601 UTC) / `days` |
| `scope` | resolved site IDs and `include_accepted` |
| `collection` | page/record counts, `api_returned_empty_list`, exclusion counts, field-discovery probes |
| `api_failures` | the failure ledger: endpoint, params, exception type, message, HTTP status |
| `vulnerabilities` | one entry per (CVE x vendor x product), with `affected_endpoints` and `endpoint_count` |
| `raw_records` | every API record, verbatim |

Zero vulnerabilities is valid evidence. `collection.api_returned_empty_list` is
true **only** when a page came back successfully and held no records; a failed
call leaves it false and populates `api_failures`, so the two cannot be confused.

## VER-RPT-VDT gap analysis

Against `$defs/vulnerabilityDetail` in
[`fedramp-common-definitions-schema-2026-06-24.json`](https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json).

### Required fields

| FedRAMP field | Status | Source / what's missing |
|---|---|---|
| `providerTrackingId` | **Partial** | SentinelOne's `id` is per (CVE x app x endpoint), so one FedRAMP vulnerability maps to N SentinelOne IDs. All of them are in `sentinelone_record_ids`; `vulnerability_key` is the stable per-vulnerability handle. The mapper must choose — a Paramify POA&M ID is the better tracking ID. |
| `detection.detectedAt` | **Yes** | `first_detected_at` (earliest `detectionDate` across affected endpoints). |
| `detection.detectionSource` | **Yes** | `detection_source` — stated by the fetcher as SentinelOne Singularity VM. |
| `vulnerabilityDescription` | **No** | Not in the API. Needs CVE enrichment (NVD lookup) or Paramify-side text. `cve_id` + application name/vendor/version are present to drive it. |

### Optional fields

| FedRAMP field | Status | Source / what's missing |
|---|---|---|
| `potentialAgencyImpact` | **No** | Judgment. Paramify-side / manual. |
| `evaluationCompletedAt` | **No** | SentinelOne has no evaluation-complete concept. `last_scanned_at` and `mitigation_status_changed_at` are *not* substitutes. Must come from Paramify's workflow — the VER-TFR-MAV clock runs from this date. |
| `isInternetReachable` | **No** | Application Risk is endpoint-scoped with no network-exposure model. Needs asset/network inventory or manual IRV classification. |
| `isLikelyExploitable` | **No** (was "inputs only") | `cvss_temporal.exploit_code_maturity` (CVSS-E) would be real LEV input, but the 2026-08-19 tenant **does not return it** — nor `epss_score` / `cisa_kev`. On a base Application Risk tier there is no LEV input at all beyond the CVSS base score. Needs a higher tier or external EPSS/KEV enrichment. |
| `currentRating` (N1–N5) | **Inputs only** | `severity` and `cvss.base_score` only — `cvss.nvd_base_score` and `sentinelone_risk_score` were absent in the 2026-08-19 tenant. The PAIN N-rating mapping is deliberately not computed here. |
| `projectedNextReduction` | **No** | Remediation plan / POA&M data from Paramify. |
| `overdueStatus` | **No** | Determination requiring `evaluationCompletedAt` plus the VER-TFR-MAV clock. `first_detected_at`, `days_detected`, and `report_period` are the available inputs. |
| `supplementaryRiskInformation` | **Thin** | `statuses_observed`, `days_detected`, and the affected-endpoint list are the usable raw material. `mitigation_status_reason` was absent and `mark_reason` was 0% populated in the 2026-08-19 tenant, so there is no operator narrative to draw on. Authored Paramify-side. |
| `finalDisposition` | **No source data yet** | `markType` / `mitigationStatus` are the intended source, but in the 2026-08-19 tenant `mitigationStatus` was absent entirely and `markType` was 0% populated with `status` 100% `Detected` — the mitigation/acceptance workflow is unused, so nothing maps. Once it is in use the mapper still needs a verified enum crosswalk. "Partially Mitigated" stays derivable from per-endpoint `status` counts across `affected_endpoints`. |

`$defs/reportPeriodDateTime` maps cleanly: `report_period.start` → `from`,
`report_period.end` → `to`. Both are ISO8601 UTC with `Z`, satisfying
`format: date-time`. Note the field rename.

For **VER-RPT-AVI** (`$defs/acceptedVulnerabilityInfo`), run with
`include_accepted: true`. `acceptanceRationale` maps from `mark_reason` /
`mitigation_status_reason` when the console captured one; otherwise it is
Paramify-side text.

### Live-tenant scope findings (2026-08-19)

Not API gaps, but they limit what this evidence can attest to — and they matter
more for VER-RPT-VDT than any missing field:

- **Coverage is Mac-laptop only.** All 89 endpoints came back `osType: macos`,
  `endpointType: laptop`. No Windows, no Linux, no servers. If the FedRAMP
  authorization boundary includes servers, they are **not represented in this
  evidence at all**. Check Application Risk agent coverage / licensing before
  treating this file as boundary-complete.
- **Report size:** 4,730 `vulnerabilityDetail` entries from 3,975 distinct CVEs
  across 12,694 (CVE x app x endpoint) records — 492 CRITICAL, 2,008 HIGH,
  2,071 MEDIUM, 159 LOW at the vulnerability level. Worth sizing the mapper for.
- **File size:** ~29 MB, mostly `raw_records`. `/evidence/` is gitignored, so it
  will not be committed, but consider whether the uploader wants the verbatim
  copy at this scale.
- **`cvssVersion` is mixed:** 3.1 (12,595), 2.0 (72), 3.0 (20), null (7). A
  mapper comparing base scores across records must read the version alongside
  the score — CVSS 2.0 and 3.x severities are not interchangeable. Seven records
  carry no score at all.

### Requested superset — what this endpoint does not expose

Confirmed absent in the 2026-08-19 run, on top of the ten tier-gated fields
listed at the top of this file. Absent from the confirmed record shape: **CVSS vector string, CWE ID, EPSS score,
CISA KEV flag, CPE, patch availability, fixed version, agent UUID, agent version,
endpoint IP, endpoint OS version, and linked ticket / POA&M / external reference
IDs.** Nothing is invented for them — each has a null slot in the payload, the
opportunistic-field maps pick them up if a tenant returns them under a likely
name, and `raw_records` preserves everything regardless.

Two of those gaps have a concrete fix inside this repo:

- **Agent UUID / agent version / IP / OS version** are all available from
  `/web/api/v2.1/agents`, which `sentinelone_agents` already collects. Join on
  `affected_endpoints[].endpoint_id` ↔ the agent record's `id`. Worth doing as a
  comparator once `depends_on` is honored by the runner, rather than a second
  API call here.
- **Patch availability / fixed version** may be reachable through a different
  Ranger Insights / patch-management endpoint. Worth investigating against a
  live tenant — it is the single most useful missing field for remediation
  reporting.

## Notes for the VER-RPT-VDT mapper (`uploaders/paramify_issues/`)

The mapper — not built here — will need to:

1. Choose a stable `providerTrackingId` per vulnerability (recommend a Paramify
   POA&M ID keyed off `vulnerability_key`, not SentinelOne's per-record `id`).
2. Enrich `vulnerabilityDescription` from `cve_id`.
3. Rename `report_period.start`/`end` → `from`/`to`.
4. Hold a verified `markType`/`mitigationStatus` → `finalDisposition` crosswalk,
   and derive "Partially Mitigated" from per-endpoint `status` counts.
5. Carry the N-rating, IRV/LEV, overdue, and impact determinations from Paramify
   state — this fetcher supplies inputs, never verdicts.
6. Treat `collection.records_excluded_risk_accepted` as the pointer to the
   VER-RPT-AVI run; a non-zero value here means an accepted set exists that this
   file deliberately omits.

## Known v0.x interim behavior

- Reads env vars directly via `os.environ` (replaced by the framework's secret
  resolver later).
- Reads `EVIDENCE_DIR` from env (replaced by the runner passing an output path).
- Writes a raw evidence dict; the runner wraps it in the standard envelope.
- `raw_records` keeps every API record verbatim for auditability, which roughly
  doubles file size on large tenants.
