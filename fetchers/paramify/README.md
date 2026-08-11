# Paramify FedRAMP VER Report Fetchers

Unlike most categories (which pull evidence *from* a third-party system into
Paramify), these fetchers read *from* Paramify's own REST API and generate the
FedRAMP Consolidated Rules 2026 vulnerability-reporting artifacts:

| Fetcher | Report | Evidence set |
|---|---|---|
| `paramify_accepted_vulnerabilities`      | VER-RPT-AVI | `EVD-PARAMIFY-VER-RPT-AVI` |
| `paramify_vulnerability_detail_report`   | VER-RPT-VDT | `EVD-PARAMIFY-VER-RPT-VDT` |
| `paramify_historical_ver_activity`       | VER-TFR-MRH | `EVD-PARAMIFY-VER-TFR-MRH` |

AVI and VDT are exact partition complements: every project issue is reported in
exactly one of them (accepted vs. not-accepted). MRH is a point-in-time snapshot
carrying both partitions in one document. All three share a single definition of
"accepted" and one issue-fetch/mapping implementation in
[`_shared/ver_common.py`](_shared/ver_common.py), so the reports cannot drift
apart.

## Credentials

A Paramify REST API Bearer token with **read** scope on the target project's
issues and deviations. It is the only `secret` these fetchers declare; everything
else is a `target` field or non-secret `config`.

| Env var | Declared as | Required | Purpose |
|---|---|---|---|
| `PARAMIFY_API_TOKEN` | secret `api_token` | yes | Bearer token (falls back to `PARAMIFY_UPLOAD_API_TOKEN` when run standalone). |
| `PARAMIFY_PROJECT_ID` | **target** `project_id` | yes | Project UUID to scope the report. One target per program. |
| `PARAMIFY_PROGRAM_NAME` | **target** `program_name` | no | Readable program name; used for the evidence filename and artifact title. Falls back to the UUID. |
| `PARAMIFY_REPORT_FROM` | fetcher config `report_from` | yes | ISO start of the report period. |
| `PARAMIFY_REPORT_TO` | fetcher config `report_to` | no | ISO end; defaults to run time. |
| `PARAMIFY_CERT_PACKAGE_URI` | **category** config `cert_package_uri` | yes | Certification Package Overview URI written into every report. |
| `PARAMIFY_API_BASE_URL` | **category** config `api_base_url` | no | Defaults to `https://app.paramify.com/api/v0`. Point at stage for testing. |
| `PARAMIFY_HTTP_TIMEOUT` | **category** config `http_timeout` | no | Per-request timeout (seconds). Default 300 — the unfiltered `/issues` call is large. |

Three layers, by what the value actually varies with:

- **target** — differs per program, so it's per fanout iteration.
- **category config** (`fetchers/_categories/paramify.yaml`, set under
  `platforms.paramify.config`) — one value for the whole workspace, shared by all
  three fetchers. The package URI belongs here: one workspace publishes one, and
  copying it onto every target would mean editing N×3 places to change it.
- **fetcher config** — the report period, which is a property of the report.

Nothing non-secret is declared under `secrets[]`, deliberately: every declared
secret is **mandatory** (the runner raises when a manifest omits one), while
config is optional and defaultable.

## Running across several programs

All three fetchers fan out: one invocation per program, one evidence file per
program, all files landing in that report's single evidence set. Fill the targets
in from the workspace rather than by hand:

```bash
paramify programs list            # readable name + project UUID
paramify programs target          # pick programs, get targets on all three fetchers
```

It asks for the Certification Package Overview URI and the report period start,
storing both as category config — no per-program bookkeeping. A later run shows
both again with the stored values as the defaults, so adding a program is enter,
enter, and moving the report window forward is typing a new date over the old one.

`report_from` is declared per-fetcher (it's a property of the report, not the
platform) but set once at the platform level: the runner merges *platform
defaults ← platform values ← per-fetcher values*, so a manifest can set any
declared field once under `platforms.paramify.config`. Override it for a single
report by putting `report_from` in that fetcher entry's own `config`.

Each program's file is named for its program (`..._Alpha_Cloud_Services_aaaaaaaa.json`,
UUID prefix appended because program names are not guaranteed unique), and the
uploader titles the artifact the same way.

## Timestamps

Every instant in a generated report uses one format — UTC, second precision,
literal `Z`:

```
2026-07-30T09:00:00Z
```

That holds regardless of source. Values the fetcher generates (`generatedAt`,
a defaulted `reportPeriod.to`) are produced in it; values from the Paramify API
(`detectedAt`, `evaluationCompletedAt`, the `dueDate` quoted in an overdue
explanation) are **normalized on the way in**, since the API returns
milliseconds; and a `report_from` / `report_to` supplied as a bare date is
expanded. A non-UTC offset is converted rather than preserved, so
`2026-02-01T09:00:00+02:00` is emitted as `2026-02-01T07:00:00Z`.

A date-only `report_to` is reported as that day's **last second**
(`2026-06-30` → `2026-06-30T23:59:59Z`), because a date-only end means "through
the end of that day" to the coverage filter — reporting its midnight would
understate the period by a day.

A value the parser can't read is passed through unchanged rather than dropped or
blanked; schema verification is the right place for a malformed source value to
surface. `tests/test_ver_timestamps.py` pins all of this.

## Notes

- **Coverage:** the fetchers keep every OPEN issue regardless of when its status
  last changed, plus anything whose status changed inside the report window.
  This avoids silently dropping open issues with a missing/epoch `statusDate`.
- **Epoch sentinel:** issues with a missing or pre-2000 (`1970-…`)
  `evaluationDate` are treated as never-evaluated — they are not time-accepted
  (the VER-TFR-MAV 192-day clock never started) and are surfaced in a
  VER-TFR-EVU warning to stderr.
- **`_summary`:** each report carries a top-level `_summary` object (count
  breakdowns computed from the report's own arrays). It is a vendor extension —
  the FedRAMP report arrays remain the source of truth.
- **`_summary.collection`:** records the collection outcome and the API-failure
  ledger *inside* the payload. `/issues` is the only call these fetchers make, so
  a failure leaves the report arrays empty; without this block an empty **failed**
  report would look identical to a genuinely clean one to anything reading the
  payload alone (the uploader's `skip_failed` defaults to false, so failed
  evidence is uploaded unless configured otherwise). A failed collection still
  exits non-zero.
- **Milestones** are read from the `milestones` array embedded in the `/issues`
  response; there are no per-issue milestone calls.
