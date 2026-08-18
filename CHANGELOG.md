# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) applied
to the contract (see [`docs/versioning.md`](docs/versioning.md)). "The contract"
is the public API surface — the `fetcher.yaml` / category / manifest / envelope
schemas and the `paramify` CLI — not the internal code.

## [Unreleased]

### Added

- `paramify programs` — a new command group over the Paramify workspace.
  `programs list` shows each program's readable name next to its project UUID;
  `programs target` selects programs (interactively, by name/id, or `--all`) and
  writes them as fanout targets, filling in the shared config they need. The API
  identifies programs by UUID while people know them by name; this closes that
  gap without anyone copying a UUID by hand. The shared values (`--cert-uri`,
  `--report-from`) are shown on every interactive run with what the manifest
  holds today as the prompt default and a note of where it comes from: enter
  keeps it and writes nothing, typing over it updates the category value. So the
  same command adds a program and rolls the report window forward, and neither
  requires opening the manifest to see what the next run will carry. Entries that
  resolve to different values get no default — either one offered as *the* answer
  would misreport the other.
- `program_name` — an optional target field on the Paramify VER fetchers. The
  fetcher uses it for its evidence filename and the uploader for the artifact
  title, so per-program artifacts read as `… - Alpha Cloud Services` rather than
  a bare UUID. A UUID prefix stays in the filename because program names are not
  guaranteed unique.
- **`requires:` on a category** — `fetchers/_categories/<name>.yaml` gains a
  `requires:` block naming the external binaries and the pip distributions its
  fetchers need, and `paramify doctor` checks them. With a manifest it checks only
  the categories that manifest actually uses, so a GitLab-only run is never told
  to install the aws CLI or 23 Azure SDKs. Version pins stay in
  `requirements.txt`, which remains the single source of truth for versions; a
  category file names only which distributions are its own. The declarations are
  themselves tested (`tests/test_category_requires.py`): an import or a
  shelled-out binary that nothing declares fails the suite, because doctor's
  report is only as good as what the category files say.
- **`paramify doctor --probe`** — authenticates against each cloud category
  (`aws`, `k8s`, `azure`, `gcp`) and reports which identity answered: caller ARN
  and account, Azure principal and subscriptions, GCP account and project.
  Without it doctor can only see whether variables are *set*, which is nearly
  meaningless for credential chains whose preferred links — IRSA, workload
  identity, managed identity, a cached CLI login — set no variable at all, so
  doctor reported a clean bill of health and the run failed on auth. It also
  answers "as whom", the more common silent failure: credentials that work but
  point at the wrong account produce a successful run full of empty evidence.
  Opt-in because it is the only part of doctor that touches the network, each
  probe runs in a subprocess under a hard timeout, and a failed probe is reported
  without failing the command.
- **`paramify doctor --require-upload`** — makes a missing API token count toward
  the exit code. Upload readiness (token presence and the destination URL) is
  always reported; gating is opt-in because collecting evidence without uploading
  it is a legitimate workflow that should not fail a preflight.
- **`paramify upload` asks for the API token** when none is set and it is safe to
  ask — a real terminal at both ends, no CI, not `--json`. Reaching the upload
  step means the collection is already paid for, and this is a failure a person
  can fix on the spot rather than by re-running the whole thing. The value is used
  for that run and written nowhere; persisting a credential is the user's call, so
  it prints how instead of guessing at a file. `paramify run` says the same thing
  up front, advisory only, so you learn it in the first second rather than the
  last.

### Changed

- The `tui` extra pins `textual>=8,<9` (was `>=1.0,<2.0`). The old range was not
  what anyone ran, and focus / `Input` behaviour differs enough across those lines
  that the TUI is not the same app on 1.x. `tests/test_tui_keys.py` (new) drives
  the real app through Textual's pilot to hold the key-and-focus contract: what
  each tab focuses, that the globals survive a repeat tab press, and that enter
  reaches an action wherever the footer says it does.
- **TUI**: the footer hint bar lists `esc` (the only way out of a focused text
  field back to the shortcut keys — an `Input` consumes every printable key) and
  the Run tab shows `enter/ctrl+r`, since focus opens on the ▶ Run button and
  `enter` presses it.
- **Paramify VER fetchers**: `report_from` / `report_to` / `api_base_url` /
  `http_timeout` moved out of `secrets[]`. Every declared secret is mandatory, so
  declaring optional knobs there made them required, contradicting their
  documented defaults. `cert_package_uri`, `api_base_url` and `http_timeout` are
  now category config (`fetchers/_categories/paramify.yaml`) — one value per
  workspace, set once under `platforms.paramify.config` instead of copied onto
  every target.
- Each VER report's `_summary` now carries a `collection` block (status + the
  API-failure ledger). `/issues` is the only call these fetchers make, so a
  failure yields empty report arrays; without this a failed report was
  indistinguishable from a genuinely clean one to anything reading the payload.
- The uploader prefers a target's `program_name` over its opaque id when titling
  an artifact. Fetchers whose id is already readable are unaffected.
- **Every timestamp in a VER report is now emitted in one format** — UTC, second
  precision, literal `Z` (`2026-07-30T09:00:00Z`). Values from the Paramify API
  (`detectedAt`, `evaluationCompletedAt`, the `dueDate` quoted in an overdue
  explanation) were previously passed through with the API's millisecond
  precision, so a single document mixed notations; they are normalized on the way
  in, and non-UTC offsets are converted rather than preserved. A `report_from` /
  `report_to` given as a bare date is expanded, with a date-only end reported as
  that day's last second (`2026-06-30` → `2026-06-30T23:59:59Z`) to match the
  window actually collected.
- **`paramify doctor` preflights the manifest, not just the environment.** It now
  runs the same validation `paramify validate` does, so it cannot pass a manifest
  the runner will refuse: a misspelled `use:`, a missing required config key, a
  `supports_targets` fetcher with no `targets[]`, or a declared secret the
  manifest never mapped. Scanning env-var references could not see any of those —
  a secret that was never mapped leaves nothing to scan, so it read as a clean
  bill of health and failed at run time. A manifest that cannot be parsed is now
  reported as a finding rather than raising a YAML traceback out of the CLI, and a
  valid one says so out loud, since silence on validity reads as "not checked".
- **Doctor checks secret *values*, not just that the variable exists.** A
  whitespace-only value counts as missing: it reads as set to a presence check and
  then fails at the API, with the variable visibly present so nothing looks wrong.
  Values shaped like copy-paste artifacts — surrounding quotes, a trailing newline
  from `$(cat file)`, a `*_URL` / `*_URI` / `*_ENDPOINT` with no scheme — are
  reported as warnings that never affect the exit code, because a legitimate value
  can look odd and a preflight that cries wolf stops being read.
- **The Paramify API token and base URL resolve in one place**
  (`framework/paramify_auth.py`), which both uploaders and doctor read, so the
  answer to "which token, which workspace" cannot differ between the preflight and
  the upload. The destination is labelled production / stage / self-hosted and
  shown as loudly as the token: pointing at stage when you meant production does
  not error, the upload just succeeds into the wrong workspace.

### Fixed

- **KnowBe4**: the three group- and campaign-scoped fetchers no longer report an
  unresolved config as a failing control. The group and campaign titles they match
  on were hardcoded to one tenant, so pointed anywhere else they emitted
  `completion_rate: 0` and exited 0 — byte-identical to a tenant where the campaign
  resolved and genuinely nobody had trained. Two very different states, one output,
  and no assertion could tell them apart. The names now come from `config_schema`
  (`high_risk_groups`, `role_specific_campaigns`, `developer_groups`,
  `developer_campaigns`, `security_awareness_campaigns`, plus
  `retraining_interval_days`), and a name that matches nothing in the tenant is
  **not** a fetcher failure — one typo must not turn a whole nightly run red. The
  fetcher exits 0 and reports every metric it could not measure as `null`, never
  `0`, alongside a `results.config_resolution` block naming what was requested,
  what matched, and what the tenant actually has. `null` means "not measured"; `0`
  still means "measured, and it is zero", so a genuine 0% remains a real finding.
  A config key that is never wired at all is caught pre-flight by
  `paramify validate`, since these are `required`.
- **KnowBe4**: names are matched exactly rather than as substrings. A group
  configured as `IT` previously also swept in `AUDIT` and `Legal-IT`, inflating the
  high-risk population.
- **KnowBe4**: config values reach `jq` as data (`--args` / `$ARGS.positional`)
  instead of being spliced into the filter text. A campaign title containing a
  quote or backslash produced a jq compile error before; making the titles
  customer-supplied would have turned that into a routine failure.
- **KnowBe4**: all four fetchers assemble their evidence in one `jq` pass. Each
  record was previously appended by re-running `jq` over the growing output file,
  which was quadratic — 1500 enrollments took 69s and 3000 took over 120s, so a
  mid-size tenant blew the runner's 600s cap. 3000 enrollments now completes in
  about 3s. `training_module_summary` for an empty tenant is `{}` rather than
  `null`.
- **KnowBe4**: a response that is not a JSON array (an error body returned with
  HTTP 200) is recorded as a failure instead of being treated as a page. Pagination
  previously looped forever on such a body, bounded only by the runner's timeout.
  Pagination also stops at a 1000-page cap, and `printf '%s'` replaces `echo` on
  every API response so a backslash in a title survives a non-bash shell.
- **TUI**: pressing the number of the tab you are already on no longer clears
  focus. Assigning `TabbedContent.active` the value it already holds fires no
  `TabActivated`, so nothing re-homed focus after it was cleared — and because a
  page's bindings only resolve while focus is inside that page, every page
  shortcut (`a`/`e`/`x`, `ctrl+r`, `j`/`k`, the arrows) silently went dead until
  you pressed escape or a different tab.
- **TUI**: `ctrl+p` on the Paramify tab runs Preview instead of opening Textual's
  command palette, which claims that key as a *priority* binding — checked ahead
  of the focused widget, so the page's own binding could never fire. `p` now does
  it too, mirroring the Manifest tab's preview key.
- **TUI**: `enter` does what the footer promises on the two tables where it did
  nothing at all — on a run it drills into that run's evidence files (where enter
  opens one), and on a manifest row it opens the entry editor.
- **TUI**: editing the manifest's output dir no longer loses the path. Textual
  selects an `Input`'s value on focus, so the first keystroke replaced the whole
  path; and an edit never submitted with `enter` was silently reverted by the next
  rebuild. Focus no longer selects the value, and leaving the field commits it.
- **TUI**: `enter` in a confirmation dialog now means No. Yes is composed first,
  so it took the default focus — on the dialogs that delete a manifest file,
  remove an entry, and upload to Paramify. `y` still confirms.
- **TUI**: config set at the category level showed as unset on every entry that
  inherited it — the manifest screen read only the entry's own `config` block and
  had no notion of `platforms.<category>.config`. Both the detail pane and the
  summary count now render `api.effective_config()`, the same merge the runner
  performs, and show which layer each value came from.
- **Paramify VER fetchers**: a pending or rejected `RISK_ADJUSTMENT` no longer
  reports `finalDisposition: "Partially Mitigated"` — mitigation now requires an
  accepted deviation, not an unapproved request.
- An issue carrying neither `poamId` nor `id` no longer raises `KeyError` and
  kills the whole report.
- `PARAMIFY_HTTP_TIMEOUT` is parsed at call time and falls back to the default on
  a malformed value, instead of aborting the run with a bare `ValueError` at
  import.
- A timestamped `report_to` no longer over-includes up to a day beyond the
  declared reporting period.
- `PARAMIFY_REPORT_TO` is now declared, so it can actually be set through a
  manifest (the runner passes only declared env vars).

## [0.3.1-beta] - 2026-07-28

### Changed

- Run manifests are no longer gitignored, and the repo no longer tracks a file at
  `./manifest.yaml`. The manifest that used to sit there ships as
  `example_manifest.yaml` instead. Manifests describe which evidence you collect,
  so teams under a compliance program generally want them in version control —
  they hold no secret values, since `${env:VAR}` resolves from the environment at
  run time. Previously `/manifest.yaml` and `/manifests/` were listed in
  `.gitignore` *and* a `manifest.yaml` was tracked; because ignore rules don't
  apply to already-tracked files, that entry had no effect and edits to the
  shipped manifest were staged by default, conflicting on every upgrade.
  **If you were relying on the tracked `manifest.yaml`,** copy
  `example_manifest.yaml` to `manifest.yaml`, or pass `--manifest` explicitly.
  `paramify manifest init` and the `manifests/` picker convention are unchanged.

### Added

- [`docs/private_mirror_workflow.md`](docs/private_mirror_workflow.md) — keeping a
  private copy of this repo that still receives upstream releases, for teams whose
  fetcher work can't be public.

## [0.3.0-beta] - 2026-07-23

### Added

- 13 Datadog fetchers (new category): Cloud SIEM detection rules & signals, SIEM
  operational configuration, log pipelines / indexes / archives, host & container
  inventory, agent check results, the APM service catalog, and incident records with
  timelines. Credential setup in [`fetchers/datadog/README.md`](fetchers/datadog/README.md).
- `paramify scripts sync` — push each fetcher's entry script (`fetcher.py` /
  `fetcher.sh`) to Paramify and CONNECT it to that fetcher's evidence set, so the
  tenant records *how* each piece of evidence is generated. A provisioning step
  separate from `paramify upload`: it reconciles the tenant to the repo GitOps-style
  (marker-keyed identity in the script description, `fetcher.yaml` `version` as the
  update signal, a sha256 drift guard). **Scoped to a manifest by default** — it
  provisions scripts only for the fetchers you collect, mirroring how `upload` is
  run-scoped — with `--all` to push the whole catalog, plus `--dry-run` / `--force` /
  `--reassociate` / `--json`. Backed by the `uploaders/paramify_scripts/` uploader.
  Only `SCRIPT` associations are automated; control / solution-capability / validator
  linkage stays Paramify-side.
- [`docs/uploader_design.md`](docs/uploader_design.md) — a dedicated uploader design
  doc covering both built uploaders and the shared evidence-set identity model, and
  a README section + docs-table entries pointing to it.

### Changed

- **TUI Paramify tab redesigned** into stacked *evidence upload* and *scripts sync*
  panels. Scripts sync gained a **Preview** action that runs a read-only dry-run and
  surfaces the per-fetcher plan (create / update / drift / noop) in a table — flagging
  which drifted scripts `--force` would push — and syncs the active manifest's fetchers.

### Fixed

- TUI: page keyboard shortcuts (`ctrl+r` / `ctrl+u` / `ctrl+s`) now fire regardless of
  which control is focused, and default focus lands in the active pane on mount, on tab
  switches (mouse clicks included), and after `escape` — previously they worked only
  right after a number-key tab switch.
- TUI: the *Add fetchers* picker no longer drops a category once all its fetchers are in
  the manifest; already-added fetchers show greyed-out and non-selectable, so a
  fully-added category (e.g. `datadog`) stays visible.
- TUI: the Paramify action row (Preview / Sync Scripts / force / reassociate) now uses
  uniform control sizes instead of content-sized widths and mismatched heights.

## [0.2.1-beta] - 2026-07-10

### Changed

- The `deploy/` bundle is now **Docker-only** (Dockerfile + compose + cron) — a
  smaller, less prescriptive deployment footprint for public use.

### Removed

- The Kubernetes deployment manifests and the multi-account hub-and-spoke
  Terraform (`deploy/k8s/`). The Kubernetes *fetchers* (`fetchers/k8s/`) are
  unaffected.

### Fixed

- The containerized deploy no longer defaults evidence uploads to Paramify
  staging; it uses production (`app.paramify.com`), matching the uploader's own
  default.

## [0.2.0-beta] - 2026-07-10

First public release — a beta / pre-release. Pre-1.0, so the contract may still
change before 1.0 (see [`docs/versioning.md`](docs/versioning.md)).

### Added

- Fetcher framework: the `paramify` CLI (list · catalog · describe · manifests ·
  validate · run · runs · evidence · upload · manifest builder) plus the
  `paramify tui` front-end, both talking only to `framework.api`.
- `paramify doctor` — a preflight that checks the Python version, the external
  CLIs each category needs on `PATH`, and (given a manifest) whether its secret
  env vars are set.
- 108 fetchers across 8 categories (aws 79, okta 8, sentinelone 5, knowbe4 4,
  gitlab 3, k8s 3, rippling 3, checkov 2). The AWS category collects where
  deployed via the ambient credential chain, with optional per-target
  profile/region fanout.
- Evidence envelope (`{schema_version, metadata, payload}`, `schema_version`
  `1.0`) wrapped around every fetcher output by the runner.
- Paramify evidence uploader (`uploaders/paramify_evidence/`).
- A containerized deployment bundle (`deploy/`) — a Docker image + compose that
  runs the collector on a schedule and uploads, with secrets injected at run time
  (environment or AWS Secrets Manager).
- A credential-free demo (`demo_hello` fetcher + `examples/demo.yaml`) that emits
  synthetic evidence, so the whole collect → envelope pipeline runs with no cloud
  account.
- KSI metadata: an optional `ksis` array on `fetcher.yaml`, mappings populated
  for 89 fetchers, and `paramify ksi` — a FedRAMP 20x KSI coverage view over
  `api.ksi_coverage()`.
- Optional `validators` metadata on `fetcher.yaml` (regex checks over the
  evidence payload).
- Versioning & contract policy ([`docs/versioning.md`](docs/versioning.md)), this
  changelog, and the manual release runbook
  ([`docs/releasing.md`](docs/releasing.md)).

### Changed

- Licensed under GPL-3.0-only.
- Documentation rewritten for public consumption; the README leads with the TUI,
  then the AI-agent path, then the CLI.
- TUI restyled — border titles, status pills, denser controls, and hatched empty
  states.

[Unreleased]: https://github.com/paramify/paramify-fetchers/compare/v0.3.1-beta...HEAD
[0.3.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.3.0-beta...v0.3.1-beta
[0.3.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.2.1-beta...v0.3.0-beta
[0.2.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.2.0-beta...v0.2.1-beta
[0.2.0-beta]: https://github.com/paramify/paramify-fetchers/releases/tag/v0.2.0-beta
