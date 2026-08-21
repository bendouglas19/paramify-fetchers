---
name: onboard-tool
description: >
  Onboard a whole tool into the fetcher catalog: research its API/CLI, agree a
  slate of fetchers, provision sandbox fixtures once, then loop each fetcher
  through build → run → real evidence → validators. Use when the user names a
  tool rather than a single fetcher ("build fetchers for Snyk", "onboard Jamf",
  "what could we pull out of Cloudflare"). Owns durable plan state under
  .onboarding/<tool>/ so the loop survives compaction and multiple sessions.
---

# Onboard a Tool

The orchestrator for the semi-automated fetcher build loop. It runs one tool
from "we have nothing" to "N fetchers producing real evidence, each with tested
validators", and it keeps its own state on disk so it can be stopped and resumed.

```
Phase 1  research ─────────────► .onboarding/<tool>/research.md
Phase 2  slate  ── GATE ───────► capabilities.yaml   (KSI-scored, user approves)
Phase 3  provision ── GATE ────► seed/  + one seed run for the whole slate
Phase 4  per fetcher, in order:
           create-fetcher → wire-manifest → run → real evidence?
             ├─ no  → diagnose, retry (max 3) → else park as blocked, next fetcher
             └─ yes → author-validators → mark done in plan.md
Phase 5  wrap: KSI delta, teardown, what's left
```

**Golden rules**
- **The plan file is the loop.** Every phase writes its result to
  `.onboarding/<tool>/` before moving on. If you cannot say which step the plan
  is on, re-read `plan.md` — never re-derive from conversation memory.
- **This skill delegates, it does not reimplement.** Building a fetcher is
  `create-fetcher`; wiring is `wire-manifest`; validators are
  `author-validators`; research is `research-tool`; fixtures are
  `seed-fixtures`. Invoke them with the `Skill` tool. If you find yourself
  writing a `fetcher.yaml` here, you skipped a delegation.
- **Nothing under `.onboarding/` is committed** — it is gitignored on purpose.
  It holds sandbox tenant ids, research notes, and validator drafts.
  Validators live here, **not** in `fetcher.yaml`. Do not add a `validators:`
  block to a fetcher (the contract has one and `fetchers/gitlab/significant_change_notifications`
  uses it, but that is a pre-existing exception, not the pattern).
- **Three gates are hard stops:** the slate, the provisioning plan, and every
  single execution of a seeder. Never spend money or write to a live tenant on
  your own initiative.
- **Bail out, don't spin.** Three failed attempts at one fetcher → write the
  reason under `blocked:` in `plan.md` and move to the next. A loop that retries
  the same 401 forever is worse than a parked fetcher with a diagnosis.

---

## State layout

```
.onboarding/
  sandboxes.yaml               # standing registry of approved sandbox tenants
  <tool>/
    plan.md                    # phase checklist + per-fetcher status. THE loop state.
    research.md                # Phase 1 output (docs URLs, auth, pagination, limits)
    capabilities.yaml          # Phase 2 output: capability inventory → KSI-scored slate
    seed/                      # Phase 3 output: seed + teardown (+ terraform/)
    validators/<fetcher>.yaml  # Phase 4 output: contract-shaped validators
    validators/<fetcher>.md    # Phase 4 output: the reasoning behind each
```

Templates for `plan.md` and `capabilities.yaml` are in this skill's
`templates/` directory — copy, don't reinvent the headings, because Phase 0
reads them back.

---

## Phase 0 — Resume or start

1. Normalize the tool name to the `<category>` slug you'd use in
   `fetchers/<category>/` (lowercase, underscores).

2. **Resume check — do this first, always:**
   ```bash
   ls .onboarding/<tool>/ 2>/dev/null && sed -n '1,80p' .onboarding/<tool>/plan.md
   ```
   - Plan exists → read it, state plainly which phase and which fetcher it is
     on, and resume there. Do not re-run a completed phase.
   - Nothing → new onboarding. Create the dir, copy in the plan template, and
     make sure `/.onboarding/` is in `.gitignore` before writing anything else.

3. **Existing-category check** — the tool may already be partly onboarded:
   ```bash
   paramify list | grep -i <tool>
   ```
   Fetchers already exist → this is an *extension*, not a greenfield onboarding.
   Say so, and seed the slate with what's already there so Phase 2 proposes
   additions rather than duplicates.

---

## Phase 1 — Research

Invoke the `research-tool` skill. It writes `research.md` and returns the
capability inventory. Do not proceed on unverified claims: anything the
researcher marked `UNVERIFIED` is a candidate for a failed fetcher later, so
carry the marker forward into the slate.

---

## Phase 2 — The slate (GATE)

1. **Score against real current coverage**, not from memory:
   ```bash
   paramify ksi --json    # covered vs gap indicators, live from the catalog
   ```
2. Turn the capability inventory into candidate fetchers in
   `capabilities.yaml`. For each candidate: the API/CLI calls, the evidence it
   yields, `ksis:` it speaks to, single vs fanout, and a one-line "what a
   validator would key on". **If you cannot name what a validator would key on,
   the candidate is not evidence** — drop it or mark it `weak`.
3. Apply the catalog's rules while shaping candidates:
   - One fetcher = one evidence set. Two unrelated payloads = two fetchers.
   - A candidate that proves only "the tool is installed and answering" is not
     evidence.
   - Prefer a candidate that closes a KSI gap over one that piles onto a
     covered indicator — but say so rather than silently reordering.
4. **GATE.** Present the slate as a table — candidate, evidence, KSI, gap or
   already-covered, fanout, weak/verified — and ask the user to cut, add, and
   set the build order. Write the approved order into `plan.md`. Do not start
   Phase 3 without this.

---

## Phase 3 — Provision fixtures, once, for the whole slate (GATE)

The whole slate is provisioned in one pass so there is one seed run and one
cost. Invoke the `seed-fixtures` skill with the approved slate; it owns the
sandbox registry check, the contrast doctrine, and teardown-before-seed.

It hands back a seed command. **You do not run it.** Show it, show the tier's
cost note, and ask. If the user runs it themselves, record in `plan.md` that
fixtures are live and when — a live fixture that nobody tears down is a
recurring bill.

Some tools have nothing to provision (read-only APIs over data that already
exists — audit logs, a training roster, an org's user list). Say that plainly
and skip to Phase 4 rather than inventing fixtures.

---

## Phase 4 — The per-fetcher loop

For each fetcher in the approved order, one at a time:

1. `Skill: create-fetcher` — it runs its own interview and fake-cred smoke test.
   Feed it the slate row so it doesn't re-interview what Phase 2 settled:
   name, runtime, auth model, fanout, evidence-set id, and the exact calls.
2. `Skill: wire-manifest` — into the tool's manifest under `manifests/`.
3. **Run it against the sandbox** and read the result, don't assume it:
   ```bash
   paramify run manifests/<tool>.yaml --json
   paramify evidence <fetcher_name>          # newest evidence, normalized
   ```
4. **Judge the evidence, not the exit code.** Three outcomes:
   - **Real, populated evidence** → step 5.
   - **Exit 0, empty payload** → the fetcher works, the *fixture* doesn't.
     Back to `seed-fixtures` for that resource, not into the fetcher code.
     This is the most common failure and the easiest to misdiagnose.
   - **Non-zero exit** → read `metadata.error` in the envelope first; it is
     where the fetcher is supposed to have said why. Fix, re-run. Attempt 3
     failing → park it: write `blocked: <reason>` in `plan.md`, tell the user,
     move to the next fetcher.
5. `Skill: author-validators` — writes `validators/<fetcher>.yaml` + `.md`.
6. **Mark it done in `plan.md`** before starting the next fetcher. This is what
   makes the loop resumable; skipping it is how a compaction costs you a rebuild.

---

## Phase 5 — Wrap up

1. **Coverage delta** — `paramify ksi` again; report which indicators the new
   fetchers moved, and regenerate the mapping doc if any `ksis:` were added:
   ```bash
   python tools/gen_ksi_mapping.py    # docs/ksi_mapping.md is generated, not hand-edited
   ```
2. **Teardown.** If fixtures are live, hand back the teardown command and say
   what it will destroy. Ask; don't run it.
3. **Report the truth:** fetchers done, fetchers parked and why, validators
   drafted, what is still `UNVERIFIED` from Phase 1, and the fact that
   validators live only under `.onboarding/` — they are not in the repo and
   nothing runs them yet.

---

## Anti-patterns

- Re-researching or re-interviewing something `plan.md` already records.
- Writing `fetcher.yaml`, seed scripts, or validators inline here instead of
  delegating to the skill that owns them.
- Running a seeder, a `terraform apply`, or a SaaS write without the user's
  explicit go-ahead for that specific command.
- Treating exit 0 as success. An empty payload exits 0 and proves nothing.
- Committing `.onboarding/`, or "helpfully" promoting validators into
  `fetcher.yaml`.
- Building all the fetchers first and testing at the end — the loop is
  per-fetcher precisely so a broken assumption surfaces on fetcher one.
- Retrying a failing fetcher indefinitely instead of parking it with a reason.
