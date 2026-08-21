---
name: suggest-validator
description: >
  Suggest ONE ad-hoc regex validator for a fetcher's evidence, printed not
  filed. Use after a fetcher has been run against a real tenant and produced a
  populated evidence file — reads
  that file, finds the field that proves the control is being implemented, and
  proposes a regex (with an explanation and its failure modes) the user can use
  as-is or refine into their own validator. Triggers on "suggest a validator",
  "regex validator", "validate this evidence", "what regex proves this control".
  Read-only: it writes nothing at all. For the full proven set for a fetcher
  (completeness + configuration checks, each proven to fail, filed as a draft),
  use `author-validators` instead.
---

# Suggest a Validator

This skill is the third beat in the fetcher lifecycle, after `create-fetcher`
(build) and `wire-manifest` (run): once a fetcher has produced **real** evidence,
it proposes a regex that asserts the evidence actually proves what it's supposed
to. The output is a suggestion for the user — a starting point for the validator
they'll attach in Paramify, not an artifact this repo stores or executes.

**Which validator skill?** This one for a single quick regex, printed to the
terminal, writing nothing anywhere. `author-validators` for the whole set for
one fetcher — one completeness check plus a configuration check per asserted
property, each proven to fail against a mutated copy, filed under
`.onboarding/<tool>/validators/`. The onboarding loop uses that one.

**Golden rules**
- **Read-only.** This skill writes nothing — no files, no schema edits, no
  manifest changes. Its entire job is: read one evidence file → propose a regex
  → show it matching. The user takes the regex from here.
- **It needs real, populated evidence.** A fake-cred smoke-test run (what
  `create-fetcher` produces) yields an empty payload — empty lists, zeroed
  counts. You cannot author a meaningful "proves the control" regex from that.
  If the newest evidence looks empty, say so and stop (Phase 1).
- **Anchor on the key name plus a value pattern**, never on byte position or
  whitespace. `"completion_rate":\s*(?:100|[1-9][0-9])`, not a brittle slice of
  pretty-printed JSON. Key ordering and indentation vary between runs.
- **Every suggestion ships with three lines: what it asserts, what it does NOT
  assert, and when it (correctly) fails.** A regex without its failure mode is a
  false sense of coverage.
- **The regex runs over the evidence JSON file as written to disk** — i.e. the
  envelope (`schema_version`+`metadata`+`payload`), since that's the file
  Paramify's validator sees. So avoid anchor keys that collide with envelope
  metadata (`fetcher_name`, `fetcher_version`, `category`, `run_id`, `target`,
  `collected_at`, `status`, `exit_code`, `error`, `evidence_set`,
  `schema_version`) unless you pin a payload-specific value too.

---

## Phase 0 — Locate the fetcher and its newest real evidence

1. **Which fetcher?** The one the user just tested, or a name they give.
   `paramify list` shows discovered fetchers if
   unsure. Read its `fetchers/<category>/<short_name>/fetcher.yaml` — you need its
   `evidence_set` and `description` in Phase 2.

2. **Find the newest successful evidence file.** Evidence lands under
   `evidence/run-<timestamp>/<fetcher_name>*.json` (fanout fetchers write one
   file per target: `<fetcher_name>_<target>.json`). Run dir names sort
   chronologically, so newest = last:
   ```bash
   .venv/bin/python - <<'PY'
   import json, glob
   FETCHER = "<fetcher_name>"            # e.g. knowbe4_module_based_summary
   for path in sorted(glob.glob(f"evidence/run-*/{FETCHER}*.json"), reverse=True):
       meta = json.load(open(path)).get("metadata", {})
       print(f'{meta.get("status","?"):8s} {path}')
   PY
   ```
   Pick the newest with `status: success`. For a fanout fetcher, pick one
   representative file (the largest is usually the most populated) and note the
   sibling target files share its shape.

3. **No evidence at all?** If nothing matches, the fetcher hasn't been run yet.
   Stop and route the user to run it first (`wire-manifest` → `paramify run`),
   against a **real tenant** — this skill has nothing to read without that.

---

## Phase 1 — Confirm the evidence is real (not empty / not a smoke test)

Before reading for content, sanity-check the payload isn't hollow. Scan it: if
every list is empty and every numeric summary value is `0`, it's almost
certainly a smoke-test or empty-tenant run.

```bash
.venv/bin/python - <<'PY'
import json
d = json.load(open("<path>"))
p = d.get("payload", d)
def signal(o):
    if isinstance(o, dict):  return any(signal(v) for v in o.values())
    if isinstance(o, list):  return len(o) > 0 and any(signal(x) for x in o)
    if isinstance(o, (int, float)): return o != 0
    if isinstance(o, str):   return bool(o.strip())
    return False
print("HAS DATA" if signal(p) else "LOOKS EMPTY — stop and ask the user to re-run against a populated tenant")
PY
```

- **LOOKS EMPTY:** stop. Tell the user the regex would be guesswork without real
  data, and that they should run once against a tenant that actually has the
  thing being measured (users with MFA, completed trainings, encrypted buckets).
- **HAS DATA:** continue — but treat this as triage, not proof. This check is
  coarse: **static descriptive fields can mask empty measurements.** A payload
  that carries a control name, a `ksi` string, or a `related_controls` list will
  read as HAS DATA even if every *measured* value (the MFA percentages, the
  enabled-counts) is empty or zero. (The okta smoke-test payloads in this repo do
  exactly this.) So the authoritative emptiness check is field-specific and
  happens once you've picked the critical field (Phase 2) and run the match
  (Phase 4): if your chosen metric matches **0 times** on a `success` run, the
  evidence is empty *for that metric* — loop back here and ask for a populated
  run.
- A genuinely-zero tenant is possible and valid — if the user confirms the zeros
  are real, you can still propose a presence regex, but say plainly it can't
  assert a non-zero posture.

---

## Phase 2 — Identify the critical field

The "critical field" is the one whose presence (and value) demonstrates the
control is **being implemented** — not just that the fetcher ran. Let the
evidence's *intent* guide the pick:

1. **What is this evidence supposed to prove?** Read `fetcher.yaml`'s
   `description` and `evidence_set.name`/`.instructions`. Many fetchers name their
   KSI directly in the description (e.g. `KSI-IAM-APM`, `KSI-CMT-VTD`); some
   payloads even carry `ksi`/`related_controls` inline (the okta ones do). That
   intent tells you which number matters.

2. **Pick the anchor, preferring the strongest signal available:**
   - **(a) A rollup metric that quantifies posture** — a rate, percentage, or
     count. Strongest, because a non-zero value means the control is working, not
     merely configured. *Examples in this repo:*
     `payload.results.summary.training_module_summary.<module>.completion_rate`
     (knowbe4); `payload.summary.phishing_resistant_mfa_percentage` (okta).
   - **(b) A status/enum whose value denotes compliance** — `"status":"Passed"`,
     `"enabled":true`, `"StorageEncrypted":true`. Good when there's no rollup.
   - **(c) Presence of a non-empty list of the key entity** — weakest; proves
     "we found some" but says nothing about coverage. Use only as a fallback.

3. **Avoid trivially-true and colliding anchors.** Skip keys that are present in
   every run regardless of posture, and skip envelope-metadata keys (see the
   golden rule) unless you pin a payload-specific value. Note that `"status"`
   appears in *both* envelope metadata (`"success"`) and some payloads
   (`"Passed"`) — anchoring on the key+value disambiguates.

If two fields are equally defensible, present both and let the user choose —
don't agonize.

---

## Phase 3 — Build the regex(es)

Construct a **presence** regex (matches the upstream "verify the critical field
exists" model) and, when a value carries meaning, a stronger **value/threshold**
variant. Rules:

- Anchor on the key: `"<key>"\s*:\s*<value-pattern>`.
- Be whitespace-tolerant (`\s*`) so pretty- vs compact-printing both match.
- Non-zero count/percent (1–100): `(?:100|[1-9][0-9]?)`. Any positive int:
  `[1-9][0-9]*`. High-only (≥90): `(?:100|9[0-9])`.
- Boolean/enum: `true`, or `"Passed"` — pin the *compliant* value.
- Non-empty array of objects: `"<key>"\s*:\s*\[\s*\{` (note in the explanation
  that this one is the most formatting-sensitive).
- Use standard PCRE / Python-`re` syntax (`\s`, `(?:…)`, classes). Tell the user
  to confirm the flavor matches Paramify's validator engine.

**Worked example (knowbe4 — the populated file in this repo):**

> Presence: `"completion_rate"\s*:\s*(?:100|[1-9][0-9])`
> - **Asserts:** a `completion_rate` of 10–100 exists — real, non-zero training
>   completion data was returned.
> - **Does NOT assert:** a coverage threshold across all modules; just that one
>   meaningful rate is present.
> - **Fails when:** the payload is empty, all rates are single-digit, or the
>   field is absent — exactly the "evidence doesn't prove the control" case.
>
> Stronger: `"completion_rate"\s*:\s*(?:100|9[0-9])` requires ≥90%.
> Alternative anchor: `"status"\s*:\s*"Passed"` proves ≥1 passing completion
> (simpler, weaker — silent on coverage).

Tailor the same pattern to the fetcher in front of you.

---

## Phase 4 — Show it matching, then hand it over

1. **Prove the regex hits the real file** (portable, no `grep -P` — BSD grep on
   macOS lacks it):
   ```bash
   .venv/bin/python - <<'PY'
   import re
   t = open("<path>").read()
   rx = r'<your regex>'
   m = re.findall(rx, t)
   print(f"{len(m)} match(es):", m[:5])
   PY
   ```
   A non-zero match count on real evidence = the suggestion works. If it matches
   **0 times on a `success` run**, the evidence is empty for this metric (Phase 1
   triage missed it because static fields masked the emptiness) — go back to
   Phase 1 and ask the user for a populated run. Optionally demonstrate the
   failure mode by showing the regex returns 0 against an empty smoke-test file of
   the same fetcher (if one exists) — that's what makes it a validator and not
   just a field-finder.

2. **Hand over the regex, the explanation, and the boundary.** State plainly:
   this is a *suggested* validator derived from one evidence sample — use it
   as-is or as a starting point, and confirm it against more runs and against
   Paramify's regex engine. The repo neither stores nor enforces it.

---

## Anti-patterns

- Authoring a regex from an empty/smoke-test payload (Phase 1 exists to stop
  this) — it'll match nothing real or, worse, match the always-present zeros.
- Anchoring on byte offsets or exact whitespace instead of `"key"\s*:\s*value`.
- Handing over a regex without its failure mode — a validator that can't fail
  proves nothing.
- Anchoring on an envelope-metadata key (`status`, `category`, `name`, …) without
  pinning a payload value, so it matches the wrapper instead of the evidence.
- Writing anything to disk or to `fetcher.yaml`. This skill only reads and
  suggests; the validator's home is Paramify, decided by the user.
- Demonstrating the match with `grep -P` (unavailable on macOS) — use Python
  `re` so the shown match is real and portable.
