---
name: author-validators
description: >
  Author the full validator set for one fetcher that has produced real evidence
  — one completeness check plus a configuration check per property the evidence
  asserts — then prove each one in a sandbox by matching real evidence AND
  failing a mutated non-compliant copy. Writes contract-shaped YAML plus the
  reasoning to .onboarding/<tool>/validators/; never touches the repo. Use after
  a real-tenant run, or as the last beat of onboard-tool's per-fetcher loop.
---

# Author Validators

The final beat of the build loop. `suggest-validator` answers "give me a regex
for this evidence" and prints it. This skill produces the **set** for a fetcher,
proves each member can fail, and files it as a durable draft.

**Golden rules**
- **A validator that has never failed is not a validator.** Every regex here is
  proven twice: it matches the real evidence, and it returns **zero** matches
  against a mutated copy representing the non-compliant state. Untested regexes
  are the whole failure mode this skill exists to prevent.
- **One fetcher = one evidence set, and validators are 1-to-many**: exactly one
  **completeness** check plus **N configuration** checks. Never one validator
  per fetcher, and never a one-to-one-to-one picture of
  fetcher→evidence→validator.
- **Nothing is written into the repo.** Not `fetcher.yaml`, not `docs/`. Output
  goes to `.onboarding/<tool>/validators/`, which is gitignored. The contract
  *has* a `validators:` block and `fetchers/gitlab/significant_change_notifications`
  uses it — that is a pre-existing exception, not an invitation.
- **The regex runs over the file on disk** — the whole envelope
  (`schema_version` + `metadata` + `payload`), because that is what Paramify's
  validator sees. So avoid anchoring on envelope keys (`status`, `category`,
  `fetcher_name`, `fetcher_version`, `run_id`, `target`, `collected_at`,
  `exit_code`, `error`, `evidence_set`, `schema_version`) unless you also pin a
  payload-specific value.
- **Anchor on key + value pattern**, never on byte position or whitespace:
  `"key"\s*:\s*<value>`. Key order and indentation vary between runs.
- **Every validator ships three lines**: what it asserts, what it does **not**
  assert, and when it correctly fails.

---

## Phase 0 — Get the real evidence

1. Read the fetcher's `fetchers/<category>/<short_name>/fetcher.yaml` — you need
   `description`, `ksis`, and `evidence_set` to know what the evidence is
   *supposed* to prove.
2. Find the newest successful evidence:
   ```bash
   paramify evidence <fetcher_name>     # normalizes the envelope
   ls -t evidence/run-*/<fetcher_name>*.json | head -3
   ```
3. **Refuse to author from a hollow payload.** A fake-cred smoke test, an empty
   tenant, or an unseeded sandbox yields empty lists and zeroed counts, and a
   regex written against those matches the always-present zeros. If every list
   is empty and every measurement is 0, stop: route back to `seed-fixtures` (the
   fixture didn't land) or ask for a populated run.

   Beware the masking case: static descriptive fields — a control name, a `ksi`
   string, a `related_controls` list — make a payload *look* populated while
   every measured value is empty. The authoritative check is per-field, in
   Phase 3.

---

## Phase 1 — The completeness check (exactly one)

Completeness asks: **did the fetcher collect the whole thing it claims to
cover?** Not "is the posture good" — that is Phase 2. It is the check that
catches a truncated run, a pagination bug, a permission that silently returned a
partial list.

Pick, in order of strength:
- A count the payload itself asserts is total (`"total_count"`, `"scanned": N`)
  — strongest, especially paired with a zero-failure counter
  (`"schema_invalid_count":\s*0`, the gitlab SCN pattern).
- A non-empty collection of the key entity, when the fetcher's only claim is
  "here is the inventory".
- A per-target presence marker, for a fanout fetcher where each file covers one
  target.

If the fetcher enumerates and the payload carries no way to tell a complete
enumeration from a truncated one, **say so** — that is a finding about the
fetcher, worth reporting back, not something to paper over with a weaker regex.

---

## Phase 2 — The configuration checks (one per asserted property)

One check per security property the evidence actually asserts. Read the
fetcher's `description` and `ksis` and enumerate the properties: encryption at
rest, log retention, MFA enforcement, key rotation, public exposure. Each gets
its own validator, because each fails independently and a reviewer needs to know
*which* one failed.

Strength ladder, and say which rung you're on:
1. **A rollup metric quantifying posture** — a rate, percentage, or ratio.
   Strongest: a non-zero value means the control is *working*, not merely
   configured.
2. **A status/enum pinned to the compliant value** — `"enabled":\s*true`,
   `"status"\s*:\s*"Passed"`.
3. **A zero-failure counter** — `"<thing>_incomplete_count":\s*0`. Strong when
   the fetcher does its own per-item judging.
4. **Presence of a non-empty list** — weakest, and the most
   formatting-sensitive (`"key"\s*:\s*\[\s*\{`). Proves "we found some", says
   nothing about coverage. Fallback only.

Regex building blocks:

| Need | Pattern |
|---|---|
| Non-zero percent/count (1–100) | `(?:100\|[1-9][0-9]?)` |
| Any positive integer | `[1-9][0-9]*` |
| Threshold ≥90 | `(?:100\|9[0-9])` |
| Exactly zero failures | `0` (pin the key: `"failed_count"\s*:\s*0`) |
| Compliant boolean | `true` |
| Non-empty array of objects | `\[\s*\{` |

Whitespace-tolerant (`\s*`) throughout, standard PCRE/Python `re`. Tell the user
to confirm the flavor against Paramify's engine.

---

## Phase 3 — Prove each one in the sandbox (both directions)

Work in the session scratchpad, never in `evidence/`. Positive match on the real file,
then negative match on a mutated copy — a regex that survives both is the only
kind worth handing over.

```bash
SB="<your session scratchpad>/validators-<fetcher_name>"; mkdir -p "$SB"
SB="$SB" .venv/bin/python - <<'EOF'
import json, re, os, pathlib
SB   = pathlib.Path(os.environ["SB"])
REAL = "<path to the real evidence file>"
text = pathlib.Path(REAL).read_text()

# Each entry: (id, regex, how to break the evidence so it SHOULD stop matching).
# The mutation puts the payload into the NON-compliant state.
CHECKS = [
    ("<id>", r'"partial_failure"\s*:\s*false',
     lambda p: p["metadata"].update({"partial_failure": True})),        # completeness
    ("<id>", r'"custom_mode_percentage"\s*:\s*(?:100|[1-9][0-9]?)',
     lambda p: p["summary"].update({"custom_mode_percentage": 0})),     # configuration
]

for vid, rx, break_it in CHECKS:
    pos  = len(re.findall(rx, text))
    # Control: re-serialized but UNMUTATED. Separates "the mutation killed the
    # match" from "re-serialization killed it". Normally identical, because
    # framework/envelope.py writes json.dumps(..., indent=2) — but a
    # hand-written or compactly-serialized file would read as a false PASS.
    ctrl = len(re.findall(rx, json.dumps(json.loads(text), indent=2)))
    doc = json.loads(text)
    payload = doc.get("payload", doc)
    try:
        break_it(payload)
    except Exception as e:
        print(f"{vid:30s} MUTATION FAILED: {e}"); continue
    neg_text = json.dumps(doc, indent=2)
    (SB / f"{vid}.negative.json").write_text(neg_text)   # keep the counter-example
    neg = len(re.findall(rx, neg_text))
    verdict = ("PASS" if pos > 0 and ctrl > 0 and neg == 0
               else "FORMAT-DEPENDENT" if pos > 0 and ctrl == 0
               else "REJECT")
    print(f"{vid:30s} real={pos:<4} ctrl={ctrl:<4} mutated={neg:<4} {verdict}")
EOF
```

Worked output from a real gcp VPC evidence file. The third row is a deliberately
bad regex anchored on the **envelope** — the harness catches it because no
mutation of the payload can affect it:

```
vpc_collection_complete        real=1    ctrl=1    mutated=0    PASS
vpc_custom_mode_present        real=1    ctrl=1    mutated=0    PASS
bad_anchor_on_envelope         real=1    ctrl=1    mutated=1    REJECT
```

Read the verdicts:
- **`real=0`** on a `success` run → the evidence is empty *for this metric*,
  whatever Phase 0 suggested. Back to Phase 0.
- **`mutated>0`** → the regex is matching something other than what you think —
  usually an envelope key, a substring in a sibling field, or a value that
  survives the mutation. Rewrite it; do not ship it with a caveat.
- **`MUTATION FAILED`** → your mental model of the payload shape is wrong. Fix
  the mutation, and re-check the regex against the real shape.
- **`FORMAT-DEPENDENT`** → it matched the raw file but not an equivalent
  re-serialization, so it is keyed on formatting rather than on evidence. Add
  `\s*`, or anchor on the key instead of the surrounding punctuation.

A `REJECT` never gets handed over. Rewrite, or drop the check and say why.

---

## Phase 4 — File the output

Two files under `.onboarding/<tool>/validators/`:

**`<fetcher_name>.yaml`** — contract-shaped, so it drops into a `validators:`
block or a future `paramify verify` unchanged:

```yaml
# Draft validators for <fetcher_name>. NOT installed in the repo.
# Proven against: evidence/run-<ts>/<fetcher_name>.json
fetcher: <fetcher_name>
validators:
  - id: <snake_case_id>
    kind: completeness            # our annotation; not in the contract schema
    regex: '"scanned_count"\s*:\s*[1-9][0-9]*'
    proves: >
      One sentence, in the voice of the gitlab SCN block: what a passing match
      demonstrates about the control being implemented.
    failure_modes:
      - Concrete, named cause — not "the regex doesn't match"
      - Another one
```

**`<fetcher_name>.md`** — the reasoning the YAML can't hold: the evidence file
it was authored from, the payload fields considered and rejected, each
validator's *asserts / does not assert / fails when*, the sandbox proof table
(`real=` / `mutated=`), the strength rung, and any finding about the fetcher
itself (e.g. no way to detect a truncated enumeration).

---

## Phase 5 — Hand back

State plainly: N validators (1 completeness + N-1 configuration), each proven in
both directions against one real sample; they live under `.onboarding/` only;
nothing in the repo runs them today (`framework/verify/` is empty), so they are
drafts for Paramify. One sample is one sample — recommend confirming against a
second run before anyone leans on them.

---

## Anti-patterns

- Handing over a regex that was never shown to fail.
- One validator for the whole fetcher, or a validator per KSI instead of per
  asserted property.
- Authoring from a smoke-test or unseeded payload (Phase 0 exists to stop this).
- Anchoring on `"status"` or another envelope key without pinning a payload
  value — it matches the wrapper, not the evidence.
- Byte offsets, exact whitespace, or pretty-print-dependent slices.
- `failure_modes` written as regex mechanics rather than real-world causes.
- Writing into `fetcher.yaml`, `docs/`, or anywhere else tracked by git.
- Mutating a file under `evidence/` instead of a scratchpad copy.
- `grep -P` for the proof — unavailable on macOS BSD grep; use Python `re`.
