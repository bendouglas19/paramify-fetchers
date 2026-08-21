---
name: seed-fixtures
description: >
  Generate a seeder and teardown that create sandbox resources so a slate of
  fetchers produces non-trivial evidence — via the tool's CLI, a Terraform
  provider, or SaaS API calls. Use when a fetcher runs clean but returns an
  empty payload, or before building fetchers for a tool with no test data. Gates
  every write on the sandbox registry; generates teardown before seed; never
  executes either on its own.
---

# Seed Fixtures

A fetcher that returns `[]` exits 0 and proves nothing. This skill builds the
fixture that gives it something true to say — and, more importantly, something a
validator can *fail* on.

**Golden rules**
- **Contrast is the point, not coverage.** One of everything is a useless
  fixture. Most platforms are secure by default — GCP encrypts disks, buckets,
  Cloud SQL and BigQuery at rest with no configuration, so `encrypted: true`
  proves nothing. Create resources in **pairs**: one CMEK-encrypted and one
  provider-managed, one with flow logs and one without, one policy-bound proxy
  and one running the permissive default. **The contrast is what the validator
  keys on.**
- **Teardown is written before seed, always.** Not after, not "next". Nothing
  gets created until the thing that destroys it exists and has been shown to
  the user. `tools/gcp-test-project/teardown.sh` is the reference, including the
  honesty about what *cannot* be undone.
- **The registry gates every write.** A target that is not in
  `.onboarding/sandboxes.yaml` gets no seeder run against it. Refuse and ask —
  do not "confirm verbally" and proceed.
- **Generate; do not execute.** You hand back a command. The user runs it. This
  holds for `terraform apply`, for a SaaS `POST`, and for a one-line `create`
  that looks harmless.
- **Prefix everything, create only.** Every resource name starts with the
  configured prefix (default `paramify`). Never modify or delete an object the
  seeder did not create — that is how a "sandbox" turns into an incident.
- **Idempotent by construction.** Re-running the seeder must not abort on the
  first resource that already exists. Best-effort each create, count failures,
  report at the end.

---

## Phase 0 — The sandbox registry (do this before anything else)

```bash
cat .onboarding/sandboxes.yaml 2>/dev/null || echo "NO REGISTRY"
```

No registry → create it, and get the user to declare this target explicitly:

```yaml
# .onboarding/sandboxes.yaml — approved seed targets. Gitignored.
# A target absent from this file is NEVER seeded. Being a "test" account by
# name is not membership; someone has to have put it here on purpose.
sandboxes:
  - tool: gcp
    kind: project
    id: <project-id>
    prefix: paramify
    approved_by: <user>
    approved: <YYYY-MM-DD>
    notes: throwaway; safe to delete entirely
    destructive_ok: true         # may this target be torn down wholesale?
```

Then check the intended target against it and say which line matched. For a
**SaaS tenant** the bar is higher, because there is no project to delete
afterward — the registry entry must name the prefix that scopes teardown, and
say plainly whether real people use this tenant. If they do, the seeder creates
only objects nobody else consumes (a suspended test user, an unassigned group)
and says so in its header.

---

## Phase 1 — Pick the mechanism

From `research.md`'s "fixture surface", in this order of preference:

| Mechanism | When | Output |
|---|---|---|
| **CLI script** | The tool ships a first-class CLI (`gcloud`, `az`, `aws`, `kubectl`) | `seed/seed.sh` + `seed/teardown.sh` |
| **Terraform** | A real provider exists and the resources are declarative infra | `seed/terraform/main.tf` (+ `.tfvars.example`) |
| **SaaS API** | No CLI, no provider — resources are users, groups, policies, campaigns | `seed/seed.py` + `seed/teardown.py` |
| **Nothing** | The evidence is inherently pre-existing (audit logs, org roster, billing) | say so, write no seeder |

Terraform notes: `.gitignore` already ignores `.terraform/` and `*.tfstate` and
commits `.terraform.lock.hcl`, so the direction is pre-sanctioned — but state
lives under `.onboarding/`, which is gitignored wholesale. Say where state
lives, because a lost state file means an un-destroyable fixture. Prefer
Terraform only when destroy-by-state is genuinely cleaner than a teardown
script; a seeder that must also create *deliberately weak* resources is often
clearer in a CLI script.

**The fourth mechanism is real and often correct.** Do not invent fixtures for
a tool whose evidence already exists.

---

## Phase 2 — Design the fixture set from the slate

Work fetcher by fetcher through the approved slate. For each, answer: *what
would make this fetcher's evidence interesting, and what would make a validator
fail?* Then write down the pair.

- **Name the fetcher in a comment above every resource block.** The gcp seeder
  does this (`# gcp_kms_key_configuration. Two locations so the fetcher's
  locations.list enumeration has more than one hit…`) and it is what lets the
  next person delete a resource without breaking a fetcher they've never read.
- **Cost tiers.** `--tier1` cheap (pennies/day: keys, buckets, rules, groups),
  `--tier2` billable (managed databases, clusters, licensed seats), `--all`.
  Put the cost in the script header. A fixture nobody tears down is a recurring
  bill, and the tier flag is what lets the user opt into that knowingly.
- **Deliberately-weak resources, made unreachable.** Some fetchers exist to
  surface a misconfiguration, so the fixture must contain one. Make it inert:
  the gcp seeder's `0.0.0.0/0` SSH rule targets a network tag no instance
  carries, and its permissive TLS proxy has no forwarding rule. Anything that
  would be *genuinely* exposed (a public dataset ACL, a database authorized from
  `0.0.0.0/0`) goes behind `--include-exposed`, **off by default**.
- **Dependency order**, and the lazy-init trap: managed-service encryption often
  fails with an opaque permission error until the service's own identity exists.
  Create identities and grants before the resources that need them.

---

## Phase 3 — Write the scripts

Mirror `tools/gcp-test-project/seed.sh`. The parts that matter:

```bash
set -euo pipefail                    # seed: strict
# teardown uses `set -uo pipefail` — deliberately NO -e, so cleanup continues
# past resources that are already gone.

try() {   # best-effort create: count failures, never abort the run
  local what="$1"; shift
  if "$@" >"$WORK/err" 2>&1; then echo "  ok    $what"
  # Every API words "already there" differently — 409, "Already Exists",
  # "alreadyExists", "you already own it". Missing a variant makes a clean
  # re-run look like a failed one. Capture BOTH streams: some CLIs report
  # errors on stdout.
  elif tr '\n' ' ' <"$WORK/err" | grep -qiE 'already exists|alreadyExists|already own it|duplicate|409'; then
    echo "  exists $what"
  else echo "  FAIL  $what"; FAILED+=("$what"); fi
}
```

Plus: a required `--<target>` arg with no default (never let it fall through to
an ambient default project/tenant), `PREFIX` configurable, a `mktemp -d` work
dir with a cleanup trap, and a failure summary at the end.

**For a SaaS seeder** (`seed.py`), the same doctrine in Python:
- Read the token from an env var; never accept it as an argument.
- Assert the target tenant matches the registry entry before the first write —
  in code, not in a comment.
- Create-only, prefix-scoped, idempotent (treat 409/"exists" as success).
- Teardown enumerates by prefix and deletes only exact prefix matches.
- Respect the rate limits `research.md` recorded; back off rather than hammer.

**Write the teardown first**, and be honest in its header about what it cannot
undo — GCP key rings have no delete verb, soft-deleted roles block re-seeding
for 7 days, some SaaS users can only be deactivated. Naming those limits is
what makes teardown trustworthy.

---

## Phase 4 — Hand back, don't run

1. Show the file tree, the tier flags, and the **cost line**.
2. Show the exact seed command and the exact teardown command, together.
3. Confirm the target matched a registry line, by id.
4. Ask. If the user runs it, record in `plan.md` that fixtures are live, with
   the timestamp and the teardown command — that record is the only thing
   standing between a fixture and a forgotten bill.
5. After a seed run, the honest check is per-fetcher: re-run the fetcher and
   look at the payload. `paramify run` exiting 0 does not mean the fixture
   landed.

---

## Anti-patterns

- One of everything, all secure-by-default → evidence no validator can fail on.
- Seeding first, writing teardown "after it works".
- Running the seeder yourself, or running `terraform apply` because the plan
  looked clean.
- Seeding a target that is not in the registry, or a production tenant because
  it was described as "our test one".
- `set -e` in teardown (aborts on the first already-deleted resource).
- Catching only stderr when the CLI reports failures on stdout, or matching one
  spelling of "already exists" — both make a clean re-run look broken.
- Creating a genuinely internet-reachable weak resource without
  `--include-exposed`.
- A resource with no comment naming the fetcher it feeds.
- Inventing fixtures for evidence that already exists.
