---
name: research-tool
description: >
  Research a third-party tool before building fetchers for it — find its API
  docs, CLI, Terraform provider, auth model, pagination and rate limits, and
  turn that into a capability inventory of everything that could become
  evidence. Use when the user names a tool the catalog has never integrated, or
  asks "what could we pull out of X". Writes research.md + capabilities.yaml
  under .onboarding/<tool>/; builds nothing.
---

# Research a Tool

Phase 1 of `onboard-tool`, usable on its own. The job is to replace guesses with
cited facts, then enumerate what the tool could evidence. **A fetcher built on a
hallucinated endpoint fails at the smoke test and costs an hour to diagnose** —
this skill exists to make that impossible.

**Golden rules**
- **Cite or mark.** Every factual claim carries the URL it came from, or the
  literal marker `UNVERIFIED`. No exceptions, including things you are confident
  about — model confidence about a REST path is not evidence.
- **A live call beats a doc page.** If the user has credentials, confirm the
  shape of the response with one real request. Docs drift; deprecated v1 paths
  outlive their pages.
- **Research the *auth* model hardest.** It is the single biggest determinant of
  the fetcher's shape (static token secret vs. ambient credential chain vs.
  OAuth client-credentials vs. signed request), and the thing docs describe
  worst.
- **Stop at the inventory.** No `fetcher.yaml`, no code, no slate decisions —
  those are the orchestrator's Phase 2 gate with the user.

---

## Phase 0 — Check what's already known

The catalog may already answer half of this:

```bash
paramify list | grep -i <tool>                    # existing fetchers?
ls fetchers/_categories/ | grep -i <tool>         # existing category contract?
grep -ril <tool> docs/ fetchers/_categories/ | head
```

An existing `fetchers/_categories/<tool>.yaml` already records the auth model,
required binaries and pip packages — read it and treat it as verified fact.

---

## Phase 1 — Find the primary sources

Use `WebSearch` to locate, then `WebFetch` to actually read. Searching alone
does not count as reading; fetch the page before citing it.

Hunt for, in this order of usefulness:

1. **REST/GraphQL API reference** — the versioned one, not the marketing
   overview. Note the base URL and the API version explicitly.
2. **An OpenAPI/Swagger spec** — the jackpot. A machine-readable spec gives you
   exact paths, params, and response schemas with no interpretation. Search
   `<tool> openapi.json`, `<tool> swagger spec`, and the docs site's
   `/openapi.json`.
3. **A first-class CLI** — name, install method, whether it emits JSON
   (`--output json`, `-o json`, `--format json`). A CLI with JSON output means
   a **bash** fetcher; no CLI means **python**.
4. **A Terraform provider** — registry page and resource names. This decides
   whether `seed-fixtures` can use Terraform for fixtures.
5. **An official SDK** — Python especially; note the pip distribution name, and
   whether it handles pagination for you.
6. **Auth docs** — token type, scopes/permissions needed for *read*, how the
   token is presented (`Authorization: Bearer`, `SSWS`, an API-key header, a
   signed request), and expiry/refresh behavior.
7. **Rate limits and pagination** — the numbers, the headers, the cursor style
   (page/offset, cursor token, `Link` header). This shapes the fetcher's loop
   and its `runtime.timeout`.

If the docs are behind a login the user must supply what they see. Ask rather
than guessing from a cached memory of the product.

---

## Phase 2 — Verify against the live tool (when creds exist)

Ask whether the user has a token/tenant you may probe read-only. If yes, confirm
the three things that break fetchers most:

```bash
# 1. Does auth work the way the docs say?  (never echo the token itself)
curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: <scheme> $TOKEN" '<base>/<cheap endpoint>'

# 2. What does one real response actually look like? (keys, nesting, casing)
curl -sS -H "Authorization: <scheme> $TOKEN" '<base>/<endpoint>?limit=1' | head -c 2000

# 3. Where does pagination live — body cursor, or a header?
curl -sSD - -o /dev/null -H "Authorization: <scheme> $TOKEN" '<base>/<endpoint>?limit=1' | grep -i 'link\|rate\|x-'
```

Route probe output through the scratchpad, never into the repo. Redact ids and
names in what you report back; you are recording *shape*, not data.

Anything you could not confirm stays `UNVERIFIED` in the write-up. That marker
is what tells the build loop which fetcher is likely to fail first.

---

## Phase 3 — Build the capability inventory

Enumerate broadly first, judge second — a capability you never listed can't be
picked later. For each capability record: the exact call, what it yields, the
security property it demonstrates, and **the field a validator would key on**.

Then map to KSIs from the live reference, not from memory:

```bash
paramify ksi --json                      # current coverage + gap indicators
grep -n 'id:\|statement:' framework/reference/ksis.yaml | head -60
```

Two judgment calls to make explicitly:

- **Is it evidence, or just liveness?** "The API returned 200 and a version
  string" proves nothing about a control. Mark `reject`.
- **Is it evidenceable at all?** `framework/reference/ksis.yaml` distinguishes
  technical state (a fetcher can show it) from organizational claims
  (policy, training, executive support — evidenced by HR/process tools or
  manual attestation). A capability that only supports an organizational
  indicator is usually still worth listing, flagged as such.

Write `capabilities.yaml` from `onboard-tool/templates/capabilities.yaml`,
leaving `slate:` empty — the user fills that at the Phase 2 gate.

---

## Phase 4 — Write it up and hand back

`.onboarding/<tool>/research.md`, in this order:

1. **Verdict line** — runtime (bash+CLI or python+SDK/REST) and auth model, one
   sentence each, because everything downstream keys on those two.
2. **Sources** — every URL fetched, with what it established.
3. **Auth** — scheme, header, scopes needed for read-only, expiry, and which
   env var names the fetcher should read.
4. **Endpoints/commands table** — call, purpose, pagination, rate limit.
5. **Fixture surface** — can resources be created (CLI / Terraform provider /
   API POST), or is the data inherently pre-existing? `seed-fixtures` reads this.
6. **Fanout axis** — is there a natural per-target unit (project, tenant,
   region, org)? Name it, or say single-tenant.
7. **UNVERIFIED list** — collected in one place, not scattered.
8. **Open questions for the user.**

Hand back: the verdict line, the capability count by verdict, the top KSI gaps
this tool could close, and the UNVERIFIED list. Then stop — the slate is the
user's call.

---

## Anti-patterns

- Reciting an API from model memory. If it wasn't fetched or called, it's
  `UNVERIFIED` — write the marker even when you're sure.
- `WebSearch` results treated as read documentation. Fetch the page.
- Researching only the happy path and skipping rate limits and pagination —
  those are what make a fetcher time out on a real tenant, not on yours.
- Probing with write calls, or probing a production tenant the user didn't
  offer.
- Printing a token, or pasting real tenant data into `research.md`.
- Proposing the slate or picking the winners here. Inventory now, decide at the
  gate.
- Skipping capabilities because they look unpromising — list them with
  `verdict: reject` and a reason, so the next session doesn't re-litigate.
