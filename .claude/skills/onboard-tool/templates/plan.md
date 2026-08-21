# Onboarding: <TOOL>

Started: <YYYY-MM-DD>   ·   Category slug: `<tool>`   ·   Manifest: `manifests/<tool>.yaml`

> Loop state lives here. Every phase updates this file before moving on.
> Gitignored — never committed.

## Phases

- [ ] **1. Research** → `research.md`
- [ ] **2. Slate approved** → `capabilities.yaml`  (approved by user on <date>)
- [ ] **3. Fixtures provisioned** → `seed/`
      - Sandbox: `<tenant/account id from sandboxes.yaml>`
      - Seeded at: `<timestamp, or "not seeded — nothing to provision">`
      - Teardown command: `<command>`
      - **LIVE RESOURCES: yes / no**  ← if yes, this is costing money
- [ ] **4. Per-fetcher loop** (table below)
- [ ] **5. Wrap-up** — KSI delta reported, mapping doc regenerated, teardown offered

## Fetchers

Status: `todo` → `built` → `wired` → `evidence` → `validated` · or `blocked`

| # | fetcher | KSI(s) | fanout | status | attempts | notes / blocked reason |
|---|---------|--------|--------|--------|----------|------------------------|
| 1 | `<category>_<short_name>` | KSI-XXX-YYY | single | todo | 0 | |

## Decisions made

- <date> — <decision and why> (mirror durable ones into the decision log)

## Open questions for the user

- <question>

## Unverified research carried forward

- <claim from research.md that could not be confirmed against a live call>
