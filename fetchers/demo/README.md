# Demo

Five synthetic fetchers that need **no credentials, no cloud account and no
network**. They exist so the whole pipeline — collect → envelope → inspect →
upload — can be watched before a single real service is wired up, and so the
shapes you will meet with real fetchers are all reachable on a laptop with
nothing configured.

Every payload is hand-written and fixed. A demo whose evidence changed between
runs would teach the wrong thing about the pipeline, and the values are obviously
fake on purpose: each payload carries
`"note": "Synthetic evidence — not collected from any real system."`

| Fetcher | Mode | Shows |
|---|---|---|
| `demo_hello` | single | the simplest case: one invocation, one file, no secrets and no targets |
| `demo_vuln_scan` | single | a run with something to watch — four stages with a configurable pause (`stage_delay_ms`, default 450ms; set 0 to make it instant) |
| `demo_encryption_at_rest` | fanout | one invocation per account, one evidence file each |
| `demo_audit_logging` | fanout | an **isolated, explained failure** — see below |
| `demo_access_review` | single | a required secret and an optional one, so `paramify doctor` has something honest to report |

## The run ends partial on purpose

`demo_audit_logging` reads three regions per account, and for `demo-sandbox` one
of them is deliberately unreadable. That target:

- writes the evidence it *did* collect, with `results.collection.status:
  "partial"` and the failed region in `results.collection.api_failures` — so a
  reader of the payload alone cannot mistake it for a complete result;
- exits non-zero, so nothing counts an incomplete report as a clean one;
- reports **why** through `$FETCHER_STATUS_FILE`, which puts
  `metadata.error: "1 of 3 regions unreadable for demo-sandbox — …"` and
  `metadata.error_code: "not_authorized"` in that file's envelope, rather than
  leaving the runner to scrape the tail of stderr.

The other two accounts collect normally. That is what fanout isolation means, and
a demo where everything is green would never show it.

`demo-sandbox` also has a region where audit logging is genuinely **off**. That is
a *finding*, not a failure — the fetcher looked and reports `enabled: false`. The
two are not the same thing and the payload keeps them apart: "we could not look"
lives in `collection.api_failures`, "we looked, and it is off" lives in the region
row.

## Running it

`manifests/demo.yaml` is the one manifest the repo ships and wires all five:

```bash
paramify doctor manifests/demo.yaml     # → ❌ DEMO_API_TOKEN missing
export DEMO_API_TOKEN=demo              # any value; it is never sent anywhere
paramify run manifests/demo.yaml        # 9 invocations, 8 ok, 1 failed
paramify evidence evidence/run-*/demo_audit_logging_demo-sandbox.json
```

`DEMO_API_TOKEN` is only checked for being non-empty; it is never written into the
evidence and never leaves the process. `DEMO_SERVICE_ACCOUNT_KEY` is the optional
one — omit it and `demo_access_review` records that it fell back to the ambient
path, which is exactly how the aws, azure, gcp and k8s categories behave when a
role or workload identity supplies the credentials instead of a static key.

## Env vars

| Var | Purpose | Declared in |
|-----|---------|-------------|
| `DEMO_ACCOUNT` | which synthetic account to report on (fanout) | `target_schema.account` |
| `DEMO_API_TOKEN` | required credential for `demo_access_review`; any non-empty value | `secrets` |
| `DEMO_SERVICE_ACCOUNT_KEY` | optional credential; omitted means the ambient path | `secrets` (`required: false`) |
| `DEMO_STAGE_DELAY_MS` | pause between `demo_vuln_scan`'s stages | `config_schema.stage_delay_ms` |
| `EVIDENCE_DIR` | output directory (runner-set) | runner |
| `FETCHER_STATUS_FILE` | where a failing fetcher writes its reason (runner-set) | runner |

## Two other things this category is for

- **The README demos.** Everything in `docs/demo/*.gif` is recorded against this
  program, which is what makes those recordings reproducible by anyone. See
  [`docs/demo/README.md`](../../docs/demo/README.md).
- **CI.** `tests/test_demo_program.py` runs the shipped manifest end to end. It is
  the only category that can be executed in CI, because it reaches no network and
  needs no account, and it pins the promises above — including that exactly one
  invocation fails and that it explains itself.

Safe to delete once you have seen it work; nothing else depends on it.
