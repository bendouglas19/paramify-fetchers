# framework/reference

Vendored copies of external sources of truth. Nothing here is ours to author —
each file is transcribed or downloaded from an upstream authority, and the point
of committing it is that the version we built against is pinned and diffable.

The bar for landing a file here is that **code reads it**. An upstream document
we only consult by eye gets cited by URL and version instead — see the note at
the bottom on the Paramify API spec, which is the case that tested this rule.

| File | Upstream | Read by |
|---|---|---|
| `ksis.yaml` | [FedRAMP consolidated rules](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) | `api.ksi_coverage()`, `tools/gen_ksi_*.py` |

`ksis.yaml` carries its own header explaining how to re-transcribe it and which
of its fields are FedRAMP's versus our judgment. Read that before touching it.

## What is deliberately *not* here: the Paramify REST API spec

The uploaders were written against **Paramify REST API v0, spec version 0.6.0**.
Read it at <https://app.paramify.com/api/documentation/> — in the app, Help (?) →
API Documentation. The machine-readable OpenAPI 3.1 document behind that page is
`https://app.paramify.com/api/v0/documentation.json`.

That spec used to be vendored here and was removed on purpose. Please don't
re-add it:

- **Nothing loads it.** It was human reference only, so the repo paid for it
  without any code depending on it.
- **It is 2.4 MB / ~54,000 lines pretty-printed** — roughly a fifth of the
  tracked repo, and the convention that made it readable (a new file per
  version, never overwritten) meant paying that again on every version bump.
- **It is public.** Unlike `ksis.yaml`, it needs no login to read, so committing
  it bought no access we didn't already have.

What actually needed pinning was the *version*, and a version is one line. Cite
it as "Paramify REST API v0 spec 0.6.0" plus the URL above, the way
[`uploaders/paramify_issues/`](../../uploaders/paramify_issues/) does, and bump
that string when the behavior is rewritten against a newer spec.

If you need to review what changed between two versions, diff the live document
against a saved copy in a scratch directory — outside the repo:

```bash
curl -sSfL https://app.paramify.com/api/v0/documentation.json \
  | python3 -m json.tool > /tmp/paramify_api_new.json
diff /tmp/paramify_api_old.json /tmp/paramify_api_new.json
```
