# Design notes

Why this fetcher is shaped the way it is. The [README](README.md) covers how to
run it; this covers the decisions behind it, including the ones that are still
open.

---

## 1. Why a merge request is the right source

FedRAMP requires a notification when a system undergoes a significant change.
The information the rule asks for — what changed, why, the customer impact, the
controls affected, the plan and timeline — is information the engineering team
already writes down when it proposes the change. Asking them to write it a second
time in a different system produces two records that disagree.

So the merge request is the source of record, and this fetcher is a translator:
it reads what engineers already wrote and emits the JSON FedRAMP wants.

**What cannot be automated:** whether a change is significant at all, and whether
it is Adaptive or Transformative. Neither is inferable from a diff — a one-line
configuration change can alter the risk profile while a ten-thousand-line
refactor does not. That judgment stays with a human, expressed as a ticked
checkbox and a change-type selection. Everything downstream of that decision is
mechanical, and this fetcher does the mechanical part.

---

## 2. Binding to schema keys, not headings

The naive parser looks for `### Reason for Change`. It breaks the day someone
renames the heading to `### Why`, and it breaks *silently* — no error, just an
empty field in a compliance artifact.

So the template annotates each field with its schema key:

```markdown
**Categorization Explanation** *(`changeTypeExplanation`)*
```

and the parser binds to the backticked key. Human-facing labels can be reworded,
translated, or reordered without touching code. A heading- and `**Key:** value`
based fallback handles templates that carry no annotations, so a team can adopt
the fetcher before adopting the template.

---

## 3. Placeholders are dropped, never emitted

Templates ship with `YYYY-MM-DD`, `KSI-XXX-XX`, `N/A`. Some fraction of them
always survives into a real merge request.

Emitting `"plannedStart": "YYYY-MM-DD"` produces a schema violation whose error
message — *"does not match format date"* — tells the reader nothing about the
actual problem, which is that nobody filled the field in. So placeholders are
recognized, dropped, and reported in `parse_notes`:

```
planAndTimeline.plannedStart: no date filled in (still the YYYY-MM-DD placeholder)
```

A milestone whose date is still a placeholder keeps its description and loses
only the date — "we plan to run a proof of concept" is real information even when
the date is not.

---

## 4. Schema validity is not completeness

**This is the most important design decision here.**

FedRAMP's SCN schema requires exactly three properties:
`certificationPackageOverviewUri`, `changeType`, `changeDescription`. The rule
behind it, SCN-CSO-INF, asks for around a dozen — impacted controls, planned
dates, customer impact, business or security impact analysis, approver name and
title.

Everything in that second list is *optional* to the validator. A notification can
therefore validate perfectly while saying nothing about which controls the change
touches, when it happens, or who approved it. It passes automation and fails
review, which is the worst possible ordering: it looks finished right up until a
human reads it.

So there are two independent gates:

| Gate | Question | Knob |
|---|---|---|
| Schema validation | Is this document well-formed? | `GITLAB_SCN_STRICT` |
| SCN-CSO-INF completeness | Does it say anything worth reading? | `GITLAB_SCN_REQUIRE_COMPLETE` |

Kept separate on purpose: "the template is broken" and "someone didn't finish
filling it in" are different problems, fixed by different people, and
`metadata.error` should say which one happened.

The two items SCN-CSO-INF marks *"if applicable"* — `assessorName`,
`relatedVulnerability` — are excluded from the completeness check. Their absence
is a legitimate answer, and demanding them would only train people to type "N/A"
to silence a checker.

---

## 5. One evidence file, many notifications

N flagged merge requests produce N notifications, but the fetcher writes **one**
file.

That is forced by the framework rather than chosen: the runner discovers evidence
by diffing `EVIDENCE_DIR` and wraps every `.json` it finds in the standard
envelope. Writing one file per notification would envelope each one, and an
enveloped SCN is no longer a valid FedRAMP document — the exact artifact the
fetcher exists to produce.

So the array lives inside a single payload, and every `notifications[].scn` is
schema-valid standing alone. Whatever submits them can lift each one out verbatim
with no unwrapping.

Two consequences:

- **Re-emission.** A weekly run with a 30-day window re-emits the same merge
  request four times. Each run is a new artifact — correct, that is the audit
  trail — but a submitter must dedupe. Every notification carries a stable
  `merge_request.notification_id` for that purpose.
- **One MR is not necessarily one change.** See below.

---

## 6. Open questions

**One merge request ≠ one change.** A large change may span many merge requests
across several repositories. Today that produces one notification per merge
request. The likely fix is a grouping key in the template — an SCN identifier
that the fetcher merges on — but it changes the template, and templates are
expensive to change once a team is using one. Worth deciding before rollout
rather than after.

**Transformative timing.** Adaptive changes are notified after completion, which
a scheduled scan over merged merge requests satisfies comfortably. Transformative
changes require notification well *before* work begins, which a post-merge scan
structurally cannot produce. Running a second target with `state: opened` catches
the plan while the merge request is still open; see
[`examples/gitlab_scn.yaml`](../../../examples/gitlab_scn.yaml). Changes planned
before any merge request exists need a different source entirely.

**Emergency changes.** SCN-CSO-EMG defines a separate path. The template's
emergency checkbox is captured, counted, and raised as a parse note on any
notification carrying it, but the distinct notification path is not implemented.

**Approver identity.** SCN-CSO-INF requires an approver name and title; the
FedRAMP JSON schema v0.1.2 has no property for either. They are carried in
`notifications[].approver`, beside the notification rather than inside it, so the
`scn` object stays a verbatim submittable document. Worth revisiting if a later
schema adds the field.

---

## 7. Where this fits

A scheduled run produces evidence and notifications after the fact. It does not,
and should not, gate a merge.

The natural complement is a CI job on merge-request events that runs the same
parse-and-validate logic against the description and fails when the SCN section
is incomplete — catching problems while the author is still present to fix them.
That job needs no credentials and writes nothing. This fetcher then produces the
durable evidence on a schedule.

The two are complements: the CI job makes the data good, the fetcher makes the
evidence.
