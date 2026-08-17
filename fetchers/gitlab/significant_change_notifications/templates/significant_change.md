<!--
Paramify change-request MR template — FedRAMP Significant Change Notification.

Install as .gitlab/merge_request_templates/Change Request.md.

This is a change-request template with three SCN-specific additions, each marked
[ADDED] below. The fetcher parses the template WITHOUT them — it falls back to
borrowing from "Requested Changes" and "Impact and Security Analysis" and notes
that it did — so adopting them is a tidiness decision, not a blocker.

How the parser reads this file:
  * The SCN section is the "## FedRAMP Significant Change Notification (SCN)"
    heading through the "---" rule. Anything after that rule is ignored.
  * Inside it, each field is identified by its backticked schema key —
    *(`changeTypeExplanation`)* — NOT by its human label. Rename the labels
    freely; keep the backticked keys exactly as they are.
  * Unfilled placeholders (`YYYY-MM-DD`, `KSI-XXX-XX`, `N/A`) are dropped and
    reported rather than emitted. A blank field costs you a note; a field
    containing "YYYY-MM-DD" would cost you a rejected notification.
-->

# Change Request
- [ ] Emergency Change (add Justification to Summary below)

### Scope
- [ ] Application Release (Helm), ticket: [ABC-??](https://example.atlassian.net/browse/ABC-??)
- [ ] Deployed Software (Helm)
- [ ] Infrastructure (Terraform)
- [ ] Other (manual changes)

### Impact
- [ ] C1: High Impact/Risk, may cause Production downtime
- [ ] C2: Med Impact/Risk, may cause Production slowness, or Staging downtime
- [ ] C3: Low Impact/Risk, may require complex manual changes
- [ ] C4: No Impact/Risk, common changes or fully automated

## Requested Changes *(`changeDescription`)*
<!-- [ADDED] the *(`changeDescription`)* annotation. changeDescription is
     REQUIRED by FedRAMP and the SCN block has no slot for it, so the fetcher
     reads this section instead. With the annotation that is explicit and the
     heading can be renamed freely; without it the fetcher falls back to
     matching the words "Requested Changes" and notes that it guessed.

     Per FedRAMP these are different fields: changeDescription is WHAT changed,
     `reason` below is WHY. Keep this section describing the change itself. -->

### Impact and Security Analysis *(`impactAnalysis`)*
<!-- [ADDED] the *(`impactAnalysis`)* annotation, same reasoning. Note this is
     the analysis section up here, not the **Impact Analysis** grouping label in
     the SCN block below — that one just introduces **Customer Impact** and has
     no body of its own. -->

## FedRAMP Significant Change Notification (SCN)
- [ ] [Routine Recurring](https://www.fedramp.gov/2026/providers/20x/rules/significant-change-notification/#routine-recurring-changes) — SCN not required
- [ ] Significant Change — SCN required (expand section below)

<!-- Tick exactly one. Ticking Routine Recurring is itself a recorded decision:
     the fetcher logs it as an explicit SCN-RTR declaration rather than as a
     form someone skipped. -->

** SCN Details** — expand if Significant Change is checked above
Fields marked **\[REQUIRED\]** map to required FedRAMP schema properties.

**Change Type** *(`changeType`)* **\[REQUIRED\]**
- [ ] Adaptive
- [ ] Transformative

[Adaptive](https://www.fedramp.gov/2026/providers/20x/rules/significant-change-notification/#adaptive-changes) changes typically require careful planning that focuses on engineering execution instead of customer adoption, can be verified with minor changes to existing automated validation procedures, and do not require large changes to operational procedures, deployment plans, or documentation.

Transformative changes typically introduce major features or capabilities that may change how a customer uses the service (in whole or in part) and require extensive updates to security assessments, operational procedures, deployment plans, and documentation.

**Approver** *(not in the FedRAMP schema)*
**Approver:**
**Approver Title:**
<!-- [ADDED]. SCN-CSO-INF requires an approver name and title, but the FedRAMP
     JSON schema v0.1.2 has no property for either. The fetcher carries these
     beside the notification rather than inside it, so the SCN object stays a
     verbatim submittable document. -->

**Categorization Explanation** *(`changeTypeExplanation`)*

**Reason for Change** *(`reason`)*

**Related Vulnerability** *(`relatedVulnerability`)*
N/A

**Assessor Name** *(`assessorName`)*
N/A

**Impact Analysis**
**Customer Impact** *(`customerImpact`)*

**Impacted Controls** **Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)* (List KSI or control identifiers that will be verified, assessed, or validated as part of this change. One per line.)

- KSI-XXX-XX
- AC-X
- SI-X

**Plan and Timeline** **Summary** *(`planAndTimeline.summary`)* **\[REQUIRED within planAndTimeline\]** (Plan and timeline summary, including verification/assessment/validation approach for impacted KSIs or controls)

<!-- Write this one even if the dates are still unknown. It is required whenever
     ANY part of the plan block is filled in, so milestones with no summary
     produce an invalid notification. -->

**Planned Start** *(`planAndTimeline.plannedStart`)*
Date: `YYYY-MM-DD`

**Planned Completion** *(`planAndTimeline.plannedCompletion`)*
Date: `YYYY-MM-DD`

**Milestones** *(`planAndTimeline.milestones[]`)*
- `YYYY-MM-DD` | Proof of Concept
- `YYYY-MM-DD` | Decision and Procurement
- `YYYY-MM-DD` | Setup and Onboarding
- `YYYY-MM-DD` | Fully functional

**Certification Package** **Certification Package Overview URI** *(`certificationPackageOverviewUri`)* **\[REQUIRED\]** `https://trust.example.com/artifacts/<your-certification-package-overview>.json`

<!-- Replace the placeholder with YOUR Certification Package Overview URI, then
     leave it alone — it is constant for every SCN and is not meant to be edited
     per merge request. It is also configured on the fetcher as
     FEDRAMP_CERT_PACKAGE_URI; when the two differ, this line wins. -->

---

### Schedule

Date/Time of Change: MM/DD/YYYY @ HH:MM

*Note: If client impact is expected then a maintenance window should be created on your status page.*

### Deployment Steps, Rollback Plan (if applicable)

(Provide code snippets or screenshots as needed)

## Results (after completion)

- [ ] Change was completed successfully
- [ ] Change was NOT completed successfully but will be rescheduled
- [ ] Change was NOT completed successfully and will be canceled

(Results of applying changes in the system)

/assign me
