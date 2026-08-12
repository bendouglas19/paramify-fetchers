# Draft validators — GCP encryption at rest

Draft regex validators, one set per evidence set, following the repo's
`suggest-validator` skill format: each ships with **what it asserts**, **what it
does NOT assert**, and **when it (correctly) fails**. They run over the evidence
**envelope JSON as written to disk** (`{schema_version, metadata, payload}`), so
anchors target payload fields, not envelope metadata.

**These are drafts to confirm against a real-tenant run.** The `suggest-validator`
skill is authoritative and read-only — it wants real, populated evidence before
finalizing a regex, and validators ultimately live Paramify-side, not in the
repo. (The fetcher schema *does* allow an inline `validators:` block, but no
fetcher in this repo ships one, so these live here as a starting point rather
than in `fetcher.yaml`.) Regex flavor: Python `re` / PCRE — confirm against
Paramify's engine.

**Judgement calls are left as marked placeholders** `<<CUSTOMER: …>>` — max
rotation period, approved key rings/regions, and whether HSM is required are the
customer's to set live. Do not invent them.

> The GCP-specific reason these matter: everything is encrypted at rest by
> default, so a "is it encrypted?" check can never fail. Every validator below
> asserts something that *can* legitimately be false — CMEK vs Google-managed,
> the right key, rotation, location, protection level.

---

## EVD-GCP-PD-ENC — Persistent Disk Encryption

**Presence — at least one disk is CMEK (not Google-managed):**
```regex
"cmek"\s*:\s*true
```
- **Asserts:** at least one disk/snapshot uses a customer-managed key.
- **Does NOT assert:** that *all* disks are CMEK, or *which* key.
- **Fails when:** every disk is Google-managed default (all `"cmek": false`) — the
  real "not using CMEK" finding.

**Coverage — 100% of disks are CMEK:**
```regex
"cmek_disk_percentage"\s*:\s*100\b
```
- **Asserts:** every disk in the project is customer-managed encrypted.
- **Does NOT assert:** snapshots (see `cmek_snapshot_percentage`), or key identity.
- **Fails when:** any disk falls back to Google-managed. `<<CUSTOMER: lower the
  threshold, e.g. (?:100|9[0-9]) for ≥90%, if partial CMEK is acceptable>>`

**Right key — CMEK points at the approved key ring:**
```regex
"kms_key_name"\s*:\s*"projects/<<CUSTOMER: PROJECT>>/locations/<<CUSTOMER: LOCATION>>/keyRings/<<CUSTOMER: KEYRING>>/cryptoKeys/[^"]+"
```
- **Asserts:** the attached key lives in the approved project/location/ring.
- **Does NOT assert:** rotation or protection level (see EVD-GCP-KMS-ROT).
- **Fails when:** a disk is CMEK but with a key outside the approved ring/region.

---

## EVD-GCP-STORAGE-ENC — Cloud Storage Encryption

**Coverage — 100% of buckets are CMEK:**
```regex
"cmek_percentage"\s*:\s*100\b
```
- **Asserts:** every bucket uses a customer-managed default encryption key.
- **Does NOT assert:** key identity, uniform access, or versioning.
- **Fails when:** any bucket uses the Google-managed default. `<<CUSTOMER: adjust
  threshold if some buckets are legitimately Google-managed>>`

**Right key — bucket default key is in the approved ring:**
```regex
"kms_key_name"\s*:\s*"projects/<<CUSTOMER: PROJECT>>/locations/<<CUSTOMER: LOCATION>>/keyRings/<<CUSTOMER: KEYRING>>/cryptoKeys/[^"]+"
```
- **Asserts / does NOT / fails:** as for disks above.

**Posture — uniform bucket-level access on (supporting evidence):**
```regex
"uniform_bucket_level_access"\s*:\s*true
```
- **Asserts:** at least one bucket enforces uniform (IAM-only) access.
- **Fails when:** no bucket has UBLA — note this is access control, not encryption.

---

## EVD-GCP-CLOUDSQL-ENC — Cloud SQL Encryption

**CMEK presence:**
```regex
"cmek"\s*:\s*true
```
- **Asserts:** at least one instance uses a customer-managed key.
- **Fails when:** every instance uses the Google-managed default. NB: a fresh test
  instance is Google-managed by design (its service agent can't be granted a key
  until it exists), so this correctly fails on that setup.

**Coverage — 100% CMEK:**
```regex
"cmek_percentage"\s*:\s*100\b
```
- `<<CUSTOMER: set the acceptable threshold; Google-managed may be acceptable for
  some instances>>`

**Backups enabled (server-side backup protection, KSI-RPL-03):**
```regex
"backup_enabled"\s*:\s*true
```
- **Asserts:** at least one instance has automated backups on.
- **Does NOT assert:** backup *encryption* (that is Google-managed and implicit),
  retention window, or PITR.
- **Fails when:** an instance has backups disabled.

---

## EVD-GCP-KMS-ROT — Cloud KMS Key Rotation

**Rotation configured:**
```regex
"rotation_enabled"\s*:\s*true
```
- **Asserts:** at least one key has automatic rotation set (`rotationPeriod`).
- **Does NOT assert:** the rotation *interval*, or that *every* key rotates.
- **Fails when:** a key has no `rotationPeriod` — the "no rotation" finding
  (matches the `no-rotation-key` in the test project).

**Coverage — 100% of keys rotate:**
```regex
"rotation_percentage"\s*:\s*100\b
```
- `<<CUSTOMER: some keys (e.g. asymmetric signing keys) can't auto-rotate; lower
  the threshold or scope the evidence set if so>>`

**Rotation within an approved window (interval check):**
```regex
"rotation_period_seconds"\s*:\s*(?:[1-9]|[1-9][0-9]{1,6}|1[0-9]{7}|<<CUSTOMER: MAX_SECONDS>>)\b
```
- **Asserts:** a rotation period is set and ≤ the approved maximum.
- `<<CUSTOMER: replace the numeric bound with your max. 90 days = 7776000s;
  1 year = 31536000s. A pure regex can't do a true numeric ≤ comparison cleanly —
  prefer a numeric assertion in Paramify's engine if available, else pin the exact
  approved value, e.g. "rotation_period_seconds"\s*:\s*7776000\b>>`

**Protection level is HSM (Authorized Cryptographic Modules, KSI-SVC-02/05):**
```regex
"protection_level"\s*:\s*"HSM"
```
- **Asserts:** at least one key is HSM-backed.
- **Does NOT assert:** that all keys are HSM.
- **Fails when:** all keys are `SOFTWARE`. `<<CUSTOMER: only enforce this if the
  control requires HSM-backed keys; FIPS 140-3 Level 3 needs HSM, Level 1/2 does
  not — Google Cloud KMS SOFTWARE keys are FIPS 140-3 validated>>`

**Key in an approved location:**
```regex
"location"\s*:\s*"<<CUSTOMER: APPROVED_LOCATION e.g. us-central1>>"
```
- **Fails when:** a key exists outside the approved region(s).
