# Draft replacement narratives — GCP (plain text, paste-ready)

Replacements for the AWS-written capability narratives in
`session1-encryption-at-rest-capabilities.csv`. Same meaning, GCP services in
place of AWS ones. `#THIS SYSTEM` and `#MAIN COMPONENT` smart tags are left
intact; only the hardcoded product names are swapped:

- Amazon S3 objects → Cloud Storage objects
- RDS databases / automated backups → Cloud SQL databases / automated backups
- EBS block volumes / snapshots → Persistent Disk block volumes / snapshots
- AWS KMS → Cloud KMS; AWS ACM → Certificate Manager

Per the brief, **FIPS 140-2 → FIPS 140-3** wherever it appeared.

> **Count discrepancy flagged (not guessed):** the brief's Deliverable 4 says
> "the three solution capabilities," but the CSV carries **four** capability
> narratives with hardcoded AWS names. All four are provided below so nothing is
> missed — drop the fourth (Server-Side Encryption Protection) if only three were
> intended.

> **FIPS note to confirm with the customer:** Google Cloud KMS SOFTWARE keys and
> Cloud HSM are FIPS 140-validated, but the exact level/module differs from AWS
> KMS. The text below asserts FIPS 140-3 as instructed; confirm the precise
> validated-module claim before submission.

---

## 1. Authorized Cryptographic Modules

#THIS SYSTEM uses only FIPS 140-3 validated cryptographic modules for all
encryption operations. Cloud KMS, Certificate Manager, and native Google Cloud
encryption services all leverage FIPS-validated cryptographic modules. Encryption
algorithms are restricted to approved ciphers (AES-256, RSA-2048+, ECDSA P-256+).

Cloud Storage Encryption : All Cloud Storage buckets encrypted confirms Cloud
Storage uses approved encryption algorithms. Cloud SQL Encryption : All Cloud SQL
instances encrypted confirms Cloud SQL uses approved encryption. Cloud KMS key
protection level (SOFTWARE vs HSM) validates that keys are backed by
FIPS-validated modules.

---

## 2. Cryptographic Key Management

#THIS SYSTEM uses #MAIN COMPONENT to manage cryptographic keys for all data
encryption operations. Cloud KMS provides FIPS 140-3 validated HSMs for key
generation, storage, and rotation. Automatic key rotation is enabled on an annual
basis for all customer-managed keys.

---

## 3. Protection of Data at Rest

#THIS SYSTEM encrypts all data at rest using AES-256. Cloud Storage objects, Cloud
SQL databases, and Persistent Disk block volumes are encrypted using Cloud KMS
customer-managed keys. Encryption is enforced at the service level and cannot be
disabled by operators.

---

## 4. Server-Side Encryption Protection

#THIS SYSTEM encrypts all backup data and server-side storage using #MAIN
COMPONENT. Cloud Storage objects, Cloud SQL automated backups, and Persistent Disk
snapshots are encrypted with Cloud KMS. Encryption keys are customer-managed and
rotated annually.
