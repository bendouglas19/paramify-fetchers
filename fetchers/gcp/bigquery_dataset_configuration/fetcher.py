#!/usr/bin/env python3
"""
GCP BigQuery Dataset Configuration

For each BigQuery dataset in one project, reports the default (dataset-level)
CMEK encryption key, the access-control list with any public grant called out,
the default table expiration, and the dataset's location. BigQuery is always
encrypted at rest, so "encrypted: true" can never fail — the facts that vary are
CMEK vs Google-managed, who is on the ACL, and where the data lives.

Ported from Prowler's GCP BigQuery service (prowler/providers/gcp/services/
bigquery/bigquery_service.py, Apache-2.0) and its three checks
(bigquery_dataset_cmk_encryption, bigquery_dataset_public_access,
bigquery_table_cmk_encryption). Prowler's Dataset collapses the datasets.get
response into name/id/region plus two booleans — cmk_encryption (any
defaultEncryptionConfiguration) and public (the string "allUsers" or
"allAuthenticatedUsers" appearing anywhere in the stringified ACL). The response
it already reads carries the key name, the individual ACL entries, the default
table and partition expirations, and the labels, which is why this projection is
wider than the checks.

Uses the official GAPIC-era client (google.cloud.bigquery) per the category's
preference, rather than Prowler's googleapiclient.discovery build of bigquery v2.
`Dataset.to_api_repr()` hands back the same REST resource dict Prowler reads, so
the pure transforms below consume that shape directly.

Three deliberate departures from the Prowler original:
- **Public access is classified per ACL entry, not grepped.** A substring match on
  the whole stringified ACL also fires on a dataset owned by, say,
  `allusers-admin@example.com`. Here each entry's principal is read from its own
  field (`specialGroup`, `iamMember`, …) and compared exactly.
- **Human identities are counted, not enumerated.** ACL entries naming a person or
  a group carry their role and a count; the address is not copied. Public,
  domain-wide, special-group and authorized-view/routine/dataset entries ARE named
  — those are the posture facts, and none of them is a personal identity. (Same
  rule the IAM service-accounts fetcher applies to project bindings.)
- **Table-level CMEK is out of scope.** Prowler's bigquery_table_cmk_encryption
  does a tables.get per table, which is one API call per table in the project.
  Dataset default encryption is the control that governs new tables; a
  table-by-table inventory belongs in its own evidence set if it is wanted.

Single-project per invocation; fanout across projects happens at the runner
layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    build_payload,
    coverage_percentage,
    credentials,
    dig_any,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    write_status,
)

logger = logging.getLogger("gcp_bigquery_dataset_configuration")

# The two principals that make a dataset readable outside the organization.
# allUsers is anyone on the internet; allAuthenticatedUsers is any Google account.
_PUBLIC_PRINCIPALS = frozenset({"allusers", "allauthenticatedusers"})

# The ACL entry fields that identify a principal, in the order the API documents
# them. Exactly one is set per entry.
_PRINCIPAL_KEYS = (
    "userByEmail",
    "groupByEmail",
    "domain",
    "specialGroup",
    "iamMember",
    "view",
    "routine",
    "dataset",
)

# Entry fields whose value is a person or a mailing list. Their role and count are
# evidence; their address is a different evidence set's business.
_PERSONAL_KEYS = frozenset({"userByEmail", "groupByEmail"})

# iamMember carries a full IAM principal string, so a personal identity can arrive
# through it too.
_PERSONAL_IAM_PREFIXES = ("user:", "group:", "principal:", "principalset:")

# Entry fields whose value is a BigQuery resource reference rather than a string.
_RESOURCE_KEYS = frozenset({"view", "routine", "dataset"})


# --- pure transforms (operate on REST-style dicts; unit-tested from fixtures) ---

def is_public_principal(principal) -> bool:
    """Exact match against allUsers / allAuthenticatedUsers.

    Tolerates the `iamMember` spelling, where the principal can arrive bare or
    prefixed. A substring test (Prowler's approach) also matches an ordinary
    account whose address happens to contain the word.
    """
    value = str(principal or "").strip().lower()
    return value in _PUBLIC_PRINCIPALS or value.split(":")[-1] in _PUBLIC_PRINCIPALS


def resource_path(ref) -> str | None:
    """A view / routine / authorized-dataset reference as project.dataset.object."""
    if not isinstance(ref, dict):
        return None
    # An authorized-dataset entry wraps the reference one level deeper.
    inner = dig_any(ref, "dataset")
    if isinstance(inner, dict):
        ref = inner
    parts = [
        dig_any(ref, "project_id"),
        dig_any(ref, "dataset_id"),
        dig_any(ref, "table_id") or dig_any(ref, "routine_id"),
    ]
    path = ".".join(str(p) for p in parts if p)
    return path or None


def access_entry_record(entry: dict) -> dict:
    """One dataset ACL entry: its role, principal type, and principal when nameable.

    `principal` is None for an entry naming a person or a group — see the module
    docstring. `public` is the fact the whole entry exists to surface.
    """
    principal_type = next((k for k in _PRINCIPAL_KEYS if dig_any(entry, k) is not None), None)
    raw = dig_any(entry, principal_type) if principal_type else None

    if principal_type in _RESOURCE_KEYS:
        principal = resource_path(raw)
    elif principal_type in _PERSONAL_KEYS:
        principal = None
    elif principal_type == "iamMember" and str(raw or "").lower().startswith(
        _PERSONAL_IAM_PREFIXES
    ):
        principal = None
    else:
        principal = str(raw) if raw is not None else None

    return {
        # Authorized views / routines / datasets carry no role.
        "role": dig_any(entry, "role") or None,
        "principal_type": principal_type,
        "principal": principal,
        "public": is_public_principal(raw) if not isinstance(raw, dict) else False,
    }


def dataset_record(dataset: dict) -> dict:
    """Normalize one dataset resource dict into an evidence record.

    CMEK is the PRESENCE of defaultEncryptionConfiguration.kmsKeyName. On a
    Google-managed dataset the whole block is absent, so this tests for presence
    rather than for an empty value — the same rule the Cloud SQL, Cloud Storage
    and Persistent Disk encryption fetchers use.
    """
    reference = dig_any(dataset, "dataset_reference") or {}
    kms = dig_any(dataset, "default_encryption_configuration", "kms_key_name")
    entries = [access_entry_record(e) for e in (dig_any(dataset, "access") or [])]

    public_entries = sorted(
        (e for e in entries if e["public"]),
        key=lambda e: (e["principal"] or "", e["role"] or ""),
    )
    # Non-personal entries are safe to name and are the ones a reviewer acts on.
    named_entries = sorted(
        (e for e in entries if e["principal"] is not None and not e["public"]),
        key=lambda e: (e["principal_type"] or "", e["principal"] or "", e["role"] or ""),
    )
    type_counts: dict[str, int] = {}
    for entry in entries:
        key = entry["principal_type"] or "unknown"
        type_counts[key] = type_counts.get(key, 0) + 1

    default_expiration_ms = dig_any(dataset, "default_table_expiration_ms")
    expiration_days = (
        int(int(default_expiration_ms) // 86_400_000)
        if str(default_expiration_ms or "").isdigit()
        else None
    )

    return {
        "name": dig_any(reference, "dataset_id") or None,
        "id": dig_any(dataset, "id") or None,
        "project": dig_any(reference, "project_id") or None,
        "location": dig_any(dataset, "location") or None,
        "friendly_name": dig_any(dataset, "friendly_name") or None,
        "labels": dig_any(dataset, "labels") or {},
        "creation_time": dig_any(dataset, "creation_time") or None,
        "last_modified_time": dig_any(dataset, "last_modified_time") or None,
        # --- encryption at rest ---
        "cmek": kms is not None,
        "kms_key_name": kms,
        # --- access control ---
        "publicly_accessible": bool(public_entries),
        "public_access_entries": public_entries,
        "access_entries": named_entries,
        "access_entry_count": len(entries),
        "access_entry_counts_by_principal_type": type_counts,
        "access_roles": sorted({e["role"] for e in entries if e["role"]}),
        "domain_access": sorted(
            e["principal"] for e in entries if e["principal_type"] == "domain" and e["principal"]
        ),
        # --- retention ---
        "default_table_expiration_ms": default_expiration_ms,
        "default_table_expiration_days": expiration_days,
        "has_default_table_expiration": default_expiration_ms is not None,
        "default_partition_expiration_ms": dig_any(dataset, "default_partition_expiration_ms"),
        "max_time_travel_hours": dig_any(dataset, "max_time_travel_hours"),
    }


def _grants_to(dataset: dict, principal: str) -> bool:
    """Whether this dataset's ACL names one specific public principal."""
    return any(
        str(entry["principal"] or "").split(":")[-1].lower() == principal
        for entry in dataset["public_access_entries"]
    )


def summarize(datasets: list[dict], *, api_readable: bool = True) -> dict:
    cmek = sum(1 for d in datasets if d["cmek"])
    public = sum(1 for d in datasets if d["publicly_accessible"])
    # Counted independently: a dataset can grant both, so one is not the other's
    # complement.
    all_users = sum(1 for d in datasets if _grants_to(d, "allusers"))
    all_authenticated = sum(1 for d in datasets if _grants_to(d, "allauthenticatedusers"))
    return {
        # False when bigquery.googleapis.com is not enabled on this project
        # (recorded in metadata.skipped_calls) — distinguishing "no datasets" from
        # "could not look".
        "bigquery_api_readable": api_readable,
        "total_datasets": len(datasets),
        # BigQuery is always encrypted at rest; CMEK vs Google-managed is the fact
        # that varies, so coverage is expressed over CMEK, not over "encrypted".
        "cmek_datasets": cmek,
        "google_managed_datasets": len(datasets) - cmek,
        "cmek_percentage": coverage_percentage(cmek, len(datasets)),
        "distinct_kms_keys": sorted({d["kms_key_name"] for d in datasets if d["kms_key_name"]}),
        "publicly_accessible_datasets": public,
        "datasets_with_all_users": all_users,
        "datasets_with_all_authenticated_users": all_authenticated,
        "non_public_dataset_percentage": coverage_percentage(
            len(datasets) - public, len(datasets)
        ),
        "datasets_with_domain_access": sum(1 for d in datasets if d["domain_access"]),
        "datasets_with_default_table_expiration": sum(
            1 for d in datasets if d["has_default_table_expiration"]
        ),
        "locations": sorted({d["location"] for d in datasets if d["location"]}),
    }


# --- collection (lazy google imports; not exercised by the fixture tests) ---

def collect_datasets(project, creds, collector: Collector) -> list[dict] | None:
    """Every dataset in the project, or None when BigQuery could not be listed.

    datasets.list returns only a reference and the location, so each dataset is
    fetched once for its ACL and encryption config — the same two-step Prowler
    does. That is one call per dataset, not per table.
    """
    from google.cloud import bigquery

    client = collector.guard(
        "bigquery.client",
        lambda: bigquery.Client(project=project, credentials=creds),
        tolerate=service_disabled,
    )
    if client is None:
        return None

    # The client's iterator walks every page; no manual page-token loop.
    listed = collector.guard(
        "bigquery.datasets.list",
        lambda: list(client.list_datasets(project=project)),
        tolerate=service_disabled,
    )
    if listed is None:
        return None

    records = []
    for item in listed:
        dataset_id = getattr(item, "dataset_id", None)

        def _get(reference=item.reference):
            return client.get_dataset(reference).to_api_repr()

        resource = collector.guard(f"bigquery.datasets.get ({dataset_id})", _get)
        if resource is not None:
            records.append(dataset_record(resource))
    return sorted(records, key=lambda r: r.get("name") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    datasets: list[dict] | None = None
    if project and creds is not None:
        datasets = collect_datasets(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"datasets": datasets or []},
        summary=summarize(datasets or [], api_readable=datasets is not None),
    )

    filename = (
        f"gcp_bigquery_dataset_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        # Reported before any success log line: the runner takes the TAIL of
        # stderr as metadata.error when the status file is empty, so an "Evidence
        # saved" INFO line last would become the reported failure reason.
        reason, code = collector.failure_report()
        logger.error("%s", reason)
        write_status(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
