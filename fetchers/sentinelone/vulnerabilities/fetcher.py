#!/usr/bin/env python3
"""
SentinelOne Vulnerabilities — FedRAMP 20x CR26 VER-RPT-VDT source evidence.

Collects vulnerability findings from SentinelOne Singularity's Application Risk /
Vulnerability Management module. Facts only: severity, CVSS scores, status, and
mitigation state are reported verbatim as SentinelOne returns them. This fetcher
computes no compliance status, pass/fail, PAIN/N-rating, or risk interpretation —
that judgment stays on the Paramify side.

===============================================================================
API CONTRACT — CORE SHAPE VERIFIED 2026-08-19; TWO ITEMS STILL OPEN
===============================================================================
SentinelOne serves its own API reference only from an authenticated tenant
console (/api-doc/overview), so the shape below was reconstructed from
third-party integrations rather than from vendor documentation, then confirmed
by a live run.

VERIFIED 2026-08-19 against a us-east-1 tenant (12,694 records over 13 cursor
pages, empty failure ledger): the endpoint path, the ApiToken auth scheme, the
limit/cursor params, cursor pagination via pagination.nextCursor, and the flat
record shape all behave as described below. Grouping was lossless — 12,694
records in, 12,694 affected-endpoint rows out.

FIELD SET IS NOT UNIFORM ACROSS TENANTS. That tenant returned only 23 of the 33
fields listed under "Records" below. Absent: exploitCodeMaturity,
remediationLevel, reportConfidence, riskScore, nvdBaseScore, nvdCvssVersion,
mitigationStatus, mitigationStatusChangeTime, mitigationStatusChangedBy,
mitigationStatusReason. That looks like a licensing tier difference — the CVSS
temporal triad and the mitigation-workflow family appear to be full Singularity
VM / Ranger Insights features rather than base Application Risk. Every one of
those fields keeps its null slot in the payload rather than being removed, so a
higher-tier tenant populates them with no code change.

CONFIRMED (Elastic's sentinel_one integration, application_risk data stream —
its CEL program, ingest pipeline, and test fixtures; endpoint list corroborated
by the Qualys SentinelOne EDR connector):

  * Endpoint    GET {api_url}/web/api/v2.1/application-management/risks
  * Auth        Authorization: ApiToken <token>
  * Pagination  cursor-based: response.pagination.nextCursor is fed back as the
                `cursor` query param; records arrive under response.data
  * Params      limit (max 1000), cursor, siteIds
  * Records     one flat record per (CVE x application x endpoint), carrying:
                id, cveId, severity, baseScore, cvssVersion, nvdBaseScore,
                nvdCvssVersion, riskScore, exploitCodeMaturity,
                remediationLevel, reportConfidence, application,
                applicationName, applicationVendor, applicationVersion,
                endpointId, endpointName, endpointType, osType, detectionDate,
                daysDetected, lastScanDate, lastScanResult, publishedDate,
                status, mitigationStatus, mitigationStatusChangeTime,
                mitigationStatusChangedBy, mitigationStatusReason, markType,
                markedBy, markedDate, reason

STILL OPEN — each of these is a specific thing to check:

  1. SCOPE PARAM — UNTESTED. The 2026-08-19 run was unscoped, so this path has
     never been exercised. Only `siteIds` is sent; sibling SentinelOne endpoints
     also accept `accountIds` and `groupIds`, but neither is confirmed here. If
     SENTINELONE_SCOPE_IDS is populated with *account* IDs, expect an empty
     result set rather than an error. Verify which scope params this endpoint
     honors, then split the config field if account scoping is needed.

  2. NO SERVER-SIDE DATE WINDOW IS SENT — a design choice, not a gap, and the
     live run confirmed it was the right one. The legacy sibling endpoint
     (/web/api/v2.1/installed-applications/cves) accepts
     updatedAt__gte / createdAt__gte style filters, but no equivalent is
     confirmed on .../risks, and SentinelOne rejects some unrecognized query
     params with HTTP 400 — sending a guessed filter would break collection
     outright. So report-period windowing is done locally: every open finding
     is collected and each carries `detected_in_report_period`. This is also the
     correct reporting behavior — a vulnerability first detected before the
     window but still open must appear in VER-RPT-VDT, and a server-side
     detectionDate filter would silently drop exactly those overdue findings.
     If a windowing param is confirmed later it becomes an optimization; the
     local flag stays valid either way. The 2026-08-19 run bears this out:
     detections ranged from 2024-09-06 to 2026-08-18 with daysDetected up to
     712, and only 2,286 of 4,730 vulnerabilities fell inside a 30-day window —
     a server-side filter would have dropped 52% of the report, biased entirely
     toward the oldest and most overdue findings.

  3. RISK-ACCEPTED DETECTION — UNTESTED, AND A ZERO HERE PROVES NOTHING. The
     accept/mitigate marking surfaces through markType / mitigationStatus /
     status, but the enum values are not publicly documented.
     _is_risk_accepted() matches "accept" case-insensitively across those three
     fields. The 2026-08-19 run did not exercise it: markType / markedBy /
     markedDate / reason came back present but 0% populated and status was 100%
     "Detected", so records_excluded_risk_accepted was 0 for lack of any marked
     record — not because the matcher agreed with the console. Re-check the
     first time a vulnerability is actually marked.

  4. FIELDS NO TENANT HAS BEEN SEEN TO EXPOSE — all confirmed absent in the
     2026-08-19 run — which VER-RPT-VDT or the requested superset wants: CVSS
     vector string, CWE ID, EPSS score, CISA KEV flag, CPE, fixed/patched
     version, patch availability, agent UUID, agent version, endpoint IP, and
     any linked ticket / POA&M / external reference ID. Nothing is invented for
     them. Three mechanisms make sure a
     tenant that DOES return one of them is not silently dropped:
       * _OPPORTUNISTIC_VULN_FIELDS / _OPPORTUNISTIC_ENDPOINT_FIELDS read each
         of these from a list of likely key names when present, and report which
         name was found in collection.opportunistic_fields_found;
       * any key not in _KNOWN_FIELDS is listed in
         collection.unmapped_field_names, so a single live run tells you exactly
         what else the tenant's API version returns;
       * every API record is preserved verbatim under `raw_records`.
     The candidate key names in those maps are guesses and cost nothing when
     absent, but a name confirmed against a live tenant should replace them.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

logger = logging.getLogger("sentinelone_vulnerabilities")

API_PATH = "/web/api/v2.1/application-management/risks"
OUTPUT_FILENAME = "sentinelone_vulnerabilities.json"
HTTP_TIMEOUT_SECONDS = 30
PAGE_LIMIT = 1000
# Backstop against a tenant that keeps handing back a nextCursor forever.
MAX_PAGES = 5000

# Vulnerability-level fields: constant for a given (CVE x product), so they are
# lifted onto the grouped entry.
_VULN_FIELDS = (
    "cveId",
    "severity",
    "baseScore",
    "cvssVersion",
    "nvdBaseScore",
    "nvdCvssVersion",
    "riskScore",
    "exploitCodeMaturity",
    "remediationLevel",
    "reportConfidence",
    "publishedDate",
    "application",
    "applicationName",
    "applicationVendor",
)
# Endpoint-identity fields.
_ENDPOINT_FIELDS = ("endpointId", "endpointName", "endpointType", "osType")
# Per-occurrence fields: vary per (vulnerability x endpoint) pair.
_OCCURRENCE_FIELDS = (
    "id",
    "applicationVersion",
    "detectionDate",
    "daysDetected",
    "lastScanDate",
    "lastScanResult",
    "status",
    "mitigationStatus",
    "mitigationStatusChangeTime",
    "mitigationStatusChangedBy",
    "mitigationStatusReason",
    "markType",
    "markedBy",
    "markedDate",
    "reason",
)
_KNOWN_FIELDS = frozenset(_VULN_FIELDS + _ENDPOINT_FIELDS + _OCCURRENCE_FIELDS)

# Fields VER-RPT-VDT (or the requested superset) wants that the confirmed record
# shape does NOT include. Nothing is invented for them, but if a tenant's API
# version happens to return one under any of these names it is picked up rather
# than silently dropped into raw_records. Which names were actually found is
# reported in collection.opportunistic_fields_found; anything unrecognized still
# shows up in collection.unmapped_field_names.
_OPPORTUNISTIC_VULN_FIELDS = {
    "cwe_id": ("cweId", "cwe", "cweIds"),
    "epss_score": ("epssScore", "epss"),
    "cisa_kev": ("isKev", "cisaKev", "kev", "isKnownExploited", "cisaKevListed"),
    "description": ("cveDescription", "vulnerabilityDescription", "description", "summary"),
    "detection_source": ("detectionSource", "discoverySource", "scanSource", "source", "engine"),
    "cvss_vector_string": ("cvssVector", "vectorString", "baseVector", "cvss3Vector", "vector"),
    "cpe": ("cpe", "cpeName", "cpes"),
    "fixed_version": ("fixedVersion", "fixVersion", "patchedVersion", "remediationVersion"),
    "patch_available": (
        "patchAvailable",
        "isPatchAvailable",
        "hasPatch",
        "remediationAvailable",
    ),
    "external_reference_ids": (
        "ticketId",
        "ticketIds",
        "externalId",
        "externalIds",
        "poamId",
        "poamIds",
    ),
}
_OPPORTUNISTIC_ENDPOINT_FIELDS = {
    "agent_uuid": ("agentUuid", "agentId", "uuid"),
    "agent_version": ("agentVersion",),
    "ip_address": ("endpointIp", "lastIpAddress", "externalIp", "ipAddress"),
    "os_version": ("osVersion", "endpointOsVersion", "agentOsVersion"),
}

# What this fetcher itself is, stated as a fact for VER-RPT-VDT's required
# detection.detectionSource. Overridden per vulnerability if the API supplies
# its own detection-source value.
DEFAULT_DETECTION_SOURCE = (
    "SentinelOne Singularity Vulnerability Management "
    "(/web/api/v2.1/application-management/risks)"
)


class MalformedResponseError(RuntimeError):
    """The API answered 200 but not in the shape this fetcher can read."""


def report_failure(msg: str, code: Optional[str] = None) -> None:
    """Tell the runner why this run failed. See docs/fetcher_contract.md.

    The runner falls back to the TAIL of stderr for metadata.error, so the
    reason must also be logged AFTER any "Evidence saved" line.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    body = {"error": msg}
    if code:
        body["code"] = code
    Path(path).write_text(json.dumps(body))


def failure_code(api_failures: List[Dict[str, Any]], records_collected: int) -> str:
    """Pick the documented status code that best describes the ledger."""
    statuses = {f.get("http_status") for f in api_failures if f.get("http_status")}
    if statuses == {401}:
        return "auth_failed"
    if statuses == {403}:
        return "not_authorized"
    if statuses == {429}:
        return "rate_limited"
    if not statuses and records_collected == 0:
        return "target_unreachable"
    return "partial_failure"


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Best-effort ISO8601 parse. Returns None rather than raising — an
    unparseable timestamp must not abort collection."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def first_present(
    record: Dict[str, Any], keys: Tuple[str, ...]
) -> Tuple[Any, Optional[str]]:
    """Return (value, api_key_it_came_from) for the first of `keys` the record
    actually carries a value for, else (None, None)."""
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value, key
    return None, None


def record_failure(
    api_failures: List[Dict[str, Any]],
    endpoint: str,
    params: Dict[str, Any],
    exc: Exception,
    note: Optional[str] = None,
) -> None:
    """Append one entry to the failure ledger. `params` never carries the API
    token (it travels in the Authorization header), so this is safe to emit."""
    entry: Dict[str, Any] = {
        "endpoint": endpoint,
        "params": {k: v for k, v in params.items()},
        "type": type(exc).__name__,
        "message": str(exc),
    }
    response = getattr(exc, "response", None)
    if response is not None:
        entry["http_status"] = response.status_code
    if note:
        entry["note"] = note
    api_failures.append(entry)


def fetch_risk_records(
    api_url: str,
    api_token: str,
    scope_ids: Optional[str],
    api_failures: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Page the Application Risk endpoint. Returns (records, pagination_stats).

    Every failure lands in `api_failures`; nothing is swallowed. Pagination stops
    at the first failure so a partial collection is never reported as complete.
    """
    endpoint = api_url.rstrip("/") + API_PATH
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"ApiToken {api_token}",
    }
    records: List[Dict[str, Any]] = []
    stats = {
        "pages_fetched": 0,
        "pagination_stopped_early": False,
        "non_dict_records_skipped": 0,
    }
    cursor: Optional[str] = None
    seen_cursors = set()

    while True:
        params: Dict[str, Any] = {"limit": PAGE_LIMIT}
        if scope_ids:
            params["siteIds"] = scope_ids
        if cursor:
            params["cursor"] = cursor

        try:
            response = requests.get(
                endpoint, headers=headers, params=params, timeout=HTTP_TIMEOUT_SECONDS
            )
            response.raise_for_status()
            body = response.json()
        # ValueError first: requests' own JSONDecodeError subclasses both
        # ValueError and RequestException, and the undecodable-body note is the
        # more useful diagnostic of the two.
        except ValueError as e:
            record_failure(
                api_failures, endpoint, params, e, note="response body was not valid JSON"
            )
            logger.warning("Undecodable response body on page %d", stats["pages_fetched"] + 1)
            stats["pagination_stopped_early"] = True
            break
        except requests.exceptions.RequestException as e:
            record_failure(api_failures, endpoint, params, e)
            logger.warning("Request failed on page %d", stats["pages_fetched"] + 1)
            stats["pagination_stopped_early"] = True
            break

        if not isinstance(body, dict):
            record_failure(
                api_failures,
                endpoint,
                params,
                MalformedResponseError(
                    f"expected a JSON object at the top level, got {type(body).__name__}"
                ),
            )
            stats["pagination_stopped_early"] = True
            break

        data = body.get("data")
        if data is None:
            record_failure(
                api_failures,
                endpoint,
                params,
                MalformedResponseError("response object has no 'data' key"),
            )
            stats["pagination_stopped_early"] = True
            break
        if not isinstance(data, list):
            record_failure(
                api_failures,
                endpoint,
                params,
                MalformedResponseError(
                    f"expected 'data' to be a list, got {type(data).__name__}"
                ),
            )
            stats["pagination_stopped_early"] = True
            break

        stats["pages_fetched"] += 1
        page_records = [r for r in data if isinstance(r, dict)]
        skipped = len(data) - len(page_records)
        if skipped:
            stats["non_dict_records_skipped"] += skipped
            record_failure(
                api_failures,
                endpoint,
                params,
                MalformedResponseError(
                    f"{skipped} of {len(data)} records on this page were not JSON objects"
                ),
            )
        records.extend(page_records)

        pagination = body.get("pagination")
        next_cursor = pagination.get("nextCursor") if isinstance(pagination, dict) else None
        if not next_cursor:
            break
        if next_cursor in seen_cursors:
            record_failure(
                api_failures,
                endpoint,
                params,
                MalformedResponseError("nextCursor repeated a cursor already seen"),
                note="pagination would not terminate; stopped to avoid an endless loop",
            )
            stats["pagination_stopped_early"] = True
            break
        if stats["pages_fetched"] >= MAX_PAGES:
            record_failure(
                api_failures,
                endpoint,
                params,
                MalformedResponseError(f"page cap of {MAX_PAGES} reached with a cursor still pending"),
                note="collection is incomplete; raise MAX_PAGES or narrow the scope",
            )
            stats["pagination_stopped_early"] = True
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return records, stats


def _is_risk_accepted(record: Dict[str, Any]) -> bool:
    """UNVERIFIED enum matching — see assumption 3 in the module docstring."""
    for key in ("markType", "mitigationStatus", "status"):
        value = record.get(key)
        if isinstance(value, str) and "accept" in value.lower():
            return True
    return False


def _group_key(record: Dict[str, Any]) -> str:
    """One grouped entry per (CVE x vendor x product). Records with no CVE are
    kept separate rather than collapsed together."""
    cve = record.get("cveId")
    if not cve:
        return f"no-cve:{record.get('id')}"
    vendor = record.get("applicationVendor") or ""
    name = record.get("applicationName") or ""
    return f"{cve}|{vendor}|{name}"


def build_vulnerabilities(
    records: List[Dict[str, Any]],
    period_start: datetime,
    period_end: datetime,
    fields_found: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Group flat API records into one entry per vulnerability, with the
    affected-endpoint list attached. Pure reshaping — no values are derived
    beyond counts and min/max of timestamps SentinelOne supplied. `fields_found`
    is populated with any opportunistic field names actually seen."""
    grouped: Dict[str, Dict[str, Any]] = {}

    for record in records:
        key = _group_key(record)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "vulnerability_key": key,
                "cve_id": record.get("cveId"),
                "sentinelone_record_ids": [],
                "severity": None,
                "cvss": {
                    "base_score": None,
                    "version": None,
                    "nvd_base_score": None,
                    "nvd_cvss_version": None,
                    "vector_string": None,
                },
                "cvss_temporal": {
                    "exploit_code_maturity": None,
                    "remediation_level": None,
                    "report_confidence": None,
                },
                "sentinelone_risk_score": None,
                "cve_published_date": None,
                "description": None,
                "detection_source": DEFAULT_DETECTION_SOURCE,
                "cwe_id": None,
                "epss_score": None,
                "cisa_kev": None,
                "external_reference_ids": [],
                "application": {
                    "composed_name": record.get("application"),
                    "name": record.get("applicationName"),
                    "vendor": record.get("applicationVendor"),
                    "versions_observed": [],
                    "cpe": None,
                    "fixed_version": None,
                    "patch_available": None,
                },
                "statuses_observed": [],
                "mitigation_statuses_observed": [],
                "mark_types_observed": [],
                "risk_accepted": False,
                "first_detected_at": None,
                "last_detected_at": None,
                "last_scanned_at": None,
                "detected_in_report_period": False,
                "endpoint_count": 0,
                "affected_endpoints": [],
            }
            grouped[key] = entry

        # Vulnerability-level slots: first non-null record wins. Idempotent, so
        # this runs for every record including the one that created the entry.
        for slot, api_key in (
            ("severity", "severity"),
            ("sentinelone_risk_score", "riskScore"),
            ("cve_published_date", "publishedDate"),
        ):
            if entry[slot] is None:
                entry[slot] = record.get(api_key)
        for cvss_slot, api_key in (
            ("base_score", "baseScore"),
            ("version", "cvssVersion"),
            ("nvd_base_score", "nvdBaseScore"),
            ("nvd_cvss_version", "nvdCvssVersion"),
        ):
            if entry["cvss"][cvss_slot] is None:
                entry["cvss"][cvss_slot] = record.get(api_key)
        for temporal_slot, api_key in (
            ("exploit_code_maturity", "exploitCodeMaturity"),
            ("remediation_level", "remediationLevel"),
            ("report_confidence", "reportConfidence"),
        ):
            if entry["cvss_temporal"][temporal_slot] is None:
                entry["cvss_temporal"][temporal_slot] = record.get(api_key)

        # Opportunistic vulnerability-level fields (see _OPPORTUNISTIC_VULN_FIELDS).
        for slot, candidates in _OPPORTUNISTIC_VULN_FIELDS.items():
            value, source_key = first_present(record, candidates)
            if source_key is None:
                continue
            fields_found[slot] = source_key
            if slot == "external_reference_ids":
                for ref in value if isinstance(value, list) else [value]:
                    if ref not in entry["external_reference_ids"]:
                        entry["external_reference_ids"].append(ref)
            elif slot == "cvss_vector_string":
                if entry["cvss"]["vector_string"] is None:
                    entry["cvss"]["vector_string"] = value
            elif slot in ("cpe", "fixed_version", "patch_available"):
                if entry["application"][slot] is None:
                    entry["application"][slot] = value
            elif slot == "detection_source":
                entry["detection_source"] = value
            elif entry[slot] is None:
                entry[slot] = value

        record_id = record.get("id")
        if record_id is not None and record_id not in entry["sentinelone_record_ids"]:
            entry["sentinelone_record_ids"].append(record_id)

        version = record.get("applicationVersion")
        if version is not None and version not in entry["application"]["versions_observed"]:
            entry["application"]["versions_observed"].append(version)

        for observed_key, api_key in (
            ("statuses_observed", "status"),
            ("mitigation_statuses_observed", "mitigationStatus"),
            ("mark_types_observed", "markType"),
        ):
            value = record.get(api_key)
            if value not in (None, "") and value not in entry[observed_key]:
                entry[observed_key].append(value)

        if _is_risk_accepted(record):
            entry["risk_accepted"] = True

        detected_at = parse_timestamp(record.get("detectionDate"))
        if detected_at is not None:
            if period_start <= detected_at <= period_end:
                entry["detected_in_report_period"] = True
            first = parse_timestamp(entry["first_detected_at"])
            if first is None or detected_at < first:
                entry["first_detected_at"] = record.get("detectionDate")
            last = parse_timestamp(entry["last_detected_at"])
            if last is None or detected_at > last:
                entry["last_detected_at"] = record.get("detectionDate")

        scanned_at = parse_timestamp(record.get("lastScanDate"))
        if scanned_at is not None:
            previous = parse_timestamp(entry["last_scanned_at"])
            if previous is None or scanned_at > previous:
                entry["last_scanned_at"] = record.get("lastScanDate")

        affected = {
            "sentinelone_record_id": record_id,
            "endpoint_id": record.get("endpointId"),
            "hostname": record.get("endpointName"),
            "endpoint_type": record.get("endpointType"),
            "os_type": record.get("osType"),
            "application_version": version,
            "detected_at": record.get("detectionDate"),
            "days_detected": record.get("daysDetected"),
            "last_scanned_at": record.get("lastScanDate"),
            "last_scan_result": record.get("lastScanResult"),
            "status": record.get("status"),
            "mitigation_status": record.get("mitigationStatus"),
            "mitigation_status_changed_at": record.get("mitigationStatusChangeTime"),
            "mitigation_status_changed_by": record.get("mitigationStatusChangedBy"),
            "mitigation_status_reason": record.get("mitigationStatusReason"),
            "mark_type": record.get("markType"),
            "marked_by": record.get("markedBy"),
            "marked_at": record.get("markedDate"),
            "mark_reason": record.get("reason"),
            "agent_uuid": None,
            "agent_version": None,
            "ip_address": None,
            "os_version": None,
        }
        for slot, candidates in _OPPORTUNISTIC_ENDPOINT_FIELDS.items():
            value, source_key = first_present(record, candidates)
            if source_key is not None:
                fields_found[slot] = source_key
                affected[slot] = value
        entry["affected_endpoints"].append(affected)

    for entry in grouped.values():
        entry["endpoint_count"] = len(
            {e["endpoint_id"] for e in entry["affected_endpoints"] if e["endpoint_id"] is not None}
        )
        for observed_key in (
            "statuses_observed",
            "mitigation_statuses_observed",
            "mark_types_observed",
        ):
            entry[observed_key] = sorted(entry[observed_key], key=str)

    return sorted(grouped.values(), key=lambda e: e["vulnerability_key"])


def collect(
    api_url: str,
    api_token: str,
    reporting_period_days: int,
    scope_ids: Optional[str],
    include_accepted: bool,
) -> Dict[str, Any]:
    api_failures: List[Dict[str, Any]] = []
    period_end = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=reporting_period_days)
    endpoint = api_url.rstrip("/") + API_PATH

    records, stats = fetch_risk_records(api_url, api_token, scope_ids, api_failures)

    if include_accepted:
        kept = records
        excluded_accepted = 0
    else:
        kept = [r for r in records if not _is_risk_accepted(r)]
        excluded_accepted = len(records) - len(kept)

    fields_found: Dict[str, str] = {}
    vulnerabilities = build_vulnerabilities(kept, period_start, period_end, fields_found)

    unmapped = sorted({k for r in records for k in r.keys()} - _KNOWN_FIELDS)

    if api_failures and not records:
        status = "error"
    elif api_failures:
        status = "partial"
    else:
        status = "success"

    return {
        "status": status,
        "api_endpoint": endpoint,
        "collected_at": current_timestamp(),
        "report_period": {
            "start": period_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": period_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days": reporting_period_days,
            "note": (
                "Window is stamped for VER-RPT-PER. Findings are NOT truncated to "
                "it: every open vulnerability is collected and each carries "
                "detected_in_report_period, so a still-open older finding is "
                "reported rather than dropped."
            ),
        },
        "scope": {
            "site_ids": [s.strip() for s in scope_ids.split(",") if s.strip()] if scope_ids else [],
            "scope_ids_requested": scope_ids or None,
            "include_accepted": include_accepted,
        },
        "collection": {
            "pages_fetched": stats["pages_fetched"],
            "records_returned_by_api": len(records),
            # True only when a page came back successfully and held no records.
            # A failed call leaves this false and populates api_failures.
            "api_returned_empty_list": stats["pages_fetched"] > 0 and len(records) == 0,
            "pagination_stopped_early": stats["pagination_stopped_early"],
            "non_dict_records_skipped": stats["non_dict_records_skipped"],
            "records_excluded_risk_accepted": excluded_accepted,
            "records_considered": len(kept),
            "vulnerability_count": len(vulnerabilities),
            "affected_endpoint_count": len(
                {r.get("endpointId") for r in kept if r.get("endpointId") is not None}
            ),
            "unmapped_field_names": unmapped,
            "opportunistic_fields_found": dict(sorted(fields_found.items())),
        },
        "api_failures": api_failures,
        "vulnerabilities": vulnerabilities,
        "raw_records": records,
    }


def write_output(output_dir: Path, result: Dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / OUTPUT_FILENAME
    with open(output_path, "w") as handle:
        json.dump(result, handle, indent=2, default=str)
    return output_path


def main() -> int:
    logging.basicConfig(
        stream=sys.stderr,
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: the fetcher loads .env itself. The framework's secret
    # resolver will hand resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))

    config_errors: List[str] = []
    api_url = os.environ.get("SENTINELONE_API_URL", "").strip()
    if not api_url:
        config_errors.append(
            "SENTINELONE_API_URL is not set (no default — console hostnames are tenant-specific)"
        )
    api_token = os.environ.get("SENTINELONE_API_TOKEN", "").strip()
    if not api_token:
        config_errors.append("SENTINELONE_API_TOKEN is not set")

    raw_days = os.environ.get("SENTINELONE_REPORTING_PERIOD_DAYS", "").strip()
    reporting_period_days = 30
    if raw_days:
        try:
            reporting_period_days = int(raw_days)
        except ValueError:
            config_errors.append(
                f"SENTINELONE_REPORTING_PERIOD_DAYS is not an integer: {raw_days!r}"
            )
    if reporting_period_days <= 0:
        config_errors.append(
            f"SENTINELONE_REPORTING_PERIOD_DAYS must be positive, got {reporting_period_days}"
        )

    scope_ids = os.environ.get("SENTINELONE_SCOPE_IDS", "").strip() or None
    include_accepted = parse_bool(os.environ.get("SENTINELONE_INCLUDE_ACCEPTED"), default=False)

    if config_errors:
        for message in config_errors:
            logger.error("%s", message)
        result = {
            "status": "error",
            "api_endpoint": None,
            "collected_at": current_timestamp(),
            "config_errors": config_errors,
            "api_failures": [],
            "vulnerabilities": [],
            "raw_records": [],
        }
        output_path = write_output(output_dir, result)
        logger.info("Evidence saved to %s", output_path)
        reason = "invalid configuration: " + "; ".join(config_errors)
        logger.error("%s", reason)
        report_failure(reason, "bad_config")
        return 1

    result = collect(
        api_url=api_url,
        api_token=api_token,
        reporting_period_days=reporting_period_days,
        scope_ids=scope_ids,
        include_accepted=include_accepted,
    )

    output_path = write_output(output_dir, result)
    logger.info("Evidence saved to %s", output_path)

    if result["api_failures"]:
        reason = (
            f"{len(result['api_failures'])} API failure(s) during collection; "
            f"first: {result['api_failures'][0].get('type')} "
            f"{result['api_failures'][0].get('message', '')[:160]}"
        )
        logger.error("%s", reason)
        report_failure(
            reason,
            failure_code(result["api_failures"], result["collection"]["records_returned_by_api"]),
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
