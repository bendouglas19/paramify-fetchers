#!/usr/bin/env python3
"""
KSI-MLA-01 / KSI-CMT-01: GCP Cloud Logging Configuration

The GCP analogue of the AWS cloudtrail_configuration evidence set. For one
project: every log sink (destination, filter, whether it exports everything,
whether it is disabled), every log bucket (retention days, locked, CMEK,
lifecycle state), the project-level log-router CMEK/storage settings, and the
log-based metrics paired with the alert policies that fire on them — the GCP
shape of "a metric filter with an alarm on it".

Ported from Prowler's GCP logging + monitoring services (prowler/providers/gcp/
services/logging/logging_service.py and .../monitoring/monitoring_service.py,
Apache-2.0). Prowler's Sink projects name/destination/filter/include_children,
its Metric projects name/type/filter/bucket_name, and its AlertPolicy projects
display_name/enabled/filters (unwrapping the four condition types); the bucket,
retention, locked, and CMEK fields come from logging buckets.list, which its
checks don't need.

Departures from the Prowler original:
- **GAPIC clients, not discovery.** logging_v2 (ConfigServiceV2 / MetricsServiceV2)
  and monitoring_v3 (AlertPolicyService) instead of googleapiclient.discovery,
  per the category's preference.
- **Ancestor sinks are resolved, not assumed.** Prowler collects org-level sinks
  for every scanned project's organization. Here the project's ancestry is walked
  (Resource Manager v3) and sinks are listed at each ancestor, so a project nested
  under folders is covered too. Those reads sit outside the project, so a
  project-scoped read-only role legitimately 403s on them: they are tolerated and
  recorded in metadata.skipped_calls rather than failing the collection.
- **No verdict on filter coverage.** Prowler's `_sink_delivers_activity_logs`
  decides whether a non-trivial filter *provably* exports the whole Admin Activity
  stream, because it has to flip a CIS check to PASS. A fetcher collects facts, so
  the filter is reported verbatim alongside two plain observations
  (`exports_all_logs`, `filters_on_audit_logs`) and the judgment is left to a
  validator.

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
    access_denied,
    basename,
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

logger = logging.getLogger("gcp_cloud_logging_configuration")

# GCP allows at most 10 levels of folders between a project and its organization,
# so the ancestry walk is bounded by the platform, not by a guess.
_MAX_ANCESTRY_DEPTH = 10

# Destination prefixes the log router supports, longest-lived first.
_DESTINATION_TYPES = (
    ("logging.googleapis.com", "log_bucket"),
    ("storage.googleapis.com", "cloud_storage"),
    ("bigquery.googleapis.com", "bigquery"),
    ("pubsub.googleapis.com", "pubsub"),
)


# --- pure transforms (operate on to_dict() output; unit-tested from fixtures) ---

def destination_type(destination: str | None) -> str | None:
    """Which sink destination service a sink writes to."""
    for prefix, kind in _DESTINATION_TYPES:
        if (destination or "").startswith(prefix):
            return kind
    return "other" if destination else None


def exports_all_logs(sink_filter: str | None) -> bool:
    """True when the sink's filter excludes nothing.

    An absent or empty filter exports every log entry in scope; Prowler spells
    the same condition as `filter == "all"` because its discovery response
    defaults a missing filter to that literal.
    """
    normalized = (sink_filter or "").strip().lower()
    return normalized in ("", "all")


def filters_on_audit_logs(sink_filter: str | None) -> bool:
    """True when the filter names a Cloud Audit log stream at all.

    Reported as an observation, not a coverage verdict: a filter can name the
    Admin Activity stream and still narrow it with AND / NOT / severity clauses.
    Sink filters may carry the stream URL-encoded, so normalize %2F first.
    """
    normalized = (sink_filter or "").replace("%2F", "/").replace("%2f", "/").lower()
    return "cloudaudit.googleapis.com/" in normalized


def location_of(resource_name: str | None) -> str | None:
    """The `locations/<loc>` segment of a log-bucket resource path."""
    parts = (resource_name or "").split("/")
    if "locations" in parts:
        index = parts.index("locations") + 1
        if index < len(parts):
            return parts[index]
    return None


def sink_record(sink: dict, scope: str = "project") -> dict:
    """Normalize one log sink into an evidence record.

    `scope` is where the sink is defined — "project", or the ancestor resource
    ("organizations/123", "folders/456"). An ancestor sink only covers this
    project when include_children is set.
    """
    sink_filter = dig_any(sink, "filter") or None
    return {
        "name": basename(dig_any(sink, "name")),
        "scope": scope,
        "destination": dig_any(sink, "destination") or None,
        "destination_type": destination_type(dig_any(sink, "destination")),
        "filter": sink_filter,
        "exports_all_logs": exports_all_logs(sink_filter),
        "filters_on_audit_logs": filters_on_audit_logs(sink_filter),
        "disabled": bool(dig_any(sink, "disabled")),
        "include_children": bool(dig_any(sink, "include_children")),
        "writer_identity": dig_any(sink, "writer_identity") or None,
        "exclusions": sorted(
            dig_any(exclusion, "name") or "" for exclusion in (dig_any(sink, "exclusions") or [])
        ),
        "description": dig_any(sink, "description") or None,
    }


def bucket_record(bucket: dict) -> dict:
    """Normalize one log bucket into an evidence record.

    CMEK is the PRESENCE of cmek_settings.kms_key_name (absent ⇒ the
    Google-managed default, as everywhere else in GCP). `locked` is the
    tamper-resistance fact: a locked bucket's retention cannot be shortened and
    the bucket cannot be deleted.
    """
    kms = dig_any(bucket, "cmek_settings", "kms_key_name") or None
    name = dig_any(bucket, "name")
    return {
        "name": basename(name),
        "resource_name": name,
        "location": location_of(name),
        "retention_days": dig_any(bucket, "retention_days"),
        "locked": bool(dig_any(bucket, "locked")),
        "lifecycle_state": dig_any(bucket, "lifecycle_state") or None,
        "analytics_enabled": bool(dig_any(bucket, "analytics_enabled")),
        "cmek": kms is not None,
        "kms_key_name": kms,
        "restricted_field_count": len(dig_any(bucket, "restricted_fields") or []),
        "index_config_count": len(dig_any(bucket, "index_configs") or []),
        "description": dig_any(bucket, "description") or None,
    }


def alert_policy_record(policy: dict) -> dict:
    """Normalize one monitoring alert policy into an evidence record.

    The filter (or MQL/PromQL query) is what ties a policy to a log-based metric,
    and it lives under one of five condition shapes — the same unwrapping
    Prowler's monitoring service does, plus the PromQL condition it predates.
    """
    filters = []
    for condition in dig_any(policy, "conditions") or []:
        for shape, key in (
            ("condition_threshold", "filter"),
            ("condition_absent", "filter"),
            ("condition_matched_log", "filter"),
            ("condition_monitoring_query_language", "query"),
            ("condition_prometheus_query_language", "query"),
        ):
            value = dig_any(condition, shape, key)
            if value:
                filters.append(value)
    return {
        "name": basename(dig_any(policy, "name")),
        "display_name": dig_any(policy, "display_name") or None,
        "enabled": bool(dig_any(policy, "enabled")),
        "condition_filters": filters,
        "condition_count": len(dig_any(policy, "conditions") or []),
        "notification_channel_count": len(dig_any(policy, "notification_channels") or []),
        "severity": dig_any(policy, "severity") or None,
    }


def metric_record(metric: dict, alert_policies: list[dict] | None = None) -> dict:
    """Normalize one log-based metric, linked to the policies that alert on it.

    A metric with no alert policy referencing it detects nothing — the pairing is
    the evidence, which is why Prowler's CIS logging checks test both.
    """
    name = dig_any(metric, "name")
    alerting = sorted(
        p["display_name"] or p["name"] or ""
        for p in (alert_policies or [])
        if any(name and name in f for f in p["condition_filters"])
    )
    return {
        "name": name,
        "metric_type": dig_any(metric, "metric_descriptor", "type") or None,
        "filter": dig_any(metric, "filter") or None,
        # Set on a bucket-scoped metric: the metric counts entries in that log
        # bucket rather than the project's stream.
        "bucket_name": dig_any(metric, "bucket_name") or None,
        "disabled": bool(dig_any(metric, "disabled")),
        "alerted": bool(alerting),
        "alerting_policies": alerting,
        "description": dig_any(metric, "description") or None,
    }


def project_captures_all_logs(sinks: list[dict]) -> bool:
    """True when some enabled sink exports every log entry for this project.

    A project-scope sink covers the project directly; an ancestor sink only counts
    with include_children. This is Prowler's `logging_sink_created` rule, kept as
    a summary fact because it is the one question the AWS CloudTrail evidence set
    also answers ("is everything being exported somewhere?").
    """
    for sink in sinks:
        if sink["disabled"] or not sink["exports_all_logs"]:
            continue
        if sink["scope"] == "project" or sink["include_children"]:
            return True
    return False


def summarize(
    sinks: list[dict],
    buckets: list[dict],
    metrics: list[dict],
    alert_policies: list[dict],
    settings: dict,
) -> dict:
    cmek_buckets = sum(1 for b in buckets if b["cmek"])
    retentions = [b["retention_days"] for b in buckets if b["retention_days"]]
    return {
        "total_sinks": len(sinks),
        "project_sinks": sum(1 for s in sinks if s["scope"] == "project"),
        "ancestor_sinks": sum(1 for s in sinks if s["scope"] != "project"),
        "enabled_sinks": sum(1 for s in sinks if not s["disabled"]),
        "sinks_exporting_all_logs": sum(1 for s in sinks if s["exports_all_logs"]),
        "sinks_filtering_audit_logs": sum(1 for s in sinks if s["filters_on_audit_logs"]),
        "all_logs_captured_by_a_sink": project_captures_all_logs(sinks),
        "total_log_buckets": len(buckets),
        "locked_log_buckets": sum(1 for b in buckets if b["locked"]),
        "cmek_log_buckets": cmek_buckets,
        "cmek_log_bucket_percentage": coverage_percentage(cmek_buckets, len(buckets)),
        "shortest_retention_days": min(retentions) if retentions else None,
        "longest_retention_days": max(retentions) if retentions else None,
        "log_router_cmek_key": settings.get("kms_key_name"),
        "log_router_storage_location": settings.get("storage_location"),
        "default_sink_disabled": settings.get("disable_default_sink"),
        "total_log_metrics": len(metrics),
        "alerted_log_metrics": sum(1 for m in metrics if m["alerted"]),
        "total_alert_policies": len(alert_policies),
        "enabled_alert_policies": sum(1 for p in alert_policies if p["enabled"]),
    }


def settings_record(settings: dict | None) -> dict:
    """Project-level log-router settings: CMEK, storage location, default sink."""
    settings = settings or {}
    return {
        "kms_key_name": dig_any(settings, "kms_key_name") or None,
        "kms_service_account": dig_any(settings, "kms_service_account_id") or None,
        "storage_location": dig_any(settings, "storage_location") or None,
        "disable_default_sink": bool(dig_any(settings, "disable_default_sink")),
    }


# --- collection (lazy google imports; not exercised by the fixture tests) ---

def _config_client(creds):
    from google.cloud import logging_v2

    return logging_v2.services.config_service_v2.ConfigServiceV2Client(credentials=creds)


def _outside_project_scope(exc: BaseException) -> bool:
    """`guard(tolerate=...)` predicate for the reads that sit above the project.

    Resource-hierarchy and ancestor-sink reads are not in a project-scoped
    read-only role's grant, and the Resource Manager API may not be enabled at
    all. Either way the project-level evidence is still complete, so these are
    recorded as skipped rather than failing the collection.
    """
    return access_denied(exc) or service_disabled(exc)


def collect_ancestry(project, creds, collector: Collector) -> list[str]:
    """The project's ancestors, nearest first (e.g. folders/1, organizations/2).

    Reading the resource hierarchy is outside a project-scoped role's grant, so a
    403 here is tolerated: the evidence then covers project-level sinks only and
    says so in metadata.skipped_calls.
    """
    from google.cloud import resourcemanager_v3

    def _parent_of_project():
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        return client.get_project(name=f"projects/{project}").parent or ""

    parent = collector.guard(
        "cloudresourcemanager.projects.get (ancestry)",
        _parent_of_project,
        default="",
        tolerate=_outside_project_scope,
    )

    ancestors: list[str] = []
    while parent and len(ancestors) < _MAX_ANCESTRY_DEPTH:
        ancestors.append(parent)
        if parent.startswith("organizations/"):
            break

        def _parent_of_folder(folder=parent):
            client = resourcemanager_v3.FoldersClient(credentials=creds)
            return client.get_folder(name=folder).parent or ""

        parent = collector.guard(
            f"cloudresourcemanager.folders.get ({parent})",
            _parent_of_folder,
            default="",
            tolerate=_outside_project_scope,
        )
    return ancestors


def collect_sinks(project, creds, collector: Collector, ancestors: list[str]) -> list[dict]:
    """Sinks defined on the project, plus any defined on its ancestors."""
    from google.cloud import logging_v2

    def _lister(parent, scope):
        """A no-arg callable for guard(), bound to one parent resource."""
        def _call():
            client = _config_client(creds)
            # The GAPIC pager iterates every page; no manual page-token loop.
            return [
                sink_record(logging_v2.types.LogSink.to_dict(s, use_integers_for_enums=False), scope)
                for s in client.list_sinks(parent=parent)
            ]

        return _call

    records = collector.guard(
        "logging.sinks.list", _lister(f"projects/{project}", "project"), default=[]
    )
    for ancestor in ancestors:
        records += collector.guard(
            f"logging.sinks.list ({ancestor})",
            _lister(ancestor, ancestor),
            default=[],
            tolerate=_outside_project_scope,
        )
    return sorted(records, key=lambda r: (r.get("scope") or "", r.get("name") or ""))


def collect_buckets(project, creds, collector: Collector) -> list[dict]:
    from google.cloud import logging_v2

    def _list():
        client = _config_client(creds)
        # locations/- covers every log bucket location (global, regional) at once.
        return [
            bucket_record(logging_v2.types.LogBucket.to_dict(b, use_integers_for_enums=False))
            for b in client.list_buckets(parent=f"projects/{project}/locations/-")
        ]

    records = collector.guard("logging.buckets.list", _list, default=[])
    return sorted(records, key=lambda r: (r.get("location") or "", r.get("name") or ""))


def collect_settings(project, creds, collector: Collector) -> dict:
    from google.cloud import logging_v2

    def _get():
        client = _config_client(creds)
        return logging_v2.types.Settings.to_dict(
            client.get_settings(name=f"projects/{project}"), use_integers_for_enums=False
        )

    return settings_record(collector.guard("logging.settings.get", _get, default={}))


def collect_alert_policies(project, creds, collector: Collector) -> list[dict]:
    from google.cloud import monitoring_v3

    def _list():
        client = monitoring_v3.AlertPolicyServiceClient(credentials=creds)
        return [
            alert_policy_record(
                monitoring_v3.AlertPolicy.to_dict(p, use_integers_for_enums=False)
            )
            for p in client.list_alert_policies(name=f"projects/{project}")
        ]

    records = collector.guard("monitoring.alertPolicies.list", _list, default=[])
    return sorted(records, key=lambda r: r.get("display_name") or r.get("name") or "")


def collect_metrics(project, creds, collector: Collector, alert_policies: list[dict]) -> list[dict]:
    from google.cloud import logging_v2

    def _list():
        client = logging_v2.services.metrics_service_v2.MetricsServiceV2Client(credentials=creds)
        return [
            metric_record(
                logging_v2.types.LogMetric.to_dict(m, use_integers_for_enums=False),
                alert_policies,
            )
            for m in client.list_log_metrics(parent=f"projects/{project}")
        ]

    records = collector.guard("logging.metrics.list", _list, default=[])
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

    sinks: list[dict] = []
    buckets: list[dict] = []
    metrics: list[dict] = []
    alert_policies: list[dict] = []
    settings = settings_record({})
    ancestors: list[str] = []
    if project and creds is not None:
        ancestors = collect_ancestry(project, creds, collector)
        sinks = collect_sinks(project, creds, collector, ancestors)
        buckets = collect_buckets(project, creds, collector)
        settings = collect_settings(project, creds, collector)
        # Metrics are matched against the alert policies, so policies come first.
        alert_policies = collect_alert_policies(project, creds, collector)
        metrics = collect_metrics(project, creds, collector, alert_policies)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={
            "ancestry": ancestors,
            "sinks": sinks,
            "log_buckets": buckets,
            "log_router_settings": settings,
            "log_metrics": metrics,
            "alert_policies": alert_policies,
        },
        summary=summarize(sinks, buckets, metrics, alert_policies, settings),
    )

    filename = f"gcp_cloud_logging_configuration_{sanitize_for_filename(project or 'unknown')}.json"
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
