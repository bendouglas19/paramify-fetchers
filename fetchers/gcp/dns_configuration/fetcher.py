#!/usr/bin/env python3
"""
GCP Cloud DNS Configuration

Every Cloud DNS managed zone in one project: whether DNSSEC is on, which
algorithms sign the keys and the zone, whether the zone is public or private, and
whether query logging is enabled — plus the project's DNS policies, which is where
logging and inbound forwarding are configured network-wide.

The findings this evidence exists to surface:
- **DNSSEC off on a public zone** — the zone's answers can be spoofed on the way
  to a resolver. Prowler's dns_dnssec_disabled.
- **RSASHA1 as the key-signing or zone-signing algorithm** — a broken hash in the
  signing chain, so DNSSEC is technically on and cryptographically hollow.
  Prowler splits this into dns_rsasha1_in_use_to_key_sign_in_dnssec and
  dns_rsasha1_in_use_to_zone_sign_in_dnssec because the two key types are
  configured separately and either can be weak on its own.
- **No query logging** — DNS queries are the earliest signal of a compromised
  workload calling home, and Cloud DNS does not log them by default.

Visibility is collected because it changes what the other facts mean: DNSSEC does
not apply to a private zone at all (there is no public resolution path to
protect), so a private zone with DNSSEC off is not the same finding as a public one
with DNSSEC off. Prowler's check does not make that distinction, and the summary
here reports DNSSEC coverage over public zones for exactly that reason.

Ported from Prowler's GCP DNS service (prowler/providers/gcp/services/dns/
dns_service.py, Apache-2.0), whose ManagedZone projects name/id/dnssec (state ==
"on")/key_specs and whose Policy projects name/id/logging/networks.

Departures from the Prowler original:
- **Discovery client, deliberately.** The Cloud DNS API has no GAPIC client that
  exposes dnssecConfig — the handwritten google-cloud-dns library predates DNSSEC
  and does not surface it — so this uses googleapiclient.discovery (dns v1), the
  same client Prowler uses and the same exception the Cloud SQL fetcher makes.
- **The DNSSEC state is reported, not flattened to a boolean.** Prowler collapses
  the state to `dnssec = state == "on"`, which loses "transfer" — a zone
  mid-migration between DNSSEC providers, which is neither on nor simply off.
- **Zone visibility, logging, and the private/forwarding/peering topology are
  collected.** Prowler's zone model carries none of them.
- **Zone-level logging is separated from policy-level logging.** Prowler reads
  `enableLogging` off DNS policies only. A managed zone carries its own
  cloudLoggingConfig, and that is the one that governs queries against that zone.

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

logger = logging.getLogger("gcp_dns_configuration")

# The signing algorithm that is the finding. SHA-1 is collision-broken, so a
# signature chain rooted in it proves nothing.
_WEAK_ALGORITHMS = frozenset({"rsasha1"})

# Cloud DNS key spec types. Key-signing and zone-signing keys are configured
# independently and either can be the weak one.
_KEY_SIGNING = "keySigning"
_ZONE_SIGNING = "zoneSigning"

# DNSSEC only protects public resolution; a private zone has no public path.
_PUBLIC_VISIBILITY = "public"


# --- pure transforms (operate on REST-style dicts; unit-tested from fixtures) ---

def key_spec_record(spec: dict) -> dict:
    """One DNSSEC key spec: which key it signs, with what, at what length."""
    algorithm = (dig_any(spec, "algorithm") or "").lower() or None
    return {
        "key_type": dig_any(spec, "key_type") or None,
        "algorithm": algorithm,
        "key_length": dig_any(spec, "key_length"),
        "weak_algorithm": algorithm in _WEAK_ALGORITHMS,
    }


def algorithms_for(specs: list[dict], key_type: str) -> list[str]:
    """The algorithms configured for one key type, deduplicated and sorted."""
    return sorted(
        {s["algorithm"] for s in specs if s["key_type"] == key_type and s["algorithm"]}
    )


def zone_record(zone: dict) -> dict:
    """Normalize one managed zone into an evidence record.

    `visibility` defaults to public: the API omits the field on a public zone, and
    guessing "private" for an absent value would understate the exposure.
    """
    specs = [key_spec_record(s) for s in (dig_any(zone, "dnssec_config", "default_key_specs") or [])]
    # "on" | "off" | "transfer". Prowler tests == "on" and loses "transfer", a zone
    # mid-migration between DNSSEC providers.
    state = (dig_any(zone, "dnssec_config", "state") or "").lower() or None
    visibility = (dig_any(zone, "visibility") or _PUBLIC_VISIBILITY).lower()

    key_signing = algorithms_for(specs, _KEY_SIGNING)
    zone_signing = algorithms_for(specs, _ZONE_SIGNING)
    rsasha1_key = any(a in _WEAK_ALGORITHMS for a in key_signing)
    rsasha1_zone = any(a in _WEAK_ALGORITHMS for a in zone_signing)

    private = dig_any(zone, "private_visibility_config") or {}

    return {
        "name": dig_any(zone, "name") or None,
        "id": dig_any(zone, "id") or None,
        "dns_name": dig_any(zone, "dns_name") or None,
        "description": dig_any(zone, "description") or None,
        "creation_time": dig_any(zone, "creation_time") or None,
        "visibility": visibility,
        "public": visibility == _PUBLIC_VISIBILITY,
        # A private zone has no public resolution path, so DNSSEC does not apply.
        "dnssec_applicable": visibility == _PUBLIC_VISIBILITY,
        "dnssec_state": state,
        "dnssec_enabled": state == "on",
        "dnssec_non_existence": dig_any(zone, "dnssec_config", "non_existence") or None,
        "key_specs": specs,
        "key_signing_algorithms": key_signing,
        "zone_signing_algorithms": zone_signing,
        # Prowler's two RSASHA1 checks, kept apart for the same reason it keeps
        # them apart: either key type can be the weak one.
        "rsasha1_key_signing": rsasha1_key,
        "rsasha1_zone_signing": rsasha1_zone,
        "uses_weak_signing_algorithm": rsasha1_key or rsasha1_zone,
        "logging_enabled": bool(dig_any(zone, "cloud_logging_config", "enable_logging")),
        "name_servers": sorted(dig_any(zone, "name_servers") or []),
        "name_server_set": dig_any(zone, "name_server_set") or None,
        "private_networks": sorted(
            basename(dig_any(net, "network_url")) or ""
            for net in (dig_any(private, "networks") or [])
        ),
        "private_gke_clusters": sorted(
            dig_any(cluster, "gke_cluster_name") or ""
            for cluster in (dig_any(private, "gke_clusters") or [])
        ),
        # A forwarding or peering zone hands resolution to somewhere else, which
        # is where the answers actually come from.
        "forwarding_targets": sorted(
            dig_any(target, "ipv4_address") or dig_any(target, "domain_name") or ""
            for target in (dig_any(zone, "forwarding_config", "target_name_servers") or [])
        ),
        "peering_target_network": basename(
            dig_any(zone, "peering_config", "target_network", "network_url")
        ),
        "reverse_lookup": dig_any(zone, "reverse_lookup_config") is not None,
    }


def policy_record(policy: dict) -> dict:
    """Normalize one DNS policy: logging and inbound forwarding, per network."""
    return {
        "name": dig_any(policy, "name") or None,
        "id": dig_any(policy, "id") or None,
        "description": dig_any(policy, "description") or None,
        "logging_enabled": bool(dig_any(policy, "enable_logging")),
        "inbound_forwarding_enabled": bool(dig_any(policy, "enable_inbound_forwarding")),
        "networks": sorted(
            basename(dig_any(net, "network_url")) or ""
            for net in (dig_any(policy, "networks") or [])
        ),
        "alternative_name_servers": sorted(
            dig_any(target, "ipv4_address") or dig_any(target, "domain_name") or ""
            for target in (
                dig_any(policy, "alternative_name_server_config", "target_name_servers") or []
            )
        ),
    }


def summarize(zones: list[dict], policies: list[dict], api_readable: bool = True) -> dict:
    public = [z for z in zones if z["public"]]
    signed_public = [z for z in public if z["dnssec_enabled"]]
    logged = [z for z in zones if z["logging_enabled"]]

    key_algorithms: dict[str, int] = {}
    zone_algorithms: dict[str, int] = {}
    for zone in zones:
        for algorithm in zone["key_signing_algorithms"]:
            key_algorithms[algorithm] = key_algorithms.get(algorithm, 0) + 1
        for algorithm in zone["zone_signing_algorithms"]:
            zone_algorithms[algorithm] = zone_algorithms.get(algorithm, 0) + 1

    return {
        # False means the Cloud DNS API is disabled or unreadable on this project,
        # not that the project has no zones.
        "dns_api_readable": api_readable,
        "total_managed_zones": len(zones),
        "public_zones": len(public),
        "private_zones": len(zones) - len(public),
        "dnssec_enabled_zones": sum(1 for z in zones if z["dnssec_enabled"]),
        "dnssec_transferring_zones": sum(1 for z in zones if z["dnssec_state"] == "transfer"),
        # Measured over PUBLIC zones only: DNSSEC does not apply to a private one,
        # so counting private zones as failures would misreport the posture.
        "dnssec_public_zone_percentage": coverage_percentage(len(signed_public), len(public)),
        "unsigned_public_zones": len(public) - len(signed_public),
        "zones_using_weak_signing_algorithm": sum(
            1 for z in zones if z["uses_weak_signing_algorithm"]
        ),
        "rsasha1_key_signing_zones": sum(1 for z in zones if z["rsasha1_key_signing"]),
        "rsasha1_zone_signing_zones": sum(1 for z in zones if z["rsasha1_zone_signing"]),
        "key_signing_algorithms": dict(sorted(key_algorithms.items())),
        "zone_signing_algorithms": dict(sorted(zone_algorithms.items())),
        "logging_enabled_zones": len(logged),
        "logging_enabled_zone_percentage": coverage_percentage(len(logged), len(zones)),
        "forwarding_zones": sum(1 for z in zones if z["forwarding_targets"]),
        "peering_zones": sum(1 for z in zones if z["peering_target_network"]),
        "total_dns_policies": len(policies),
        "logging_enabled_policies": sum(1 for p in policies if p["logging_enabled"]),
        "inbound_forwarding_policies": sum(
            1 for p in policies if p["inbound_forwarding_enabled"]
        ),
    }


# --- collection (lazy google imports; not exercised by the fixture tests) ---

def _service(creds):
    from googleapiclient.discovery import build

    return build("dns", "v1", credentials=creds, cache_discovery=False)


def _paginate(request_factory, key: str) -> list[dict]:
    """Walk a discovery list endpoint's pageToken chain to the end."""
    items: list[dict] = []
    page_token = None
    while True:
        response = request_factory(page_token).execute()
        items.extend(response.get(key) or [])
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return items


def collect_zones(project, creds, collector: Collector) -> tuple[list[dict], bool]:
    """Managed zones in the project.

    A project that never enabled dns.googleapis.com 403s with SERVICE_DISABLED,
    which is evidence ("this project serves no DNS"), so it is tolerated and
    reported as an unreadable API rather than as a collection failure.
    """
    def _list():
        service = _service(creds)
        zones = _paginate(
            lambda token: service.managedZones().list(project=project, pageToken=token),
            "managedZones",
        )
        return [zone_record(z) for z in zones]

    zones = collector.guard(
        "dns.managedZones.list", _list, default=None, tolerate=service_disabled
    )
    records = sorted(zones or [], key=lambda z: z.get("name") or "")
    return records, zones is not None


def collect_policies(project, creds, collector: Collector) -> list[dict]:
    def _list():
        service = _service(creds)
        policies = _paginate(
            lambda token: service.policies().list(project=project, pageToken=token),
            "policies",
        )
        return [policy_record(p) for p in policies]

    records = collector.guard(
        "dns.policies.list", _list, default=[], tolerate=service_disabled
    )
    return sorted(records, key=lambda p: p.get("name") or "")


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

    zones: list[dict] = []
    policies: list[dict] = []
    api_readable = False
    if project and creds is not None:
        zones, api_readable = collect_zones(project, creds, collector)
        policies = collect_policies(project, creds, collector)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"managed_zones": zones, "dns_policies": policies},
        summary=summarize(zones, policies, api_readable=api_readable),
    )

    filename = f"gcp_dns_configuration_{sanitize_for_filename(project or 'unknown')}.json"
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
