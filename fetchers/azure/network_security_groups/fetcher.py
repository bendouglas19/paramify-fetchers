#!/usr/bin/env python3
"""
KSI-CNA-01 / KSI-CNA-02 / KSI-CNA-03 / KSI-CNA-05: Azure network traffic controls

For one subscription, collects every network security group with its inline
security rules, and every virtual network with its subnets' NSG association and
DDoS protection state. Together these evidence the four things a reviewer asks of
an Azure network: inbound/outbound traffic is controlled, no admin port (SSH/RDP)
is open to the Internet, every subnet is actually behind an NSG, and DDoS
protection is on.

Field projections are ported verbatim from Prowler's
prowler/providers/azure/services/network/network_service.py (Apache-2.0), which
reads the same azure-mgmt-network SDK. The "open to the Internet" match replicates
prowler/providers/azure/services/network/network_ssh_internet_access_restricted.

Single-subscription per invocation; fanout across subscriptions happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    first,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    to_dict,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_network_security_groups")

# Prowler's match set for "the whole Internet" as a rule source, and for "any
# protocol". Kept as literals so the evidence's own summary math matches what a
# Prowler run would flag.
INTERNET_SOURCE_PREFIXES = ("Internet", "*", "0.0.0.0/0")
ANY_TCP_PROTOCOLS = ("TCP", "Tcp", "*")

# The admin ports the summary counts Internet exposure for.
ADMIN_PORTS = {"ssh": 22, "rdp": 3389}


# --- pure transforms (operate on as_dict()-shaped dicts; unit-tested from fixtures) ---

def _prop(obj: dict, *names: str):
    """Read a field azure-mgmt flattens out of the wire `properties` bag.

    `Model.as_dict()` hoists `properties.*` to top-level snake_case attributes;
    `serialize()` / raw REST keep them nested under "properties" in camelCase.
    """
    val = first(obj, *names)
    if val is not None:
        return val
    nested = obj.get("properties") if isinstance(obj, dict) else None
    return first(nested, *names)


def security_rule_record(rule: dict) -> dict:
    """Normalize one NSG security rule — Prowler's exact six-field projection.

    Prowler defaults `access` to "Allow" and `direction` to "Inbound" when absent,
    which is the conservative reading (assume the rule is permitting inbound
    traffic unless the API says otherwise). `destination_port_ranges` /
    `source_address_prefixes` (the plural, list-valued forms) are carried too:
    Prowler's checks only read the singular form, but a rule that uses the plural
    form has the singular set to null, so without them the evidence would silently
    show an empty port for a real open rule.
    """
    return {
        "id": first(rule, "id"),
        "name": first(rule, "name"),
        "destination_port_range": _prop(rule, "destination_port_range", "destinationPortRange"),
        "destination_port_ranges": _prop(rule, "destination_port_ranges", "destinationPortRanges")
        or [],
        "protocol": _prop(rule, "protocol"),
        "source_address_prefix": _prop(rule, "source_address_prefix", "sourceAddressPrefix"),
        "source_address_prefixes": _prop(rule, "source_address_prefixes", "sourceAddressPrefixes")
        or [],
        "access": _prop(rule, "access") or "Allow",
        "direction": _prop(rule, "direction") or "Inbound",
    }


def security_group_record(group: dict) -> dict:
    """Normalize one NSG with its inline rules."""
    resource_id = first(group, "id")
    return {
        "id": resource_id,
        "name": first(group, "name"),
        "location": first(group, "location"),
        "resource_group": resource_group_from_id(resource_id),
        "security_rules": [
            security_rule_record(rule)
            for rule in (_prop(group, "security_rules", "securityRules") or [])
        ],
    }


def subnet_record(subnet: dict) -> dict:
    """Normalize one VNet subnet with the id of the NSG attached to it (or None)."""
    nsg = _prop(subnet, "network_security_group", "networkSecurityGroup") or {}
    return {
        "id": first(subnet, "id"),
        "name": first(subnet, "name"),
        "nsg_id": first(nsg, "id"),
    }


def virtual_network_record(vnet: dict) -> dict:
    """Normalize one virtual network with its subnets and DDoS protection state."""
    resource_id = first(vnet, "id")
    return {
        "id": resource_id,
        "name": first(vnet, "name"),
        "location": first(vnet, "location"),
        "resource_group": resource_group_from_id(resource_id),
        "enable_ddos_protection": bool(
            _prop(vnet, "enable_ddos_protection", "enableDdosProtection") or False
        ),
        "subnets": [subnet_record(s) for s in (_prop(vnet, "subnets") or [])],
    }


def _port_in_range(port_range, port: int) -> bool:
    """Does a rule's destination port range cover `port`?

    Prowler's condition, verbatim: an exact match on the port, or a "low-high"
    range that spans it. Extended with "*" (any port), which the SDK also returns
    and which unambiguously covers every port.
    """
    if not port_range:
        return False
    text = str(port_range).strip()
    if text == "*":
        return True
    if text == str(port):
        return True
    if "-" in text:
        low, _, high = text.partition("-")
        try:
            return int(low) <= port <= int(high)
        except ValueError:
            return False
    return False


def rule_opens_port_to_internet(rule: dict, port: int) -> bool:
    """Prowler's fail condition for "port <n> reachable from the Internet".

    All five clauses must hold: the destination port range covers the port, the
    protocol is TCP or any, the source is the whole Internet, the action is Allow,
    and the direction is Inbound.
    """
    ranges = [rule.get("destination_port_range"), *(rule.get("destination_port_ranges") or [])]
    sources = [rule.get("source_address_prefix"), *(rule.get("source_address_prefixes") or [])]
    return (
        any(_port_in_range(r, port) for r in ranges)
        and rule.get("protocol") in ANY_TCP_PROTOCOLS
        and any(s in INTERNET_SOURCE_PREFIXES for s in sources)
        and rule.get("access") == "Allow"
        and rule.get("direction") == "Inbound"
    )


def summarize(security_groups: list[dict], virtual_networks: list[dict]) -> dict:
    """Counts a reviewer reads first: admin ports exposed, subnets left unprotected."""
    rules = [rule for g in security_groups for rule in g["security_rules"]]
    subnets = [s for v in virtual_networks for s in v["subnets"]]
    associated = sum(1 for s in subnets if s["nsg_id"])

    exposure = {
        f"{label}_open_to_internet_groups": sum(
            1
            for g in security_groups
            if any(rule_opens_port_to_internet(r, port) for r in g["security_rules"])
        )
        for label, port in ADMIN_PORTS.items()
    }

    return {
        "total_network_security_groups": len(security_groups),
        "total_security_rules": len(rules),
        "inbound_allow_rules": sum(
            1 for r in rules if r["direction"] == "Inbound" and r["access"] == "Allow"
        ),
        "internet_sourced_allow_rules": sum(
            1
            for r in rules
            if r["access"] == "Allow"
            and r["direction"] == "Inbound"
            and (
                r["source_address_prefix"] in INTERNET_SOURCE_PREFIXES
                or any(s in INTERNET_SOURCE_PREFIXES for s in r["source_address_prefixes"])
            )
        ),
        **exposure,
        "total_virtual_networks": len(virtual_networks),
        "ddos_protected_virtual_networks": sum(
            1 for v in virtual_networks if v["enable_ddos_protection"]
        ),
        "total_subnets": len(subnets),
        "subnets_with_nsg": associated,
        "subnets_without_nsg": len(subnets) - associated,
        "subnet_nsg_coverage_percentage": coverage_percentage(associated, len(subnets)),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_network(subscription_id, cred, collector: Collector) -> tuple[list[dict], list[dict]]:
    """Two subscription-wide list calls: NSGs (with inline rules) and VNets.

    `list_all()` is the subscription-scoped variant (vs `list(resource_group)`) and
    returns an ItemPaged, so the SDK follows nextLink itself.
    """
    from azure.mgmt.network import NetworkManagementClient

    def _client():
        return NetworkManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("network.NetworkManagementClient (init)", _client)
    if client is None:
        return [], []

    groups = collector.guard(
        "network.network_security_groups.list_all",
        lambda: [
            security_group_record(to_dict(g)) for g in client.network_security_groups.list_all()
        ],
        default=[],
    )
    vnets = collector.guard(
        "network.virtual_networks.list_all",
        lambda: [virtual_network_record(to_dict(v)) for v in client.virtual_networks.list_all()],
        default=[],
    )

    return (
        sorted(groups, key=lambda r: r.get("id") or ""),
        sorted(vnets, key=lambda r: r.get("id") or ""),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which
    # buries this fetcher's own lines and would dominate the runner's stderr tail.
    # Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    security_groups: list[dict] = []
    virtual_networks: list[dict] = []
    if subscription_id and cred is not None:
        security_groups, virtual_networks = collect_network(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "network_security_groups": security_groups,
            "virtual_networks": virtual_networks,
        },
        summary=summarize(security_groups, virtual_networks),
    )

    filename = (
        f"azure_network_security_groups_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        logger.error(
            "Encountered %d Azure API failure(s) during collection", len(collector.failures)
        )
        write_status(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
