"""Fixture-based tests for the GCP compute-posture fetchers.

Covers `gcp_firewall_rules`, `gcp_compute_instance_configuration`,
`gcp_vpc_network_configuration` and `gcp_load_balancer_tls_configuration` — the
sibling of tests/test_gcp_encryption_fetchers.py and
tests/test_gcp_platform_fetchers.py for the Compute Engine network-exposure and
host-hardening evidence sets.

Like those modules, these exercise each fetcher's PURE transform functions (no
live API calls, no credentials, no google client libraries — the heavy google
imports live inside each fetcher's collect_*() and are never triggered here),
plus an end-to-end run with deliberately-broken credentials.

**Every fixture here is SYNTHETIC.** These four fetchers have had no live-tenant
run, so the fixtures are hand-built from the Compute Engine v1 resource shapes.
Each set covers a hardened resource and a default/unhardened one, because the
whole point is the fields that differ between them — and roughly half are written
in the REST camelCase spelling to prove the transforms tolerate either. The
snake_case spellings (including the odd ones: `I_p_protocol`, `nat_i_p`, `type_`,
`I_pv4_range`) were verified against google-cloud-compute's `to_dict()` output,
not guessed.

Run: pytest tests/test_gcp_compute_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GCP_ROOT = REPO_ROOT / "fetchers" / "gcp"

STATUS_CODES = {
    "auth_failed",
    "not_authorized",
    "target_unreachable",
    "rate_limited",
    "bad_config",
    "partial_failure",
    "internal_error",
}

COMPUTE_FETCHERS = [
    "firewall_rules",
    "compute_instance_configuration",
    "vpc_network_configuration",
    "load_balancer_tls_configuration",
]


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GCP_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"gcp_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Firewall rules — Firewall.to_dict() shape (snake_case, `I_p_protocol`) and the
# REST camelCase spelling (`IPProtocol`) of the same resource
# --------------------------------------------------------------------------- #

FW_DEFAULT_ALLOW_SSH = {  # SYNTHETIC — the default network's SSH hole
    "name": "default-allow-ssh",
    "id": "1",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/default",
    "direction": "INGRESS",
    "priority": 65534,
    "disabled": False,
    "source_ranges": ["0.0.0.0/0"],
    "allowed": [{"I_p_protocol": "tcp", "ports": ["22"]}],
    "log_config": {"enable": False},
}

FW_WEB_REST = {  # SYNTHETIC — REST camelCase; internet-facing but only 80/443
    "name": "web-https",
    "id": "2",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
    "direction": "INGRESS",
    "priority": 1000,
    "sourceRanges": ["0.0.0.0/0"],
    "targetTags": ["web"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}],
    "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"},
}

FW_ALLOW_EVERYTHING = {  # SYNTHETIC — protocol `all` from anywhere, no targets
    "name": "allow-everything",
    "id": "3",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/legacy-vpc",
    "direction": "INGRESS",
    "priority": 1000,
    "source_ranges": ["0.0.0.0/0"],
    "allowed": [{"I_p_protocol": "all"}],
    "log_config": {"enable": False},
}

FW_DISABLED_RDP = {  # SYNTHETIC — RDP to the world, but switched off
    "name": "legacy-rdp",
    "id": "4",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
    "direction": "INGRESS",
    "priority": 1000,
    "disabled": True,
    "sourceRanges": ["0.0.0.0/0"],
    "targetServiceAccounts": ["jump@example-prod.iam.gserviceaccount.com"],
    "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
}

FW_IPV6_ADMIN = {  # SYNTHETIC — ::/0 with a port RANGE spanning ftp/ssh/telnet
    "name": "v6-admin",
    "id": "5",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
    "direction": "INGRESS",
    "priority": 1000,
    "source_ranges": ["::/0"],
    "allowed": [{"I_p_protocol": "tcp", "ports": ["20-30"]}],
    "log_config": {"enable": True},
}

FW_INTERNAL = {  # SYNTHETIC — same shape, but sourced from RFC1918
    "name": "internal-app",
    "id": "6",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
    "direction": "INGRESS",
    "priority": 1000,
    "source_ranges": ["10.0.0.0/8"],
    "target_tags": ["app"],
    "allowed": [{"I_p_protocol": "tcp", "ports": ["3000-3100"]}],
    "log_config": {"enable": True},
}

FW_EGRESS_DENY = {  # SYNTHETIC — a deny rule; exposes nothing by construction
    "name": "deny-egress-all",
    "id": "7",
    "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod-vpc",
    "direction": "EGRESS",
    "priority": 65535,
    "destinationRanges": ["0.0.0.0/0"],
    "denied": [{"IPProtocol": "all"}],
    "logConfig": {"enable": True},
}

ALL_FIREWALLS = [
    FW_DEFAULT_ALLOW_SSH,
    FW_WEB_REST,
    FW_ALLOW_EVERYTHING,
    FW_DISABLED_RDP,
    FW_IPV6_ADMIN,
    FW_INTERNAL,
    FW_EGRESS_DENY,
]


def _firewall_records():
    fw = _load("firewall_rules")
    return fw, [fw.firewall_record(r) for r in ALL_FIREWALLS]


def test_firewall_port_spec_expansion():
    fw = _load("firewall_rules")
    assert fw.port_spec_covers("22", 22) is True
    assert fw.port_spec_covers("22", 23) is False
    assert fw.port_spec_covers("20-30", 22) is True
    assert fw.port_spec_covers("20-30", 31) is False
    assert fw.port_spec_covers("3389-3389", 3389) is True
    # A malformed entry must not raise — a bad rule can't take down collection.
    assert fw.port_spec_covers("not-a-port", 22) is False
    assert fw.port_spec_covers("", 22) is False


def test_firewall_protocol_rule_reads_both_protocol_spellings():
    fw = _load("firewall_rules")
    gapic = fw.protocol_rule({"I_p_protocol": "tcp", "ports": ["22"]})
    assert gapic == {"protocol": "tcp", "ports": ["22"], "all_ports": False}
    # REST spelling, and no `ports` key at all = every port of that protocol.
    rest = fw.protocol_rule({"IPProtocol": "tcp"})
    assert rest == {"protocol": "tcp", "ports": [], "all_ports": True}


def test_firewall_ssh_open_to_the_internet():
    """Prowler's compute_firewall_ssh_access_from_the_internet_allowed."""
    _fw, records = _firewall_records()
    ssh = records[0]
    assert ssh["direction"] == "INGRESS"
    assert ssh["network"] == "default"          # basename, not the self-link
    assert ssh["action"] == "allow"
    assert ssh["source_includes_internet"] is True
    assert ssh["open_to_internet"] is True
    assert ssh["internet_exposed_sensitive_services"] == ["ssh"]
    assert ssh["exposes_all_ports"] is False
    assert ssh["applies_to_all_instances"] is True
    assert ssh["logging_enabled"] is False


def test_firewall_internet_facing_web_ports_are_not_a_sensitive_exposure():
    """80/443 from anywhere is what a public web tier IS, not a finding."""
    _fw, records = _firewall_records()
    web = records[1]
    assert web["open_to_internet"] is True
    assert web["internet_exposed_sensitive_services"] == []
    # A target tag scopes the rule instead of hitting every instance.
    assert web["target_tags"] == ["web"]
    assert web["applies_to_all_instances"] is False
    assert web["logging_enabled"] is True
    assert web["log_metadata"] == "INCLUDE_ALL_METADATA"


def test_firewall_protocol_all_exposes_every_sensitive_port():
    _fw, records = _firewall_records()
    everything = records[2]
    assert everything["exposes_all_ports"] is True
    fw = _load("firewall_rules")
    assert everything["internet_exposed_sensitive_services"] == sorted(
        set(fw.SENSITIVE_PORTS.values())
    )


def test_firewall_disabled_rule_exposes_nothing():
    """The departure from Prowler: a switched-off rule is not an exposure."""
    _fw, records = _firewall_records()
    disabled = records[3]
    assert disabled["disabled"] is True
    assert disabled["enforced"] is False
    # The source range still says 0.0.0.0/0 — the fact is reported...
    assert disabled["source_includes_internet"] is True
    # ...but it is not counted as open.
    assert disabled["open_to_internet"] is False
    assert disabled["internet_exposed_sensitive_services"] == []
    assert disabled["target_service_accounts"] == [
        "jump@example-prod.iam.gserviceaccount.com"
    ]


def test_firewall_ipv6_any_address_counts_as_the_internet():
    """The second departure from Prowler, which only matches 0.0.0.0/0."""
    _fw, records = _firewall_records()
    v6 = records[4]
    assert v6["source_ranges"] == ["::/0"]
    assert v6["open_to_internet"] is True
    # 20-30 spans ftp (21), ssh (22) and telnet (23).
    assert v6["internet_exposed_sensitive_services"] == ["ftp", "ssh", "telnet"]


def test_firewall_private_source_and_egress_deny_are_not_exposures():
    _fw, records = _firewall_records()
    internal, egress = records[5], records[6]
    assert internal["source_includes_internet"] is False
    assert internal["open_to_internet"] is False
    assert internal["internet_exposed_sensitive_services"] == []

    assert egress["action"] == "deny"
    assert egress["allowed"] == []
    assert egress["denied"] == [{"protocol": "all", "ports": [], "all_ports": True}]
    assert egress["destination_ranges"] == ["0.0.0.0/0"]
    assert egress["open_to_internet"] is False


def test_firewall_summary_counts():
    fw, records = _firewall_records()
    summary = fw.summarize(records)
    assert summary["compute_api_readable"] is True
    assert summary["total_rules"] == 7
    assert summary["ingress_rules"] == 6
    assert summary["egress_rules"] == 1
    assert summary["allow_rules"] == 6
    assert summary["deny_rules"] == 1
    assert summary["disabled_rules"] == 1
    assert summary["rules_open_to_internet"] == 4
    # The headline count: ssh, allow-everything, v6-admin.
    assert summary["rules_exposing_sensitive_ports_to_internet"] == 3
    assert summary["ssh_open_to_internet"] is True
    assert summary["rdp_open_to_internet"] is True
    assert summary["rules_exposing_all_ports_to_internet"] == 1
    assert summary["internet_open_rules_applying_to_all_instances"] == 3
    assert summary["rules_with_logging_enabled"] == 4
    assert summary["logging_enabled_percentage"] == 57
    assert summary["networks_with_rules"] == ["default", "legacy-vpc", "prod-vpc"]


def test_firewall_summary_marks_an_unreadable_api():
    fw = _load("firewall_rules")
    summary = fw.summarize([], api_readable=False)
    assert summary["compute_api_readable"] is False
    assert summary["total_rules"] == 0
    assert summary["ssh_open_to_internet"] is False
    assert summary["logging_enabled_percentage"] == 0


# --------------------------------------------------------------------------- #
# Compute instances — Instance.to_dict() shape (snake_case, `nat_i_p`, `type_`)
# and the REST camelCase spelling (`natIP`, `type`)
# --------------------------------------------------------------------------- #

PROJECT_HARDENED = {  # SYNTHETIC — OS Login + 2FA enforced project-wide
    "common_instance_metadata": {
        "items": [
            {"key": "enable-oslogin", "value": "TRUE"},
            {"key": "enable-oslogin-2fa", "value": "true"},
        ]
    },
    "default_service_account": "111-compute@developer.gserviceaccount.com",
    "default_network_tier": "PREMIUM",
}

PROJECT_DEFAULT_REST = {  # SYNTHETIC — REST camelCase; no OS Login, shared keys
    "commonInstanceMetadata": {
        "items": [{"key": "ssh-keys", "value": "FIXTURE-NOT-A-REAL-SSH-KEY"}]
    },
    "defaultServiceAccount": "222-compute@developer.gserviceaccount.com",
}

HARDENED_INSTANCE = {  # SYNTHETIC — the posture a hardened VM reports
    "name": "app-1",
    "id": "11",
    "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
    "machine_type": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/machineTypes/n2-standard-4",
    "status": "RUNNING",
    "creation_timestamp": "2026-01-05T00:00:00.000-08:00",
    "tags": {"items": ["app", "internal"]},
    "shielded_instance_config": {
        "enable_secure_boot": True,
        "enable_vtpm": True,
        "enable_integrity_monitoring": True,
    },
    "confidential_instance_config": {
        "enable_confidential_compute": True,
        "confidential_instance_type": "SEV",
    },
    # The same block carries a startup script; the transform must read only the
    # hardening keys out of it.
    "metadata": {
        "items": [
            {"key": "block-project-ssh-keys", "value": "true"},
            {"key": "serial-port-enable", "value": "false"},
            {"key": "startup-script", "value": "FIXTURE-NOT-A-REAL-SECRET"},
        ]
    },
    "deletion_protection": True,
    "service_accounts": [
        {
            "email": "app@example-prod.iam.gserviceaccount.com",
            "scopes": [
                "https://www.googleapis.com/auth/logging.write",
                "https://www.googleapis.com/auth/devstorage.read_only",
            ],
        }
    ],
    "network_interfaces": [
        {
            "name": "nic0",
            "network": "https://x/projects/p/global/networks/prod-vpc",
            "subnetwork": "https://x/projects/p/regions/us-central1/subnetworks/app",
            "stack_type": "IPV4_ONLY",
            "nic_type": "GVNIC",
        }
    ],
    "scheduling": {
        "on_host_maintenance": "MIGRATE",
        "automatic_restart": True,
        "provisioning_model": "STANDARD",
    },
}

DEFAULT_INSTANCE_REST = {  # SYNTHETIC — REST camelCase, everything left at default
    "name": "legacy-vm",
    "id": "12",
    "zone": "https://x/projects/p/zones/us-east1-b",
    "machineType": "https://x/projects/p/zones/us-east1-b/machineTypes/e2-medium",
    "status": "RUNNING",
    # No shieldedInstanceConfig / confidentialInstanceConfig blocks at all — the
    # API omits them when unset.
    "metadata": {
        "items": [
            {"key": "serial-port-enable", "value": "1"},
            {"key": "enable-oslogin", "value": "FALSE"},
            {"key": "ssh-keys", "value": "FIXTURE-NOT-A-REAL-SSH-KEY"},
        ]
    },
    "canIpForward": True,
    "serviceAccounts": [
        {
            "email": "222-compute@developer.gserviceaccount.com",
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        }
    ],
    "networkInterfaces": [
        {
            "name": "nic0",
            "network": "https://x/projects/p/global/networks/default",
            "subnetwork": "https://x/projects/p/regions/us-east1/subnetworks/default",
            "accessConfigs": [
                {"name": "External NAT", "natIP": "203.0.113.10", "type": "ONE_TO_ONE_NAT"}
            ],
        },
        {
            "name": "nic1",
            "network": "https://x/projects/p/global/networks/mgmt",
            "subnetwork": "https://x/projects/p/regions/us-east1/subnetworks/mgmt",
        },
    ],
    "scheduling": {
        "onHostMaintenance": "TERMINATE",
        "preemptible": True,
        "provisioningModel": "SPOT",
    },
}

GKE_NODE_INSTANCE = {  # SYNTHETIC — a GKE node pool VM; default SA is required
    "name": "gke-prod-default-pool-3f2a-xk7q",
    "id": "13",
    "zone": "https://x/projects/p/zones/us-east1-b",
    "machine_type": "https://x/projects/p/zones/us-east1-b/machineTypes/e2-standard-2",
    "status": "RUNNING",
    "shielded_instance_config": {
        "enable_secure_boot": True,
        "enable_vtpm": True,
        "enable_integrity_monitoring": True,
    },
    "metadata": {"items": [{"key": "enable-oslogin", "value": "true"}]},
    "service_accounts": [
        {
            "email": "222-compute@developer.gserviceaccount.com",
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        }
    ],
    "network_interfaces": [
        {
            "name": "nic0",
            "network": "https://x/projects/p/global/networks/default",
            "subnetwork": "https://x/projects/p/regions/us-east1/subnetworks/default",
        }
    ],
}


def _instance_records():
    """(module, hardened, default, gke_node, hardened_project, default_project)."""
    vm = _load("compute_instance_configuration")
    hardened_project = vm.project_record(PROJECT_HARDENED)
    default_project = vm.project_record(PROJECT_DEFAULT_REST)
    return (
        vm,
        vm.instance_record(HARDENED_INSTANCE, hardened_project),
        vm.instance_record(DEFAULT_INSTANCE_REST, default_project),
        vm.instance_record(GKE_NODE_INSTANCE, default_project),
        hardened_project,
        default_project,
    )


def test_instance_metadata_truthiness_matches_the_api():
    vm = _load("compute_instance_configuration")
    for on in ("true", "TRUE", "True", "1", "yes"):
        assert vm.metadata_enabled(on) is True
    for off in ("false", "FALSE", "0", "", None, "maybe"):
        assert vm.metadata_enabled(off) is False


def test_instance_project_defaults_both_spellings():
    _vm, _h, _d, _g, hardened, default = _instance_records()
    assert hardened["os_login_enabled"] is True
    assert hardened["os_login_2fa_enabled"] is True
    assert hardened["default_service_account"].startswith("111-compute@")
    assert hardened["default_network_tier"] == "PREMIUM"
    assert hardened["project_wide_ssh_keys_present"] is False

    assert default["os_login_enabled"] is False
    assert default["os_login_2fa_enabled"] is False
    assert default["project_wide_ssh_keys_present"] is True


def test_instance_project_defaults_survive_a_failed_call():
    """A failed projects.get leaves the block present with everything off."""
    vm = _load("compute_instance_configuration")
    assert vm.project_record(None) == {
        "os_login_enabled": False,
        "os_login_2fa_enabled": False,
        "default_service_account": None,
        "default_network_tier": None,
        "project_wide_ssh_keys_present": False,
    }


def test_instance_hardened_posture():
    _vm, hardened, _d, _g, _hp, _dp = _instance_records()
    assert hardened["zone"] == "us-central1-a"           # basename, not the URL
    assert hardened["machine_type"] == "n2-standard-4"
    assert hardened["network_tags"] == ["app", "internal"]
    assert hardened["secure_boot"] is True
    assert hardened["vtpm"] is True
    assert hardened["integrity_monitoring"] is True
    assert hardened["shielded_vm_enabled"] is True
    assert hardened["confidential_computing"] is True
    assert hardened["confidential_instance_type"] == "SEV"
    # Inherited from the project, which is what os_login_source records.
    assert hardened["os_login_enabled"] is True
    assert hardened["os_login_source"] == "project"
    assert hardened["os_login_2fa_enabled"] is True
    assert hardened["serial_port_access_enabled"] is False
    assert hardened["block_project_ssh_keys"] is True
    assert hardened["instance_ssh_keys_present"] is False
    assert hardened["can_ip_forward"] is False
    assert hardened["public_ip"] is False
    assert hardened["network_interface_count"] == 1
    assert hardened["network_interfaces"][0]["network"] == "prod-vpc"
    assert hardened["network_interfaces"][0]["subnetwork"] == "app"
    assert hardened["deletion_protection"] is True
    assert hardened["service_account_attached"] is True
    assert hardened["uses_default_compute_service_account"] is False
    assert hardened["has_full_api_access_scope"] is False
    assert hardened["default_service_account_with_full_api_access"] is False
    assert hardened["gke_managed"] is False


def test_instance_never_copies_metadata_payloads():
    """The metadata block carries startup scripts and SSH keys — neither may leak."""
    _vm, hardened, default, _g, _hp, _dp = _instance_records()
    assert "FIXTURE-NOT-A-REAL-SECRET" not in json.dumps(hardened)
    assert "startup-script" not in json.dumps(hardened)
    assert "FIXTURE-NOT-A-REAL-SSH-KEY" not in json.dumps(default)
    # Only the presence flag survives.
    assert default["instance_ssh_keys_present"] is True


def test_instance_default_posture_in_rest_spelling():
    _vm, _h, default, _g, _hp, _dp = _instance_records()
    assert default["secure_boot"] is False
    assert default["vtpm"] is False
    assert default["shielded_vm_enabled"] is False
    assert default["confidential_computing"] is False
    # The instance overrides the (already-off) project default explicitly.
    assert default["os_login_enabled"] is False
    assert default["os_login_source"] == "instance"
    assert default["serial_port_access_enabled"] is True     # "1" counts
    assert default["block_project_ssh_keys"] is False
    assert default["can_ip_forward"] is True
    assert default["deletion_protection"] is False
    assert default["preemptible"] is True
    assert default["provisioning_model"] == "SPOT"
    assert default["network_interface_count"] == 2
    # natIP present on nic0 only -> the instance has a public IP.
    assert default["network_interfaces"][0]["has_external_ip"] is True
    assert default["network_interfaces"][0]["access_config_types"] == ["ONE_TO_ONE_NAT"]
    assert default["network_interfaces"][1]["has_external_ip"] is False
    assert default["public_ip"] is True
    # The address itself is not posture and is not copied.
    assert "203.0.113.10" not in json.dumps(default)
    # The classic finding: default compute SA + cloud-platform scope.
    assert default["uses_default_compute_service_account"] is True
    assert default["has_full_api_access_scope"] is True
    assert default["default_service_account_with_full_api_access"] is True


def test_instance_gke_nodes_are_exempt_from_the_default_sa_finding():
    """Prowler exempts gke-* instances; GKE requires that SA + scope pairing."""
    _vm, _h, _d, gke, _hp, _dp = _instance_records()
    assert gke["gke_managed"] is True
    assert gke["uses_default_compute_service_account"] is True
    assert gke["has_full_api_access_scope"] is True
    assert gke["default_service_account_with_full_api_access"] is False
    # Its own metadata turns OS Login on even though the project is silent.
    assert gke["os_login_enabled"] is True
    assert gke["os_login_source"] == "instance"


def test_instance_summary_counts():
    vm, hardened, default, gke, _hp, default_project = _instance_records()
    summary = vm.summarize([hardened, default, gke], default_project)
    assert summary["compute_api_readable"] is True
    assert summary["project_os_login_enabled"] is False
    assert summary["project_default_service_account"].startswith("222-compute@")
    assert summary["project_wide_ssh_keys_present"] is True
    assert summary["total_instances"] == 3
    assert summary["running_instances"] == 3
    assert summary["gke_managed_instances"] == 1
    assert summary["shielded_vm_instances"] == 2
    assert summary["shielded_vm_percentage"] == 66
    assert summary["secure_boot_instances"] == 2
    assert summary["confidential_computing_instances"] == 1
    assert summary["os_login_instances"] == 2
    assert summary["os_login_percentage"] == 66
    assert summary["os_login_2fa_instances"] == 1
    assert summary["serial_port_access_instances"] == 1
    assert summary["block_project_ssh_keys_instances"] == 1
    assert summary["public_ip_instances"] == 1
    assert summary["ip_forwarding_instances"] == 1
    assert summary["multi_nic_instances"] == 1
    assert summary["instances_without_service_account"] == 0
    assert summary["default_service_account_instances"] == 2
    assert summary["default_service_account_full_api_access_instances"] == 1
    assert summary["full_api_access_scope_instances"] == 2
    assert summary["deletion_protection_instances"] == 1
    assert summary["preemptible_instances"] == 1


def test_instance_summary_marks_an_unreadable_api():
    vm = _load("compute_instance_configuration")
    summary = vm.summarize([], vm.project_record(None), api_readable=False)
    assert summary["compute_api_readable"] is False
    assert summary["total_instances"] == 0
    assert summary["shielded_vm_percentage"] == 0


# --------------------------------------------------------------------------- #
# VPC networks + subnets — Network/Subnetwork to_dict() and REST spellings
# --------------------------------------------------------------------------- #

NET_DEFAULT = {  # SYNTHETIC — the auto-created default network, still present
    "name": "default",
    "id": "1",
    "auto_create_subnetworks": True,
    "routing_config": {"routing_mode": "REGIONAL"},
    "subnetworks": [
        "https://x/projects/p/regions/us-central1/subnetworks/default",
        "https://x/projects/p/regions/us-west1/subnetworks/mgmt",
    ],
    "mtu": 1460,
}

NET_CUSTOM_REST = {  # SYNTHETIC — REST camelCase, custom mode, peered
    "name": "prod-vpc",
    "id": "2",
    "autoCreateSubnetworks": False,
    "routingConfig": {"routingMode": "GLOBAL"},
    "subnetworks": [
        "https://x/projects/p/regions/us-central1/subnetworks/app",
        "https://x/projects/p/regions/europe-west1/subnetworks/app-euw1",
    ],
    "peerings": [{"name": "to-shared-services", "state": "ACTIVE"}],
    "networkFirewallPolicyEnforcementOrder": "AFTER_CLASSIC_FIREWALL",
}

NET_LEGACY = {  # SYNTHETIC — no autoCreateSubnetworks key AT ALL = legacy
    "name": "legacy-net",
    "id": "3",
    "I_pv4_range": "10.240.0.0/16",
}

SUB_FULLY_LOGGED = {  # SYNTHETIC — 100% sampling, private Google access on
    "name": "app",
    "id": "10",
    "region": "https://x/projects/p/regions/us-central1",
    "network": "https://x/projects/p/global/networks/prod-vpc",
    "ip_cidr_range": "10.10.0.0/20",
    "private_ip_google_access": True,
    "purpose": "PRIVATE",
    "stack_type": "IPV4_ONLY",
    "state": "READY",
    "log_config": {
        "enable": True,
        "aggregation_interval": "INTERVAL_5_SEC",
        "flow_sampling": 1.0,
        "metadata": "INCLUDE_ALL_METADATA",
        "metadata_fields": [],
    },
}

SUB_SAMPLED_REST = {  # SYNTHETIC — REST camelCase; logging, but 10% and filtered
    "name": "app-euw1",
    "id": "11",
    "region": "https://x/projects/p/regions/europe-west1",
    "network": "https://x/projects/p/global/networks/prod-vpc",
    "ipCidrRange": "10.20.0.0/20",
    "privateIpGoogleAccess": False,
    "secondaryIpRanges": [{"rangeName": "pods", "ipCidrRange": "10.60.0.0/14"}],
    "logConfig": {
        "enable": True,
        "aggregationInterval": "INTERVAL_15_MIN",
        "flowSampling": 0.1,
        "metadata": "EXCLUDE_ALL_METADATA",
        "filterExpr": 'connection.protocol == 6',
    },
}

SUB_NO_LOGS_LEGACY_FLAG = {  # SYNTHETIC — only the deprecated top-level flag, off
    "name": "default",
    "id": "12",
    "region": "https://x/projects/p/regions/us-central1",
    "network": "https://x/projects/p/global/networks/default",
    "ipCidrRange": "10.128.0.0/20",
    "enableFlowLogs": False,
}

SUB_LOGS_LEGACY_FLAG = {  # SYNTHETIC — the deprecated flag, ON; no logConfig block
    "name": "mgmt",
    "id": "13",
    "region": "https://x/projects/p/regions/us-west1",
    "network": "https://x/projects/p/global/networks/default",
    "ip_cidr_range": "10.138.0.0/20",
    "enable_flow_logs": True,
}


def _vpc_records():
    vpc = _load("vpc_network_configuration")
    networks = [vpc.network_record(n) for n in (NET_DEFAULT, NET_CUSTOM_REST, NET_LEGACY)]
    subnets = [
        vpc.subnet_record(s)
        for s in (
            SUB_FULLY_LOGGED,
            SUB_SAMPLED_REST,
            SUB_NO_LOGS_LEGACY_FLAG,
            SUB_LOGS_LEGACY_FLAG,
        )
    ]
    return vpc, networks, subnets


def test_vpc_subnet_mode_is_a_presence_test_not_a_boolean_read():
    """Prowler's rule: the field ABSENT means legacy, which False does not."""
    vpc = _load("vpc_network_configuration")
    assert vpc.subnet_mode({"auto_create_subnetworks": True}) == "auto"
    assert vpc.subnet_mode({"auto_create_subnetworks": False}) == "custom"
    assert vpc.subnet_mode({"autoCreateSubnetworks": False}) == "custom"
    assert vpc.subnet_mode({"name": "old"}) == "legacy"


def test_vpc_network_records():
    _vpc, networks, _subnets = _vpc_records()
    default, custom, legacy = networks

    assert default["subnet_mode"] == "auto"
    assert default["auto_mode"] is True
    assert default["is_default_network"] is True
    assert default["routing_mode"] == "REGIONAL"
    assert default["subnet_count"] == 2
    assert default["subnet_names"] == ["default", "mgmt"]

    assert custom["subnet_mode"] == "custom"
    assert custom["custom_mode"] is True
    assert custom["is_default_network"] is False
    assert custom["routing_mode"] == "GLOBAL"
    assert custom["peering_count"] == 1
    assert custom["peerings"] == ["to-shared-services"]
    assert custom["firewall_policy_enforcement_order"] == "AFTER_CLASSIC_FIREWALL"

    assert legacy["legacy"] is True
    assert legacy["subnet_mode"] == "legacy"
    assert legacy["legacy_ipv4_range"] == "10.240.0.0/16"
    assert legacy["subnet_count"] == 0
    assert legacy["routing_mode"] is None


def test_vpc_subnet_flow_log_parameters():
    _vpc, _networks, subnets = _vpc_records()
    logged, sampled, _off, _legacy_on = subnets

    assert logged["region"] == "us-central1"          # basename, not the URL
    assert logged["network"] == "prod-vpc"
    assert logged["ip_cidr_range"] == "10.10.0.0/20"
    assert logged["private_google_access"] is True
    assert logged["flow_logs_enabled"] is True
    assert logged["flow_log_aggregation_interval"] == "INTERVAL_5_SEC"
    assert logged["flow_log_sampling"] == 1.0
    assert logged["flow_log_metadata"] == "INCLUDE_ALL_METADATA"
    assert logged["flow_log_filtered"] is False

    # Logging "on" at 10% with a filter is materially different evidence, which is
    # why the parameters are reported and not just the boolean Prowler keeps.
    assert sampled["flow_logs_enabled"] is True
    assert sampled["flow_log_sampling"] == 0.1
    assert sampled["flow_log_aggregation_interval"] == "INTERVAL_15_MIN"
    assert sampled["flow_log_filtered"] is True
    assert sampled["private_google_access"] is False
    assert sampled["secondary_range_count"] == 1


def test_vpc_subnet_falls_back_to_the_deprecated_flow_log_flag():
    """logConfig is preferred; enableFlowLogs still has to be honored."""
    _vpc, _networks, subnets = _vpc_records()
    _logged, _sampled, off, legacy_on = subnets
    assert off["flow_logs_enabled"] is False
    assert off["flow_log_aggregation_interval"] is None
    assert legacy_on["flow_logs_enabled"] is True
    assert legacy_on["flow_log_sampling"] is None


def test_vpc_summary_counts():
    vpc, networks, subnets = _vpc_records()
    summary = vpc.summarize(networks, subnets)
    assert summary["compute_api_readable"] is True
    assert summary["total_networks"] == 3
    assert summary["default_network_present"] is True
    assert summary["legacy_networks"] == 1
    assert summary["auto_mode_networks"] == 1
    assert summary["custom_mode_networks"] == 1
    assert summary["custom_mode_percentage"] == 33
    assert summary["peered_networks"] == 1
    assert summary["networks_without_subnets"] == ["legacy-net"]
    assert summary["total_subnets"] == 4
    assert summary["regions_with_subnets"] == ["europe-west1", "us-central1", "us-west1"]
    assert summary["subnets_with_flow_logs"] == 3
    assert summary["flow_log_percentage"] == 75
    assert summary["subnets_with_filtered_flow_logs"] == 1
    assert summary["flow_log_aggregation_intervals"] == [
        "INTERVAL_15_MIN",
        "INTERVAL_5_SEC",
    ]
    assert summary["lowest_flow_log_sampling"] == 0.1
    assert summary["subnets_with_private_google_access"] == 1
    assert summary["private_google_access_percentage"] == 25


def test_vpc_summary_marks_an_unreadable_api():
    vpc = _load("vpc_network_configuration")
    summary = vpc.summarize([], [], api_readable=False)
    assert summary["compute_api_readable"] is False
    assert summary["default_network_present"] is False
    assert summary["flow_log_percentage"] == 0
    assert summary["lowest_flow_log_sampling"] is None


# --------------------------------------------------------------------------- #
# Load balancer TLS — SslPolicy / TargetHttpsProxy / TargetSslProxy shapes
# --------------------------------------------------------------------------- #

POLICY_RESTRICTED = {  # SYNTHETIC — the hardened policy
    "name": "tls12-restricted",
    "id": "1",
    "min_tls_version": "TLS_1_2",
    "profile": "RESTRICTED",
    "enabled_features": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"],
    "post_quantum_key_exchange": "ENABLED",
}

POLICY_COMPATIBLE_REST = {  # SYNTHETIC — REST camelCase, regional, 1.2 but COMPATIBLE
    "name": "regional-compat",
    "id": "2",
    "region": "https://x/projects/p/regions/us-central1",
    "minTlsVersion": "TLS_1_2",
    "profile": "COMPATIBLE",
    "enabledFeatures": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
}

POLICY_TLS10 = {  # SYNTHETIC — MODERN profile, but the floor is TLS 1.0
    "name": "legacy-modern",
    "id": "3",
    "min_tls_version": "TLS_1_0",
    "profile": "MODERN",
    "enabled_features": ["TLS_RSA_WITH_AES_128_GCM_SHA256"],
}

PROXY_STRICT = {  # SYNTHETIC — global HTTPS proxy on the hardened policy
    "name": "prod-https",
    "id": "20",
    "ssl_policy": "https://x/projects/p/global/sslPolicies/tls12-restricted",
    "ssl_certificates": ["https://x/projects/p/global/sslCertificates/prod-cert"],
    "url_map": "https://x/projects/p/global/urlMaps/prod-map",
    "quic_override": "ENABLE",
    "tls_early_data": "DISABLED",
}

PROXY_DEFAULT_REST = {  # SYNTHETIC — REST camelCase, NO sslPolicy at all
    "name": "marketing-https",
    "id": "21",
    "sslCertificates": ["https://x/projects/p/global/sslCertificates/marketing"],
    "urlMap": "https://x/projects/p/global/urlMaps/marketing-map",
    "certificateMap": "//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/mk-map",
}

PROXY_UNRESOLVED = {  # SYNTHETIC — names a regional policy this run couldn't read
    "name": "regional-https",
    "id": "22",
    "region": "https://x/projects/p/regions/us-east1",
    "ssl_policy": "https://x/projects/p/regions/us-east1/sslPolicies/missing-policy",
    "ssl_certificates": [],
}

PROXY_SSL_REST = {  # SYNTHETIC — a target SSL proxy (global-only resource)
    "name": "tcp-ssl",
    "id": "23",
    "sslPolicy": "https://x/projects/p/global/sslPolicies/regional-compat",
    "service": "https://x/projects/p/global/backendServices/tcp-backend",
    "sslCertificates": ["https://x/projects/p/global/sslCertificates/tcp-cert"],
    "proxyHeader": "NONE",
}


def _tls_records():
    lb = _load("load_balancer_tls_configuration")
    policies = [
        lb.ssl_policy_record(p)
        for p in (POLICY_RESTRICTED, POLICY_COMPATIBLE_REST, POLICY_TLS10)
    ]
    by_name = {p["name"]: p for p in policies}
    proxies = [
        lb.proxy_record(PROXY_STRICT, "target_https_proxy", by_name),
        lb.proxy_record(PROXY_DEFAULT_REST, "target_https_proxy", by_name),
        lb.proxy_record(PROXY_UNRESOLVED, "target_https_proxy", by_name),
        lb.proxy_record(PROXY_SSL_REST, "target_ssl_proxy", by_name),
    ]
    return lb, policies, proxies


def test_tls_version_ordering_and_unknown_values():
    lb = _load("load_balancer_tls_configuration")
    assert lb.tls_at_least("TLS_1_2") is True
    assert lb.tls_at_least("TLS_1_3") is True
    assert lb.tls_at_least("TLS_1_1") is False
    assert lb.tls_at_least("TLS_1_0") is False
    # An unknown or absent version must never read as meeting the floor.
    assert lb.tls_at_least(None) is False
    assert lb.tls_at_least("TLS_9_9") is False
    assert lb.tls_at_least("TLS_1_1", floor="TLS_1_1") is True


def test_tls_weakness_rule_has_two_independent_legs():
    lb = _load("load_balancer_tls_configuration")
    assert lb.is_weak_tls("TLS_1_2", "RESTRICTED") is False
    assert lb.is_weak_tls("TLS_1_2", "MODERN") is False
    # Leg 1: the version floor is too low.
    assert lb.is_weak_tls("TLS_1_0", "RESTRICTED") is True
    # Leg 2: COMPATIBLE re-admits weak ciphers whatever the floor says.
    assert lb.is_weak_tls("TLS_1_3", "COMPATIBLE") is True


def test_tls_ssl_policy_records_both_spellings_and_scopes():
    _lb, policies, _proxies = _tls_records()
    restricted, compatible, tls10 = policies

    assert restricted["scope"] == "global"
    assert restricted["min_tls_version"] == "TLS_1_2"
    assert restricted["profile"] == "RESTRICTED"
    assert restricted["enabled_cipher_count"] == 2
    assert restricted["enabled_ciphers"] == [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
    ]
    assert restricted["post_quantum_key_exchange"] == "ENABLED"
    assert restricted["meets_tls_floor"] is True
    assert restricted["weak_tls"] is False

    # Regional, camelCase input; the version is fine but the profile is not.
    assert compatible["scope"] == "us-central1"
    assert compatible["meets_tls_floor"] is True
    assert compatible["permissive_profile"] is True
    assert compatible["weak_tls"] is True

    assert tls10["meets_tls_floor"] is False
    assert tls10["permissive_profile"] is False
    assert tls10["weak_tls"] is True


def test_tls_proxy_resolves_its_ssl_policy():
    _lb, _policies, proxies = _tls_records()
    strict = proxies[0]
    assert strict["type"] == "target_https_proxy"
    assert strict["scope"] == "global"
    assert strict["ssl_policy"] == "tls12-restricted"     # basename of the link
    assert strict["uses_default_ssl_policy"] is False
    assert strict["ssl_policy_resolved"] is True
    assert strict["effective_min_tls_version"] == "TLS_1_2"
    assert strict["effective_profile"] == "RESTRICTED"
    assert strict["meets_tls_floor"] is True
    assert strict["weak_tls"] is False
    assert strict["ssl_certificate_count"] == 1
    assert strict["ssl_certificates"] == ["prod-cert"]
    assert strict["url_map"] == "prod-map"
    assert strict["quic_override"] == "ENABLE"


def test_tls_proxy_with_no_policy_reports_the_gcp_default_explicitly():
    """The finding this evidence set exists for: no policy = TLS 1.0 + COMPATIBLE."""
    lb, _policies, proxies = _tls_records()
    default = proxies[1]
    assert default["ssl_policy"] is None
    assert default["uses_default_ssl_policy"] is True
    assert default["ssl_policy_resolved"] is True
    assert default["effective_min_tls_version"] == lb.DEFAULT_MIN_TLS_VERSION == "TLS_1_0"
    assert default["effective_profile"] == lb.DEFAULT_PROFILE == "COMPATIBLE"
    assert default["meets_tls_floor"] is False
    assert default["weak_tls"] is True
    assert default["certificate_map"] == "mk-map"


def test_tls_proxy_with_an_unreadable_policy_is_unknown_not_defaulted():
    _lb, _policies, proxies = _tls_records()
    unresolved = proxies[2]
    assert unresolved["scope"] == "us-east1"
    assert unresolved["ssl_policy"] == "missing-policy"
    # A named-but-unread policy must NOT silently become the GCP default.
    assert unresolved["uses_default_ssl_policy"] is False
    assert unresolved["ssl_policy_resolved"] is False
    assert unresolved["effective_min_tls_version"] is None
    assert unresolved["effective_profile"] is None
    # Unknown is reported as not meeting the floor — never as a pass.
    assert unresolved["meets_tls_floor"] is False
    assert unresolved["weak_tls"] is True


def test_tls_target_ssl_proxy_shape():
    _lb, _policies, proxies = _tls_records()
    ssl_proxy = proxies[3]
    assert ssl_proxy["type"] == "target_ssl_proxy"
    assert ssl_proxy["backend_service"] == "tcp-backend"
    assert ssl_proxy["url_map"] is None
    assert ssl_proxy["proxy_header"] == "NONE"
    assert ssl_proxy["effective_min_tls_version"] == "TLS_1_2"
    assert ssl_proxy["effective_profile"] == "COMPATIBLE"
    assert ssl_proxy["meets_tls_floor"] is True
    assert ssl_proxy["weak_tls"] is True          # the permissive profile


def test_tls_summary_counts():
    lb, policies, proxies = _tls_records()
    summary = lb.summarize(policies, proxies)
    assert summary["compute_api_readable"] is True
    assert summary["tls_floor"] == "TLS_1_2"
    assert summary["default_min_tls_version_when_no_policy"] == "TLS_1_0"
    assert summary["total_ssl_policies"] == 3
    assert summary["weak_ssl_policies"] == 2
    assert summary["permissive_profile_ssl_policies"] == 1
    assert summary["ssl_policy_min_tls_versions"] == ["TLS_1_0", "TLS_1_2"]
    assert summary["ssl_policy_profiles"] == ["COMPATIBLE", "MODERN", "RESTRICTED"]
    assert summary["total_proxies"] == 4
    assert summary["https_proxies"] == 3
    assert summary["ssl_proxies"] == 1
    assert summary["proxies_with_ssl_policy"] == 3
    assert summary["proxies_on_default_ssl_policy"] == 1
    assert summary["proxies_meeting_tls_floor"] == 2
    assert summary["tls_floor_percentage"] == 50
    assert summary["proxies_with_weak_tls"] == 3
    assert summary["proxies_with_unresolved_ssl_policy"] == 1
    assert summary["proxies_with_certificate_map"] == 1
    assert summary["proxies_with_server_tls_policy"] == 0


def test_tls_summary_marks_an_unreadable_api():
    lb = _load("load_balancer_tls_configuration")
    summary = lb.summarize([], [], api_readable=False)
    assert summary["compute_api_readable"] is False
    assert summary["total_proxies"] == 0
    assert summary["tls_floor_percentage"] == 0


# --------------------------------------------------------------------------- #
# End to end with broken credentials. Offline: GOOGLE_APPLICATION_CREDENTIALS
# points at a file that does not exist, so ADC resolution fails before any
# network call. (Deliberately a local copy of the harness in
# test_gcp_platform_fetchers.py — each test module stands alone, and the repo has
# no tests/conftest.py to share it through.)
# --------------------------------------------------------------------------- #

def run_with_broken_credentials(short_name: str, tmp_path: Path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    status_file = tmp_path / "status.json"
    env = {
        **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TZ")},
        "PYTHONUNBUFFERED": "1",
        "EVIDENCE_DIR": str(evidence_dir),
        "FETCHER_STATUS_FILE": str(status_file),
        "GOOGLE_CLOUD_PROJECT": "paramify-not-a-real-project",
        "GCP_ENVIRONMENT": "pytest",
        "GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "no-such-adc.json"),
        "CLOUDSDK_CONFIG": str(tmp_path / "no-such-gcloud-config"),
    }
    proc = subprocess.run(
        [sys.executable, str(GCP_ROOT / short_name / "fetcher.py")],
        env=env, capture_output=True, text=True, timeout=300,
    )
    return proc, evidence_dir, status_file


@pytest.mark.parametrize("short_name", COMPUTE_FETCHERS)
def test_broken_credentials_fail_loudly_and_explain_themselves(short_name, tmp_path):
    pytest.importorskip("dotenv")
    proc, evidence_dir, status_file = run_with_broken_credentials(short_name, tmp_path)

    assert proc.returncode != 0, "unusable credentials must not look like success"

    evidence_files = list(evidence_dir.glob("*.json"))
    assert len(evidence_files) == 1, f"expected one evidence file, got {evidence_files}"
    payload = json.loads(evidence_files[0].read_text())
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"]

    assert status_file.exists(), "no failure reason reported to $FETCHER_STATUS_FILE"
    body = json.loads(status_file.read_text())
    assert set(body) <= {"error", "code"}
    assert isinstance(body["error"], str) and body["error"].strip()
    assert "\n" not in body["error"]
    assert body["code"] in STATUS_CODES
    assert "google.auth.default" in body["error"], f"unexpected reason: {body['error']}"

    # The issue #24 regression: the reason must not be the success message, which
    # is what the runner would have taken from the tail of stderr.
    assert "Evidence saved" not in body["error"]
    assert "Evidence saved" not in proc.stderr.strip().splitlines()[-1]
