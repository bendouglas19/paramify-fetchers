#!/usr/bin/env python3
"""
GCP Compute Engine Instance Configuration

Per-instance hardening posture for every VM in one project: Shielded VM (secure
boot, vTPM, integrity monitoring), Confidential Computing, OS Login, serial-port
access, IP forwarding, block-project-ssh-keys, the attached service account and
its OAuth scopes, public-IP presence, and deletion protection. Plus the
project-wide defaults those instance settings inherit from
(`commonInstanceMetadata`), so an instance that simply doesn't override OS Login
can still be read correctly.

Ported from Prowler's GCP compute service (prowler/providers/gcp/services/
compute/compute_service.py, Apache-2.0) and its per-instance checks:
compute_instance_shielded_vm_enabled, _confidential_computing_enabled,
_serial_ports_in_use, _block_project_wide_ssh_keys_disabled,
_ip_forwarding_is_enabled, _public_ip, _deletion_protection_enabled,
_default_service_account_in_use, _default_service_account_in_use_with_full_api_access,
_single_network_interface, _on_host_maintenance_migrate, _preemptible_vm_disabled,
_automatic_restart_enabled, and the project-level compute_project_os_login_enabled
/ _os_login_2fa_enabled.

Departures from the Prowler original:
- **GAPIC client, not discovery.** Prowler builds `compute` v1 through
  googleapiclient.discovery; google-cloud-compute is the stable GAPIC client, so
  per the category's preference this uses compute_v1.
- **No per-zone fanout.** Prowler lists zones then lists instances in each, one
  threaded call per zone. `instances.aggregatedList` returns every zone's
  instances in one paged call.
- **Shielded VM secure boot is reported too.** Prowler's Instance model carries
  only vTPM and integrity monitoring (its check tests those two), but the same
  `shieldedInstanceConfig` block carries `enableSecureBoot`, which is the third
  leg of Shielded VM. `shielded_vm_enabled` keeps Prowler's definition (vTPM AND
  integrity monitoring) so the two are comparable.
- **OS Login is resolved, not assumed project-wide.** Prowler reads OS Login only
  from the project's `commonInstanceMetadata`. An instance's own
  `enable-oslogin` metadata overrides that, so the effective per-instance value
  is computed and `os_login_source` records which level decided it.

Instance metadata is read key by key on purpose: the same block carries
`startup-script` and `ssh-keys`, which must never land in evidence. Only the
documented hardening keys are ever copied out, and SSH keys are reduced to a
presence flag.

Disk-level encryption is deliberately out of scope — `gcp_persistent_disk_encryption_status`
is that evidence set.

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
    first,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    write_status,
)

logger = logging.getLogger("gcp_compute_instance_configuration")

# The suffix of the Compute Engine default service account. Every project gets
# one, it is a project Editor by default, and Prowler's
# compute_instance_default_service_account_in_use flags any instance running as it.
DEFAULT_COMPUTE_SA_SUFFIX = "-compute@developer.gserviceaccount.com"

# The scope that grants an instance every API the service account can reach.
# Paired with the default service account it is the classic finding.
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Instances GKE creates for its node pools are named `gke-*`. Prowler exempts
# them from the default-SA-with-full-access check because GKE requires that
# combination; `gcp_gke_cluster_configuration` is where node identity is judged.
GKE_INSTANCE_PREFIX = "gke-"

# Metadata keys this fetcher reads. Nothing else is copied out of the metadata
# block — see the module docstring.
OS_LOGIN_KEY = "enable-oslogin"
OS_LOGIN_2FA_KEY = "enable-oslogin-2fa"
SERIAL_PORT_KEY = "serial-port-enable"
BLOCK_PROJECT_SSH_KEYS_KEY = "block-project-ssh-keys"
SSH_KEYS_KEYS = ("ssh-keys", "sshKeys")


# --- pure transforms (operate on Instance.to_dict() / REST dicts; unit-tested) ---

def metadata_enabled(value) -> bool:
    """True for the values GCP accepts as "on" in a metadata entry.

    Metadata values are always strings; Prowler's serial-port check accepts "1"
    and "true", its OS Login and block-project-ssh-keys checks accept "true"
    case-insensitively. One truthy rule covers all of them.
    """
    return str(value).strip().lower() in ("true", "1", "y", "yes")


def metadata_items(metadata: dict | None) -> dict:
    """{key: value} from a Compute metadata block's `items` list.

    Callers only ever look up the documented hardening keys — this is a lookup
    table, not something that gets copied into the evidence.
    """
    out: dict = {}
    for item in first(metadata, "items") or []:
        key = first(item, "key")
        if key is not None:
            out[str(key)] = first(item, "value")
    return out


def project_record(project: dict | None) -> dict:
    """Project-wide defaults from compute projects.get.

    A failed or absent call leaves the block present with everything off, rather
    than missing: "OS Login is not set project-wide" and "we could not read the
    project" must not look the same, and the latter is already recorded in
    metadata.api_failures.
    """
    common = metadata_items(first(project, "commonInstanceMetadata", "common_instance_metadata"))
    return {
        "os_login_enabled": metadata_enabled(common.get(OS_LOGIN_KEY)),
        "os_login_2fa_enabled": metadata_enabled(common.get(OS_LOGIN_2FA_KEY)),
        "default_service_account": first(
            project, "defaultServiceAccount", "default_service_account"
        ),
        "default_network_tier": first(project, "defaultNetworkTier", "default_network_tier"),
        # Project-wide SSH keys are the shared credential block-project-ssh-keys
        # exists to shut out; only presence is recorded, never the keys.
        "project_wide_ssh_keys_present": any(k in common for k in SSH_KEYS_KEYS),
    }


def service_account_record(service_account: dict) -> dict:
    """Normalize one attached service account + its OAuth scopes."""
    email = first(service_account, "email")
    scopes = sorted(first(service_account, "scopes") or [])
    return {
        "email": email,
        "scopes": scopes,
        "default_compute_service_account": bool(
            email and DEFAULT_COMPUTE_SA_SUFFIX in str(email)
        ),
        "full_api_access": CLOUD_PLATFORM_SCOPE in scopes,
    }


def network_interface_record(interface: dict) -> dict:
    """Normalize one NIC.

    A public IP is an accessConfig carrying a natIP. `nat_i_p` is the GAPIC
    `to_dict()` spelling (verified against google-cloud-compute) and `natIP` the
    REST one; `type_` likewise. Only presence is recorded — the address itself is
    not posture.
    """
    access_configs = first(interface, "accessConfigs", "access_configs") or []
    return {
        "name": first(interface, "name"),
        "network": basename(first(interface, "network")),
        "subnetwork": basename(first(interface, "subnetwork")),
        "stack_type": first(interface, "stackType", "stack_type"),
        "nic_type": first(interface, "nicType", "nic_type"),
        "has_external_ip": any(
            first(cfg, "natIP", "nat_i_p", "nat_ip", "natIp") for cfg in access_configs
        ),
        "access_config_types": sorted(
            {
                str(first(cfg, "type", "type_"))
                for cfg in access_configs
                if first(cfg, "type", "type_")
            }
        ),
    }


def instance_record(instance: dict, project_defaults: dict) -> dict:
    """Normalize one instance resource into an evidence record."""
    name = first(instance, "name")
    shielded = first(instance, "shieldedInstanceConfig", "shielded_instance_config") or {}
    confidential = (
        first(instance, "confidentialInstanceConfig", "confidential_instance_config") or {}
    )
    scheduling = first(instance, "scheduling") or {}
    flags = metadata_items(first(instance, "metadata"))
    service_accounts = [
        service_account_record(sa)
        for sa in (first(instance, "serviceAccounts", "service_accounts") or [])
    ]
    interfaces = [
        network_interface_record(n)
        for n in (first(instance, "networkInterfaces", "network_interfaces") or [])
    ]
    network_tags = sorted(first(first(instance, "tags") or {}, "items") or [])

    vtpm = bool(first(shielded, "enableVtpm", "enable_vtpm"))
    integrity = bool(first(shielded, "enableIntegrityMonitoring", "enable_integrity_monitoring"))
    gke_managed = str(name or "").startswith(GKE_INSTANCE_PREFIX)

    os_login_override = flags.get(OS_LOGIN_KEY)
    os_login_2fa_override = flags.get(OS_LOGIN_2FA_KEY)

    return {
        "name": name,
        "id": first(instance, "id"),
        "zone": basename(first(instance, "zone")),
        "machine_type": basename(first(instance, "machineType", "machine_type")),
        "status": first(instance, "status"),
        "creation_timestamp": first(instance, "creationTimestamp", "creation_timestamp"),
        "network_tags": network_tags,
        # An instance GKE manages; its posture is judged by the GKE evidence set.
        "gke_managed": gke_managed,
        # --- Shielded VM ---
        "secure_boot": bool(first(shielded, "enableSecureBoot", "enable_secure_boot")),
        "vtpm": vtpm,
        "integrity_monitoring": integrity,
        # Prowler's definition, kept so the two are comparable: vTPM AND integrity
        # monitoring. Secure boot is reported separately above.
        "shielded_vm_enabled": vtpm and integrity,
        # --- Confidential Computing ---
        "confidential_computing": bool(
            first(confidential, "enableConfidentialCompute", "enable_confidential_compute")
        ),
        "confidential_instance_type": first(
            confidential, "confidentialInstanceType", "confidential_instance_type"
        ),
        # --- SSH / console access ---
        "os_login_enabled": (
            metadata_enabled(os_login_override)
            if os_login_override is not None
            else bool(project_defaults.get("os_login_enabled"))
        ),
        # Which level decided the value above: an instance that never sets the key
        # inherits the project default (which is "off" when the project is silent).
        "os_login_source": "instance" if os_login_override is not None else "project",
        "os_login_2fa_enabled": (
            metadata_enabled(os_login_2fa_override)
            if os_login_2fa_override is not None
            else bool(project_defaults.get("os_login_2fa_enabled"))
        ),
        "serial_port_access_enabled": metadata_enabled(flags.get(SERIAL_PORT_KEY)),
        "block_project_ssh_keys": metadata_enabled(flags.get(BLOCK_PROJECT_SSH_KEYS_KEY)),
        # Presence only. The key's value is a list of public keys and is not copied.
        "instance_ssh_keys_present": any(k in flags for k in SSH_KEYS_KEYS),
        # --- network posture ---
        "can_ip_forward": bool(first(instance, "canIpForward", "can_ip_forward")),
        "network_interfaces": interfaces,
        "network_interface_count": len(interfaces),
        "public_ip": any(n["has_external_ip"] for n in interfaces),
        # --- identity ---
        "service_accounts": service_accounts,
        "service_account_attached": bool(service_accounts),
        "uses_default_compute_service_account": any(
            sa["default_compute_service_account"] for sa in service_accounts
        ),
        "has_full_api_access_scope": any(sa["full_api_access"] for sa in service_accounts),
        # Prowler's compute_instance_default_service_account_in_use_with_full_api_access,
        # gke-* exemption included.
        "default_service_account_with_full_api_access": (
            not gke_managed
            and any(
                sa["default_compute_service_account"] and sa["full_api_access"]
                for sa in service_accounts
            )
        ),
        # --- availability / lifecycle ---
        "deletion_protection": bool(
            first(instance, "deletionProtection", "deletion_protection")
        ),
        "on_host_maintenance": first(scheduling, "onHostMaintenance", "on_host_maintenance"),
        "automatic_restart": bool(first(scheduling, "automaticRestart", "automatic_restart")),
        "preemptible": bool(first(scheduling, "preemptible")),
        "provisioning_model": first(scheduling, "provisioningModel", "provisioning_model"),
    }


def summarize(
    instances: list[dict], project_defaults: dict, *, api_readable: bool = True
) -> dict:
    total = len(instances)
    shielded = sum(1 for i in instances if i["shielded_vm_enabled"])
    os_login = sum(1 for i in instances if i["os_login_enabled"])
    return {
        # False when compute.googleapis.com is not enabled on this project
        # (recorded in metadata.skipped_calls) or the list call failed —
        # distinguishing "no instances" from "could not look".
        "compute_api_readable": api_readable,
        # Project-wide defaults every instance above inherits from.
        "project_os_login_enabled": bool(project_defaults.get("os_login_enabled")),
        "project_os_login_2fa_enabled": bool(project_defaults.get("os_login_2fa_enabled")),
        "project_default_service_account": project_defaults.get("default_service_account"),
        "project_wide_ssh_keys_present": bool(
            project_defaults.get("project_wide_ssh_keys_present")
        ),
        "total_instances": total,
        "running_instances": sum(1 for i in instances if str(i["status"] or "") == "RUNNING"),
        "gke_managed_instances": sum(1 for i in instances if i["gke_managed"]),
        # --- host hardening ---
        "shielded_vm_instances": shielded,
        "shielded_vm_percentage": coverage_percentage(shielded, total),
        "secure_boot_instances": sum(1 for i in instances if i["secure_boot"]),
        "vtpm_instances": sum(1 for i in instances if i["vtpm"]),
        "integrity_monitoring_instances": sum(
            1 for i in instances if i["integrity_monitoring"]
        ),
        "confidential_computing_instances": sum(
            1 for i in instances if i["confidential_computing"]
        ),
        # --- access ---
        "os_login_instances": os_login,
        "os_login_percentage": coverage_percentage(os_login, total),
        "os_login_2fa_instances": sum(1 for i in instances if i["os_login_2fa_enabled"]),
        "serial_port_access_instances": sum(
            1 for i in instances if i["serial_port_access_enabled"]
        ),
        "block_project_ssh_keys_instances": sum(
            1 for i in instances if i["block_project_ssh_keys"]
        ),
        # --- network ---
        "public_ip_instances": sum(1 for i in instances if i["public_ip"]),
        "ip_forwarding_instances": sum(1 for i in instances if i["can_ip_forward"]),
        "multi_nic_instances": sum(1 for i in instances if i["network_interface_count"] > 1),
        # --- identity ---
        "instances_without_service_account": sum(
            1 for i in instances if not i["service_account_attached"]
        ),
        "default_service_account_instances": sum(
            1 for i in instances if i["uses_default_compute_service_account"]
        ),
        # The classic finding: the default service account plus cloud-platform.
        "default_service_account_full_api_access_instances": sum(
            1 for i in instances if i["default_service_account_with_full_api_access"]
        ),
        "full_api_access_scope_instances": sum(
            1 for i in instances if i["has_full_api_access_scope"]
        ),
        # --- lifecycle ---
        "deletion_protection_instances": sum(1 for i in instances if i["deletion_protection"]),
        "preemptible_instances": sum(1 for i in instances if i["preemptible"]),
    }


# --- collection (lazy google imports; not exercised by the fixture tests) ---

def collect_project_defaults(project, creds, collector: Collector) -> dict:
    """Project-wide instance metadata (OS Login defaults, default service account)."""
    from google.cloud import compute_v1

    def _get():
        client = compute_v1.ProjectsClient(credentials=creds)
        return compute_v1.Project.to_dict(client.get(project=project))

    return project_record(
        collector.guard("compute.projects.get", _get, tolerate=service_disabled)
    )


def collect_instances(
    project, creds, collector: Collector, project_defaults: dict
) -> list[dict] | None:
    """Every instance in the project, or None when Compute could not be listed."""
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.InstancesClient(credentials=creds)
        out = []
        # aggregatedList covers every zone in one paged call; zones with no
        # instances come back with an empty scoped list.
        for _zone, scoped in client.aggregated_list(project=project):
            for instance in getattr(scoped, "instances", []) or []:
                out.append(
                    instance_record(compute_v1.Instance.to_dict(instance), project_defaults)
                )
        return out

    records = collector.guard(
        "compute.instances.aggregatedList", _list, tolerate=service_disabled
    )
    if records is None:
        return None
    return sorted(records, key=lambda r: (r.get("zone") or "", r.get("name") or ""))


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

    project_defaults = project_record(None)
    instances: list[dict] | None = None
    if project and creds is not None:
        project_defaults = collect_project_defaults(project, creds, collector)
        instances = collect_instances(project, creds, collector, project_defaults)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"project_defaults": project_defaults, "instances": instances or []},
        summary=summarize(
            instances or [], project_defaults, api_readable=instances is not None
        ),
    )

    filename = (
        f"gcp_compute_instance_configuration_{sanitize_for_filename(project or 'unknown')}.json"
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
