#!/usr/bin/env python3
"""
KSI-SVC-06 / KSI-SVC-05 / KSI-SVC-03: Azure Key Vault key rotation and expiration

For each key vault in one subscription, reports every key's rotation policy and
expiration date, plus every secret's expiration date — the evidence that key
management is automated rather than manual.

**This fetcher spans TWO PLANES, which is the whole reason it exists separately
from azure_key_vault_configuration.** The management plane
(azure-mgmt-keyvault: keys.list / secrets.list) enumerates what a vault holds but
CANNOT see a key's rotation policy in a LIST response, so Prowler builds a
data-plane `azure.keyvault.keys.KeyClient` per vault and calls
list_properties_of_keys() then get_key_rotation_policy() per key. Both planes are
read here and merged by key name: the management plane is the inventory (it works
with plain ARM Reader), the data plane adds the rotation policy (it needs a Key
Vault data-plane grant on top).

**Verified live, and better than Prowler's premise:** the management plane's
per-key `keys.get` DOES return `rotationPolicy` (plus `kty` and `keySize`) — only
`keys.list` omits them. Confirmed against a real vault, where `keys.list` returned
just `{attributes, keyUri}` while `keys.get` on the same key returned
`rotationPolicy.lifetimeActions`. So each listed key is followed by one GET: it
fills in the key's strength, and it means a collector holding ONLY ARM Reader still
gets rotation policies for a vault whose data plane it cannot open. The data plane
still wins where it is reachable (it is the authoritative view, and it carries the
policy's own attributes), and `rotation_policy_source` records which plane each
answer came from.

**A vault the credential cannot open on the data plane is EXPECTED, not a
collection failure.** ARM Reader conveys no data actions, so a perfectly healthy
vault answers 403 to list_properties_of_keys(). Prowler catches HttpResponseError
there and logs "has no access policy configured for keyvault" rather than failing;
this fetcher records it as that vault's `data_plane_status` and leaves the exit
code alone. Only a management-plane failure (or a transport failure, which is not
an HttpResponseError) flips the run to exit 1.

Field projections are ported from Prowler's
prowler/providers/azure/services/keyvault/keyvault_service.py (Apache-2.0) —
`_get_keys`, `_get_single_rotation_policy` and `_get_secrets` — and read by the
checks keyvault_key_rotation_enabled, keyvault_rbac_key_expiration_set,
keyvault_key_expiration_set_in_non_rbac, keyvault_rbac_secret_expiration_set and
keyvault_non_rbac_secret_expiration_set.

**No key material or secret value is ever read or emitted.** Key names, dates,
public cryptographic parameters (type / size / curve) and rotation policies only;
secret names and dates only. The data-plane calls used here return key METADATA —
neither `get_key` nor any secret-value call is made.

Single-subscription per invocation; fanout across subscriptions happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_key_vault_key_rotation")

# Per-vault data-plane outcome. "inaccessible" is a normal posture, not a fault:
# the ambient credential holds ARM Reader (control plane) but no Key Vault data
# action, so the rotation policies simply cannot be read for that vault.
DATA_PLANE_ACCESSIBLE = "accessible"
DATA_PLANE_INACCESSIBLE = "inaccessible"
DATA_PLANE_NOT_ATTEMPTED = "not_attempted"

# The lifetime action that means "Key Vault will rotate this key by itself".
# Case-insensitive on purpose: the data plane's KeyRotationPolicyAction spells it
# "Rotate" while azure-mgmt-keyvault's KeyRotationPolicyActionType spells it
# "rotate" (both verified against the installed SDKs), and this fetcher merges
# policies from both planes into one field.
ROTATE_ACTION = "rotate"

# Where a merged rotation policy came from, so a reader can tell "no policy" from
# "we could not see the policy".
SOURCE_DATA_PLANE = "data_plane"
SOURCE_MANAGEMENT_PLANE = "management_plane"

# Fallback vault data-plane host suffix, used only when the management plane did
# not return `vault_uri`. Prowler hardcodes this form; reading `vault_uri` first is
# what keeps the fetcher correct in the sovereign clouds, where the suffix is
# vault.usgovcloudapi.net / vault.azure.cn instead.
DEFAULT_VAULT_URI_SUFFIX = "vault.azure.net"


# --- projection: the only code here that touches an SDK model ---

def properties_bag(model):
    """Return the model's `properties` sub-model, or the model itself.

    azure-mgmt-keyvault 14.x does NOT flatten `properties` onto the resource
    (`Key` carries exactly {id, name, type, location, tags, properties}), which is
    why Prowler reads `secret.properties.attributes`. Older msrest-generated
    releases DO flatten it, and then there is no `properties` attribute at all —
    returning the model itself covers that shape with the same projection.
    """
    bag = model_attr(model, "properties")
    return model if bag is None else bag


def _iso8601_duration(value) -> str | None:
    """Render a `timedelta` as the ISO-8601 duration string the wire carries.

    Rotation policies are all durations — `expires_in`, `time_after_create`,
    `time_before_expiry` — and the wire format is "P90D". The installed SDKs type
    them as `str` and hand them over unchanged, but msrest deserializes a
    duration-typed field into a `timedelta`, and then `json.dump(default=str)`
    would write "90 days, 0:00:00" into the evidence instead: a payload change for
    identical input. This was a real bug on
    azure-mgmt-security's free_trial_remaining_time (see
    fetchers/azure/defender_plans/fetcher.py, whose implementation this copies),
    so every duration field emitted here goes through it.

    Matches the SDK serializer's output exactly: zero-valued components are
    omitted, a bare zero is "P0D", and fractional seconds keep no trailing zeros
    ("P2DT30.5S"). Anything that is not a timedelta (the plain string the current
    SDKs return, or None) passes straight through.
    """
    if not isinstance(value, timedelta):
        return value
    hours, remainder = divmod(value.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    date_part = f"{value.days}D" if value.days else ""
    time_part = ""
    if hours:
        time_part += f"{hours}H"
    if minutes:
        time_part += f"{minutes}M"
    if seconds or value.microseconds:
        if value.microseconds:
            fractional = f"{seconds + value.microseconds / 1_000_000:.6f}"
            time_part += fractional.rstrip("0").rstrip(".") + "S"
        else:
            time_part += f"{seconds}S"
    if not date_part and not time_part:
        return "P0D"
    return f"P{date_part}" + (f"T{time_part}" if time_part else "")


def _iso8601_timestamp(value) -> str | None:
    """Render a key/secret attribute date as one UTC ISO-8601 string.

    The SAME conceptual field arrives in two different types from ONE package:
    azure-mgmt-keyvault 14.x types `KeyAttributes.created/updated/expires` as
    `int` (epoch seconds, straight off the wire) but `SecretAttributes`' inherited
    equivalents as `datetime` (the generator applies format="unix-timestamp"
    there), and the data plane's `KeyProperties.created_on` is a `datetime` again.
    All three verified against the installed SDK.

    Left alone, `json.dump(default=str)` would write 1749081600 for a key's
    expiry and "2026-06-05 00:00:00+00:00" for a secret's — two renderings of one
    field in one evidence file, neither matching the other fetchers' timestamps.
    This normalizes all of them to the category's "%Y-%m-%dT%H:%M:%SZ".
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, bool):
        # bool is an int subclass; an epoch of True/False is nonsense, not a date.
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def project_management_key(key) -> dict:
    """Read an azure-mgmt-keyvault `Key` (control-plane list item) into a flat dict.

    Public parameters only: `kty` / `key_size` / `curve_name` describe the key's
    strength, which is the evidence a reviewer wants for KSI-SVC-03. The key
    material itself is not exposed by this API and is never requested.
    """
    properties = properties_bag(key)
    attributes = model_attr(properties, "attributes")
    return {
        "id": model_attr(key, "id"),
        "name": model_attr(key, "name"),
        "location": model_attr(key, "location"),
        "enabled": model_attr(attributes, "enabled"),
        "created": model_attr(attributes, "created"),
        "updated": model_attr(attributes, "updated"),
        "expires": model_attr(attributes, "expires"),
        "not_before": model_attr(attributes, "not_before"),
        "recovery_level": model_attr(attributes, "recovery_level"),
        "key_type": model_attr(properties, "kty"),
        "key_size": model_attr(properties, "key_size"),
        "curve_name": model_attr(properties, "curve_name"),
        # Returned by keys.get but NOT by keys.list (verified live), which is why
        # each listed key is followed by a GET.
        "rotation_policy": project_management_rotation_policy(
            model_attr(properties, "rotation_policy")
        ),
    }


def project_management_secret(secret) -> dict:
    """Read an azure-mgmt-keyvault `Secret` into a flat dict — NAME AND DATES ONLY.

    `SecretProperties.value` exists on this model and is deliberately NOT read:
    the evidence must never carry secret material. Nor is `content_type`, which is
    caller-supplied free text.
    """
    properties = properties_bag(secret)
    attributes = model_attr(properties, "attributes")
    return {
        "id": model_attr(secret, "id"),
        "name": model_attr(secret, "name"),
        "location": model_attr(secret, "location"),
        "enabled": model_attr(attributes, "enabled"),
        "created": model_attr(attributes, "created"),
        "updated": model_attr(attributes, "updated"),
        "expires": model_attr(attributes, "expires"),
        "not_before": model_attr(attributes, "not_before"),
    }


def project_key_properties(properties) -> dict:
    """Read a data-plane `azure.keyvault.keys.KeyProperties` into a flat dict.

    Same shape as `project_management_key`, so the two planes merge into one
    record. The data plane spells the dates `*_on` and returns them as datetimes.
    """
    return {
        "id": model_attr(properties, "id"),
        "name": model_attr(properties, "name"),
        "location": None,
        "enabled": model_attr(properties, "enabled"),
        "created": model_attr(properties, "created_on"),
        "updated": model_attr(properties, "updated_on"),
        "expires": model_attr(properties, "expires_on"),
        "not_before": model_attr(properties, "not_before"),
        "recovery_level": model_attr(properties, "recovery_level"),
        "key_type": None,
        "key_size": None,
        "curve_name": None,
        "rotation_policy": None,
    }


def project_rotation_policy(policy) -> dict | None:
    """Read a data-plane `KeyRotationPolicy` into a flat dict.

    Every duration goes through `_iso8601_duration`; `action` is an enum on this
    plane, which `model_attr` unwraps to its wire string ("Rotate").
    """
    if policy is None:
        return None
    return {
        "id": model_attr(policy, "id"),
        "expires_in": _iso8601_duration(model_attr(policy, "expires_in")),
        "created": model_attr(policy, "created_on"),
        "updated": model_attr(policy, "updated_on"),
        "lifetime_actions": [
            {
                "action": model_attr(action, "action"),
                "time_after_create": _iso8601_duration(
                    model_attr(action, "time_after_create")
                ),
                "time_before_expiry": _iso8601_duration(
                    model_attr(action, "time_before_expiry")
                ),
            }
            for action in (model_attr(policy, "lifetime_actions") or [])
        ],
    }


def project_management_rotation_policy(policy) -> dict | None:
    """Read an azure-mgmt-keyvault `RotationPolicy` into the SAME flat dict.

    The control plane nests what the data plane flattens: the duration lives under
    `lifetime_actions[].trigger` and the verb under `lifetime_actions[].action.type`
    (spelled "rotate", lowercase, unlike the data plane's "Rotate"). Projecting
    both planes to one shape is what lets a single `rotation_policy_record` and a
    single summary read either source.
    """
    if policy is None:
        return None
    attributes = model_attr(policy, "attributes")
    actions = []
    for action in model_attr(policy, "lifetime_actions") or []:
        trigger = model_attr(action, "trigger")
        actions.append(
            {
                "action": model_attr(model_attr(action, "action"), "type"),
                "time_after_create": _iso8601_duration(
                    model_attr(trigger, "time_after_create")
                ),
                "time_before_expiry": _iso8601_duration(
                    model_attr(trigger, "time_before_expiry")
                ),
            }
        )
    return {
        "id": model_attr(policy, "id"),
        "expires_in": _iso8601_duration(model_attr(attributes, "expiry_time")),
        "created": model_attr(attributes, "created"),
        "updated": model_attr(attributes, "updated"),
        "lifetime_actions": actions,
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def rotation_policy_record(policy: dict | None) -> dict | None:
    """Normalize a projected rotation policy from either plane."""
    if not policy:
        return None
    return {
        "id": policy.get("id"),
        "expires_in": _iso8601_duration(policy.get("expires_in")),
        "created": _iso8601_timestamp(policy.get("created")),
        "updated": _iso8601_timestamp(policy.get("updated")),
        "lifetime_actions": [
            {
                "action": action.get("action"),
                "time_after_create": _iso8601_duration(action.get("time_after_create")),
                "time_before_expiry": _iso8601_duration(action.get("time_before_expiry")),
            }
            for action in (policy.get("lifetime_actions") or [])
        ],
    }


def has_rotate_action(policy: dict | None) -> bool:
    """Prowler's keyvault_key_rotation_enabled predicate, case-insensitively.

    Prowler compares `action.action == "Rotate"`, which is the data plane's
    spelling; the control plane says "rotate". Comparing case-folded means a
    policy merged from either plane reads the same, so the evidence never claims a
    rotating key has no rotation.
    """
    if not policy:
        return False
    return any(
        str(action.get("action") or "").strip().lower() == ROTATE_ACTION
        for action in (policy.get("lifetime_actions") or [])
    )


def key_record(
    key: dict, policy_source: str | None = None, policy_readable: bool = False
) -> dict:
    """Normalize one projected key (from either plane) into an evidence record.

    `policy_readable` is the caller's assertion that it got a DEFINITIVE answer
    about this key's rotation policy — the plane it asked answered, whether with a
    policy or with "there is none". It is what separates "this key does not rotate"
    from "we could not see whether it rotates", and it is the denominator the
    summary's rotation percentage is measured over.
    """
    policy = rotation_policy_record(key.get("rotation_policy"))
    expires = _iso8601_timestamp(key.get("expires"))
    return {
        "id": key.get("id"),
        "name": key.get("name"),
        "location": key.get("location"),
        # Coerced: ARM omits `enabled` on a key that was never disabled, and absent
        # means enabled for a key attribute set — but a validator asserting `true`
        # would not match `null`, so the default is made explicit.
        "enabled": True if key.get("enabled") is None else bool(key.get("enabled")),
        "created": _iso8601_timestamp(key.get("created")),
        "updated": _iso8601_timestamp(key.get("updated")),
        "expires": expires,
        "not_before": _iso8601_timestamp(key.get("not_before")),
        "expiration_set": expires is not None,
        "recovery_level": key.get("recovery_level"),
        # Public cryptographic parameters — key strength, never key material.
        "key_type": key.get("key_type"),
        "key_size": key.get("key_size"),
        "curve_name": key.get("curve_name"),
        "rotation_policy": policy,
        "rotation_enabled": has_rotate_action(policy),
        "rotation_policy_source": policy_source if policy else None,
        "rotation_policy_readable": bool(policy_readable),
    }


def secret_record(secret: dict) -> dict:
    """Normalize one projected secret — name and dates, never a value."""
    expires = _iso8601_timestamp(secret.get("expires"))
    return {
        "id": secret.get("id"),
        "name": secret.get("name"),
        "location": secret.get("location"),
        "enabled": True if secret.get("enabled") is None else bool(secret.get("enabled")),
        "created": _iso8601_timestamp(secret.get("created")),
        "updated": _iso8601_timestamp(secret.get("updated")),
        "expires": expires,
        "not_before": _iso8601_timestamp(secret.get("not_before")),
        "expiration_set": expires is not None,
    }


def merge_rotation_policies(keys: list[dict], data_plane_policies: dict) -> list[dict]:
    """Attach each data-plane rotation policy to its management-plane key, by name.

    Prowler's merge, with one addition: a key the data plane knows about but the
    management-plane list did not return is still emitted (rather than dropped), so
    the count of keys in the evidence can never be quietly short. Prowler's
    `keys_dict[name]` lookup silently discards those.
    """
    by_name = {key["name"]: key for key in keys if key.get("name")}
    for name, policy in sorted(data_plane_policies.items()):
        record = by_name.get(name)
        if record is None:
            record = key_record({"name": name})
            keys.append(record)
            by_name[name] = record
        if policy is None:
            # The data plane was open but answered nothing for this key (a 404, or a
            # rotation-policy read the credential is not granted). Whatever the
            # management plane already knows stands; readability is not upgraded.
            continue
        normalized = rotation_policy_record(policy)
        record["rotation_policy"] = normalized
        record["rotation_enabled"] = has_rotate_action(normalized)
        record["rotation_policy_source"] = SOURCE_DATA_PLANE
        record["rotation_policy_readable"] = True
    return sorted(keys, key=lambda r: r.get("name") or "")


def vault_record(vault: dict) -> dict:
    """Normalize one projected vault's key/secret inventory into a record."""
    resource_id = vault.get("id")
    return {
        "id": resource_id,
        "name": vault.get("name"),
        "location": vault.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "vault_uri": vault.get("vault_uri"),
        "rbac_authorization_enabled": bool(vault.get("enable_rbac_authorization") or False),
        # Whether the data plane could be opened AT ALL, and why not when it could
        # not. Carried per vault because it decides how `rotation_policy: null`
        # reads: "no policy configured" vs "not visible to this credential".
        "data_plane_status": vault.get("data_plane_status") or DATA_PLANE_NOT_ATTEMPTED,
        "data_plane_message": vault.get("data_plane_message"),
        "keys": vault.get("keys") or [],
        "secrets": vault.get("secrets") or [],
    }


def summarize(vaults: list[dict]) -> dict:
    """Rotation-policy coverage across keys is the headline.

    Measured over the keys whose policy could actually be READ, on either plane
    (`rotation_policy_readable`), because a percentage computed over keys the
    collector was never able to ask about would measure the fetcher's permissions
    rather than the tenant's key management.
    """
    keys = [key for vault in vaults for key in vault["keys"]]
    secrets = [secret for vault in vaults for secret in vault["secrets"]]
    visible_keys = [key for key in keys if key["rotation_policy_readable"]]
    rotating = sum(1 for key in visible_keys if key["rotation_enabled"])
    keys_with_expiration = sum(1 for key in keys if key["expiration_set"])
    secrets_with_expiration = sum(1 for secret in secrets if secret["expiration_set"])

    return {
        "total_key_vaults": len(vaults),
        "data_plane_accessible_vaults": sum(
            1 for v in vaults if v["data_plane_status"] == DATA_PLANE_ACCESSIBLE
        ),
        "data_plane_inaccessible_vaults": sum(
            1 for v in vaults if v["data_plane_status"] == DATA_PLANE_INACCESSIBLE
        ),
        "rbac_authorization_vaults": sum(1 for v in vaults if v["rbac_authorization_enabled"]),
        "total_keys": len(keys),
        "enabled_keys": sum(1 for key in keys if key["enabled"]),
        "keys_with_readable_rotation_policy": len(visible_keys),
        "keys_with_rotation_policy": sum(1 for key in keys if key["rotation_policy"]),
        "keys_with_rotation_enabled": rotating,
        "rotation_enabled_percentage": coverage_percentage(rotating, len(visible_keys)),
        "keys_with_expiration": keys_with_expiration,
        "key_expiration_percentage": coverage_percentage(keys_with_expiration, len(keys)),
        "total_secrets": len(secrets),
        "enabled_secrets": sum(1 for secret in secrets if secret["enabled"]),
        "secrets_with_expiration": secrets_with_expiration,
        "secret_expiration_percentage": coverage_percentage(
            secrets_with_expiration, len(secrets)
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def is_data_plane_inaccessible(exc: BaseException) -> bool:
    """Is this "the credential cannot open this vault's data plane"?

    Prowler catches `azure.core.exceptions.HttpResponseError` around the whole
    data-plane block and logs "has no access policy configured for keyvault". This
    matches the same class by walking the exception's class NAMES rather than using
    isinstance, for two reasons: every HTTP-shaped Key Vault error is a subclass
    (ResourceNotFoundError for a key with no policy, ClientAuthenticationError for
    a 401, HttpResponseError itself for a 403), and the predicate stays importable
    and testable with no azure-core installed.

    A TRANSPORT failure (ServiceRequestError, a DNS or TLS error) is deliberately
    NOT in that class hierarchy, so it still lands on Collector and flips the run
    to exit 1 — "the vault is unreachable" is a broken run, "this credential holds
    no data actions" is a posture.
    """
    return any(cls.__name__ == "HttpResponseError" for cls in type(exc).__mro__)


def vault_data_plane_uri(vault: dict) -> str | None:
    """The vault's data-plane URL: `vault_uri` from ARM, else Prowler's form.

    Prowler hardcodes f"https://{name}.vault.azure.net/". Preferring the
    `vault_uri` ARM already returned is what keeps this correct in Azure
    Government / China, whose vault hosts are vault.usgovcloudapi.net /
    vault.azure.cn.
    """
    uri = vault.get("vault_uri")
    if uri:
        return uri
    name = vault.get("name")
    return f"https://{name}.{DEFAULT_VAULT_URI_SUFFIX}/" if name else None


def collect_management_plane_keys(client, collector: Collector, group: str, name: str) -> list[dict]:
    """keys.list for one vault, then one keys.get per key.

    The GET is not redundant: ARM's LIST response carries only `{attributes,
    keyUri}` (verified live), while the GET adds `kty`, `keySize` and —
    crucially — `rotationPolicy`. Both are `Microsoft.KeyVault/vaults/keys/read`,
    so if the list succeeded the GET is permitted too, and a failure on it is a
    real collection failure rather than a posture.
    """
    records = []
    for listed in client.keys.list(group, name):
        key_name = model_attr(listed, "name")
        detailed = collector.guard(
            f"keyvault.keys.get ({name}/{key_name})",
            lambda key_name=key_name: client.keys.get(group, name, key_name),
        )
        records.append(
            key_record(
                project_management_key(detailed if detailed is not None else listed),
                SOURCE_MANAGEMENT_PLANE,
                policy_readable=detailed is not None,
            )
        )
    return records


def collect_management_plane(subscription_id, cred, collector: Collector) -> list[dict]:
    """vaults.list_by_subscription(), then keys.list/get + secrets.list per vault.

    All of these are control-plane calls covered by ARM Reader, so a failure here IS
    a collection failure and goes through `Collector.guard`.
    """
    from azure.mgmt.keyvault import KeyVaultManagementClient

    def _client():
        return KeyVaultManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("keyvault.KeyVaultManagementClient (init)", _client)
    if client is None:
        return []

    def _list_vaults():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            {
                "id": model_attr(v, "id"),
                "name": model_attr(v, "name"),
                "location": model_attr(v, "location"),
                "vault_uri": model_attr(properties_bag(v), "vault_uri"),
                "enable_rbac_authorization": model_attr(
                    properties_bag(v), "enable_rbac_authorization"
                ),
            }
            for v in client.vaults.list_by_subscription()
        ]

    vaults = collector.guard("keyvault.vaults.list_by_subscription", _list_vaults, default=[])

    for vault in vaults:
        group, name = resource_group_from_id(vault.get("id")), vault.get("name")
        if not group or not name:
            collector.record(
                "keyvault.keys.list",
                RuntimeError(f"key vault {name!r} has no resource group in its id"),
            )
            vault["keys"], vault["secrets"] = [], []
            continue
        vault["keys"] = collector.guard(
            f"keyvault.keys.list ({name})",
            lambda group=group, name=name: collect_management_plane_keys(
                client, collector, group, name
            ),
            default=[],
        )
        vault["secrets"] = sorted(
            collector.guard(
                f"keyvault.secrets.list ({name})",
                lambda group=group, name=name: [
                    secret_record(project_management_secret(s))
                    for s in client.secrets.list(group, name)
                ],
                default=[],
            ),
            key=lambda r: r.get("name") or "",
        )

    return vaults


def collect_rotation_policies(vault: dict, cred, collector: Collector) -> None:
    """Open one vault's data plane and read every key's rotation policy.

    Mutates `vault` with `data_plane_status` / `data_plane_message` and merges the
    policies into its `keys`. Nothing here can flip the exit code except a
    non-HTTP failure — see `is_data_plane_inaccessible`.
    """
    from azure.keyvault.keys import KeyClient

    vault_uri = vault_data_plane_uri(vault)
    if not vault_uri:
        vault["data_plane_status"] = DATA_PLANE_NOT_ATTEMPTED
        vault["data_plane_message"] = "no vault uri and no vault name to derive one from"
        return

    name = vault.get("name")
    try:
        key_client = KeyClient(vault_url=vault_uri, credential=cred)
        # list() forces the ItemPaged: a 403 surfaces on the first page, not here.
        properties = list(key_client.list_properties_of_keys())
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_data_plane_inaccessible(exc):
            # Prowler's exact reading: a vault the credential holds no data action
            # on is a posture to report, not a failed collection.
            logger.warning(
                "key vault %s: data plane not accessible to this credential "
                "(no Key Vault data-plane role assignment or access policy) — %s",
                name,
                str(exc).strip().splitlines()[0],
            )
            vault["data_plane_status"] = DATA_PLANE_INACCESSIBLE
            vault["data_plane_message"] = " ".join(str(exc).split())[:300]
            return
        collector.record(f"keyvault.keys.list_properties_of_keys ({name})", exc)
        vault["data_plane_status"] = DATA_PLANE_NOT_ATTEMPTED
        vault["data_plane_message"] = " ".join(str(exc).split())[:300]
        return

    policies: dict[str, dict | None] = {}
    for key_properties in properties:
        key_name = model_attr(key_properties, "name")
        if not key_name:
            continue
        policies.setdefault(key_name, None)
        try:
            policies[key_name] = project_rotation_policy(
                key_client.get_key_rotation_policy(key_name)
            )
        except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash
            if is_data_plane_inaccessible(exc):
                # Prowler's `_get_single_rotation_policy` returns (name, None) here.
                # A key with no policy configured answers 404, which is the finding.
                logger.warning(
                    "key vault %s: no readable rotation policy for key %s — %s",
                    name,
                    key_name,
                    str(exc).strip().splitlines()[0],
                )
                continue
            collector.record(f"keyvault.keys.get_key_rotation_policy ({name}/{key_name})", exc)

    vault["data_plane_status"] = DATA_PLANE_ACCESSIBLE
    vault["keys"] = merge_rotation_policies(vault.get("keys") or [], policies)


def collect_key_vaults(subscription_id, cred, collector: Collector) -> list[dict]:
    """Both planes: the management-plane inventory, then per-vault rotation policies."""
    vaults = collect_management_plane(subscription_id, cred, collector)
    for vault in vaults:
        collect_rotation_policies(vault, cred, collector)
    return sorted((vault_record(v) for v in vaults), key=lambda r: r.get("id") or "")


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

    vaults: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-vault result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.KeyVault"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.KeyVault is not registered on subscription %s — no key "
                "vaults in use; reporting status not_registered",
                subscription_id,
            )
        vaults = collect_key_vaults(subscription_id, cred, collector)
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
            "key_vaults": vaults,
            "provider_registration_status": registration,
        },
        summary={**summarize(vaults), "provider_registration_status": registration},
    )

    filename = (
        f"azure_key_vault_key_rotation_"
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
