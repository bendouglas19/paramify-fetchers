#!/usr/bin/env python3
"""
Azure App Service (web app) configuration and hardening posture

For every web app in one subscription, reports the transport and identity posture
(HTTPS-only, minimum TLS version, HTTP/2, FTP/FTPS deployment state, client
certificate mode, App Service Authentication, managed identity) together with the
declared language runtime versions — `linux_fx_version` plus the Windows-stack
`java_version` / `php_version` / `python_version` fields. The runtime versions are
what a "supported / non-end-of-life runtime" control is evidenced from, so all of
them are kept even when only one is populated for a given app.

Field projections are ported from Prowler's
prowler/providers/azure/services/app/app_service.py (Apache-2.0), which reads the
same azure-mgmt-web SDK, so the attribute paths transfer directly. Two deliberate
divergences from Prowler:

- **Auth settings are read with the GET, not the POST.** Prowler calls
  `web_apps.get_auth_settings_v2()`, which is POST `.../config/authsettingsV2/list`
  and needs `Microsoft.Web/sites/config/list/Action` — beyond the built-in Reader
  role. `get_auth_settings_v2_without_secrets()` is GET
  `.../config/authsettingsV2`, returns the same `platform.enabled`, and by
  definition cannot hand back a secret. Reader is therefore sufficient for this
  whole fetcher (unlike the function-app one next door).
- **The resource group comes from the resource ID.** Prowler reads
  `app.resource_group`, a read-only convenience property that exists only on the
  older msrest-generated azure-mgmt-web. On 11.x (the `_utils.model_base`
  generator) it is absent and reads as None, which would silently break every
  per-app GET, so `resource_group_from_id()` parses it out of the ARM ID instead.

Function apps are excluded here (`kind` starting with "functionapp") — they are a
separate evidence set, fetchers/azure/function_app_configuration, because their
collection needs permissions beyond Reader.

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
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    dig,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("azure_app_service_configuration")

# `kind` is a comma-joined string: "app", "app,linux", "app,linux,container",
# "functionapp", "functionapp,linux". Prowler splits web apps from function apps on
# exactly these prefixes, and the two sets are collected by different fetchers here
# because the function-app calls need permissions Reader does not carry.
WEB_APP_KIND_PREFIX = "app"
FUNCTION_APP_KIND_PREFIX = "functionapp"

# minTlsVersion is a bare version string on this API ("1.0" … "1.3"), not the
# "TLS1_2" spelling azure-mgmt-storage uses.
MODERN_TLS_VERSIONS = ("1.2", "1.3")

# ftpsState: "AllAllowed" (plaintext FTP accepted), "FtpsOnly", "Disabled".
FTP_DISABLED_STATES = ("Disabled",)
FTP_ENCRYPTED_STATES = ("Disabled", "FtpsOnly")


# --- projection: the only code here that touches an azure-mgmt model ---

def project_site(site) -> dict:
    """Read a `Site` model's attributes into a flat snake_case dict.

    Attribute access is stable across the azure-mgmt generator styles; `as_dict()`
    is not (on the `_model_base`/`model_base` SDKs — which azure-mgmt-web 11.x is —
    it emits the camelCase wire shape nested under "properties"). Confining the SDK
    to this one function keeps every transform below pure dict-in/dict-out, and
    testable with no azure-* package installed.

    Values are the SDK's own, un-defaulted: `None` here means "the API did not
    return this field". `identity` is absent on every app without a managed
    identity, which is why each hop is `model_attr`'s None-tolerant read.
    """
    identity = model_attr(site, "identity")
    return {
        "id": model_attr(site, "id"),
        "name": model_attr(site, "name"),
        "location": model_attr(site, "location"),
        "kind": model_attr(site, "kind"),
        "state": model_attr(site, "state"),
        "default_host_name": model_attr(site, "default_host_name"),
        # --- transport ---
        "https_only": model_attr(site, "https_only"),
        # --- mutual TLS ---
        "client_cert_enabled": model_attr(site, "client_cert_enabled"),
        "client_cert_mode": model_attr(site, "client_cert_mode"),
        # --- network exposure ---
        "public_network_access": model_attr(site, "public_network_access"),
        "virtual_network_subnet_id": model_attr(site, "virtual_network_subnet_id"),
        # --- workload identity ---
        "identity": {
            "principal_id": model_attr(identity, "principal_id"),
            "tenant_id": model_attr(identity, "tenant_id"),
            "type": model_attr(identity, "type"),
        },
    }


def project_site_config(config) -> dict:
    """Read a `SiteConfigResource` (web_apps.get_configuration) into a flat dict.

    `ftps_state` and `min_tls_version` are SDK `str` enums (FtpsState,
    SupportedTlsVersions); `model_attr` unwraps them to their wire value, without
    which `str()` would put "FtpsState.DISABLED" in the evidence and a lowercased
    comparison would silently stop matching.
    """
    return {
        "id": model_attr(config, "id"),
        "name": model_attr(config, "name"),
        # --- declared runtime versions (all of them: only one is set per app) ---
        "linux_fx_version": model_attr(config, "linux_fx_version"),
        "windows_fx_version": model_attr(config, "windows_fx_version"),
        "java_version": model_attr(config, "java_version"),
        "php_version": model_attr(config, "php_version"),
        "python_version": model_attr(config, "python_version"),
        "net_framework_version": model_attr(config, "net_framework_version"),
        "node_version": model_attr(config, "node_version"),
        # --- transport / protocol ---
        "http20_enabled": model_attr(config, "http20_enabled"),
        "ftps_state": model_attr(config, "ftps_state"),
        "min_tls_version": model_attr(config, "min_tls_version"),
        # --- operational hardening ---
        "remote_debugging_enabled": model_attr(config, "remote_debugging_enabled"),
        "always_on": model_attr(config, "always_on"),
        "http_logging_enabled": model_attr(config, "http_logging_enabled"),
    }


def project_auth_settings(settings) -> dict:
    """Read a `SiteAuthSettingsV2` into a flat dict.

    `platform.enabled` is the field Prowler's app_ensure_auth_is_set_up check reads.
    `global_validation` is ours: "auth is switched on" and "unauthenticated callers
    are actually rejected" are different facts, and only the second one shows an
    anonymous caller cannot reach the app.
    """
    platform = model_attr(settings, "platform")
    global_validation = model_attr(settings, "global_validation")
    return {
        "platform_enabled": model_attr(platform, "enabled"),
        "platform_runtime_version": model_attr(platform, "runtime_version"),
        "require_authentication": model_attr(global_validation, "require_authentication"),
        "unauthenticated_client_action": model_attr(
            global_validation, "unauthenticated_client_action"
        ),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def is_web_app(kind) -> bool:
    """Prowler's split: `kind` starting with "app" is a web app, not a function app.

    An app with no `kind` at all is treated as a web app — that is Prowler's default
    (`getattr(app, "kind", "app")`) and matches the API, which omits `kind` only for
    plain Windows web apps.
    """
    text = str(kind or WEB_APP_KIND_PREFIX).lower()
    return text.startswith(WEB_APP_KIND_PREFIX) and not text.startswith(
        FUNCTION_APP_KIND_PREFIX
    )


def effective_client_cert_mode(client_cert_enabled, client_cert_mode) -> str:
    """Ported verbatim from Prowler's `App._get_client_cert_mode`.

    The two ARM fields are not independent: `clientCertMode` keeps its last value
    after `clientCertEnabled` is switched off, so the raw mode alone reads as
    "Required" on an app that no longer asks for a certificate. This collapses the
    pair into the one mode the portal shows.
    """
    enabled = bool(client_cert_enabled or False)
    mode = str(client_cert_mode or "Ignore")
    if enabled and mode == "OptionalInteractiveUser":
        return "Optional"
    if enabled and mode == "Optional":
        return "Allow"
    if enabled and mode == "Required":
        return "Required"
    return "Ignore"


def web_app_record(site: dict) -> dict:
    """Normalize one projected web app into an evidence record.

    Optional booleans are coerced with `bool(x or False)`: Azure OMITS a false-y
    field rather than returning `false` (confirmed live against this SDK), so a
    validator asserting `"https_only": false` would not match `null`. Absent means
    off for every flag here — there is no third state.

    `configuration` and `authentication` start as None and are filled in by the
    per-app enrichment; None therefore means "not collected for this app", which is
    distinguishable from a collected-but-empty block.
    """
    resource_id = site.get("id")
    identity = site.get("identity") or {}
    identity_type = identity.get("type")
    return {
        "id": resource_id,
        "name": site.get("name"),
        "location": site.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "kind": site.get("kind"),
        "state": site.get("state"),
        "default_host_name": site.get("default_host_name"),
        # --- transport ---
        "https_only": bool(site.get("https_only") or False),
        # --- mutual TLS ---
        "client_cert_enabled": bool(site.get("client_cert_enabled") or False),
        "client_cert_mode": site.get("client_cert_mode"),
        "effective_client_cert_mode": effective_client_cert_mode(
            site.get("client_cert_enabled"), site.get("client_cert_mode")
        ),
        # --- network exposure ---
        "public_network_access": site.get("public_network_access"),
        "vnet_integrated": bool(site.get("virtual_network_subnet_id")),
        "vnet_subnet_id": site.get("virtual_network_subnet_id"),
        # --- workload identity: "None" is the literal type ARM returns ---
        "identity": {
            "principal_id": identity.get("principal_id"),
            "tenant_id": identity.get("tenant_id"),
            "type": identity_type,
        },
        "managed_identity_enabled": str(identity_type or "None").lower() != "none",
        # Filled in by the per-app enrichment.
        "configuration": None,
        "authentication": None,
    }


def configuration_record(config: dict) -> dict:
    """Normalize a projected site configuration — runtime versions plus hardening."""
    return {
        "linux_fx_version": config.get("linux_fx_version"),
        "windows_fx_version": config.get("windows_fx_version"),
        "java_version": config.get("java_version"),
        "php_version": config.get("php_version"),
        "python_version": config.get("python_version"),
        "net_framework_version": config.get("net_framework_version"),
        "node_version": config.get("node_version"),
        "http20_enabled": bool(config.get("http20_enabled") or False),
        "ftps_state": config.get("ftps_state"),
        "min_tls_version": config.get("min_tls_version"),
        "remote_debugging_enabled": bool(config.get("remote_debugging_enabled") or False),
        "always_on": bool(config.get("always_on") or False),
        "http_logging_enabled": bool(config.get("http_logging_enabled") or False),
    }


def authentication_record(settings: dict) -> dict:
    """Normalize projected auth settings — App Service Authentication ("Easy Auth")."""
    return {
        "auth_enabled": bool(settings.get("platform_enabled") or False),
        "auth_runtime_version": settings.get("platform_runtime_version"),
        "require_authentication": bool(settings.get("require_authentication") or False),
        "unauthenticated_client_action": settings.get("unauthenticated_client_action"),
    }


def summarize(apps: list[dict]) -> dict:
    """Transport, identity and runtime coverage across the subscription's web apps."""
    total = len(apps)
    https_only = sum(1 for a in apps if a["https_only"])
    managed_identity = sum(1 for a in apps if a["managed_identity_enabled"])
    return {
        "total_web_apps": total,
        "https_only_apps": https_only,
        "https_only_percentage": coverage_percentage(https_only, total),
        "managed_identity_apps": managed_identity,
        "managed_identity_percentage": coverage_percentage(managed_identity, total),
        "auth_enabled_apps": sum(1 for a in apps if dig(a, "authentication", "auth_enabled")),
        "client_cert_required_apps": sum(
            1 for a in apps if a["effective_client_cert_mode"] == "Required"
        ),
        "minimum_tls_1_2_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "min_tls_version") or "") in MODERN_TLS_VERSIONS
        ),
        "http2_enabled_apps": sum(
            1 for a in apps if dig(a, "configuration", "http20_enabled")
        ),
        "ftp_deployment_disabled_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "ftps_state") or "") in FTP_DISABLED_STATES
        ),
        "ftp_encrypted_or_disabled_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "ftps_state") or "") in FTP_ENCRYPTED_STATES
        ),
        "remote_debugging_enabled_apps": sum(
            1 for a in apps if dig(a, "configuration", "remote_debugging_enabled")
        ),
        "always_on_apps": sum(1 for a in apps if dig(a, "configuration", "always_on")),
        "http_logging_enabled_apps": sum(
            1 for a in apps if dig(a, "configuration", "http_logging_enabled")
        ),
        "vnet_integrated_apps": sum(1 for a in apps if a["vnet_integrated"]),
        "public_network_access_disabled_apps": sum(
            1 for a in apps if str(a["public_network_access"] or "").lower() == "disabled"
        ),
        # Runtime-version evidence is per app (the versions themselves are in each
        # record); the summary only reports how many apps declared one at all, so a
        # reviewer can see the runtime projection was actually populated.
        "apps_with_declared_runtime": sum(
            1
            for a in apps
            if any(
                dig(a, "configuration", field)
                for field in (
                    "linux_fx_version",
                    "windows_fx_version",
                    "java_version",
                    "php_version",
                    "python_version",
                    "net_framework_version",
                    "node_version",
                )
            )
        ),
    }


# --- collection (lazy azure imports; not exercised by the fixture tests) ---

def collect_web_apps(subscription_id, cred, collector: Collector) -> list[dict]:
    """One web_apps.list(), then a configuration + auth-settings GET per web app.

    The list response carries the identity / transport / client-certificate
    projection; the runtime versions and the protocol settings only exist on
    `config/web`, and Easy Auth only on `config/authsettingsV2`. Both are
    Reader-permitted GETs.
    """
    from azure.mgmt.web import WebSiteManagementClient

    def _client():
        return WebSiteManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("web.WebSiteManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            web_app_record(project_site(site))
            for site in client.web_apps.list()
            if is_web_app(model_attr(site, "kind"))
        ]

    apps = collector.guard("web.web_apps.list", _list, default=[])

    for app in apps:
        group, name = app.get("resource_group"), app.get("name")
        if not group or not name:
            collector.record(
                "web.web_apps.get_configuration",
                RuntimeError(f"web app {name!r} has no resource group in its id"),
            )
            continue
        config = collector.guard(
            f"web.web_apps.get_configuration ({name})",
            lambda group=group, name=name: project_site_config(
                client.web_apps.get_configuration(resource_group_name=group, name=name)
            ),
        )
        if config is not None:
            app["configuration"] = configuration_record(config)
        settings = collector.guard(
            f"web.web_apps.get_auth_settings_v2_without_secrets ({name})",
            lambda group=group, name=name: project_auth_settings(
                client.web_apps.get_auth_settings_v2_without_secrets(
                    resource_group_name=group, name=name
                )
            ),
        )
        if settings is not None:
            app["authentication"] = authentication_record(settings)

    return sorted(apps, key=lambda r: r.get("id") or "")


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

    apps: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-app result is legible: Azure returns
        # an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Web"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Web is not registered on subscription %s — no App Service "
                "in use; reporting status not_registered",
                subscription_id,
            )
        apps = collect_web_apps(subscription_id, cred, collector)
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
            "web_apps": apps,
            "provider_registration_status": registration,
        },
        summary={**summarize(apps), "provider_registration_status": registration},
    )

    filename = (
        f"azure_app_service_configuration_"
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
