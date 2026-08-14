"""Microsoft Graph plumbing shared by the tenant-scoped Entra fetchers.

Separate from `azure_common.py` on purpose: everything here is Graph-specific and
has no bearing on the ARM (azure-mgmt-*) fetchers, which is most of the category.
The two halves of the Azure category differ in three ways that matter:

1. **Scope.** ARM evidence is per SUBSCRIPTION; Graph evidence is per TENANT. The
   Entra fetchers therefore fan out over tenants, record the tenant in the payload
   metadata, and deliberately do NOT call
   `azure_common.provider_registration_status()` — Graph is not an ARM resource
   provider, so there is no `Microsoft.*` namespace whose registration state could
   be asked about. (`Microsoft.Graph` is not one; asking would 404.)
2. **Auth.** Graph needs BOTH a Graph OAuth scope and an HTTP transport pointed at
   the Graph host. `GraphServiceClient(credentials, scopes=[...])` only changes the
   scope — the transport's base URL stays at graph.microsoft.com — so a sovereign
   cloud silently authenticates against the wrong host. `graph_service_client()`
   below builds the `GraphRequestAdapter` that fixes it, the same construction
   Prowler makes in prowler/providers/azure/lib/service/service.py (Apache-2.0).
3. **Async + manual pagination.** msgraph-sdk is async-only and does NOT hand back
   an auto-paging iterator the way azure-mgmt's `ItemPaged` does. Every collection
   response carries `@odata.nextLink`, which the caller must follow itself; the
   contract requires fetchers to paginate internally, so `paginate()` does.

Nothing here imports msgraph at module scope, so the pure transforms in each
fetcher (and their tests) import with only the standard library present.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import date, datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional
from uuid import UUID

_LOGGER = logging.getLogger("entra_graph")

# --------------------------------------------------------------------------- #
# Which Graph cloud to talk to
# --------------------------------------------------------------------------- #
#
# AZURE_AUTHORITY_HOST is the existing, already-declared selector for a sovereign
# cloud (see fetchers/_categories/azure.yaml — the runner lets it through the env
# whitelist for exactly this reason), so the Graph host is DERIVED from it rather
# than adding a second, separately-settable knob that could disagree with the
# credential's own authority. Hosts are the values of msgraph_core.NationalClouds;
# they are spelled out here so the mapping is readable without the SDK installed.
GRAPH_HOST_GLOBAL = "https://graph.microsoft.com"

_AUTHORITY_TO_GRAPH_HOST = {
    "login.microsoftonline.com": GRAPH_HOST_GLOBAL,
    "login.microsoftonline.us": "https://graph.microsoft.us",
    "login.microsoftonline.de": "https://graph.microsoft.de",
    "login.chinacloudapi.cn": "https://microsoftgraph.chinacloudapi.cn",
    "login.partner.microsoftonline.cn": "https://microsoftgraph.chinacloudapi.cn",
}


def graph_host() -> str:
    """Graph host for the cloud the credential's authority points at.

    Falls back to the public cloud when AZURE_AUTHORITY_HOST is unset (the
    `az login` / managed-identity default) or names an authority we have no
    mapping for — with a warning in the latter case, because silently collecting
    against the wrong cloud would produce empty evidence that looks valid.

    US Government tenants are ambiguous by authority alone: both the GCC High
    (graph.microsoft.us) and DoD (dod-graph.microsoft.us) clouds authenticate
    against login.microsoftonline.us. GCC High is chosen because it is the far
    more common of the two; a DoD tenant is a known gap.
    """
    authority = (os.environ.get("AZURE_AUTHORITY_HOST") or "").strip()
    if not authority:
        return GRAPH_HOST_GLOBAL
    host = authority.replace("https://", "").replace("http://", "").strip("/").lower()
    mapped = _AUTHORITY_TO_GRAPH_HOST.get(host)
    if mapped is None:
        _LOGGER.warning(
            "AZURE_AUTHORITY_HOST %r is not a recognized sovereign authority; "
            "collecting against the public Graph host %s",
            authority,
            GRAPH_HOST_GLOBAL,
        )
        return GRAPH_HOST_GLOBAL
    return mapped


def graph_scope() -> str:
    """OAuth scope for the Graph host. Always `<host>/.default` for app auth."""
    return f"{graph_host()}/.default"


# --------------------------------------------------------------------------- #
# The Graph model boundary
# --------------------------------------------------------------------------- #

def graph_attr(model: Any, name: str) -> Any:
    """Read ONE attribute off a Graph (kiota) model, normalized to a plain value.

    The Graph analogue of `azure_common.model_attr()`, with one normalization the
    ARM models never need: **datetimes**.

    - **Absent reads as None**, so a projection can chain through an omitted nested
      model (`conditions`, `grant_controls`, `sign_in_activity`) without raising.
    - **Enum members unwrap to their wire value.** Graph enums are plain `Enum`s,
      NOT `str` subclasses, so `str(ConditionalAccessGrantControl.Mfa)` is
      "ConditionalAccessGrantControl.Mfa". That repr is the source of a real bug in
      Prowler's conditional-access projection (see
      entra_conditional_access_policies/fetcher.py) and would also put an enum repr
      straight into the evidence.
    - **datetimes render as ISO-8601 with a `Z`.** kiota deserializes Graph's
      timestamps into `datetime` objects. Writing one through
      `json.dump(default=str)` yields "2026-08-14 12:00:00+00:00" — a space instead
      of the `T`, and `+00:00` instead of `Z` — which is neither the shape Graph
      sent nor a shape a validator regex written against the API would match. This
      is the same class of trap as the timedelta in `defender_plans`.
    - **UUIDs render as their string form**, so credential `key_id`s compare and
      sort as the strings the rest of the evidence uses.
    """
    return _plain(getattr(model, name, None))


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        # Graph timestamps are UTC; "+00:00" is spelled "Z" on the wire.
        rendered = value.isoformat()
        return rendered[:-6] + "Z" if rendered.endswith("+00:00") else rendered
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def graph_list(model: Any, name: str) -> List[Any]:
    """Read a list-valued Graph attribute, normalizing each element.

    Graph omits empty collections rather than sending `[]`, so an absent list must
    read as `[]` and not as None — otherwise every downstream `len()` and
    membership test needs its own None guard.
    """
    values = getattr(model, name, None) or []
    return [_plain(v) for v in values]


# --------------------------------------------------------------------------- #
# Client construction + async failure guarding
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def graph_service_client(cred):
    """A `GraphServiceClient` wired to the right Graph host, transport closed on exit.

    `GraphServiceClient(credentials, scopes=[...])` is NOT enough: the `scopes`
    argument only reaches the OAuth token request, while the underlying httpx
    client keeps its default base URL of graph.microsoft.com. So the scope and the
    host have to be set in two different places, and the way to set the host is to
    build the request adapter yourself — which is what Prowler does
    (prowler/providers/azure/lib/service/service.py, `__set_clients__`) and what
    this does.

    The httpx client is closed on exit; leaving it open leaks a connection pool and
    emits an "unclosed client" warning onto the stderr the runner reports.
    """
    from kiota_authentication_azure.azure_identity_authentication_provider import (
        AzureIdentityAuthenticationProvider,
    )
    from msgraph import GraphServiceClient
    from msgraph.graph_request_adapter import GraphRequestAdapter
    from msgraph_core import GraphClientFactory

    scope, host = graph_scope(), graph_host()
    _LOGGER.info("Microsoft Graph: host=%s scope=%s", host, scope)
    # allowed_hosts is deliberately left at its default: kiota treats an empty
    # allow-list as "any host", which is what lets the sovereign hosts above work.
    auth_provider = AzureIdentityAuthenticationProvider(cred, scopes=[scope])
    http_client = GraphClientFactory.create_with_default_middleware(host=host)
    try:
        yield GraphServiceClient(
            request_adapter=GraphRequestAdapter(auth_provider, client=http_client)
        )
    finally:
        try:
            await http_client.aclose()
        except Exception as exc:  # noqa: BLE001 — closing must never fail the run
            _LOGGER.debug("closing the Graph transport raised %s", exc)


async def aguard(collector, operation: str, fn: Callable[[], Awaitable[Any]], default: Any = None):
    """`Collector.guard()` for a coroutine: record the failure, return `default`.

    `Collector.guard` calls `fn()` and returns whatever it gets, which for an
    `async def` is an un-awaited coroutine — the call would appear to succeed and
    the evidence would contain a coroutine object. This awaits it inside the
    try/except so a Graph failure is recorded like any other API failure and still
    drives the exit code.
    """
    try:
        return await fn()
    except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
        collector.record(operation, exc)
        return default


async def with_graph_client(collector, cred, work, default=None):
    """Build the Graph client, run `await work(client)`, always close the transport.

    Only construction- and transport-level failures land here (a missing
    msgraph-sdk, a DNS failure reaching the token endpoint); per-call failures are
    recorded by `aguard` inside `work` so one denied endpoint doesn't erase the
    endpoints that answered.
    """
    if cred is None:
        return default
    try:
        async with graph_service_client(cred) as client:
            return await work(client)
    except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
        collector.record("msgraph.GraphServiceClient (init)", exc)
        return default


# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #

async def paginate(
    collector,
    operation: str,
    builder,
    request_configuration=None,
    page_limit: int = 1000,
) -> List[Any]:
    """Follow `@odata.nextLink` to the end and return every item.

    msgraph-sdk has no `ItemPaged` equivalent: `.get()` returns ONE page whose
    `odata_next_link` is the absolute URL of the next one, and the caller re-issues
    it through `builder.with_url(next_link).get()` (the link already carries the
    original `$select`/`$filter`, so the request configuration is passed on the
    first call only). Prowler paginates by hand the same way.

    A failure part-way through is recorded and the items gathered so far are
    returned, so a tenant that 429s on page 40 still yields 39 pages of evidence
    *and* a non-zero exit — silently returning a truncated list as if complete is
    the failure mode this whole layer exists to prevent.

    `page_limit` is a runaway guard, not a paging cap: a server that echoed the
    same nextLink back would otherwise loop forever inside the fetcher's timeout.
    """
    items: List[Any] = []
    try:
        response = await builder.get(request_configuration=request_configuration)
        pages = 0
        while response is not None:
            items.extend(getattr(response, "value", None) or [])
            next_link = getattr(response, "odata_next_link", None)
            pages += 1
            if not next_link:
                break
            if pages >= page_limit:
                collector.record(
                    operation,
                    RuntimeError(
                        f"stopped after {pages} pages with a nextLink still present; "
                        "refusing to keep paging"
                    ),
                )
                break
            response = await builder.with_url(next_link).get()
    except Exception as exc:  # noqa: BLE001 — boundary: record, keep what we have
        collector.record(operation, exc)
    return items


# --------------------------------------------------------------------------- #
# Tenant identity — the Graph fetchers' equivalent of `resolve_subscription`
# --------------------------------------------------------------------------- #

TENANT_UNRESOLVED = "unresolved"


async def resolve_tenant(collector, client) -> Dict[str, Any]:
    """Identify the tenant this Graph evidence came from.

    Provenance, not evidence: without it a reviewer cannot tell whose directory the
    users and roles belong to. Two sources, in order:

    1. `organization.get()` — the authoritative answer, and the only one that also
       yields the default verified domain (the human-legible tenant name, and what
       Prowler keys its per-tenant results by).
    2. AZURE_TENANT_ID — already in the category's passthrough env for the
       credential chain.

    A failing `organization.get()` is logged and falls through to the env var
    WITHOUT being recorded as an API failure: `Organization.Read.All` can be absent
    from an app registration that still holds every permission the actual evidence
    needs, and losing the whole run over a metadata read would be wrong. Only the
    case where BOTH sources come up empty is recorded — then the tenant genuinely
    is unknown, which does invalidate the evidence.
    """
    env_tenant = (os.environ.get("AZURE_TENANT_ID") or "").strip() or None

    org = None
    try:
        response = await client.organization.get()
        orgs = getattr(response, "value", None) or []
        org = orgs[0] if orgs else None
    except Exception as exc:  # noqa: BLE001 — provenance, not evidence: warn and fall back
        _LOGGER.warning(
            "organization.get() failed (%s: %s); falling back to AZURE_TENANT_ID for "
            "the tenant identity",
            type(exc).__name__,
            " ".join(str(exc).split())[:200],
        )

    if org is not None:
        domains = getattr(org, "verified_domains", None) or []
        default_domain = next(
            (graph_attr(d, "name") for d in domains if graph_attr(d, "is_default")),
            None,
        )
        return {
            "tenant_id": graph_attr(org, "id") or env_tenant,
            "tenant_name": graph_attr(org, "display_name"),
            "tenant_domain": default_domain
            or next((graph_attr(d, "name") for d in domains), None),
            "tenant_source": "organization",
        }

    if env_tenant:
        return {
            "tenant_id": env_tenant,
            "tenant_name": None,
            "tenant_domain": None,
            "tenant_source": "environment",
        }

    collector.record(
        "resolve_tenant",
        RuntimeError(
            "could not identify the tenant (organization.get() failed and "
            "AZURE_TENANT_ID is unset), so the collected evidence has no provenance"
        ),
    )
    return {
        "tenant_id": None,
        "tenant_name": None,
        "tenant_domain": None,
        "tenant_source": TENANT_UNRESOLVED,
    }


def tenant_payload(build_payload, *, tenant: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """`azure_common.build_payload()` with the tenant added to its metadata block.

    `build_payload` is shared with the subscription-scoped ARM fetchers and knows
    nothing about tenants, so the tenant is merged in here rather than by changing
    a signature four other fetchers depend on. The subscription fields it emits are
    kept — a Graph fetcher records the subscription the target named (when it named
    one) purely so its evidence can be correlated with the ARM evidence from the
    same manifest entry; it never scopes the collection.
    """
    payload = build_payload(**kwargs)
    payload["metadata"].update(
        {
            "tenant_id": tenant.get("tenant_id"),
            "tenant_name": tenant.get("tenant_name"),
            "tenant_domain": tenant.get("tenant_domain"),
            "tenant_source": tenant.get("tenant_source"),
        }
    )
    return payload


def tenant_scoping() -> Dict[str, Optional[str]]:
    """What the runner told us about scoping, for the payload's metadata block.

    Graph data is tenant-wide, so `subscription_id` never narrows a query here. It
    is still reported (as `not_applicable` when absent) so the evidence says
    plainly that it was seen and not used, rather than leaving a reader to wonder.
    """
    subscription_id = (os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip() or None
    return {
        "subscription_id": subscription_id,
        "subscription_source": "target_correlation_only" if subscription_id else "not_applicable",
    }


def tenant_filename_key(tenant: Dict[str, Any]) -> str:
    """The per-target discriminator for a Graph fetcher's output filename.

    The runner gives every target invocation the SAME `EVIDENCE_DIR` and works out
    which files an invocation produced by diffing the directory listing before and
    after. Two targets that write the same filename therefore look like the second
    one produced no output at all, so the name has to be unique per target.

    The tenant is that discriminator. AZURE_TENANT_ID (what the target named) wins
    over the id resolved from `organization.get()`, so the filename stays stable
    even on a run where the organization read was denied. `subscription_id`
    deliberately does not appear — putting it in the filename of tenant-wide
    evidence would imply a per-subscription scope that does not exist. One target
    per tenant is the intended manifest shape; two targets differing only by
    subscription would collect identical Graph evidence, and see each
    fetcher.yaml's target_schema.
    """
    from azure_common import sanitize_for_filename

    key = (os.environ.get("AZURE_TENANT_ID") or "").strip() or tenant.get("tenant_id")
    return sanitize_for_filename(str(key) if key else "unknown")
