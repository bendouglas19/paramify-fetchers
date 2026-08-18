"""Live credential probes: does the ambient identity actually authenticate, and as whom.

`paramify doctor` without this checks that env vars are *set*. For the cloud
categories that is nearly meaningless — they authenticate through a credential
chain whose preferred links (IRSA, workload identity, managed identity, a cached
CLI login) set no env var at all, so doctor reports a clean bill of health and
the run then fails on auth. These probes close that gap.

They also answer "as whom", which is the more common silent failure. Credentials
that work but point at the wrong account produce a successful run full of empty
evidence, and nothing in the output says so.

Opt-in, because unlike the rest of doctor these make network calls.

Every probe runs in a subprocess with a hard timeout. The SDK paths in
particular can block on metadata-server or IMDS lookups that have no reliable
in-process cancellation, and a preflight that hangs is worse than one that says
"could not tell".
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

DEFAULT_TIMEOUT = 20

# Categories that authenticate through an ambient credential chain. Token-based
# categories (datadog, gitlab, okta, …) are deliberately absent: their secret is
# declared, so doctor's existing "is it set" check is already most of the answer,
# and probing them would mean a bespoke API call per vendor.
PROBEABLE = ("aws", "k8s", "azure", "gcp")

_AZURE_SCRIPT = """
import base64, json
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

cred = DefaultAzureCredential()
token = cred.get_token("https://management.azure.com/.default").token

# Read the principal out of the token's own claims. Decoding without verifying
# is fine here: Azure just issued it to us and we only display it, never trust
# it. It is the one place the SDK exposes WHO authenticated -- a service
# principal has appid, a human has upn.
def claims(jwt):
    try:
        part = jwt.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}

c = claims(token)
who = c.get("upn") or c.get("unique_name") or c.get("appid") or c.get("oid") or "unknown principal"

subs = []
for s in SubscriptionClient(cred).subscriptions.list():
    subs.append({"id": s.subscription_id, "name": s.display_name, "state": str(s.state)})
    if len(subs) >= 5:
        break
enabled = [s for s in subs if "Enabled" in s["state"]]
first = (enabled or subs or [None])[0]
print(json.dumps({
    "identity": str(who),
    "detail": {
        "subscription": first["name"] if first else "none visible",
        "subscription_id": first["id"] if first else None,
        "subscriptions_visible": len(subs),
        "tenant": c.get("tid"),
    },
}))
"""

_GCP_SCRIPT = """
import json
import google.auth
from google.auth.transport.requests import Request

creds, project = google.auth.default()
# Refresh rather than trusting construction: building a credential object
# succeeds off a malformed or expired file; minting a token does not.
creds.refresh(Request())

who = getattr(creds, "service_account_email", None)
if not who:
    # A user (ADC) credential carries no email attribute. Google's tokeninfo
    # endpoint is the supported way to ask whose token this is.
    try:
        import urllib.request, urllib.parse
        url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode(
            {"access_token": creds.token}
        )
        with urllib.request.urlopen(url, timeout=8) as r:
            who = json.loads(r.read()).get("email")
    except Exception:
        who = None

print(json.dumps({
    "identity": str(who or type(creds).__name__),
    "detail": {"project": project, "credential_type": type(creds).__name__},
}))
"""


def _fail(category: str, error: str) -> dict:
    return {"category": category, "ok": False, "identity": None, "detail": {}, "error": error}


def _run(argv: List[str], timeout: int) -> tuple[bool, str, str]:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return False, "", f"timed out after {timeout}s"
    except OSError as exc:
        return False, "", str(exc)
    if proc.returncode != 0:
        # Credential errors are verbose and multi-line; the last non-empty line
        # is almost always the actionable one.
        lines = [ln.strip() for ln in (proc.stderr or "").splitlines() if ln.strip()]
        return False, "", lines[-1] if lines else f"exit {proc.returncode}"
    return True, proc.stdout, ""


def _probe_aws(category: str, timeout: int) -> dict:
    if shutil.which("aws") is None:
        return _fail(category, "aws CLI not on PATH")
    ok, out, err = _run(
        ["aws", "sts", "get-caller-identity", "--output", "json"], timeout
    )
    if not ok:
        return _fail(category, err)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return _fail(category, "could not parse sts get-caller-identity output")
    return {
        "category": category,
        "ok": True,
        "identity": data.get("Arn"),
        "detail": {"account": data.get("Account"), "user_id": data.get("UserId")},
        "error": None,
    }


def _probe_python(category: str, script: str, timeout: int) -> dict:
    ok, out, err = _run([sys.executable, "-c", script], timeout)
    if not ok:
        return _fail(category, err)
    try:
        data = json.loads(out.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return _fail(category, "probe produced no readable result")
    return {
        "category": category,
        "ok": True,
        "identity": data.get("identity"),
        "detail": data.get("detail") or {},
        "error": None,
    }


def probe_category(category: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[dict]:
    """Probe one category's credentials. None if the category has nothing to probe."""
    if category in ("aws", "k8s"):
        # k8s reaches EKS with the AWS credential chain, so this is the same
        # question. Cluster reachability additionally needs a target's cluster
        # name, which a preflight without a manifest entry does not have.
        return _probe_aws(category, timeout)
    if category == "azure":
        return _probe_python(category, _AZURE_SCRIPT, timeout)
    if category == "gcp":
        return _probe_python(category, _GCP_SCRIPT, timeout)
    return None


def probe_categories(
    categories: List[str], timeout: int = DEFAULT_TIMEOUT
) -> List[Dict]:
    """Probe each probeable category, in the order given. Never raises."""
    results = []
    for cat in categories:
        result = probe_category(cat, timeout)
        if result is not None:
            results.append(result)
    return results
