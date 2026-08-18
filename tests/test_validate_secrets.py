"""What `paramify validate` demands of a manifest's secrets.

validate exists to answer one question before a run costs anything: would the
runner accept this manifest? So its secret rules have to be the runner's rules.
Two ways they can drift, both covered here:

  - an OPTIONAL secret (`required: false`) the manifest omits. The runner skips
    it (executor._build_env); validate demanding it would fail a manifest that
    runs perfectly well -- which is every manifest naming a fetcher that declares
    the ambient-identity key pair, i.e. all of aws, azure and k8s.
  - a CATEGORY-declared secret. The runner resolves those exactly like a
    fetcher's own (contract.effective_secrets), so validate has to see them too,
    or a manifest missing a required credential passes preflight and dies in the
    run.
"""

from __future__ import annotations

from pathlib import Path

from framework import api
from framework.contract import Fetcher, PlatformSpec, Secret

REPO_ROOT = Path(__file__).resolve().parent.parent


def make_fetcher(**overrides) -> Fetcher:
    defaults = dict(
        name="testcat_thing",
        version="0.1.0",
        description="test fetcher",
        category="testcat",
        runtime_type="python",
        runtime_entry="fetcher.py",
        runtime_timeout=None,
        output_type="json",
        output_path="out.json",
        output_aggregation=None,
        secrets=[],
        supports_targets=False,
        target_schema={},
        path=REPO_ROOT / "fetchers" / "testcat" / "thing",
        config_schema={},
        evidence_set=None,
    )
    defaults.update(overrides)
    return Fetcher(**defaults)


def _manifest(secrets: dict | None = None) -> dict:
    entry: dict = {"use": "testcat_thing"}
    if secrets:
        entry["secrets"] = secrets
    return {"run": {"output_dir": "./evidence", "fetchers": [entry]}}


def _validate(fetcher: Fetcher, spec: PlatformSpec | None, manifest: dict) -> list[str]:
    return api.validate(
        manifest, REPO_ROOT,
        fetchers={fetcher.name: fetcher},
        platforms={spec.category: spec} if spec else {},
    )


def _spec(secrets: list[Secret]) -> PlatformSpec:
    return PlatformSpec(category="testcat", config_schema={}, secrets=secrets, passthrough_env=[])


def test_optional_fetcher_secret_may_be_omitted() -> None:
    f = make_fetcher(secrets=[Secret(name="key", env="TEST_KEY", required=False)])
    assert _validate(f, None, _manifest()) == []


def test_required_fetcher_secret_may_not_be_omitted() -> None:
    f = make_fetcher(secrets=[Secret(name="key", env="TEST_KEY")])
    errors = _validate(f, None, _manifest())
    assert any("missing secret 'key'" in e for e in errors)


def test_wiring_an_optional_secret_is_still_valid() -> None:
    """Omitting it is allowed; supplying it must not become an error either."""
    f = make_fetcher(secrets=[Secret(name="key", env="TEST_KEY", required=False)])
    assert _validate(f, None, _manifest({"key": "${env:TEST_KEY}"})) == []


def test_optional_category_secret_may_be_omitted() -> None:
    """The shipped case: aws/azure/k8s declare their static keys optional."""
    f = make_fetcher()
    spec = _spec([Secret(name="access_key_id", env="AWS_ACCESS_KEY_ID", required=False)])
    assert _validate(f, spec, _manifest()) == []


def test_required_category_secret_is_demanded() -> None:
    f = make_fetcher()
    spec = _spec([Secret(name="api_token", env="CAT_TOKEN")])
    errors = _validate(f, spec, _manifest())
    assert any("missing secret 'api_token'" in e for e in errors)


def test_fetcher_secret_overrides_category_on_name_clash() -> None:
    """effective_secrets lets a fetcher relax a category credential to optional;
    validate must honor the fetcher's answer, like the runner does."""
    f = make_fetcher(secrets=[Secret(name="api_token", env="CAT_TOKEN", required=False)])
    spec = _spec([Secret(name="api_token", env="CAT_TOKEN")])
    assert _validate(f, spec, _manifest()) == []
