"""Dataclasses for the runner's internal representation of fetchers, manifests, and run results.

These are the in-memory shapes the runner uses; the on-disk yaml/json shapes are
documented in framework/schemas/*.json and parsed by config_loader / manifest_loader.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Secret:
    """A credential the fetcher reads from the environment at run time.

    `required=False` declares a credential the fetcher CAN use but does not need.
    That is the ambient-identity case: the AWS, Azure, GCP and k8s categories all
    authenticate through a credential chain whose preferred links — IRSA, workload
    identity, managed identity — hand over no secret at all, while the same chain
    also accepts static keys. Declaring those keys optional is what lets a fetcher
    advertise "you may supply these" without breaking the deployments that supply
    none.
    """
    name: str
    env: str
    per_target: bool = False
    required: bool = True
    description: Optional[str] = None


def effective_secrets(fetcher, platform_spec=None) -> List["Secret"]:
    """The secrets a fetcher actually takes: category-declared, then its own.

    Per-fetcher wins on a name clash, matching how `_apply_config` merges
    config (platform defaults <- per-fetcher). Both the describe/TUI surface and
    the runner resolve through here so what the UI advertises and what the runner
    demands cannot drift apart.
    """
    merged: Dict[str, "Secret"] = {}
    if platform_spec is not None:
        for s in platform_spec.secrets:
            merged[s.name] = s
    for s in fetcher.secrets:
        merged[s.name] = s
    return list(merged.values())


@dataclass
class TargetField:
    name: str
    type: str
    required: bool = True
    env: Optional[str] = None
    default: Any = None
    description: Optional[str] = None


@dataclass
class EvidenceSet:
    """Paramify evidence-set identity for a fetcher (1 fetcher = 1 evidence set).

    Shipped default declared in fetcher.yaml; the runner carries it into the
    envelope and the uploader get-or-creates the set by reference_id. Customers
    override reference_id per program in the uploader config, not here.
    """
    reference_id: str
    name: str
    instructions: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ConfigField:
    """A non-secret config knob a fetcher (or platform) accepts.

    Mirrors TargetField: declared in fetcher.yaml `config_schema` (per-fetcher)
    or in fetchers/_categories/<category>.yaml `config_schema` (platform-wide).
    The runner resolves a value and, when `env` is set, injects it as that env
    var for the invocation.
    """
    name: str
    type: str = "string"
    required: bool = False
    env: Optional[str] = None
    default: Any = None
    description: Optional[str] = None


@dataclass
class Fetcher:
    name: str
    version: str
    description: str
    category: Optional[str]
    runtime_type: str
    runtime_entry: str
    runtime_timeout: Optional[int]
    output_type: str
    output_path: str
    output_aggregation: Optional[str]
    secrets: List[Secret]
    supports_targets: bool
    target_schema: Dict[str, TargetField]
    path: Path
    config_schema: Dict[str, ConfigField] = field(default_factory=dict)
    evidence_set: Optional["EvidenceSet"] = None
    ksis: List[str] = field(default_factory=list)

    @property
    def entry_path(self) -> Path:
        return self.path / self.runtime_entry


@dataclass
class PlatformSpec:
    """Code-side declaration for a category, from fetchers/_categories/<name>.yaml.

    Holds config and secrets shared across every fetcher in the category plus the
    default auth passthrough list. Empty/absent category files yield an empty spec.

    `secrets` exists so a category whose credentials are the same for every
    fetcher declares them once. Azure's service principal is three env vars used
    identically by all 27 of its fetchers; repeating that in 27 fetcher.yaml files
    is duplication that drifts. Per-fetcher secrets still win on a name clash,
    mirroring how config_schema already merges.
    """
    category: str
    config_schema: Dict[str, ConfigField] = field(default_factory=dict)
    secrets: List["Secret"] = field(default_factory=list)
    passthrough_env: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class PlatformConfig:
    """Customer-side values for a category, from a manifest `platforms:` block."""
    config: Dict[str, Any] = field(default_factory=dict)
    passthrough_env: List[str] = field(default_factory=list)


@dataclass
class TargetInstance:
    """A single target from a manifest entry — values for one fanout iteration."""
    values: Dict[str, Any]
    secrets: Dict[str, str]


@dataclass
class ManifestEntry:
    use: str
    config: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)
    targets: List[TargetInstance] = field(default_factory=list)


@dataclass
class Manifest:
    output_dir: Path
    entries: List[ManifestEntry]
    platforms: Dict[str, PlatformConfig] = field(default_factory=dict)


@dataclass
class InvocationResult:
    """Result of a single fetcher invocation (one target if fanout, else just one)."""
    fetcher_name: str
    fetcher_version: str
    target: Optional[Dict[str, Any]]
    started_at: str
    completed_at: str
    duration_sec: float
    exit_code: int
    stdout: str
    stderr: str
    outputs: List[str]
    # What the fetcher reported via $FETCHER_STATUS_FILE, already secret-redacted
    # by the executor (the only place the injected values are still in scope).
    # None when the fetcher wrote nothing readable, which is not an error — the
    # envelope then falls back to the stderr tail. See docs/fetcher_contract.md.
    error: Optional[str] = None
    error_code: Optional[str] = None
