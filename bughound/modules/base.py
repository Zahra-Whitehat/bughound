"""Scanner module base class and registry."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..http_client import HttpClient
from ..models import Category, Finding, ScanConfig, Target


@dataclass
class RequestTarget:
    """A discovered injectable location (URL query or form)."""

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    source: str = ""  # e.g. "query", "form"


@dataclass
class ScanContext:
    client: HttpClient
    config: ScanConfig
    target: Target
    base_url: str
    # populated by the crawler:
    urls: list[str] = field(default_factory=list)
    request_targets: list[RequestTarget] = field(default_factory=list)
    # shared cache of the landing page response text/headers:
    seed_html: str = ""
    seed_headers: dict[str, str] = field(default_factory=dict)
    log: Callable[[str], None] = lambda msg: None


class Module:
    """Base class for all scanner modules."""

    name: str = "base"
    categories: list[Category] = []
    #: passive modules never send attack payloads (safe against any target)
    passive: bool = True
    #: modules that require --aggressive because they send exploitation payloads
    aggressive_required: bool = False

    async def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in REGISTRY:
        raise ValueError(f"Duplicate module name: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls


def load_all_modules() -> None:
    """Import module packages so their @register decorators run."""

    from . import active, passive  # noqa: F401


def build_modules(config: ScanConfig) -> list[Module]:
    load_all_modules()
    selected = config.modules
    modules: list[Module] = []
    for name, cls in sorted(REGISTRY.items()):
        if selected is not None and name not in selected:
            continue
        inst = cls()
        if inst.aggressive_required and not config.aggressive:
            continue
        modules.append(inst)
    return modules
