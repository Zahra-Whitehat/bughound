"""Squad orchestration -- every module staffed on a named specialist squad.

Bug-Bounty-Agents runs an engagement as phases: reconnaissance &
intelligence first, then web/API hunting, then exploitation & chaining.
bughound maps the same idea onto its scanner modules:

- **RECON SQUAD** (phase 1, passive): maps the attack surface --
  subdomains, DNS, wayback, tech fingerprint, WAF, admin panels, API
  docs, JS endpoints, backup files, source maps, emails, robots.
- **CONFIG SQUAD** (phase 1, passive): hardening posture -- security
  headers, TLS, cookies, CORS, info disclosure, secret leakage.
- **INJECTION SQUAD** (phase 2, active): the web-hunter payload
  specialists -- SQLi, NoSQLi, command injection, XSS, SSRF, traversal,
  header injection, open redirect, XXE, JWT attacks.
- **ACCESS SQUAD** (phase 2, active): access-control / auth / API
  surface -- advisory checks, GraphQL hunting, host-header poisoning,
  prototype pollution, default-credential checks.

Phase 1 always runs before phase 2 so the planner (and the chain phase)
can use recon facts (tech stack, WAF, discovered endpoints) to steer the
hunting squads -- exactly the recon-advisor -> web-hunter hand-off from
the reference workflow.
"""

from __future__ import annotations

from ..modules.base import Module

#: Squad name -> module names. A module not listed here lands in the
#: fallback squad ("access" for active modules, "config" for passive
#: ones) so newly added modules keep running without edits here.
SQUADS: dict[str, list[str]] = {
    "RECON SQUAD": [
        "robots-sitemap",
        "dns-recon",
        "subdomain-enum",
        "whois-recon",
        "wayback-urls",
        "tech-fingerprint",
        "waf-detection",
        "http-methods",
        "js-endpoints",
        "admin-panels",
        "api-discovery",
        "backup-files",
        "sourcemap-exposure",
        "email-harvest",
    ],
    "CONFIG SQUAD": [
        "security-headers",
        "tls",
        "cookies",
        "cors",
        "info-disclosure",
        "secrets",
    ],
    "INJECTION SQUAD": [
        "sqli",
        "nosqli",
        "command-injection",
        "xss",
        "ssrf",
        "path-traversal",
        "header-injection",
        "open-redirect",
        "xxe-prober",
        "jwt-attacks",
    ],
    "ACCESS SQUAD": [
        "advisory",
        "graphql-hunter",
        "host-header-poison",
        "prototype-pollution",
        "default-logins",
    ],
}

#: Fallback squads by module class.
_PASSIVE_FALLBACK = "CONFIG SQUAD"
_ACTIVE_FALLBACK = "ACCESS SQUAD"

_LOOKUP: dict[str, str] = {
    mod: squad for squad, mods in SQUADS.items() for mod in mods
}


def module_squad(name: str, passive: bool = False) -> str:
    """Squad label for module ``name`` (fallback keeps new modules running)."""
    if name in _LOOKUP:
        return _LOOKUP[name]
    return _PASSIVE_FALLBACK if passive else _ACTIVE_FALLBACK


def split_by_phase(modules: list[Module]) -> tuple[list[Module], list[Module]]:
    """Split modules into (phase 1 recon+config, phase 2 hunting).

    Ordering inside each phase is preserved (the registry's alphabetical
    order), so results are deterministic across runs.
    """
    phase1: list[Module] = []
    phase2: list[Module] = []
    for m in modules:
        squad = module_squad(m.name, passive=m.passive)
        if squad in ("RECON SQUAD", "CONFIG SQUAD"):
            phase1.append(m)
        else:
            phase2.append(m)
    return phase1, phase2
