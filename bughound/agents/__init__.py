"""bughound.agents -- Bug-Bounty-Agents-style specialist layer.

The `Bug-Bounty-Agents <https://github.com/matty69v/Bug-Bounty-Agents>`_
project organizes bug-bounty work as *phases staffed by specialist
personas* (recon-advisor, attack-planner, web-hunter, exploit-chainer,
poc-validator, report-generator...) coordinated by a swarm orchestrator
with a hard scope-guard. bughound borrows that structure and implements
the personas as deterministic code around the existing scanner modules:

- :mod:`bughound.agents.squads` -- the swarm orchestrator: every scanner
  module belongs to a named squad; squads run in phases (recon squad
  first, then the hunting squads) with phase-grouped console output.
- :mod:`bughound.agents.planner` -- the attack-planner / threat-modeler
  persona: reads the recon squad's structured output and writes an
  attack plan (focus areas, tech-specific guidance, WAF notes) that
  steers the rest of the scan and is rendered in the report.
- :mod:`bughound.agents.exploit_chainer` -- the exploit-chainer persona:
  combines individually-Medium findings into attack chains whose impact
  is Critical (traversal -> credentials -> takeover, XSS -> session
  theft, ...), each chain backed by the evidence already captured.

Scope enforcement is NOT re-implemented here: every request the agents
influence flows through the same denylist-guarded HttpClient the rest of
bughound uses (the ``_scope-guard`` persona is ``bughound.authorization``
and applies to all phases equally).
"""

from __future__ import annotations

from .exploit_chainer import run_chain_phase
from .planner import build_attack_plan
from .squads import SQUADS, module_squad, split_by_phase

__all__ = [
    "SQUADS",
    "module_squad",
    "split_by_phase",
    "build_attack_plan",
    "run_chain_phase",
]
