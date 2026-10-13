"""Scan modes -- Sn1per-style phased operation, bughound-flavoured.

Sn1per popularised the idea that an offensive tool should expose *modes*
(``sniper -t target -m stealth``) instead of a dozen disconnected boolean
flags. Each mode is a named, safe-by-default bundle of the same knobs
bughound already had (``--aggressive``, ``--no-exploit``, concurrency,
external tools, credential testing):

============  ==========================================================
Mode          Behaviour
============  ==========================================================
``stealth``   Passive recon + config checks only. Active modules never
              run, concurrency is throttled to stay under WAF/IPS
              radar (Sn1per's stealth mode).
``normal``    Passive + active detection, but the exploit phase stays
              off. "Find everything, prove nothing yet."
``aggressive`` Full pipeline: passive + active + exploit phase + external
              tools. Equivalent to the legacy ``--aggressive`` flag.
``nuke``      Aggressive plus opt-in default-credential testing
              (``--brute``, Sn1per's ``-b``) and external tools forced
              on. Maximum coverage, still strictly read-only.
============  ==========================================================

Passing ``--mode`` overrides the legacy ``--aggressive``/``--no-exploit``
flags; when no mode is given the legacy flags keep working unchanged
(backwards compatibility with 0.6.x invocations and tests).
"""

from __future__ import annotations

from dataclasses import dataclass

#: Modes understood by ``--mode`` / ``apply_mode``.
KNOWN_MODES: tuple[str, ...] = ("stealth", "normal", "aggressive", "nuke")


@dataclass
class ModeProfile:
    """The knob settings a mode expands to."""

    mode: str
    aggressive: bool
    exploit: bool
    bruteforce: bool
    concurrency: int
    use_external_tools: bool | None  # None = leave the operator's choice alone

    @property
    def description(self) -> str:
        return {
            "stealth": "passive recon only, low-and-slow (WAF-friendly)",
            "normal": "passive + active detection, exploit phase off",
            "aggressive": "passive + active detection + exploit proofs",
            "nuke": "aggressive + default-credential checks + external tools",
        }.get(self.mode, "")


_PROFILES: dict[str, ModeProfile] = {
    "stealth": ModeProfile("stealth", False, False, False, 2, False),
    "normal": ModeProfile("normal", True, False, False, 8, None),
    "aggressive": ModeProfile("aggressive", True, True, False, 8, None),
    "nuke": ModeProfile("nuke", True, True, True, 8, True),
}


def is_known_mode(mode: str | None) -> bool:
    return bool(mode) and mode.strip().lower() in KNOWN_MODES


def mode_profile(mode: str | None) -> ModeProfile | None:
    """Return the :class:`ModeProfile` for ``mode`` (None if unknown/empty)."""
    if not mode:
        return None
    return _PROFILES.get(mode.strip().lower())


def apply_mode(config, mode: str | None) -> ModeProfile | None:
    """Expand ``mode`` into ``config``'s boolean knobs, in place.

    ``config`` is a :class:`bughound.models.ScanConfig`. Unknown or empty
    modes are ignored (returns None) so legacy flag behaviour is preserved.
    Returns the applied profile so callers can report what changed.
    """
    profile = mode_profile(mode)
    if profile is None:
        return None
    config.mode = profile.mode
    config.aggressive = profile.aggressive
    config.exploit = profile.exploit
    config.bruteforce = profile.bruteforce
    config.concurrency = profile.concurrency
    if profile.use_external_tools is not None:
        config.use_external_tools = profile.use_external_tools
    return profile
