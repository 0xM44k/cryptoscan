"""Quantum-migration priority using Mosca's inequality, with YOUR numbers.

X = how long the protected data must stay secret (years)
Y = how long migration will take you (years)
Q = how many years until a cryptographically relevant quantum computer exists
Start now when X + Y > Q. This tool supplies no value for Q: it is a forecast,
not a fact, and you must choose it. See docs/RESEARCH.md.
"""
from __future__ import annotations

import fnmatch


def settings_for(rel, cfg):
    x = None
    for rule in cfg.get("paths", []):
        if fnmatch.fnmatch(rel, rule["glob"]):
            x = rule.get("data_lifetime_years", x)
    return x


def classify(hit, cfg):
    """Return (priority, reason) for a hit. Non-quantum-vulnerable hits return (None, '')."""
    if hit["quantum"] != "vulnerable":
        return None, ""
    q, y = cfg.get("quantum_horizon_years"), cfg.get("migration_years")
    x = settings_for(hit["file"], cfg)
    if q is None or y is None:
        return "unassessed", "Set quantum_horizon_years and migration_years in the config to assess."
    if hit["usage"] == "authenticity":
        life = cfg.get("signature_validity_years")
        if life is None:
            return "unassessed", "Signatures matter if forged ones can be accepted after the break: set signature_validity_years."
        return ("start-now" if life + y > q else "plan"), f"signature validity {life} + migration {y} {'>' if life + y > q else '<='} horizon {q}"
    if x is None:
        return "unassessed", "No data_lifetime_years matches this path in the config."
    return ("start-now" if x + y > q else "plan"), f"data lifetime {x} + migration {y} {'>' if x + y > q else '<='} horizon {q}" + (" (usage unclear: treated as confidentiality)" if hit["usage"] == "unknown" else "")
