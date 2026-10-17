"""Transparent 0-100 risk score (spec section 7).

Rules: each DISTINCT rule contributes its fixed weight once, and every additional distinct
rule in the same window adds a small bonus. The total is capped at 100. The score is a
prioritization aid, not a probability, and the weights are heuristic and configurable.
Incident correlation (Phase 6) calls `compute_risk` with the rules matched in an incident.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from sentinelpi.config import ScoringSettings

RULE_LABELS = {
    "SP-001": "Repeated SSH failures",
    "SP-002": "New listening port",
    "SP-003": "Sustained resource anomaly",
    "SP-004": "Unexpected process",
}


class ScoreComponent(BaseModel):
    label: str
    points: int


class RiskScore(BaseModel):
    score: int
    band: str  # low | medium | high | critical
    capped: bool
    breakdown: list[ScoreComponent]


def rule_weight(rule_id: str, scoring: ScoringSettings) -> int:
    return {
        "SP-001": scoring.ssh_failures,
        "SP-002": scoring.new_listening_port,
        "SP-003": scoring.sustained_cpu,
        "SP-004": scoring.watchlisted_process,
    }.get(rule_id, 0)


def band_for(score: int, scoring: ScoringSettings) -> str:
    if score >= scoring.band_critical:
        return "critical"
    if score >= scoring.band_high:
        return "high"
    if score >= scoring.band_medium:
        return "medium"
    return "low"


def compute_risk(rule_ids: Iterable[str], scoring: ScoringSettings) -> RiskScore:
    distinct = sorted({r for r in rule_ids if r in RULE_LABELS})
    breakdown = [
        ScoreComponent(label=f"{r}: {RULE_LABELS[r]}", points=rule_weight(r, scoring))
        for r in distinct
    ]
    extra = len(distinct) - 1
    if extra > 0 and scoring.independent_rule_bonus:
        breakdown.append(
            ScoreComponent(
                label="Independent rule matches in the same window "
                f"(+{scoring.independent_rule_bonus} x {extra})",
                points=scoring.independent_rule_bonus * extra,
            )
        )
    raw = sum(c.points for c in breakdown)
    score = min(100, raw)
    return RiskScore(
        score=score, band=band_for(score, scoring), capped=raw > 100, breakdown=breakdown
    )
