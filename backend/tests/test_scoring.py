import pytest
from pydantic import ValidationError

from sentinelpi.config import ScoringSettings
from sentinelpi.detection.scoring import band_for, compute_risk

S = ScoringSettings()


def test_default_weights_match_the_spec():
    for rule, pts in {"SP-001": 35, "SP-002": 20, "SP-004": 30, "SP-003": 10}.items():
        r = compute_risk([rule], S)
        assert r.score == pts and len(r.breakdown) == 1 and not r.capped


def test_independent_rules_add_a_bonus_per_extra_rule():
    r = compute_risk(["SP-001", "SP-004"], S)
    assert r.score == 35 + 30 + 10 and r.band == "critical"
    assert [c.points for c in r.breakdown] == [35, 30, 10]


def test_total_is_capped_at_100():
    r = compute_risk(["SP-001", "SP-002", "SP-003", "SP-004"], S)
    assert r.score == 100 and r.capped is True and sum(c.points for c in r.breakdown) == 125


def test_repeated_matches_of_one_rule_count_once():
    assert compute_risk(["SP-001"] * 50, S).score == 35


def test_unknown_rules_and_empty_input():
    assert compute_risk(["SP-999"], S).score == 0
    empty = compute_risk([], S)
    assert empty.score == 0 and empty.band == "low" and empty.breakdown == []


def test_breakdown_is_transparent_and_sums_to_the_score():
    r = compute_risk(["SP-002", "SP-003"], S)
    assert sum(c.points for c in r.breakdown) == r.score == 20 + 10 + 10
    assert all(c.label for c in r.breakdown)


@pytest.mark.parametrize(
    "score,band",
    [
        (0, "low"),
        (24, "low"),
        (25, "medium"),
        (49, "medium"),
        (50, "high"),
        (74, "high"),
        (75, "critical"),
        (100, "critical"),
    ],
)
def test_band_boundaries(score, band):
    assert band_for(score, S) == band


def test_weights_and_bands_are_configurable_and_validated():
    custom = ScoringSettings(ssh_failures=50, independent_rule_bonus=0)
    assert compute_risk(["SP-001", "SP-002"], custom).score == 70
    with pytest.raises(ValidationError):
        ScoringSettings(band_medium=60, band_high=50)
    with pytest.raises(ValidationError):
        ScoringSettings(ssh_failures=101)
    with pytest.raises(ValidationError):
        ScoringSettings(unknown_key=1)
