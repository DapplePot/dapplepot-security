"""Unit tests for Bayesian agent trust scoring (trust.py)."""
from datetime import datetime, timedelta

from consumers.security_eval.scorer.trust import compute_agent_trust_score


AGENT_ID = "00000000-0000-0000-0000-000000000003"
NOW = datetime.utcnow()


def _hist(score: int, days_ago: int) -> dict:
    return {
        "llm_score": score,
        "asi_score": score,
        "scored_at": (NOW - timedelta(days=days_ago)).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Basic output shape
# ─────────────────────────────────────────────────────────────────────────────

def test_returns_required_keys():
    result = compute_agent_trust_score(AGENT_ID, 10, 10, [], 0)
    assert "trust_score" in result
    assert "trend" in result
    assert "trend_slope" in result
    assert "sessions_evaluated" in result
    assert "decay_weighted_avg" in result
    assert "alpha" in result
    assert "beta" in result


def test_trust_score_is_in_range():
    result = compute_agent_trust_score(AGENT_ID, 50, 50, [], 0)
    assert 0 <= result["trust_score"] <= 100


# ─────────────────────────────────────────────────────────────────────────────
# Prior: no history
# ─────────────────────────────────────────────────────────────────────────────

def test_clean_new_session_gives_high_trust():
    result = compute_agent_trust_score(AGENT_ID, 5, 5, [], 0)
    assert result["trust_score"] >= 70, "Clean agent should start with high trust"


def test_risky_new_session_lowers_trust():
    clean = compute_agent_trust_score(AGENT_ID, 5, 5, [], 0)
    risky = compute_agent_trust_score(AGENT_ID, 90, 90, [], 0)
    assert risky["trust_score"] < clean["trust_score"]


# ─────────────────────────────────────────────────────────────────────────────
# Bayesian update with history
# ─────────────────────────────────────────────────────────────────────────────

def test_many_risky_sessions_degrades_trust():
    hist = [_hist(85, i) for i in range(1, 20)]
    result = compute_agent_trust_score(AGENT_ID, 85, 85, hist, len(hist))
    assert result["trust_score"] < 40, "Many risky sessions should degrade trust significantly"


def test_many_clean_sessions_builds_trust():
    hist = [_hist(5, i) for i in range(1, 20)]
    result = compute_agent_trust_score(AGENT_ID, 5, 5, hist, len(hist))
    assert result["trust_score"] >= 75, "Many clean sessions should build high trust"


def test_sessions_evaluated_increments():
    hist = [_hist(10, i) for i in range(5)]
    result = compute_agent_trust_score(AGENT_ID, 10, 10, hist, 5)
    assert result["sessions_evaluated"] == 6


# ─────────────────────────────────────────────────────────────────────────────
# Trend detection
# ─────────────────────────────────────────────────────────────────────────────

def test_trend_stable_with_few_sessions():
    result = compute_agent_trust_score(AGENT_ID, 20, 20, [], 0)
    assert result["trend"] == "stable"


def test_trend_degrading_on_rising_risk():
    # Increasing risk scores over time → trend should be "degrading"
    hist = [_hist(i * 5, 20 - i) for i in range(1, 16)]
    result = compute_agent_trust_score(AGENT_ID, 75, 75, hist, len(hist))
    assert result["trend"] in ("degrading", "stable")


def test_trend_improving_on_falling_risk():
    # Decreasing risk scores over time → trend should be "improving"
    hist = [_hist(75 - i * 5, 20 - i) for i in range(1, 16)]
    result = compute_agent_trust_score(AGENT_ID, 5, 5, hist, len(hist))
    assert result["trend"] in ("improving", "stable")


def test_trend_values_are_valid():
    hist = [_hist(30, i) for i in range(10)]
    result = compute_agent_trust_score(AGENT_ID, 30, 30, hist, len(hist))
    assert result["trend"] in ("improving", "stable", "degrading")


# ─────────────────────────────────────────────────────────────────────────────
# Temporal decay
# ─────────────────────────────────────────────────────────────────────────────

def test_old_risky_sessions_weighted_less():
    # One recent risky session vs many old risky sessions
    recent_risky = compute_agent_trust_score(AGENT_ID, 90, 90, [_hist(90, 1)], 1)
    old_risky = compute_agent_trust_score(AGENT_ID, 10, 10, [_hist(90, 365)], 1)
    assert old_risky["trust_score"] > recent_risky["trust_score"], (
        "Old risky sessions should weigh less than recent ones"
    )


# ─────────────────────────────────────────────────────────────────────────────
# String timestamps
# ─────────────────────────────────────────────────────────────────────────────

def test_string_scored_at_is_handled():
    hist = [{"llm_score": 20, "asi_score": 20, "scored_at": "2026-01-01T00:00:00Z"}]
    result = compute_agent_trust_score(AGENT_ID, 20, 20, hist, 1)
    assert "trust_score" in result


def test_invalid_scored_at_falls_back():
    hist = [{"llm_score": 20, "asi_score": 20, "scored_at": "not-a-date"}]
    result = compute_agent_trust_score(AGENT_ID, 20, 20, hist, 1)
    assert "trust_score" in result


# ─────────────────────────────────────────────────────────────────────────────
# Posterior alpha / beta
# ─────────────────────────────────────────────────────────────────────────────

def test_alpha_increases_with_risky_session():
    clean = compute_agent_trust_score(AGENT_ID, 5, 5, [], 0)
    risky = compute_agent_trust_score(AGENT_ID, 80, 80, [], 0)
    assert risky["alpha"] > clean["alpha"]


def test_beta_increases_with_clean_session():
    risky = compute_agent_trust_score(AGENT_ID, 80, 80, [], 0)
    clean = compute_agent_trust_score(AGENT_ID, 5, 5, [], 0)
    assert clean["beta"] > risky["beta"]
