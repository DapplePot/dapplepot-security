"""Bayesian agent trust scoring for v3.

Prior: Beta(α=2, β=8) — agents start at ~80% trust.
Each session updates the posterior based on whether it was risky or clean.
Temporal decay down-weights older sessions.
"""
import math
from datetime import datetime, timezone


_ALPHA_PRIOR = 2.0
_BETA_PRIOR = 8.0
_DECAY_LAMBDA = 0.05  # per-day decay factor


def compute_agent_trust_score(
    agent_id: str,
    new_session_llm_score: int,
    new_session_asi_score: int,
    historical_scores: list[dict],  # [{llm_score, asi_score, scored_at}, ...]
    session_count: int,
) -> dict:
    """
    Bayesian update of agent trust.

    Returns:
        {
            "trust_score": float,         # 0-100, higher = more trusted
            "trend": str,                 # "improving" | "stable" | "degrading"
            "trend_slope": float,         # linear regression slope
            "sessions_evaluated": int,
            "decay_weighted_avg": float,  # exponential decay weighted average
            "alpha": float,               # posterior alpha (for persistence)
            "beta": float,                # posterior beta (for persistence)
        }
    """
    alpha = _ALPHA_PRIOR
    beta = _BETA_PRIOR

    now = datetime.now(timezone.utc)
    decay_weighted_scores: list[float] = []

    for hist in sorted(historical_scores, key=lambda x: x["scored_at"]):
        scored_at = hist["scored_at"]
        if isinstance(scored_at, str):
            try:
                scored_at = datetime.fromisoformat(scored_at)
                if scored_at.tzinfo is None:
                    scored_at = scored_at.replace(tzinfo=timezone.utc)
            except Exception:
                scored_at = now
        elif isinstance(scored_at, datetime) and scored_at.tzinfo is None:
            scored_at = scored_at.replace(tzinfo=timezone.utc)

        days_ago = (now - scored_at).total_seconds() / 86400
        weight = math.exp(-_DECAY_LAMBDA * days_ago)

        max_score = max(
            int(hist.get("llm_score", 0) or 0),
            int(hist.get("asi_score", 0) or 0),
        )

        # Score > 40 = risk event → increases alpha (risk)
        # Score <= 40 = clean event → increases beta (trust)
        if max_score > 40:
            alpha += weight * (max_score / 100)
        else:
            beta += weight * ((100 - max_score) / 100)

        decay_weighted_scores.append(max_score * weight)

    # Update with new session
    new_max = max(new_session_llm_score, new_session_asi_score)
    if new_max > 40:
        alpha += new_max / 100
    else:
        beta += (100 - new_max) / 100

    # Trust = 100 * (1 - E[Beta(α,β)])
    # E[Beta] = α/(α+β) = risk probability
    risk_probability = alpha / (alpha + beta)
    trust_score = round(100 * (1 - risk_probability), 1)

    # Trend: linear regression on last 20 sessions
    recent = historical_scores[-20:] if len(historical_scores) >= 5 else []
    slope = 0.0
    if len(recent) >= 5:
        x = list(range(len(recent)))
        y = [max(int(h.get("llm_score", 0) or 0), int(h.get("asi_score", 0) or 0)) for h in recent]
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi ** 2 for xi in x)
        denom = n * sum_x2 - sum_x ** 2
        if denom != 0:
            slope = (n * sum_xy - sum_x * sum_y) / denom

    if slope > 2.0:
        trend = "degrading"
    elif slope < -2.0:
        trend = "improving"
    else:
        trend = "stable"

    decay_avg = (
        sum(decay_weighted_scores) / len(decay_weighted_scores)
        if decay_weighted_scores
        else 0.0
    )

    return {
        "trust_score": trust_score,
        "trend": trend,
        "trend_slope": round(slope, 3),
        "sessions_evaluated": session_count + 1,
        "decay_weighted_avg": round(decay_avg, 2),
        "alpha": round(alpha, 3),
        "beta": round(beta, 3),
    }
