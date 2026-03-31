"""
Integration tests for the post-session scorer.
Requires: docker compose up -d from dapplepot_pipeline (Kafka, Postgres, ClickHouse, Redis).
"""
import pytest
import asyncpg
from unittest.mock import AsyncMock, patch

from core.config import settings
from tests.conftest import SESSION_ID, TENANT_ID, AGENT_ID, EVENT_ID
from consumers.security_eval.findings import Finding
from consumers.security_eval.scorer.post_session import score_session


def _finding(signal_id: str, severity: str = "critical", score_contrib: int = 0) -> Finding:
    return Finding(
        tenant_id=TENANT_ID,
        session_id=SESSION_ID,
        event_id=EVENT_ID,
        event_type="llm_start",
        signal_id=signal_id,
        sig_type="injection",
        owasp_id="LLM01",
        severity=severity,
        matched_text="...",
        detail=None,
        score_contrib=score_contrib,
        detection_phase="online",
    )


@pytest.fixture(scope="module")
async def pg():
    pool = await asyncpg.create_pool(settings.postgres_dsn)
    yield pool
    await pool.close()


@pytest.mark.asyncio
async def test_inject_prompt_scores_medium_or_high(pg):
    """Session with INJ-001 should get risk_score >= 40 and risk_band medium or high."""
    online_findings = [_finding("INJ-001", severity="critical")]

    # Mock ClickHouse and Postgres session fetch — no real infra needed for logic test
    mock_events = []
    mock_session = {"initial_input": "test", "graph_state": "{}", "graph_runs": 1, "duration_ms": 100}

    with (
        patch("consumers.security_eval.scorer.post_session.ch.fetch", new=AsyncMock(return_value=mock_events)),
        patch("consumers.security_eval.scorer.post_session.score_session.__wrapped__", create=True),
    ):
        # We need the pool to work — use real pg for write but mock CH
        with patch("consumers.security_eval.scorer.signals.get_pool", new=AsyncMock(return_value=pg)):
            score_row = await score_session(
                tenant_id=TENANT_ID,
                session_id=SESSION_ID,
                agent_id=AGENT_ID,
                online_findings=online_findings,
            )

    assert score_row["risk_score"] >= 40
    assert score_row["risk_band"] in ("medium", "high", "critical")

    # Verify written to DB
    row = await pg.fetchrow(
        "SELECT risk_score, risk_band FROM session_risk_scores WHERE session_id = $1",
        SESSION_ID,
    )
    assert row is not None
    assert row["risk_score"] >= 40

    # Cleanup
    await pg.execute("DELETE FROM session_risk_scores WHERE session_id = $1", SESSION_ID)
    await pg.execute("DELETE FROM security_findings WHERE session_id = $1", SESSION_ID)


@pytest.mark.asyncio
async def test_pii_and_passthrough_score_triggers_alert(pg):
    """PII-001 + OUT-001 critical should produce risk_score >= 65 and an alert."""
    online_findings = [
        _finding("PII-001", severity="critical"),
        _finding("OUT-001", severity="critical"),
    ]

    mock_events = []

    alert_produced = []

    async def mock_alert(score_row, findings):
        alert_produced.append(score_row)

    with (
        patch("consumers.security_eval.scorer.post_session.ch.fetch", new=AsyncMock(return_value=mock_events)),
        patch("consumers.security_eval.scorer.post_session.produce_security_alert", side_effect=mock_alert),
        patch("consumers.security_eval.scorer.signals.get_pool", new=AsyncMock(return_value=pg)),
    ):
        score_row = await score_session(
            tenant_id=TENANT_ID,
            session_id=SESSION_ID,
            agent_id=AGENT_ID,
            online_findings=online_findings,
        )

    assert score_row["risk_score"] >= 65
    assert score_row["risk_band"] in ("high", "critical")
    assert len(alert_produced) == 1, "Alert should have been produced"

    # Cleanup
    await pg.execute("DELETE FROM session_risk_scores WHERE session_id = $1", SESSION_ID)
    await pg.execute("DELETE FROM security_findings WHERE session_id = $1", SESSION_ID)


@pytest.mark.asyncio
async def test_happy_checkout_is_clean(pg):
    """Session with no findings should score 0–10 and be clean."""
    online_findings = []
    mock_events = []

    with (
        patch("consumers.security_eval.scorer.post_session.ch.fetch", new=AsyncMock(return_value=mock_events)),
        patch("consumers.security_eval.scorer.signals.get_pool", new=AsyncMock(return_value=pg)),
    ):
        score_row = await score_session(
            tenant_id=TENANT_ID,
            session_id=SESSION_ID,
            agent_id=AGENT_ID,
            online_findings=online_findings,
        )

    assert score_row["risk_score"] <= 10
    assert score_row["risk_band"] == "clean"

    # Cleanup
    await pg.execute("DELETE FROM session_risk_scores WHERE session_id = $1", SESSION_ID)
