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
from consumers.security_eval.scorer.orchestrator import score_session


def _finding(owasp_signal_id: str, sub_check_id: str, check_score: int = 85,
             severity: str = "critical") -> Finding:
    return Finding(
        tenant_id=TENANT_ID,
        session_id=SESSION_ID,
        event_id=EVENT_ID,
        event_type="llm_start",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label="test finding",
        check_score=check_score,
        category="prompt_injection",
        severity=severity,
        matched_text="...",
        detection_phase="online",
    )


@pytest.fixture(scope="module")
async def pg():
    pool = await asyncpg.create_pool(settings.postgres_dsn)
    yield pool
    await pool.close()


@pytest.mark.asyncio
async def test_inject_prompt_scores_medium_or_high(pg):
    """Session with OW-LLM01 finding should get llm_score >= 40."""
    online_findings = [_finding("OW-LLM01", "PI-01a", check_score=85)]

    mock_events = []
    mock_session = {"initial_input": "test", "graph_state": "{}", "graph_runs": 1, "duration_ms": 100}

    with (
        patch("consumers.security_eval.scorer.orchestrator.ch.fetch", new=AsyncMock(return_value=mock_events)),
        patch("consumers.security_eval.scorer.llm_signals.get_pool", new=AsyncMock(return_value=pg)),
    ):
        score_row = await score_session(
            tenant_id=TENANT_ID,
            session_id=SESSION_ID,
            agent_id=AGENT_ID,
            online_findings=online_findings,
        )

    assert score_row["llm_score"] >= 40
    assert score_row["llm_band"] in ("medium", "high", "critical")

    # Verify written to DB
    row = await pg.fetchrow(
        "SELECT llm_score, llm_band FROM session_risk_scores WHERE session_id = $1",
        SESSION_ID,
    )
    assert row is not None
    assert row["llm_score"] >= 40

    # Cleanup
    await pg.execute("DELETE FROM session_risk_scores WHERE session_id = $1", SESSION_ID)
    await pg.execute("DELETE FROM security_findings WHERE session_id = $1", SESSION_ID)


@pytest.mark.asyncio
async def test_pii_and_passthrough_score_triggers_alert(pg):
    """OW-LLM02 + OW-LLM05 critical should produce llm_score >= 65 and an alert."""
    online_findings = [
        _finding("OW-LLM02", "SID-01a", check_score=95),
        _finding("OW-LLM05", "IOH-01a", check_score=90),
    ]

    mock_events = []
    alert_produced = []

    async def mock_alert(score_row, findings):
        alert_produced.append(score_row)

    with (
        patch("consumers.security_eval.scorer.orchestrator.ch.fetch", new=AsyncMock(return_value=mock_events)),
        patch("consumers.security_eval.scorer.orchestrator.produce_security_alert", side_effect=mock_alert),
        patch("consumers.security_eval.scorer.llm_signals.get_pool", new=AsyncMock(return_value=pg)),
    ):
        score_row = await score_session(
            tenant_id=TENANT_ID,
            session_id=SESSION_ID,
            agent_id=AGENT_ID,
            online_findings=online_findings,
        )

    assert score_row["llm_score"] >= 65
    assert score_row["llm_band"] in ("high", "critical")
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
        patch("consumers.security_eval.scorer.orchestrator.ch.fetch", new=AsyncMock(return_value=mock_events)),
        patch("consumers.security_eval.scorer.llm_signals.get_pool", new=AsyncMock(return_value=pg)),
    ):
        score_row = await score_session(
            tenant_id=TENANT_ID,
            session_id=SESSION_ID,
            agent_id=AGENT_ID,
            online_findings=online_findings,
        )

    assert score_row["llm_score"] <= 10
    assert score_row["llm_band"] == "clean"

    # Cleanup
    await pg.execute("DELETE FROM session_risk_scores WHERE session_id = $1", SESSION_ID)
