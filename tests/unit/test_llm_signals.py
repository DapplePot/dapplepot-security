"""Unit tests for post-session signal functions S-01 through S-10 — no infra required."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from tests.conftest import SESSION_ID, TENANT_ID, AGENT_ID, EVENT_ID
from consumers.security_eval.findings import Finding
from consumers.security_eval.scorer import signals


def _finding(signal_id: str, severity: str = "critical", score_contrib: int = 10) -> Finding:
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


def _event(event_type: str, tool_name: str | None = None, **kwargs) -> dict:
    e = {
        "event_type": event_type,
        "event_id": EVENT_ID,
        "session_id": SESSION_ID,
        "tool_name": tool_name,
        "llm_input_tokens": kwargs.get("input_tokens", 0),
        "llm_output_tokens": kwargs.get("output_tokens", 0),
        "payload": kwargs.get("payload", {}),
    }
    return e


SESSION = {
    "initial_input": "show me the user list",
    "graph_state": "{}",
    "graph_runs": 1,
    "duration_ms": 500,
}


# S-01
@pytest.mark.asyncio
async def test_s01_fires_on_inj001():
    online = [_finding("INJ-001")]
    result = await signals.signal_s01([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.signal_id == "S-01"
    assert result.score_contrib == 40


@pytest.mark.asyncio
async def test_s01_silent_without_injection():
    online = [_finding("PII-004")]
    result = await signals.signal_s01([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is None


# S-02
@pytest.mark.asyncio
async def test_s02_fires_on_inj004():
    online = [_finding("INJ-004")]
    result = await signals.signal_s02([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.signal_id == "S-02"
    assert result.score_contrib == 20


# S-03
@pytest.mark.asyncio
async def test_s03_fires_on_out001_critical():
    online = [_finding("OUT-001", severity="critical")]
    result = await signals.signal_s03([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.signal_id == "S-03"
    assert result.score_contrib == 30


@pytest.mark.asyncio
async def test_s03_silent_on_out001_warning():
    online = [_finding("OUT-001", severity="warning")]
    result = await signals.signal_s03([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is None


# S-04
@pytest.mark.asyncio
async def test_s04_gives_35_for_critical_pii():
    online = [_finding("PII-001")]
    result = await signals.signal_s04([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.score_contrib == 35


@pytest.mark.asyncio
async def test_s04_gives_10_for_warning_pii():
    online = [_finding("PII-004", severity="warning")]
    result = await signals.signal_s04([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.score_contrib == 10


@pytest.mark.asyncio
async def test_s04_silent_with_no_pii():
    online = [_finding("INJ-001")]
    result = await signals.signal_s04([], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is None


# S-05
@pytest.mark.asyncio
async def test_s05_fires_above_baseline():
    events = [_event("tool_start") for _ in range(20)]
    # baseline: 10 historical sessions with mean=3, stddev ~2 → 20 calls is way above
    baseline = [{"tool_call_count": i} for i in range(1, 11)]  # 1..10, mean=5.5
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(return_value=baseline)):
        result = await signals.signal_s05(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.signal_id == "S-05"
    assert result.score_contrib > 0


@pytest.mark.asyncio
async def test_s05_silent_at_baseline():
    events = [_event("tool_start") for _ in range(5)]
    # baseline mean=5.5, 5 calls is below mean → no finding
    baseline = [{"tool_call_count": i} for i in range(1, 11)]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(return_value=baseline)):
        result = await signals.signal_s05(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# S-06
@pytest.mark.asyncio
async def test_s06_fires_on_out_of_scope_tool():
    events = [_event("tool_start", tool_name="delete_user")]
    with patch(
        "consumers.security_eval.scorer.signals.settings.get_tool_manifests",
        return_value={AGENT_ID: ["read_user", "list_users"]},
    ):
        result = await signals.signal_s06(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.signal_id == "S-06"


@pytest.mark.asyncio
async def test_s06_silent_when_tool_in_manifest():
    events = [_event("tool_start", tool_name="read_user")]
    with patch(
        "consumers.security_eval.scorer.signals.settings.get_tool_manifests",
        return_value={AGENT_ID: ["read_user", "list_users"]},
    ):
        result = await signals.signal_s06(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_s06_silent_when_no_manifest():
    events = [_event("tool_start", tool_name="any_tool")]
    with patch(
        "consumers.security_eval.scorer.signals.settings.get_tool_manifests",
        return_value={},
    ):
        result = await signals.signal_s06(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# S-07
@pytest.mark.asyncio
async def test_s07_fires_on_write_in_read_session():
    events = [_event("tool_start", tool_name="delete_record")]
    session = {"initial_input": "show me the records", "graph_state": "{}"}
    result = await signals.signal_s07(events, session, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.signal_id == "S-07"


@pytest.mark.asyncio
async def test_s07_silent_on_non_read_intent():
    events = [_event("tool_start", tool_name="delete_record")]
    session = {"initial_input": "delete all old records", "graph_state": "{}"}
    result = await signals.signal_s07(events, session, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None
