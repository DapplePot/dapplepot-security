"""Unit tests for OW-ASI post-session signal functions — no infra required."""
import pytest
from unittest.mock import AsyncMock, patch

from tests.conftest import SESSION_ID, TENANT_ID, AGENT_ID, EVENT_ID
from consumers.security_eval.findings import Finding
from consumers.security_eval.scorer import asi_signals as agent_signals


def _finding(owasp_signal_id: str, sub_check_id: str, check_score: int = 88,
             severity: str = "high") -> Finding:
    """Build a minimal Finding with the new v2 signature."""
    return Finding(
        tenant_id=TENANT_ID,
        session_id=SESSION_ID,
        event_id=EVENT_ID,
        event_type="llm_start",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label="test label",
        check_score=check_score,
        category="prompt_injection",
        severity=severity,
        matched_text="...",
        detection_phase="online",
    )


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


SESSION_READ = {
    "initial_input": "show me the user list",
    "graph_state": "{}",
    "graph_runs": 1,
    "duration_ms": 500,
}

SESSION_WRITE = {
    "initial_input": "delete all old orders",
    "graph_state": "{}",
    "graph_runs": 1,
    "duration_ms": 500,
}

SESSION_HITL = {
    "initial_input": "process the payment",
    "graph_state": '{"hitl_enabled": true}',
    "graph_runs": 1,
    "duration_ms": 500,
}


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI01: signal_a01 (AGH-01b — goal hijack)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a01_fires_when_context_injection_leads_to_write():
    online = [_finding("OW-ASI06", "MCP-01a")]
    events = [_event("tool_start", tool_name="delete_record")]
    result = await agent_signals.signal_a01(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI01"
    assert result.sub_check_id == "AGH-01b"
    assert result.framework == "ASI"


@pytest.mark.asyncio
async def test_a01_silent_without_context_injection():
    online = [_finding("OW-LLM01", "PI-01a")]
    events = [_event("tool_start", tool_name="delete_record")]
    result = await agent_signals.signal_a01(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is None


@pytest.mark.asyncio
async def test_a01_silent_when_write_intent_matches():
    online = [_finding("OW-ASI06", "MCP-01a")]
    events = [_event("tool_start", tool_name="delete_record")]
    result = await agent_signals.signal_a01(events, SESSION_WRITE, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI02: signal_a02 (TME-01a — tool misuse)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a02_fires_on_online_findings():
    online = [_finding("OW-ASI02", "TME-01a", check_score=65), _finding("OW-ASI02", "TME-01b", check_score=70)]
    result = await agent_signals.signal_a02([], SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI02"
    assert result.check_score == 70  # max of hits


@pytest.mark.asyncio
async def test_a02_silent_without_online_findings():
    result = await agent_signals.signal_a02([], SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, [])
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI03: signal_a03 (IPA-01a — privilege escalation)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a03_fires_on_privilege_tool():
    events = [_event("tool_start", tool_name="assume_role")]
    result = await agent_signals.signal_a03(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI03"
    assert result.sub_check_id == "IPA-01a"


@pytest.mark.asyncio
async def test_a03_silent_on_normal_tool():
    events = [_event("tool_start", tool_name="list_users")]
    result = await agent_signals.signal_a03(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI04: signal_a04 (ASCV-01a — supply chain)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a04_fires_when_all_tools_unknown():
    events = [
        _event("tool_start", tool_name="shadow_tool_a"),
        _event("tool_start", tool_name="shadow_tool_b"),
    ]
    with patch(
        "consumers.security_eval.scorer.asi_signals.settings.get_tool_manifests",
        return_value={AGENT_ID: ["read_user", "list_users"]},
    ):
        result = await agent_signals.signal_a04(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI04"
    assert result.sub_check_id == "ASCV-01a"


@pytest.mark.asyncio
async def test_a04_silent_when_some_tools_known():
    events = [
        _event("tool_start", tool_name="read_user"),
        _event("tool_start", tool_name="shadow_tool"),
    ]
    with patch(
        "consumers.security_eval.scorer.asi_signals.settings.get_tool_manifests",
        return_value={AGENT_ID: ["read_user", "list_users"]},
    ):
        result = await agent_signals.signal_a04(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI05: signal_a05 (RCE-01b)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a05_fires_on_online_rce_finding():
    online = [_finding("OW-ASI05", "RCE-01b", check_score=95)]
    result = await agent_signals.signal_a05([], SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI05"
    assert result.sub_check_id == "RCE-01b"
    assert result.check_score == 95


@pytest.mark.asyncio
async def test_a05_fires_on_rce03a_container_escape():
    online = [_finding("OW-ASI05", "RCE-03a", check_score=98)]
    result = await agent_signals.signal_a05([], SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.check_score == 98


@pytest.mark.asyncio
async def test_a05_silent_without_rce_finding():
    result = await agent_signals.signal_a05([], SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, [])
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI06: signal_a06 (MCP-01a — context injection)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a06_fires_on_online_injection_findings():
    online = [_finding("OW-ASI06", "MCP-01a"), _finding("OW-ASI06", "MCP-01a")]
    result = await agent_signals.signal_a06([], SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID, online)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI06"
    assert result.sub_check_id == "MCP-01a"
    assert result.check_score == 90  # 88 + (2-1)*2


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI07: signal_a07 (IAC-01a — inter-agent communication)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a07_fires_on_delegation_tool():
    events = [_event("tool_start", tool_name="agent_handoff")]
    result = await agent_signals.signal_a07(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI07"
    assert result.sub_check_id == "IAC-01a"


@pytest.mark.asyncio
async def test_a07_silent_on_normal_tool():
    events = [_event("tool_start", tool_name="search_db")]
    result = await agent_signals.signal_a07(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI08: signal_a08 (CF-01a — cascading failure)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a08_fires_on_error_after_many_tools():
    events = (
        [_event("tool_start") for _ in range(6)]
        + [_event("graph_error")]
    )
    result = await agent_signals.signal_a08(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI08"
    assert result.sub_check_id == "CF-01a"


@pytest.mark.asyncio
async def test_a08_silent_on_error_with_few_tools():
    events = [_event("tool_start"), _event("graph_error")]
    result = await agent_signals.signal_a08(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_a08_silent_without_error():
    events = [_event("tool_start") for _ in range(10)]
    result = await agent_signals.signal_a08(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI09: signal_a09 (HAT-01a — human-agent trust exploitation)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a09_fires_on_authority_plus_high_stakes():
    session = {"initial_input": "as an admin, process the payment", "graph_state": "{}"}
    events = [_event("tool_start", tool_name="send_payment")]
    result = await agent_signals.signal_a09(events, session, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI09"
    assert result.sub_check_id == "HAT-01a"


@pytest.mark.asyncio
async def test_a09_silent_with_hitl():
    session = {"initial_input": "as admin, charge customer", "graph_state": "{}"}
    events = [_event("tool_start", tool_name="payment"), _event("interrupt_raised")]
    result = await agent_signals.signal_a09(events, session, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI10: signal_a10 (RA-01a — rogue agent)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a10_fires_on_high_tool_deviation():
    # current session: 15 distinct tools; baseline mean ~2, stddev ~1 → well above 3σ
    events = [_event("tool_start", tool_name=f"tool_{i}") for i in range(15)]
    baseline = [{"distinct_tools": i} for i in range(1, 6)]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(return_value=baseline)):
        result = await agent_signals.signal_a10(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is not None
    assert result.owasp_signal_id == "OW-ASI10"
    assert result.sub_check_id == "RA-01a"


@pytest.mark.asyncio
async def test_a10_silent_within_normal_range():
    events = [_event("tool_start", tool_name="tool_1"), _event("tool_start", tool_name="tool_2")]
    baseline = [{"distinct_tools": i} for i in range(1, 6)]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(return_value=baseline)):
        result = await agent_signals.signal_a10(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None


@pytest.mark.asyncio
async def test_a10_silent_with_insufficient_baseline():
    events = [_event("tool_start", tool_name=f"tool_{i}") for i in range(10)]
    with patch("core.infra.clickhouse.fetch", new=AsyncMock(return_value=[{"distinct_tools": 3}])):
        result = await agent_signals.signal_a10(events, SESSION_READ, TENANT_ID, SESSION_ID, AGENT_ID)
    assert result is None
