"""S-01 through S-10 signal functions — pure, independently testable."""
import json
import math
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

# Signals S-01–S-04 consume online findings already emitted during the session.
# Signals S-05–S-10 require the full ClickHouse event list.

# Write/delete/send tool name patterns used by S-07
WRITE_TOOL_PATTERNS = [
    r"(?i)(write|create|insert|update|delete|remove|send|post|put|patch|drop|truncate|exec)",
]

# High-stakes action tool name patterns used by S-08
HIGH_STAKES_TOOL_PATTERNS = [
    r"(?i)(payment|charge|transfer|purchase|buy|send_email|send_message|notify|deploy|publish)",
]

# Max points per signal
SIGNAL_MAX = {
    "S-01": 40,
    "S-02": 20,
    "S-03": 30,
    "S-04": 35,
    "S-05": 20,
    "S-06": 25,
    "S-07": 30,
    "S-08": 15,
    "S-09": 10,
    "S-10": 10,
}

SIGNAL_OWASP = {
    "S-01": "LLM01",
    "S-02": "LLM01",
    "S-03": "LLM02",
    "S-04": "LLM06",
    "S-05": "LLM08",
    "S-06": "LLM07",
    "S-07": "LLM08",
    "S-08": "LLM09",
    "S-09": "LLM10",
    "S-10": "LLM04",
}


def _make_finding(
    signal_id: str,
    session_id: str,
    tenant_id: str,
    score_contrib: int,
    detail: str,
    event_id: str = "00000000-0000-0000-0000-000000000000",
) -> "Finding":
    from consumers.security_eval.findings import Finding
    return Finding(
        tenant_id=tenant_id,
        session_id=session_id,
        event_id=event_id,
        event_type="post_session",
        signal_id=signal_id,
        sig_type="agency" if signal_id in ("S-05", "S-06", "S-07", "S-08") else "scorer",
        owasp_id=SIGNAL_OWASP[signal_id],
        severity="critical" if score_contrib >= 25 else "warning",
        matched_text=None,
        detail=detail,
        score_contrib=score_contrib,
        detection_phase="post_session",
    )


# S-01: Confirmed injection (INJ-001/002)
async def signal_s01(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"],
) -> "Finding | None":
    hit = next(
        (f for f in online_findings if f.signal_id in ("INJ-001", "INJ-002")),
        None,
    )
    if not hit:
        return None
    return _make_finding("S-01", session_id, tenant_id, 40, "Confirmed prompt injection detected")


# S-02: Indirect injection vector (INJ-004)
async def signal_s02(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"],
) -> "Finding | None":
    hit = next((f for f in online_findings if f.signal_id == "INJ-004"), None)
    if not hit:
        return None
    return _make_finding("S-02", session_id, tenant_id, 20, "Indirect injection vector detected")


# S-03: Output passthrough (OUT-001 critical)
async def signal_s03(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"],
) -> "Finding | None":
    hit = next(
        (f for f in online_findings if f.signal_id == "OUT-001" and f.severity == "critical"),
        None,
    )
    if not hit:
        return None
    return _make_finding("S-03", session_id, tenant_id, 30, "LLM output passed through to tool without sanitisation")


# S-04: PII in LLM or tool output
async def signal_s04(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"],
) -> "Finding | None":
    critical_pii = [f for f in online_findings if f.signal_id in ("PII-001", "PII-002", "PII-003", "PII-006")]
    warning_pii  = [f for f in online_findings if f.signal_id in ("PII-004", "PII-005")]

    points = 0
    if critical_pii:
        points = 35
    elif warning_pii:
        points = 10

    if points == 0:
        return None

    detail = f"PII detected: {', '.join(set(f.signal_id for f in critical_pii + warning_pii))}"
    return _make_finding("S-04", session_id, tenant_id, points, detail)


# S-05: Excessive tool calls vs baseline
async def signal_s05(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"] | None = None,
) -> "Finding | None":
    tool_events = [e for e in events if e["event_type"] == "tool_start"]
    tool_call_count = len(tool_events)

    # Fetch 7-day tool-call baseline from ClickHouse
    from core.infra import clickhouse as ch
    baseline_rows = await ch.fetch(
        """
        SELECT session_id, count() AS tool_call_count
        FROM obs_events
        WHERE agent_id   = %(agent_id)s
          AND event_type = 'tool_start'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id
        """,
        agent_id=str(agent_id),
    )

    if len(baseline_rows) < 2:
        return None

    counts = [float(r["tool_call_count"]) for r in baseline_rows]
    mean   = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    stddev = variance ** 0.5

    if stddev == 0:
        return None

    sigmas = (tool_call_count - mean) / stddev

    if sigmas <= 0:
        return None

    points = min(int(sigmas * 5), SIGNAL_MAX["S-05"])
    if points <= 0:
        return None

    return _make_finding(
        "S-05", session_id, tenant_id, points,
        f"Tool calls ({tool_call_count}) is {sigmas:.1f}σ above 7-day baseline (mean={mean:.1f})",
    )


# S-06: Out-of-scope tool invocations
async def signal_s06(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"] | None = None,
) -> "Finding | None":
    from core.config import settings
    tool_manifests = settings.get_tool_manifests()
    allowed = tool_manifests.get(str(agent_id))
    if not allowed:
        return None  # No manifest configured — cannot determine scope

    tool_names_used = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    out_of_scope = [t for t in tool_names_used if t not in allowed]
    if not out_of_scope:
        return None

    unique_oos = list(dict.fromkeys(out_of_scope))  # preserve order, deduplicate
    points = min(25 + (len(unique_oos) - 1) * 10, SIGNAL_MAX["S-06"])
    return _make_finding(
        "S-06", session_id, tenant_id, points,
        f"Out-of-scope tools invoked: {', '.join(unique_oos[:5])}",
    )


# S-07: Write action on read-intent session
READ_INTENT_PATTERNS = [
    r"(?i)\b(show|list|get|find|search|lookup|check|read|view|display|fetch|retrieve)\b",
]


async def signal_s07(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"] | None = None,
) -> "Finding | None":
    initial_input = session.get("initial_input", "") or ""
    is_read_intent = any(re.search(p, initial_input) for p in READ_INTENT_PATTERNS)
    if not is_read_intent:
        return None

    tool_names = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    write_tools = [
        t for t in tool_names
        if any(re.search(p, t) for p in WRITE_TOOL_PATTERNS)
    ]
    if not write_tools:
        return None

    return _make_finding(
        "S-07", session_id, tenant_id, 30,
        f"Write/delete tools used ({', '.join(dict.fromkeys(write_tools))[:5]}) on read-intent session",
    )


# S-08: High-stakes action without HITL
async def signal_s08(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"] | None = None,
) -> "Finding | None":
    tool_names = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    high_stakes = [
        t for t in tool_names
        if any(re.search(p, t) for p in HIGH_STAKES_TOOL_PATTERNS)
    ]
    if not high_stakes:
        return None

    interrupt_raised = any(e["event_type"] == "interrupt_raised" for e in events)
    if interrupt_raised:
        return None  # HITL was invoked

    # Only fire if HITL is configured (graph_state carries hitl flag)
    graph_state = session.get("graph_state") or {}
    if isinstance(graph_state, str):
        try:
            graph_state = json.loads(graph_state)
        except Exception:
            graph_state = {}

    hitl_configured = graph_state.get("hitl_enabled", False)
    if not hitl_configured:
        return None

    return _make_finding(
        "S-08", session_id, tenant_id, 15,
        f"High-stakes action completed without HITL: {', '.join(dict.fromkeys(high_stakes))}",
    )


# S-09: Cross-session model theft probe — delegated to cohort.py
async def signal_s09(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"] | None = None,
) -> "Finding | None":
    from consumers.security_eval.scorer.cohort import detect_model_theft_probe
    return await detect_model_theft_probe(
        events=events,
        session=session,
        tenant_id=tenant_id,
        session_id=session_id,
        agent_id=agent_id,
    )


# S-10: Token spike anomaly
async def signal_s10(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list["Finding"] | None = None,
) -> "Finding | None":
    llm_events = [e for e in events if e["event_type"] in ("llm_end",)]
    total_tokens = sum(
        (e.get("llm_input_tokens") or 0) + (e.get("llm_output_tokens") or 0)
        for e in llm_events
    )

    from core.infra import clickhouse as ch
    baseline_rows = await ch.fetch(
        """
        SELECT session_id,
               SUM(llm_input_tokens + llm_output_tokens) AS total_tokens
        FROM obs_events
        WHERE agent_id   = %(agent_id)s
          AND event_type = 'llm_end'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id
        """,
        agent_id=str(agent_id),
    )

    if len(baseline_rows) < 2:
        return None

    token_counts = [float(r["total_tokens"]) for r in baseline_rows]
    mean         = sum(token_counts) / len(token_counts)
    variance     = sum((t - mean) ** 2 for t in token_counts) / len(token_counts)
    stddev       = variance ** 0.5

    if stddev == 0:
        return None
    sigmas = (total_tokens - mean) / stddev

    if sigmas < 4.0:
        return None

    return _make_finding(
        "S-10", session_id, tenant_id, 10,
        f"Token count ({total_tokens}) is {sigmas:.1f}σ above 7-day agent baseline",
    )


SIGNAL_FUNCTIONS = [
    signal_s05,
    signal_s06,
    signal_s07,
    signal_s08,
    signal_s09,
    signal_s10,
]
