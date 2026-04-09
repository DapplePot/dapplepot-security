"""OW-ASI01 through OW-ASI10 signal functions — OWASP Agentic Top 10, pure and independently testable.

OW-ASI01  Agent Goal Hijack
OW-ASI02  Tool Misuse & Exploitation
OW-ASI03  Identity & Privilege Abuse
OW-ASI04  Agentic Supply Chain Vulnerabilities
OW-ASI05  Unexpected Code Execution (RCE)
OW-ASI06  Memory & Context Poisoning
OW-ASI07  Insecure Inter-Agent Communication
OW-ASI08  Cascading Failures
OW-ASI09  Human-Agent Trust Exploitation
OW-ASI10  Rogue Agents
"""
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

# ─────────────────────────────────────────────────────────────────────────────
# Shared patterns
# ─────────────────────────────────────────────────────────────────────────────
_PRIVILEGE_TOOL_PATTERNS = [
    r"(?i)\b(admin|sudo|su|impersonate|elevate|assume_role|"
    r"switch_user|become|run_as|escalate|grant_access|set_permissions)\b",
]
_INTER_AGENT_PATTERNS = [
    r"(?i)\b(agent_handoff|delegate|sub_agent|call_agent|"
    r"invoke_agent|spawn_agent|agent_call|forward_to_agent)\b",
]
_AUTHORITY_PATTERNS = [
    r"(?i)\b(as (an? )?(admin|administrator|supervisor|manager|ceo|cto|root|superuser))\b",
    r"(?i)\b(i (hereby )?authorize|by order of|i am (your )?(creator|owner|operator))\b",
    r"(?i)(override (safety|security|policy|restriction)|ignore (safety|policy|restriction))\b",
]
_HIGH_STAKES_TOOL_PATTERNS = [
    r"(?i)(payment|charge|transfer|purchase|buy|send_email|send_message|notify|deploy|publish)",
]
_READ_INTENT_PATTERNS = [
    r"(?i)\b(show|list|get|find|search|lookup|check|read|view|display|fetch|retrieve)\b",
]
_WRITE_TOOL_PATTERNS = [
    r"(?i)(write|create|insert|update|delete|remove|send|post|put|patch|drop|truncate|exec)",
]

_NULL_UUID = "00000000-0000-0000-0000-000000000000"

_SIGNAL_CATEGORY = {
    "OW-ASI01": "prompt_injection",
    "OW-ASI02": "excessive_agency",
    "OW-ASI03": "privilege_escalation",
    "OW-ASI04": "supply_chain",
    "OW-ASI05": "code_execution",
    "OW-ASI06": "context_poisoning",
    "OW-ASI07": "inter_agent_communication",
    "OW-ASI08": "cascading_failure",
    "OW-ASI09": "trust_exploitation",
    "OW-ASI10": "excessive_agency",
}


def _make_finding(
    owasp_signal_id: str,
    sub_check_id: str,
    check_label: str,
    check_score: int,
    session_id: str,
    tenant_id: str,
    detail: str,
    severity: str | None = None,
    event_id: str = _NULL_UUID,
) -> "Finding":
    from consumers.security_eval.findings import Finding
    if severity is None:
        severity = "critical" if check_score >= 90 else "high" if check_score >= 70 else "medium"
    return Finding(
        tenant_id=tenant_id,
        session_id=session_id,
        event_id=event_id,
        event_type="post_session",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label=check_label,
        check_score=check_score,
        category=_SIGNAL_CATEGORY.get(owasp_signal_id, "agentic"),
        severity=severity,
        matched_text=None,
        detail=detail,
        detection_phase="post_session",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI01: Agent Goal Hijack
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a01(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list | None = None,
) -> "Finding | None":
    """AGH-01b — goal hijack: context injection led to write action on read-intent session."""
    if not online_findings:
        return None

    ctx_injection = next(
        (f for f in online_findings if f.owasp_signal_id == "OW-ASI06"),
        None,
    )
    if not ctx_injection:
        return None

    initial_input = session.get("initial_input", "") or ""
    is_read_intent = any(re.search(p, initial_input) for p in _READ_INTENT_PATTERNS)
    if not is_read_intent:
        return None

    tool_names = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    hijacked_tools = [t for t in tool_names if any(re.search(p, t) for p in _WRITE_TOOL_PATTERNS)]
    if not hijacked_tools:
        return None

    return _make_finding(
        "OW-ASI01", "AGH-01b",
        "Agent states a different goal explicitly",
        92, session_id, tenant_id,
        detail=f"Agent goal hijacked: context injection led to write action "
               f"({', '.join(dict.fromkeys(hijacked_tools))}) on read-intent session",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI03: Identity & Privilege Abuse
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a03(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """IPA-01a — agent requests scope beyond role definition (privilege escalation tools)."""
    tool_names = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    priv_tools = [
        t for t in tool_names
        if any(re.search(p, t) for p in _PRIVILEGE_TOOL_PATTERNS)
    ]
    if not priv_tools:
        return None

    unique = list(dict.fromkeys(priv_tools))
    check_score = min(80 + (len(unique) - 1) * 5, 95)
    return _make_finding(
        "OW-ASI03", "IPA-01a",
        "Agent requests scope beyond role definition",
        check_score, session_id, tenant_id,
        detail=f"Privilege escalation tools invoked: {', '.join(unique[:5])}",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI04: Agentic Supply Chain Vulnerabilities
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a04(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """ASCV-01a — all tools used are outside the registered manifest (possible registry substitution)."""
    from core.config import settings
    tool_manifests = settings.get_tool_manifests()

    allowed = tool_manifests.get(str(agent_id))
    if not allowed:
        return None

    tool_names_used = list(dict.fromkeys(
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ))
    if not tool_names_used:
        return None

    unknown = [t for t in tool_names_used if t not in allowed]
    if not unknown or len(unknown) < len(tool_names_used):
        return None

    return _make_finding(
        "OW-ASI04", "ASCV-01a",
        "MCP server endpoint URL changed / all tools outside manifest",
        85, session_id, tenant_id,
        detail=f"All tools used are outside the registered manifest — possible supply chain substitution: "
               f"{', '.join(unknown[:5])}",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI07: Insecure Inter-Agent Communication
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a07(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """IAC-01a — sub-agent message lacks auth signature."""
    delegation_tools = list(dict.fromkeys(
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start"
        and e.get("tool_name")
        and any(re.search(p, e["tool_name"]) for p in _INTER_AGENT_PATTERNS)
    ))
    if not delegation_tools:
        return None

    check_score = min(75 + (len(delegation_tools) - 1) * 3, 88)
    return _make_finding(
        "OW-ASI07", "IAC-01a",
        "Sub-agent message lacks auth signature",
        check_score, session_id, tenant_id,
        detail=f"Unverified inter-agent delegation detected: {', '.join(delegation_tools[:5])}",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI08: Cascading Failures
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a08(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """CF-01a — tool retry count > threshold (cascading failure pattern)."""
    error_events = [e for e in events if e["event_type"] == "graph_error"]
    if not error_events:
        return None

    tool_calls_before_error = sum(
        1 for e in events if e["event_type"] == "tool_start"
    )
    if tool_calls_before_error < 5:
        return None

    check_score = min(70 + tool_calls_before_error, 85)
    return _make_finding(
        "OW-ASI08", "CF-01a",
        "Tool retry count exceeds threshold",
        check_score, session_id, tenant_id,
        detail=f"Cascading failure: session ended in error after {tool_calls_before_error} tool calls",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI09: Human-Agent Trust Exploitation
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a09(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """HAT-01a — agent mimics human / authority claim + uninspected high-stakes action."""
    initial_input = session.get("initial_input", "") or ""
    authority_match = next(
        (re.search(p, initial_input) for p in _AUTHORITY_PATTERNS
         if re.search(p, initial_input)),
        None,
    )
    if not authority_match:
        return None

    tool_names = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    high_stakes = [t for t in tool_names if any(re.search(p, t) for p in _HIGH_STAKES_TOOL_PATTERNS)]
    if not high_stakes:
        return None

    interrupt_raised = any(e["event_type"] == "interrupt_raised" for e in events)
    if interrupt_raised:
        return None

    return _make_finding(
        "OW-ASI09", "HAT-01a",
        "Agent mimics human communication style",
        65, session_id, tenant_id,
        severity="medium",
        detail=f"Trust exploitation: authority claim in input combined with "
               f"uninspected high-stakes action ({', '.join(dict.fromkeys(high_stakes))})",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI10: Rogue Agents
# ─────────────────────────────────────────────────────────────────────────────
async def signal_a10(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """RA-01a — tool usage pattern deviates from agent profile (>3σ)."""
    tool_names_this = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    distinct_tools_this = len(set(tool_names_this))

    from core.infra import clickhouse as ch
    baseline_rows = await ch.fetch(
        """
        SELECT session_id, countDistinct(tool_name) AS distinct_tools
        FROM obs_events
        WHERE agent_id   = %(agent_id)s
          AND event_type = 'tool_start'
          AND emitted_at >= now() - INTERVAL 30 DAY
        GROUP BY session_id
        """,
        agent_id=str(agent_id),
    )
    if len(baseline_rows) < 5:
        return None

    counts = [float(r["distinct_tools"]) for r in baseline_rows]
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    stddev = variance ** 0.5
    if stddev == 0:
        return None

    sigmas = (distinct_tools_this - mean) / stddev
    if sigmas < 3.0:
        return None

    check_score = min(78 + int(sigmas * 5), 95)
    return _make_finding(
        "OW-ASI10", "RA-01a",
        "Tool usage pattern deviates from agent profile",
        check_score, session_id, tenant_id,
        detail=f"Rogue agent pattern: {distinct_tools_this} distinct tool types is "
               f"{sigmas:.1f}σ above 30-day baseline (mean={mean:.1f})",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Signal registry for orchestrator
# ─────────────────────────────────────────────────────────────────────────────
AGENT_SIGNAL_ID_FUNCTIONS: list[tuple[str, object]] = [
    # signal_a01 is called separately in orchestrator with per-event findings
    ("OW-ASI03", signal_a03),
    ("OW-ASI04", signal_a04),
    # signal_a02/a05/a06 were wrappers around per-event findings; removed now that
    # _run_per_event_detectors produces those findings directly.
    ("OW-ASI07", signal_a07),
    ("OW-ASI08", signal_a08),
    ("OW-ASI09", signal_a09),
    ("OW-ASI10", signal_a10),
]

AGENT_SIGNAL_DESCRIPTION = {
    "OW-ASI01": "Agent Goal Hijack",
    "OW-ASI02": "Tool Misuse & Exploitation",
    "OW-ASI03": "Identity & Privilege Abuse",
    "OW-ASI04": "Agentic Supply Chain Vulnerabilities",
    "OW-ASI05": "Unexpected Code Execution (RCE)",
    "OW-ASI06": "Memory & Context Poisoning",
    "OW-ASI07": "Insecure Inter-Agent Communication",
    "OW-ASI08": "Cascading Failures",
    "OW-ASI09": "Human-Agent Trust Exploitation",
    "OW-ASI10": "Rogue Agents",
}

# Legacy alias kept for any external callers
AGENT_SIGNAL_OWASP = {k: k[3:] for k in AGENT_SIGNAL_DESCRIPTION}  # "OW-ASI01" → "ASI01"
