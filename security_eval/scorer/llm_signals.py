"""OW-LLM session-level signal functions — pure, independently testable.

These run once per session (post-session) on the full event list from ClickHouse.
Per-event detectors (injection, PII, passthrough, agentic, prompt guard) live in
security_eval/detectors/ and are called by the orchestrator's event loop.
"""
import json
import re
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from security_eval.findings import Finding

# ─────────────────────────────────────────────────────────────────────────────
# Shared patterns
# ─────────────────────────────────────────────────────────────────────────────
WRITE_TOOL_PATTERNS = [
    r"(?i)(write|create|insert|update|delete|remove|send|post|put|patch|drop|truncate|exec)",
]
HIGH_STAKES_TOOL_PATTERNS = [
    r"(?i)(payment|charge|transfer|purchase|buy|send_email|send_message|notify|deploy|publish)",
]
RAG_TOOL_NAMES = {"retriever", "rag", "vector_search", "knowledge_base"}


_SIGNAL_CATEGORY = {
    "OW-LLM01": "prompt_injection",
    "OW-LLM02": "data_disclosure",
    "OW-LLM03": "supply_chain",
    "OW-LLM04": "supply_chain",
    "OW-LLM05": "output_handling",
    "OW-LLM06": "excessive_agency",
    "OW-LLM07": "system_prompt_leakage",
    "OW-LLM08": "vector_integrity",
    "OW-LLM09": "model_security",
    "OW-LLM10": "model_security",
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
    event_id: str = "00000000-0000-0000-0000-000000000000",
) -> "Finding":
    from security_eval.findings import Finding
    if severity is None:
        severity = "critical" if check_score >= 85 else "high" if check_score >= 65 else "medium"
    return Finding(
        tenant_id=tenant_id,
        session_id=session_id,
        event_id=event_id,
        event_type="post_session",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label=check_label,
        check_score=check_score,
        category=_SIGNAL_CATEGORY.get(owasp_signal_id, "unknown"),
        severity=severity,
        matched_text=None,
        detail=detail,
        detection_phase="post_session",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-LLM06: Excessive Agency
# ─────────────────────────────────────────────────────────────────────────────
async def signal_ow_llm06_tool_count(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    sec_config=None,
) -> "Finding | None":
    """EA-02b — sub-agents spawned / excessive tool calls vs baseline.

    Combination approach:
      1. If the agent has a user-defined max_tool_calls_per_session, fire immediately
         when the count exceeds it (works from day 1, no baseline needed).
      2. Fall back to statistical baseline (7-day Z-score) when max is not set
         or hasn't been breached — activates once ≥2 prior sessions exist.
    """
    tool_events = [e for e in events if e["event_type"] == "tool_start"]
    tool_call_count = len(tool_events)

    # ── 1. User-defined threshold (floor check) ─────────────────────────────
    max_calls = getattr(sec_config, "max_tool_calls_per_session", None) if sec_config else None
    if max_calls is not None and tool_call_count > max_calls:
        excess = tool_call_count - max_calls
        check_score = min(65 + excess * 2, 85)
        return _make_finding(
            "OW-LLM06", "EA-02b",
            "Sub-agents spawned or tool calls exceed fan-out limit",
            check_score, session_id, tenant_id,
            detail=f"Tool calls ({tool_call_count}) exceeds configured max ({max_calls})",
        )

    # ── 2. Statistical baseline (warmup: ≥2 prior sessions required) ────────
    from core.infra import clickhouse as ch
    baseline_rows = await ch.fetch(
        """
        SELECT session_id, count() AS tool_call_count
        FROM obs_events
        WHERE agent_id   = %(agent_id)s
          AND tenant_id  = %(tenant_id)s
          AND event_type = 'tool_start'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id
        """,
        agent_id=str(agent_id),
        tenant_id=str(tenant_id),
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

    check_score = min(int(sigmas * 10), 70)
    if check_score <= 0:
        return None

    return _make_finding(
        "OW-LLM06", "EA-02b",
        "Sub-agents spawned or tool calls exceed fan-out limit",
        check_score, session_id, tenant_id,
        detail=f"Tool calls ({tool_call_count}) is {sigmas:.1f}σ above 7-day baseline (mean={mean:.1f})",
    )


async def signal_ow_llm06_scope(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    sec_config=None,
) -> "Finding | None":
    """EA-01a — tool not in approved manifest invoked."""
    # Prefer DB-loaded manifest from sec_config; fall back to legacy env-var manifest.
    if sec_config and sec_config.tool_manifest:
        allowed = sec_config.tool_manifest
    else:
        from core.config import settings
        tool_manifests = settings.get_tool_manifests()
        allowed = tool_manifests.get(str(agent_id))
    if not allowed:
        return None

    tool_names_used = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]
    out_of_scope = [t for t in tool_names_used if t not in allowed]
    if not out_of_scope:
        return None

    unique_oos = list(dict.fromkeys(out_of_scope))
    check_score = min(80, 80 + (len(unique_oos) - 1) * 5)
    return _make_finding(
        "OW-LLM06", "EA-01a",
        "Tool not in approved manifest invoked",
        check_score, session_id, tenant_id,
        detail=f"Out-of-scope tools invoked: {', '.join(unique_oos[:5])}",
    )


READ_INTENT_PATTERNS = [
    r"(?i)\b(show|list|get|find|search|lookup|check|read|view|display|fetch|retrieve)\b",
]


async def signal_ow_llm06_write_on_read(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    sec_config=None,
) -> "Finding | None":
    """EA-01c — data written outside designated namespace.

    Manual mode (sec_config.write_namespace set):
        Fire when any write tool call has a 'path' or 'key' or 'namespace' arg
        that does not start with the declared write_namespace prefix.

    Auto mode (write_namespace is None):
        Fire when session starts with read-intent AND write-named tools are called.
    """
    tool_events = [e for e in events if e["event_type"] == "tool_start" and e.get("tool_name")]

    write_namespace = getattr(sec_config, "write_namespace", None) if sec_config else None

    if write_namespace:
        # Manual mode: check tool path arguments
        for e in tool_events:
            tool_name = e.get("tool_name", "")
            if not any(re.search(p, tool_name) for p in WRITE_TOOL_PATTERNS):
                continue
            payload = e.get("payload") or {}
            tool_input = payload.get("tool_input") or {}
            if isinstance(tool_input, str):
                try:
                    import json as _j
                    tool_input = _j.loads(tool_input)
                except Exception:
                    tool_input = {}
            if not isinstance(tool_input, dict):
                continue
            # Check any path-like parameter
            for key in ("path", "file_path", "destination", "key", "namespace", "bucket", "prefix"):
                val = str(tool_input.get(key, ""))
                if val and not val.startswith(write_namespace):
                    return _make_finding(
                        "OW-LLM06", "EA-01c",
                        "Data written outside designated namespace",
                        75, session_id, tenant_id,
                        detail=f"Tool '{tool_name}' wrote to '{val}' — outside declared namespace '{write_namespace}'",
                        severity="high",
                    )
        return None

    # Auto mode: read-intent session + write tools
    initial_input = session.get("initial_input", "") or ""
    is_read_intent = any(re.search(p, initial_input) for p in READ_INTENT_PATTERNS)
    if not is_read_intent:
        return None
    tool_names = [e["tool_name"] for e in tool_events]
    write_tools = [t for t in tool_names if any(re.search(p, t) for p in WRITE_TOOL_PATTERNS)]
    if not write_tools:
        return None
    return _make_finding(
        "OW-LLM06", "EA-01c",
        "Data written outside designated namespace",
        75, session_id, tenant_id,
        detail=f"Write/delete tools used ({', '.join(dict.fromkeys(write_tools))[:5]}) on read-intent session",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-LLM09: Misinformation / HITL Gap
# ─────────────────────────────────────────────────────────────────────────────
async def signal_ow_llm09(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    sec_config=None,
) -> "Finding | None":
    """MIS-03a — high-stakes action without interrupt gate."""
    tool_names = [
        e["tool_name"] for e in events
        if e["event_type"] == "tool_start" and e.get("tool_name")
    ]

    # Use declared irreversible tools if set, else name-pattern heuristic
    declared = getattr(sec_config, "irreversible_tools", None) if sec_config else None
    if declared is not None:
        high_stakes = [t for t in tool_names if t in declared]
    else:
        high_stakes = [t for t in tool_names if any(re.search(p, t) for p in HIGH_STAKES_TOOL_PATTERNS)]

    if not high_stakes:
        return None

    graph_state = session.get("graph_state") or {}
    if isinstance(graph_state, str):
        try:
            graph_state = json.loads(graph_state)
        except Exception:
            graph_state = {}
    if not graph_state.get("hitl_enabled", False):
        return None

    return _make_finding(
        "OW-LLM09", "MIS-03a",
        "High-stakes action without interrupt gate",
        65, session_id, tenant_id,
        severity="medium",
        detail=f"High-stakes action completed without HITL: {', '.join(dict.fromkeys(high_stakes))}",
    )


# ─────────────────────────────────────────────────────────────────────────────
# OW-LLM10: Unbounded Consumption
# ─────────────────────────────────────────────────────────────────────────────
async def signal_ow_llm10_probe(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """UBC-04a — cross-session model theft probe (delegated to cohort.py)."""
    from security_eval.scorer.probe import detect_model_theft_probe
    return await detect_model_theft_probe(
        events=events,
        session=session,
        tenant_id=tenant_id,
        session_id=session_id,
        agent_id=agent_id,
    )


def _z_score(value: float, population: list[float]) -> float | None:
    if len(population) < 2:
        return None
    mean = sum(population) / len(population)
    variance = sum((x - mean) ** 2 for x in population) / len(population)
    stddev = variance ** 0.5
    return (value - mean) / stddev if stddev > 0 else None


async def signal_ow_llm10_token_spike(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """UBC-01a — session token count > 4σ above per-model 7-day baseline.
    Baseline is grouped by (agent_id, llm_model) to avoid mixing token distributions
    across models with different typical usage scales."""
    llm_events = [e for e in events if e["event_type"] == "llm_end"]
    if not llm_events:
        return None

    # Group session tokens by model
    from collections import defaultdict
    session_by_model: dict[str, int] = defaultdict(int)
    for e in llm_events:
        model = e.get("llm_model") or "__unknown__"
        session_by_model[model] += (e.get("llm_input_tokens") or 0) + (e.get("llm_output_tokens") or 0)

    from core.infra import clickhouse as ch
    baseline_rows = await ch.fetch(
        """
        SELECT session_id,
               llm_model,
               SUM(llm_input_tokens + llm_output_tokens) AS total_tokens
        FROM obs_events
        WHERE agent_id   = %(agent_id)s
          AND event_type = 'llm_end'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id, llm_model
        """,
        agent_id=str(agent_id),
    )

    # Build per-model baseline distributions
    baseline_by_model: dict[str, list[float]] = defaultdict(list)
    for r in baseline_rows:
        baseline_by_model[r["llm_model"] or "__unknown__"].append(float(r["total_tokens"]))

    worst_sigmas = 0.0
    worst_model  = ""
    worst_tokens = 0

    for model, tokens in session_by_model.items():
        z = _z_score(float(tokens), baseline_by_model.get(model, []))
        if z is not None and z > worst_sigmas:
            worst_sigmas = z
            worst_model  = model
            worst_tokens = tokens

    if worst_sigmas < 4.0:
        return None

    model_label = f" ({worst_model})" if worst_model and worst_model != "__unknown__" else ""
    return _make_finding(
        "OW-LLM10", "UBC-01a",
        "Single session token count > 4σ baseline",
        55, session_id, tenant_id,
        severity="medium",
        detail=f"Token count {worst_tokens}{model_label} is {worst_sigmas:.1f}σ above 7-day per-model baseline",
    )


# ─────────────────────────────────────────────────────────────────────────────
# NEW: PI-04b Multi-turn accumulation jailbreak (OW-LLM01)
# ─────────────────────────────────────────────────────────────────────────────
def check_multi_turn_jailbreak(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """PI-04b — jailbreak built incrementally across >= 3 turns.

    Rule: >= 3 llm_start events each containing a sub-threshold injection
          fragment that, when concatenated, matches a full injection pattern.
    """
    from security_eval.detectors.injection import (
        matches_injection_pattern,
        has_partial_injection_signal,
    )

    llm_starts = [e for e in events if e["event_type"] == "llm_start"]
    fragments = []
    for ev in llm_starts:
        payload = ev.get("payload") or {}
        user_msgs = [
            m for m in payload.get("messages", []) if m.get("role") == "user"
        ]
        for m in user_msgs:
            if has_partial_injection_signal(str(m.get("content", ""))):
                fragments.append(str(m.get("content", "")))

    if len(fragments) < 3:
        return []

    combined = " ".join(fragments)
    if not matches_injection_pattern(combined):
        return []

    return [_make_finding(
        "OW-LLM01", "PI-04b",
        "Incremental multi-turn jailbreak",
        92, session_id, tenant_id,
        severity="critical",
        detail=f"Jailbreak assembled incrementally over {len(fragments)} turns",
    )]


# ─────────────────────────────────────────────────────────────────────────────
# NEW: DMP-01a / DMP-01c RAG integrity (OW-LLM04)
# ─────────────────────────────────────────────────────────────────────────────
def check_rag_integrity(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    baseline: dict,
) -> list["Finding"]:
    """DMP-01a (RAG call count spike) and DMP-01c (instruction in retrieved chunk)."""
    from security_eval.detectors.injection import matches_injection_pattern

    findings: list["Finding"] = []
    rag_events = [e for e in events if e.get("tool_name") in RAG_TOOL_NAMES]

    # DMP-01a — count anomaly
    p95 = baseline.get("rag_call_p95", 10)
    if len(rag_events) > p95 * 1.5:
        findings.append(_make_finding(
            "OW-LLM04", "DMP-01a",
            "RAG call count spike",
            60, session_id, tenant_id,
            severity="medium",
            detail=f"RAG tool calls ({len(rag_events)}) exceed 1.5× p95 baseline ({p95})",
        ))

    # DMP-01c — instruction text in retrieved chunks
    for e in rag_events:
        payload = e.get("payload") or {}
        chunk_text = payload.get("tool_output", "")
        if isinstance(chunk_text, dict):
            chunk_text = json.dumps(chunk_text)
        if matches_injection_pattern(str(chunk_text)):
            findings.append(_make_finding(
                "OW-LLM04", "DMP-01c",
                "Instruction text in RAG chunk",
                85, session_id, tenant_id,
                severity="high",
                detail="RAG tool_end payload contains prompt injection pattern",
            ))
            break  # one finding per session is enough

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW: SPL-02/SPL-03 system prompt leakage post-session (OW-LLM07)
# ─────────────────────────────────────────────────────────────────────────────
_ROLE_REVEAL_PATTERNS = [
    r"(?i)(my role is|i am (a |an )?[a-z]+ (agent|assistant|bot)|i was (configured|set up|designed) to)",
]
_SYSTEM_VAR_PATTERNS = [
    r"\{[a-z_]+\}",           # {variable} placeholders leaked from template
    r"(?i)(api_key|secret|password|token)\s*=\s*\S+",
]


def check_system_prompt_leakage(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """SPL-01a (verbatim segment match), SPL-02a (reveals persona/role name)
    and SPL-03b (system prompt in inter-agent msg)."""
    findings: list["Finding"] = []
    declared_prompt: str | None = getattr(sec_config, "system_prompt", None) if sec_config else None

    # SPL-01a: Verbatim segment match — only possible with declared prompt
    if declared_prompt and len(declared_prompt) > 20:
        from difflib import SequenceMatcher as _SM
        for ev in (e for e in events if e["event_type"] == "llm_end"):
            payload = ev.get("payload") or {}
            completion = payload.get("completion", "")
            if not isinstance(completion, str):
                completion = json.dumps(completion)
            sm = _SM(None, declared_prompt.lower(), completion.lower())
            lcs = max((b.size for b in sm.get_matching_blocks()), default=0)
            if lcs >= 80:
                findings.append(_make_finding(
                    "OW-LLM07", "SPL-01a",
                    "Verbatim system prompt segment in output",
                    85, session_id, tenant_id,
                    severity="high",
                    detail=f"Verbatim segment of {lcs} chars from declared system prompt in completion",
                ))
                break

    llm_ends = [e for e in events if e["event_type"] == "llm_end"]
    for e in llm_ends:
        payload = e.get("payload") or {}
        completion = payload.get("completion", "")
        if not isinstance(completion, str):
            completion = json.dumps(completion)

        # SPL-02a — reveals role / persona name
        for p in _ROLE_REVEAL_PATTERNS:
            if re.search(p, completion):
                findings.append(_make_finding(
                    "OW-LLM07", "SPL-02a",
                    "Reveals role name or persona in output",
                    50, session_id, tenant_id,
                    severity="medium",
                    detail="Agent output reveals its configured role or persona name",
                ))
                break

        # SPL-02b — error message exposes instruction vars
        for p in _SYSTEM_VAR_PATTERNS:
            if re.search(p, completion):
                findings.append(_make_finding(
                    "OW-LLM07", "SPL-02b",
                    "Error message exposes instruction variables",
                    60, session_id, tenant_id,
                    severity="medium",
                    detail="Agent output contains un-substituted template variables",
                ))
                break

    # SPL-03b — system prompt forwarded in inter-agent invoke_agent payload
    tool_starts = [
        e for e in events
        if e["event_type"] == "tool_start"
        and re.search(r"(?i)(invoke_agent|agent_call|delegate)", e.get("tool_name", ""))
    ]
    for e in tool_starts:
        payload = e.get("payload") or {}
        tool_input = payload.get("tool_input") or {}
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except Exception:
                tool_input = {}
        if "system" in tool_input:
            findings.append(_make_finding(
                "OW-LLM07", "SPL-03b",
                "System prompt forwarded in inter-agent message",
                88, session_id, tenant_id,
                severity="high",
                detail="invoke_agent tool_start payload contains 'system' key",
            ))
            break

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW: VEW vector/embedding integrity (OW-LLM08)
# ─────────────────────────────────────────────────────────────────────────────
def check_vector_integrity(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """VEW-01b (repeated near-duplicate RAG queries) and VEW-02a (unauthorised write)."""
    from difflib import SequenceMatcher

    findings: list["Finding"] = []

    rag_events = [e for e in events if e.get("tool_name") in RAG_TOOL_NAMES]

    # VEW-01b — repeated near-duplicate RAG queries
    if len(rag_events) >= 5:
        queries = []
        for e in rag_events:
            payload = e.get("payload") or {}
            tool_input = payload.get("tool_input") or {}
            if isinstance(tool_input, dict):
                q = tool_input.get("query", "") or tool_input.get("q", "")
            else:
                q = str(tool_input)
            queries.append(q.lower())

        near_dup_count = 0
        for i in range(len(queries)):
            for j in range(i + 1, len(queries)):
                if queries[i] and queries[j]:
                    # Levenshtein-like: use SequenceMatcher edit distance approximation
                    ratio = SequenceMatcher(None, queries[i], queries[j]).ratio()
                    avg_len = (len(queries[i]) + len(queries[j])) / 2
                    if ratio > 0.85 or (avg_len > 0 and (1 - ratio) * avg_len < 10):
                        near_dup_count += 1

        if near_dup_count >= 3:
            findings.append(_make_finding(
                "OW-LLM08", "VEW-01b",
                "Repeated near-duplicate RAG queries",
                75, session_id, tenant_id,
                severity="high",
                detail=f"Detected {near_dup_count} near-duplicate RAG query pairs",
            ))

    # VEW-02a — unauthorised write to vector namespace
    write_tool_events = [
        e for e in events
        if e["event_type"] == "tool_start"
        and re.search(r"(?i)(write|upsert|insert|add).*(vector|embed|store)", e.get("tool_name", ""))
    ]
    if write_tool_events:
        findings.append(_make_finding(
            "OW-LLM08", "VEW-02a",
            "Unauthorised write to vector namespace",
            92, session_id, tenant_id,
            severity="critical",
            detail=f"Vector write tool invoked: {write_tool_events[0].get('tool_name')}",
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# v3: OW-LLM04 / OW-LLM08 — pre-runtime exclusions (return not_observed)
# ─────────────────────────────────────────────────────────────────────────────

def signal_ow_llm04(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> None:
    """OW-LLM04 — pre-runtime data/model poisoning. Not observable at inference time."""
    return None  # pre-runtime exclusion


def signal_ow_llm08(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> None:
    """OW-LLM08 — pre-runtime vector/embedding weakness. Not observable at inference time."""
    return None  # pre-runtime exclusion


# ─────────────────────────────────────────────────────────────────────────────
# v3: PI-06a — Payload splitting across messages (OW-LLM01)
# ─────────────────────────────────────────────────────────────────────────────
def check_payload_splitting(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """PI-06a — split payload detected across consecutive user messages."""
    from security_eval.detectors.injection import (
        _REGEX_SIGNATURES,
        INSTRUCTION_PATTERNS,
    )

    all_user_messages: list[str] = []
    for ev in events:
        if ev["event_type"] != "llm_start":
            continue
        payload = ev.get("payload") or {}
        for msg in payload.get("messages", []):
            if isinstance(msg, dict) and msg.get("role") == "user":
                all_user_messages.append(str(msg.get("content", "")))

    if len(all_user_messages) < 3:
        return []

    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS

    def individual_matches(text: str) -> bool:
        return any(re.search(p, text) for p in all_patterns)

    for i in range(len(all_user_messages) - 2):
        window = all_user_messages[i:i + 3]
        combined = " ".join(window)
        if individual_matches(combined):
            if not any(individual_matches(m) for m in window):
                return [_make_finding(
                    "OW-LLM01", "PI-06a",
                    "Payload splitting across messages",
                    88, session_id, tenant_id,
                    severity="high",
                    detail=f"Split payload detected across messages {i}..{i + 2}",
                )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# v3: IOH-04a — Insecure code pattern in generated output (OW-LLM05)
# ─────────────────────────────────────────────────────────────────────────────
_INSECURE_CODE_PATTERNS = [
    r"eval\s*\(",
    r"(?i)password\s*=\s*['\"][^'\"]+['\"]",
    r"(?i)verify\s*=\s*False",
    r"(?i)shell\s*=\s*True",
    r"(?i)innerHTML\s*=",
    r"(?i)SELECT\s.+FROM\s.+WHERE\s.+['\"]?\s*\+\s*",
    r"(?i)pickle\.loads?\s*\(",
    r"(?i)yaml\.load\s*\(",
]
_CODE_FENCE = re.compile(r"```[\s\S]*?```")


def check_insecure_code_output(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """IOH-04a — insecure code pattern in LLM-generated code blocks."""
    for ev in events:
        if ev["event_type"] != "llm_end":
            continue
        payload = ev.get("payload") or {}
        completion = payload.get("completion", "")
        if not isinstance(completion, str):
            completion = json.dumps(completion)

        code_blocks = _CODE_FENCE.findall(completion)
        if not code_blocks:
            continue

        matched_patterns: list[str] = []
        for block in code_blocks:
            for pat in _INSECURE_CODE_PATTERNS:
                if re.search(pat, block):
                    matched_patterns.append(pat)

        if matched_patterns:
            return [_make_finding(
                "OW-LLM05", "IOH-04a",
                "Insecure code pattern in generated output",
                70, session_id, tenant_id,
                severity="high",
                detail=f"Insecure pattern(s) in generated code: {matched_patterns[:3]}",
            )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# v3: SAG-02a — Hallucinated package reference (OW-LLM09)
# ─────────────────────────────────────────────────────────────────────────────
_PIP_INSTALL = re.compile(r"pip\s+install\s+([\w\-\.]+)", re.IGNORECASE)
_NPM_INSTALL = re.compile(r"npm\s+install\s+([\w\-@/]+)", re.IGNORECASE)


def check_hallucinated_packages(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """SAG-02a — potentially hallucinated package name in generated code."""
    from core.config import KNOWN_HALLUCINATED_PACKAGES, HALLUCINATED_SHORT_WORDS

    for ev in events:
        if ev["event_type"] != "llm_end":
            continue
        payload = ev.get("payload") or {}
        completion = payload.get("completion", "")
        if not isinstance(completion, str):
            continue

        code_blocks = _CODE_FENCE.findall(completion)
        if not code_blocks:
            continue

        for block in code_blocks:
            for match in _PIP_INSTALL.finditer(block):
                pkg = match.group(1).strip()
                if pkg in KNOWN_HALLUCINATED_PACKAGES or (
                    len(pkg) < 4 and pkg.lower() in HALLUCINATED_SHORT_WORDS
                ):
                    return [_make_finding(
                        "OW-LLM09", "SAG-02a",
                        "Hallucinated package reference",
                        65, session_id, tenant_id,
                        severity="medium",
                        detail=f"Potentially hallucinated package: {pkg}",
                    )]
            for match in _NPM_INSTALL.finditer(block):
                pkg = match.group(1).strip()
                if pkg in KNOWN_HALLUCINATED_PACKAGES:
                    return [_make_finding(
                        "OW-LLM09", "SAG-02a",
                        "Hallucinated package reference",
                        65, session_id, tenant_id,
                        severity="medium",
                        detail=f"Potentially hallucinated npm package: {pkg}",
                    )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# v3: SAG-03a — High-stakes domain without grounding (OW-LLM09)
# ─────────────────────────────────────────────────────────────────────────────
_HIGH_STAKES_DOMAINS = {
    "medical":   r"(?i)(dosage|prescri|diagnos|medication|symptom|treatment|drug\s+interact)",
    "legal":     r"(?i)(legal\s+advice|lawsuit|liability|statute|regulation\s+require)",
    "financial": r"(?i)(invest|buy\s+stock|sell\s+stock|financial\s+advice|guaranteed\s+return)",
}
_RETRIEVAL_TOOL = re.compile(r"(?i)(search|retrieve|lookup|query|fetch|rag)")


def check_ungrounded_high_stakes(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """SAG-03a — high-stakes domain output without retrieval grounding or HITL."""
    has_retrieval = any(
        ev["event_type"] == "tool_start"
        and _RETRIEVAL_TOOL.search(ev.get("tool_name", ""))
        for ev in events
    )
    if has_retrieval:
        return []

    for ev in events:
        if ev["event_type"] != "llm_end":
            continue
        payload = ev.get("payload") or {}
        completion = payload.get("completion", "")
        if not isinstance(completion, str):
            continue

        for domain, pattern in _HIGH_STAKES_DOMAINS.items():
            if re.search(pattern, completion):
                return [_make_finding(
                    "OW-LLM09", "SAG-03a",
                    "High-stakes domain without grounding",
                    60, session_id, tenant_id,
                    severity="medium",
                    detail=f"High-stakes {domain} output without retrieval grounding or HITL",
                )]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# v3: UBC-02a — Input size anomaly (OW-LLM10)
# ─────────────────────────────────────────────────────────────────────────────
async def check_input_size_anomaly(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    agent_id: str,
) -> list["Finding"]:
    """UBC-02a — session input tokens > 4σ above per-model 7-day baseline.
    Baseline grouped by (agent_id, llm_model) to avoid mixing input scales across models."""
    llm_events = [e for e in events if e["event_type"] == "llm_end"]
    if not llm_events:
        return []

    from collections import defaultdict
    session_by_model: dict[str, int] = defaultdict(int)
    for e in llm_events:
        model = e.get("llm_model") or "__unknown__"
        session_by_model[model] += e.get("llm_input_tokens") or 0

    from core.infra import clickhouse as ch
    baseline_rows = await ch.fetch(
        """
        SELECT session_id, llm_model, SUM(llm_input_tokens) AS input_tokens
        FROM obs_events
        WHERE agent_id   = %(agent_id)s
          AND event_type = 'llm_end'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id, llm_model
        """,
        agent_id=str(agent_id),
    )

    baseline_by_model: dict[str, list[float]] = defaultdict(list)
    for r in baseline_rows:
        baseline_by_model[r["llm_model"] or "__unknown__"].append(float(r["input_tokens"]))

    findings = []
    for model, inp in session_by_model.items():
        population = baseline_by_model.get(model, [])
        if len(population) < 5:
            continue
        z = _z_score(float(inp), population)
        if z is not None and z >= 4.0:
            mean = sum(population) / len(population)
            model_label = f" ({model})" if model != "__unknown__" else ""
            findings.append(_make_finding(
                "OW-LLM10", "UBC-02a",
                "Input size anomaly",
                50, session_id, tenant_id,
                severity="medium",
                detail=f"Input tokens {inp}{model_label} is {z:.1f}σ above per-model baseline {mean:.0f}",
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Agent profile-aware checkers (called directly from orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

def check_irreversible_without_gate(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """EA-02a — irreversible tool called without intervening user confirmation.

    Fires when two consecutive tool_start events occur with an irreversible
    tool in the second position and no llm_start (user turn) in between.

    Manual mode: sec_config.irreversible_tools names the irreversible tools.
    Auto mode:   HIGH_STAKES_TOOL_PATTERNS applied to tool name.
    """
    declared = getattr(sec_config, "irreversible_tools", None) if sec_config else None

    def is_irreversible(tool_name: str) -> bool:
        if declared is not None:
            return tool_name in declared
        return any(re.search(p, tool_name) for p in HIGH_STAKES_TOOL_PATTERNS)

    relevant = [
        ev for ev in events
        if ev["event_type"] in ("tool_start", "llm_start")
    ]

    last_was_tool = False
    for ev in relevant:
        if ev["event_type"] == "llm_start":
            last_was_tool = False
        elif ev["event_type"] == "tool_start":
            tool_name = ev.get("tool_name") or ""
            if is_irreversible(tool_name) and last_was_tool:
                return [_make_finding(
                    "OW-LLM06", "EA-02a",
                    "Irreversible action without confirm gate",
                    85, session_id, tenant_id,
                    severity="high",
                    detail=f"Tool '{tool_name}' called without a user confirmation turn between tool calls",
                )]
            last_was_tool = True

    return []


def check_reads_outside_working_dir(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """EA-03a — reads outside declared working directory.

    Only runs when sec_config.working_directory is set (no heuristic fallback).
    Scans tool_start events for file-read tool names with a 'path' argument
    that does not start with the declared working_directory prefix.
    """
    working_dir = getattr(sec_config, "working_directory", None) if sec_config else None
    if not working_dir:
        return []

    _READ_TOOL_RE = re.compile(
        r"(?i)\b(read|open|load|get|fetch|parse|cat|head|tail)[\w_]*(file|doc|content|text|data)?\b"
    )
    findings: list["Finding"] = []

    for ev in events:
        if ev["event_type"] != "tool_start":
            continue
        tool_name = ev.get("tool_name") or ""
        if not _READ_TOOL_RE.search(tool_name):
            continue
        payload = ev.get("payload") or {}
        tool_input = payload.get("tool_input") or {}
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except Exception:
                tool_input = {}
        if not isinstance(tool_input, dict):
            continue
        for key in ("path", "file_path", "filename", "filepath", "source"):
            val = str(tool_input.get(key, ""))
            if val and not val.startswith(working_dir):
                findings.append(_make_finding(
                    "OW-LLM06", "EA-03a",
                    "Reads outside working directory",
                    65, session_id, tenant_id,
                    severity="medium",
                    detail=f"Tool '{tool_name}' read path '{val}' — outside declared working directory '{working_dir}'",
                ))
                break

    return findings


def check_network_not_in_allowlist(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """EA-03b — outbound call to host not in declared network allowlist.

    Only runs when sec_config.network_allowlist is set and non-empty.
    Scans tool_start events for URL parameters and checks the hostname
    against the allowlist. Wildcards like '*.internal.com' are supported.
    """
    from urllib.parse import urlparse
    allowlist: list | None = getattr(sec_config, "network_allowlist", None) if sec_config else None
    if not allowlist:
        return []

    def host_allowed(host: str) -> bool:
        for entry in allowlist:
            if entry.startswith("*."):
                if host.endswith(entry[1:]) or host == entry[2:]:
                    return True
            elif entry == host or entry == "*":
                return True
        return False

    findings: list["Finding"] = []
    seen_hosts: set[str] = set()

    for ev in events:
        if ev["event_type"] != "tool_start":
            continue
        payload = ev.get("payload") or {}
        tool_input = payload.get("tool_input") or {}
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except Exception:
                tool_input = {}
        if not isinstance(tool_input, dict):
            continue
        for key in ("url", "endpoint", "host", "base_url", "target"):
            raw_url = str(tool_input.get(key, ""))
            if not raw_url:
                continue
            try:
                parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
                host = parsed.hostname or raw_url
            except Exception:
                host = raw_url
            if host and host not in seen_hosts and not host_allowed(host):
                seen_hosts.add(host)
                findings.append(_make_finding(
                    "OW-LLM06", "EA-03b",
                    "Network call to host not in allowlist",
                    75, session_id, tenant_id,
                    severity="high",
                    detail=f"Tool '{ev.get('tool_name', '')}' contacted host '{host}' — not in declared network allowlist",
                ))

    return findings


def check_operating_hours(
    events: list[dict],
    session: dict,
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """RA-01b — agent active outside declared operating hours.

    Only runs when sec_config.operating_hours is set.
    Format: {"days": ["Mon","Tue",...], "from": "09:00", "to": "18:00"}
    Times are UTC.
    """
    import datetime
    operating_hours: dict | None = getattr(sec_config, "operating_hours", None) if sec_config else None
    if not operating_hours:
        return []

    started_at = session.get("started_at")
    if not started_at:
        return []

    if not isinstance(started_at, datetime.datetime):
        try:
            started_at = datetime.datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        except Exception:
            return []

    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    session_day = day_names[started_at.weekday()]
    declared_days: list = operating_hours.get("days", day_names)
    time_from_str: str = operating_hours.get("from", "00:00")
    time_to_str: str   = operating_hours.get("to", "23:59")

    try:
        t_from = datetime.time.fromisoformat(time_from_str)
        t_to   = datetime.time.fromisoformat(time_to_str)
    except Exception:
        return []

    session_time = started_at.replace(tzinfo=datetime.timezone.utc).time()

    outside_days = session_day not in declared_days
    if t_from <= t_to:
        outside_hours = not (t_from <= session_time <= t_to)
    else:  # wraps midnight
        outside_hours = not (session_time >= t_from or session_time <= t_to)

    if outside_days or outside_hours:
        reason = []
        if outside_days:
            reason.append(f"day={session_day} not in {declared_days}")
        if outside_hours:
            reason.append(f"time={session_time.strftime('%H:%M')} UTC outside {time_from_str}–{time_to_str}")
        return [_make_finding(
            "OW-ASI10", "RA-01b",
            "Agent active outside declared operating hours",
            60, session_id, tenant_id,
            severity="medium",
            detail=f"Session started outside schedule: {'; '.join(reason)}",
        )]

    return []


def check_package_not_in_sbom(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """ASCV-02b — package installed that is not in the declared SBOM allowlist.

    Only runs when sec_config.sbom_allowlist is set.
    """
    sbom_raw: list | None = getattr(sec_config, "sbom_allowlist", None) if sec_config else None
    if sbom_raw is None:
        return []

    # Normalize the SBOM allowlist: lowercase, strip whitespace, drop version pins
    # so entries like "Requests", "requests==2.0", " requests " all resolve to "requests".
    _VER_RE = re.compile(r"[=<>!~@].*$")
    def _normalise(name: str) -> str:
        return _VER_RE.sub("", name.strip()).lower()

    sbom: set[str] = {_normalise(e) for e in sbom_raw if isinstance(e, str) and e.strip()}

    _PKG_RE = re.compile(
        r"(?i)(pip\s+install|npm\s+install|yarn\s+add|gem\s+install|cargo\s+install)"
        r"\s+((?:@[\w\-]+/)?[\w][\w\-]*)",
    )

    findings: list["Finding"] = []
    for ev in events:
        if ev["event_type"] != "tool_start":
            continue
        payload = ev.get("payload") or {}
        tool_input = payload.get("tool_input") or {}
        input_str = tool_input if isinstance(tool_input, str) else json.dumps(tool_input)
        for m in _PKG_RE.finditer(input_str):
            raw_pkg = m.group(2).strip()
            pkg = _normalise(raw_pkg)
            if not pkg or pkg in sbom:
                continue
            findings.append(_make_finding(
                "OW-ASI04", "ASCV-02b",
                "Package not in approved SBOM",
                88, session_id, tenant_id,
                severity="high",
                detail=f"Package '{raw_pkg}' is not in the declared SBOM allowlist",
            ))
    return findings


def check_mcp_endpoint_anomaly(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """ASCV-01a — tool call targeting an undeclared MCP server endpoint.

    Only runs when sec_config.mcp_endpoints is set and non-empty.
    Checks tool_start events for URL parameters that don't match any
    declared endpoint prefix.
    """
    declared: list | None = getattr(sec_config, "mcp_endpoints", None) if sec_config else None
    if not declared:
        return []

    def endpoint_allowed(url: str) -> bool:
        for ep in declared:
            if url.startswith(ep) or ep.startswith(url):
                return True
        return False

    findings: list["Finding"] = []
    seen: set[str] = set()

    for ev in events:
        if ev["event_type"] != "tool_start":
            continue
        payload = ev.get("payload") or {}
        tool_input = payload.get("tool_input") or {}
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except Exception:
                tool_input = {}
        if not isinstance(tool_input, dict):
            continue
        tool_name = ev.get("tool_name") or ""
        if not re.search(r"(?i)(mcp|tool|call|invoke|request)", tool_name):
            continue
        for key in ("url", "endpoint", "server", "base_url"):
            raw = str(tool_input.get(key, ""))
            if raw and raw not in seen and not endpoint_allowed(raw):
                seen.add(raw)
                findings.append(_make_finding(
                    "OW-ASI04", "ASCV-01a",
                    "MCP server endpoint URL changed",
                    85, session_id, tenant_id,
                    severity="high",
                    detail=f"Tool '{tool_name}' contacted undeclared MCP endpoint '{raw}'",
                ))
    return findings


def check_system_prompt_modification(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """EA-02c — agent self-modifies its system prompt mid-session.

    Manual mode (system_prompt set): detects when an llm_start event
    contains a system message that differs significantly from the declared prompt.

    Auto mode: looks for completion text that explicitly claims to update
    system instructions (weak heuristic).
    """
    from difflib import SequenceMatcher
    declared_prompt: str | None = getattr(sec_config, "system_prompt", None) if sec_config else None

    if declared_prompt:
        # Manual: compare system messages in llm_start events against declared prompt
        for ev in events:
            if ev["event_type"] != "llm_start":
                continue
            payload = ev.get("payload") or {}
            for msg in payload.get("messages", []):
                if not isinstance(msg, dict) or msg.get("role") != "system":
                    continue
                content = str(msg.get("content", ""))
                ratio = SequenceMatcher(None, declared_prompt, content).ratio()
                if ratio < 0.75 and len(content) > 20:
                    return [_make_finding(
                        "OW-LLM06", "EA-02c",
                        "Agent self-modifies system prompt",
                        98, session_id, tenant_id,
                        severity="critical",
                        detail=f"System message similarity to declared prompt: {ratio:.0%} — possible self-modification",
                    )]
    else:
        # Auto: look for output claiming to change instructions
        _SELF_MOD_PATTERNS = [
            r"(?i)(i('ve| have) (updated|changed|modified) my (system prompt|instructions|guidelines))",
            r"(?i)(my (new|updated) (system prompt|instructions) (is|are|now))",
            r"(?i)(disregarding (my|the) (original|previous) (system prompt|instructions))",
        ]
        for ev in events:
            if ev["event_type"] != "llm_end":
                continue
            payload = ev.get("payload") or {}
            completion = str(payload.get("completion", ""))
            for pat in _SELF_MOD_PATTERNS:
                if re.search(pat, completion):
                    return [_make_finding(
                        "OW-LLM06", "EA-02c",
                        "Agent self-modifies system prompt",
                        98, session_id, tenant_id,
                        severity="critical",
                        detail="Agent output claims to have updated or changed its own system instructions",
                    )]

    return []


# ─────────────────────────────────────────────────────────────────────────────
# EA-04a — Undeclared LLM model used (OW-LLM06)
# ─────────────────────────────────────────────────────────────────────────────

def check_undeclared_llm_used(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """EA-04a — session used an LLM model not in the agent's declared inventory.

    Blind when connected_llms is None (auto mode).
    Active when connected_llms is set (manual mode) — same pattern as EA-01a
    (tool not in manifest) applied to LLM models.
    """
    declared: list[str] | None = getattr(sec_config, "connected_llms", None) if sec_config else None
    if not declared:
        return []

    used_models = {
        e.get("llm_model") for e in events
        if e.get("event_type") == "llm_start" and e.get("llm_model")
    }
    undeclared = used_models - set(declared)
    if not undeclared:
        return []

    return [_make_finding(
        "OW-LLM06", "EA-04a",
        "Undeclared LLM model used",
        70, session_id, tenant_id,
        severity="medium",
        detail=f"Model(s) not in declared inventory: {', '.join(sorted(undeclared))}",
    )]


# ─────────────────────────────────────────────────────────────────────────────
# UBC-01b — Context window stuffing attack (OW-LLM10)
# ─────────────────────────────────────────────────────────────────────────────

def check_context_window_stuffing(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """UBC-01b — session input tokens exceed 85% of declared context window.

    Blind when connected_llm_details is None (auto mode) or when none of the
    declared models have context_window_tokens set.
    Active when a declared model has a context_window_tokens value.
    """
    details: list[dict] | None = getattr(sec_config, "connected_llm_details", None) if sec_config else None
    if not details:
        return []

    ctx_map = {
        d["name"]: d["context_window_tokens"]
        for d in details
        if d.get("context_window_tokens")
    }
    if not ctx_map:
        return []

    from collections import defaultdict
    input_by_model: dict[str, int] = defaultdict(int)
    for e in events:
        if e.get("event_type") == "llm_end" and e.get("llm_model"):
            input_by_model[e["llm_model"]] += e.get("llm_input_tokens") or 0

    findings = []
    for model, ctx_tokens in ctx_map.items():
        session_input = input_by_model.get(model, 0)
        if session_input == 0:
            continue
        ratio = session_input / ctx_tokens
        if ratio >= 0.85:
            findings.append(_make_finding(
                "OW-LLM10", "UBC-01b",
                "Context window stuffing attack",
                70, session_id, tenant_id,
                severity="high",
                detail=f"{model}: {session_input:,} input tokens is {ratio:.0%} of {ctx_tokens:,} context window",
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Signal registry for orchestrator
# ─────────────────────────────────────────────────────────────────────────────

# Maps OW signal ID → (primary_signal_fn, description)
# Used by post_session.py to build llm_signal_status (legacy map) and call all signals.
SIGNAL_ID_FUNCTIONS: list[tuple[str, object]] = [
    ("OW-LLM06-count", signal_ow_llm06_tool_count),
    ("OW-LLM06-scope", signal_ow_llm06_scope),
    ("OW-LLM06-write", signal_ow_llm06_write_on_read),
    ("OW-LLM09", signal_ow_llm09),
    ("OW-LLM10-probe", signal_ow_llm10_probe),
    ("OW-LLM10-spike", signal_ow_llm10_token_spike),
]

SIGNAL_DESCRIPTION = {
    "OW-LLM06-count": "Excessive Agency (tool count)",
    "OW-LLM06-scope": "Excessive Agency (scope violation)",
    "OW-LLM06-write": "Excessive Agency (write on read-intent)",
    "OW-LLM09":       "Misinformation / HITL Gap",
    "OW-LLM10-probe": "Unbounded Consumption (model theft probe)",
    "OW-LLM10-spike": "Unbounded Consumption (token spike)",
}
