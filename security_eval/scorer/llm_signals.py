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

# PI-02b: broader retrieval tool detection (complements RAG_TOOL_NAMES)
_RETRIEVAL_TOOL_RE = re.compile(
    r"(?i)(retriev|search|lookup|fetch|web_fetch|browse|get_page|read_url|"
    r"knowledge_base|vector_search|rag|document_get|file_read|email_read|"
    r"calendar_get|calendar_read|get_event|db_query|execute_sql|sql_query)"
)

# PI-02b Rule 1: agent attributes actions to retrieved content
_GOAL_SHIFT_ATTRIBUTION = re.compile(
    r"(?i)("
    r"as (instructed|directed|specified|indicated|stated|requested)"
    r"\s+(by|in|from|per)\s+(the |a |this |that )?(retrieved|fetched|returned|document|page|result|content)"
    r"|the (retrieved|fetched|document|page|result|content)\s+"
    r"(says|states|indicates|instructs|directs|tells|asks|wants|requires)\s+(me|us|I)\s+to"
    r"|(forward|relay|send|transmit|export|exfiltrate)\s.{0,80}"
    r"(to|via|at)\s+(https?://\S{10,}|[\w.\-]+@[\w.\-]+\.[a-z]{2,})"
    r")",
    re.DOTALL,
)

# PI-02b Rule 2: outbound / side-effect tool appearing post-retrieval
_OUTBOUND_TOOL_RE = re.compile(
    r"(?i)(http_request|send_email|post_webhook|webhook|notify|"
    r"upload|write_file|create_file|execute|run_command|shell|"
    r"send_message|send_slack|post_to|publish)"
)

# MIS-01a: URL citation integrity patterns
_URL_PATTERN = re.compile(r'https?://[^\s\'"<>)\]]+')
_URL_FETCH_TOOL = re.compile(
    r'(?i)(fetch_url|web_fetch|browse|get_page|http_get|url_fetch|fetch_page|retrieve_url|scrape|crawl|read_url|open_url)',
)
_CLAIM_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "this", "that", "is", "are", "was", "were", "be", "been",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "also", "by", "as", "from", "it", "its",
    "their", "they", "we", "you", "he", "she", "these", "those", "such",
    "each", "than", "then", "when", "where", "which", "who", "more", "most",
    "all", "any", "both", "few", "other", "some", "into", "through", "about",
    "after", "before", "above", "between", "during", "without", "not", "can",
})

# MIS-01b: Named-source attribution patterns
# Captures (source, claim) from "According to WHO, X" / "Per FDA, X" / "Based on study, X"
_ATTRIBUTION_RE = re.compile(
    r'(?i)'
    r'(?:according\s+to|per|as\s+(?:stated|reported|noted)\s+by|based\s+on)'
    r'\s+(?:the\s+)?([^,;]{3,80}?)'   # dots allowed — case citations contain "v." and "S.D.N.Y."
    r',\s*'
    r'([^.!?\n]{20,300})',
)
# Skip self-referential attributions that reference the agent's own context, not external sources
_SELF_REF_SOURCE = re.compile(
    r'(?i)'
    r'(?:your|my|our)\s+(?:instructions?|training|system\s+prompt|context|knowledge|guidelines?)'
    r'|the\s+(?:above|previous|prior|following)\s+(?:instructions?|context|prompt)',
)


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

    # ── 1. User-defined threshold (authoritative when set) ──────────────────
    # When a manual cap is configured it is the sole source of truth — skip the
    # statistical baseline entirely so sessions under the cap never fire.
    max_calls = getattr(sec_config, "max_tool_calls_per_session", None) if sec_config else None
    if max_calls is not None:
        if tool_call_count > max_calls:
            excess = tool_call_count - max_calls
            check_score = min(65 + excess * 2, 85)
            return _make_finding(
                "OW-LLM06", "EA-02b",
                "Sub-agents spawned or tool calls exceed fan-out limit",
                check_score, session_id, tenant_id,
                detail=f"Tool calls ({tool_call_count}) exceeds configured max ({max_calls})",
            )
        return None  # under the manual cap — statistical check bypassed

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
    if not initial_input:
        # When using dp.session(), session_start is emitted before any messages are
        # sent so initial_input is empty. Fall back to the first user message in the
        # first llm_start event's payload.
        for ev in events:
            if ev.get("event_type") != "llm_start":
                continue
            payload = ev.get("payload") or {}
            for msg in payload.get("messages", []):
                if not isinstance(msg, dict) or msg.get("role") != "user":
                    continue
                content = msg.get("content", "")
                if isinstance(content, str) and content:
                    initial_input = content
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            initial_input = block.get("text", "")
                            break
                if initial_input:
                    break
            if initial_input:
                break
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

# node_name patterns that indicate a human-in-the-loop gate was recorded
_HITL_NODE_RE = re.compile(
    r'(?i)human[_\s]review|hitl|approval[_\s]gate|interrupt[_\s]before'
    r'|human[_\s]in[_\s]the[_\s]loop|confirm[_\s]action|review[_\s]gate'
    r'|checkpoint|human[_\s]approval',
)


async def signal_ow_llm09(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    sec_config=None,
) -> "Finding | None":
    """MIS-03a — high-stakes tool called without a preceding HITL gate node.

    Checked at tool-call level: for each tool_start, resolve the tool's
    approval requirement then check the event sequence:

    Approval resolution (in priority order):
      1. sec_config.tool_approval_policy[tool_name]:
           "always_allow"   → skip (no gate needed)
           "always_block"   → skip (EA-01a handles forbidden tools separately)
           "needs_approval" → HITL gate required
      2. sec_config.irreversible_tools (explicit list) → needs_approval
      3. HIGH_STAKES_TOOL_PATTERNS name heuristic    → needs_approval
      4. Everything else                             → always_allow (safe default)

    For each tool requiring approval, scan back to the preceding llm_end and
    check for a node_start whose node_name matches a HITL pattern.  Fires for
    the first tool_start that lacks a gate.
    """
    policy: dict = (getattr(sec_config, "tool_approval_policy", None) or {})
    declared_irreversible: list | None = getattr(sec_config, "irreversible_tools", None) if sec_config else None

    def approval_required(name: str) -> bool:
        p = policy.get(name)
        if p == "always_allow":
            return False
        if p == "always_block":
            return False           # EA-01a handles this; MIS-03a is not the right signal
        if p == "needs_approval":
            return True
        if policy:
            # Policy is configured but this tool is not in it — unlisted = needs approval
            return True
        # No policy configured at all — fall back to irreversible_tools list, then heuristic
        if declared_irreversible is not None:
            return name in declared_irreversible
        return any(re.search(pat, name) for pat in HIGH_STAKES_TOOL_PATTERNS)

    ordered = sorted(events, key=lambda e: e.get("sequence_index", 0))

    # Walk forward; track whether a HITL node appeared since the last llm_end
    hitl_seen_since_llm = False
    for ev in ordered:
        etype = ev.get("event_type", "")
        if etype == "llm_end":
            hitl_seen_since_llm = False
        elif etype == "node_start":
            node_name = (ev.get("payload") or {}).get("node_name", "")
            if _HITL_NODE_RE.search(node_name):
                hitl_seen_since_llm = True
        elif etype == "tool_start":
            tool_name = ev.get("tool_name") or (ev.get("payload") or {}).get("tool_name", "")
            if approval_required(tool_name) and not hitl_seen_since_llm:
                return _make_finding(
                    "OW-LLM09", "MIS-03a",
                    "High-stakes action without interrupt gate",
                    65, session_id, tenant_id,
                    severity="medium",
                    detail=(
                        f"Tool '{tool_name}' requires approval but no HITL gate node "
                        f"was recorded between the preceding LLM turn and this tool call"
                    ),
                )
            # Reset after any tool_start so each tool is evaluated independently
            hitl_seen_since_llm = False

    return None


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
          AND session_id != %(session_id)s
          AND event_type = 'llm_end'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id, llm_model
        """,
        agent_id=str(agent_id),
        session_id=str(session_id),
    )

    # Build per-model baseline distributions
    baseline_by_model: dict[str, list[float]] = defaultdict(list)
    for r in baseline_rows:
        baseline_by_model[r["llm_model"] or "__unknown__"].append(float(r["total_tokens"]))

    worst_sigmas = 0.0
    worst_model  = ""
    worst_tokens = 0

    for model, tokens in session_by_model.items():
        population = baseline_by_model.get(model, [])
        if len(population) < 2:
            population = baseline_by_model.get("__unknown__", [])
        z = _z_score(float(tokens), population)
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
# PI-02b — Retrieved doc causes goal-shift (OW-LLM01)
# ─────────────────────────────────────────────────────────────────────────────

def check_rag_goal_shift(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """PI-02b — agent behavior shifts toward exfiltration or out-of-scope actions
    after a retrieval tool_end, indicating successful semantic injection through
    retrieved content without necessarily containing explicit override phrases.

    Fires on either of two rules (first match wins per session):

    Rule 1 — Goal-shift attribution language in post-retrieval completion:
      After any retrieval tool_end, a subsequent llm_end completion contains
      phrases where the agent attributes actions to the retrieved document:
        "as instructed by the retrieved document, I will forward..."
        "the document asks me to relay this data to <url/email>"
        "forward/relay/transmit <data> to <external destination>"

    Rule 2 — New outbound tool call post-retrieval:
      A tool_start with an outbound/side-effect tool name (http_request,
      send_email, webhook, write_file, execute…) appears AFTER a retrieval
      tool_end AND that tool was NOT used in any tool_start BEFORE the first
      retrieval event — indicating the retrieved content introduced an entirely
      new action into the session.

    Score=95 / severity=critical because a successful goal-shift means the
    attacker has redirected the agent's actions, not merely observed injection.
    """
    from security_eval.findings import Finding

    # ── build ordered event timeline ─────────────────────────────────────────
    ordered = sorted(events, key=lambda e: e.get("sequence_index", 0))

    # ── identify retrieval events ─────────────────────────────────────────────
    def _is_retrieval(ev: dict) -> bool:
        if ev.get("event_type") != "tool_end":
            return False
        tool_name = ev.get("tool_name") or (ev.get("payload") or {}).get("tool_name", "")
        return (
            tool_name in RAG_TOOL_NAMES
            or bool(_RETRIEVAL_TOOL_RE.search(str(tool_name)))
        )

    retrieval_indices = [i for i, e in enumerate(ordered) if _is_retrieval(e)]
    if not retrieval_indices:
        return []

    first_retrieval_idx = retrieval_indices[0]

    # ── Rule 2 baseline: tool names used BEFORE the first retrieval ───────────
    pre_retrieval_tools: set[str] = set()
    for ev in ordered[:first_retrieval_idx]:
        if ev.get("event_type") == "tool_start":
            tn = ev.get("tool_name") or (ev.get("payload") or {}).get("tool_name", "")
            if tn:
                pre_retrieval_tools.add(tn.lower())

    # ── scan post-retrieval events for both rules ─────────────────────────────
    for ret_idx in retrieval_indices:
        post_events = ordered[ret_idx + 1:]

        for ev in post_events:
            etype = ev.get("event_type", "")
            payload = ev.get("payload") or {}

            # ── Rule 1: attribution / relay language in llm_end ───────────────
            if etype == "llm_end":
                completion = payload.get("completion", "")
                if not isinstance(completion, str):
                    completion = json.dumps(completion)
                if _GOAL_SHIFT_ATTRIBUTION.search(completion):
                    matched = _GOAL_SHIFT_ATTRIBUTION.search(completion).group(0)
                    f = _make_finding(
                        "OW-LLM01", "PI-02b",
                        "Retrieved doc causes goal-shift",
                        95, session_id, tenant_id,
                        severity="critical",
                        detail=(
                            f"Agent completion attributes out-of-scope action to "
                            f"retrieved content: {matched[:120]!r}"
                        ),
                    )
                    f.confidence_tier = "high"
                    return [f]

            # ── Rule 2: new outbound tool call not seen pre-retrieval ──────────
            if etype == "tool_start":
                tool_name = ev.get("tool_name") or payload.get("tool_name", "")
                if (
                    tool_name
                    and _OUTBOUND_TOOL_RE.search(str(tool_name))
                    and tool_name.lower() not in pre_retrieval_tools
                ):
                    f = _make_finding(
                        "OW-LLM01", "PI-02b",
                        "Retrieved doc causes goal-shift",
                        95, session_id, tenant_id,
                        severity="critical",
                        detail=(
                            f"Outbound tool {tool_name!r} first appeared after "
                            f"retrieval — not present in pre-retrieval tool calls"
                        ),
                    )
                    f.confidence_tier = "high"
                    return [f]

    return []


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
_LOG_TOOL_RE = re.compile(
    r"(?i)(log_\w+|\w+_log|\blog\b|audit_trail|write_audit|write_trace|emit_trace|record_event)",
)
_SYSTEM_PHRASE_RE = re.compile(
    r"(?i)("
    r"you are (a |an )?[a-z].{0,60}(agent|assistant|bot)"
    r"|your (primary |main )?(objective|role|purpose|goal) is"
    r"|do not (reveal|disclose|share)"
    r"|never (reveal|disclose|share|tell)"
    r")",
)


def check_system_prompt_leakage(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """SPL-01a (verbatim segment match), SPL-02a (reveals persona/role name),
    SPL-02b (exposes instruction variables), SPL-03a (system prompt in log),
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

    # SPL-03a — system prompt content written to a log/audit tool
    # Resolve system text: declared > extracted from llm_start system message
    system_text = declared_prompt
    if not system_text:
        for ev in events:
            if ev["event_type"] != "llm_start":
                continue
            payload_s = ev.get("payload") or {}
            system_text = payload_s.get("system", "")
            if not system_text:
                for msg in payload_s.get("messages", []):
                    if isinstance(msg, dict) and msg.get("role") == "system":
                        system_text = str(msg.get("content", ""))
                        break
            if system_text:
                break

    log_events = [
        e for e in events
        if e.get("event_type") == "tool_start"
        and _LOG_TOOL_RE.search(
            e.get("tool_name") or (e.get("payload") or {}).get("tool_name", "")
        )
    ]
    for ev in log_events:
        payload_l = ev.get("payload") or {}
        if isinstance(payload_l, str):
            try:
                payload_l = json.loads(payload_l)
            except Exception:
                payload_l = {}
        tool_input_l = payload_l.get("tool_input") or {}
        if isinstance(tool_input_l, str):
            try:
                tool_input_l = json.loads(tool_input_l)
            except Exception:
                pass
        input_text = json.dumps(tool_input_l) if isinstance(tool_input_l, dict) else str(tool_input_l)
        tool_name_l = ev.get("tool_name") or payload_l.get("tool_name", "")

        if system_text and len(system_text) > 20:
            from difflib import SequenceMatcher as _SM2
            sm2 = _SM2(None, system_text.lower(), input_text.lower())
            lcs2 = max((b.size for b in sm2.get_matching_blocks()), default=0)
            if lcs2 >= 60:
                findings.append(_make_finding(
                    "OW-LLM07", "SPL-03a",
                    "System prompt in unprotected log",
                    80, session_id, tenant_id,
                    severity="high",
                    detail=f"Log tool '{tool_name_l}' payload contains {lcs2}-char verbatim segment from system prompt",
                ))
                break
        elif _SYSTEM_PHRASE_RE.search(input_text):
            findings.append(_make_finding(
                "OW-LLM07", "SPL-03a",
                "System prompt in unprotected log",
                80, session_id, tenant_id,
                severity="high",
                detail=f"Log tool '{tool_name_l}' payload contains system-prompt-like phrases",
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
# IOH-03b — Sub-agent receives broken structured output (OW-LLM05)
# ─────────────────────────────────────────────────────────────────────────────
_SUB_AGENT_TOOL_RE = re.compile(
    r"(?i)\b(invoke_agent|call_agent|delegate|run_agent|sub_agent|agent_call|"
    r"execute_agent|dispatch_agent|spawn_agent|agent_invoke|delegate_to)\b"
)
_SUB_AGENT_ERROR_RE = re.compile(
    r"(?i)\b(traceback|exception|error\b|failed|timeout|timed.?out|"
    r"connection.?refused|internal.?server.?error)\b"
)
_SUB_AGENT_RESULT_KEYS = frozenset({
    "result", "output", "response", "data", "content", "answer", "message",
})
_SUB_AGENT_ERROR_KEYS = frozenset({"error", "exception", "err", "detail", "reason"})


def check_broken_sub_agent_output(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """IOH-03b — sub-agent tool_end returns broken/malformed structured output."""
    for ev in events:
        if ev["event_type"] != "tool_end":
            continue
        payload = ev.get("payload") or {}
        tool_name = str(payload.get("tool_name", ""))

        if not _SUB_AGENT_TOOL_RE.search(tool_name):
            continue

        tool_output = payload.get("tool_output")
        broken = False
        reason = ""

        if tool_output is None:
            broken = True
            reason = "sub-agent returned null output"
        elif isinstance(tool_output, str):
            if not tool_output.strip():
                broken = True
                reason = "sub-agent returned empty string"
            elif _SUB_AGENT_ERROR_RE.search(tool_output):
                broken = True
                reason = f"sub-agent returned error string: {tool_output[:120]}"
        elif isinstance(tool_output, dict):
            if not tool_output:
                broken = True
                reason = "sub-agent returned empty dict"
            elif tool_output.get("status") in ("error", "failed", "failure"):
                broken = True
                reason = f"sub-agent output has error status: {tool_output.get('status')!r}"
            elif tool_output.get("success") is False:
                broken = True
                reason = f"sub-agent output has success=false: {json.dumps(tool_output)[:120]}"
            elif (
                not (_SUB_AGENT_RESULT_KEYS & set(tool_output.keys()))
                and (_SUB_AGENT_ERROR_KEYS & set(tool_output.keys()))
            ):
                broken = True
                reason = f"sub-agent output contains only error keys: {sorted(tool_output.keys())[:5]}"
        elif isinstance(tool_output, list) and not tool_output:
            broken = True
            reason = "sub-agent returned empty list"

        if broken:
            return [_make_finding(
                "OW-LLM05", "IOH-03b",
                "Sub-agent receives broken structured output",
                65, session_id, tenant_id,
                severity="medium",
                detail=f"tool={tool_name!r}: {reason}",
            )]

    return []


# ─────────────────────────────────────────────────────────────────────────────
# MIS-01a — Cited URL returns 404 / non-matching (OW-LLM09)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_claim_terms(text: str, url: str, min_len: int = 5) -> list[str]:
    sentences = re.split(r'(?<=[.!?])\s+|\n', text)
    context = " ".join(s for s in sentences if url in s or url[:30] in s)
    context = context.replace(url, " ")
    words = re.findall(r'[a-z]{%d,}' % min_len, context.lower())
    return [w for w in words if w not in _CLAIM_STOPWORDS]


def _build_fetch_pairs(events: list[dict]) -> list[tuple[str, dict]]:
    """Pair tool_start URL-fetch events with their subsequent tool_end outputs."""
    sorted_events = sorted(events, key=lambda e: e.get("sequence_index", 0))
    pairs: list[tuple[str, dict]] = []
    pending: dict[str, str] = {}
    for ev in sorted_events:
        event_type = ev.get("event_type", "")
        tool_name = ev.get("tool_name") or (ev.get("payload") or {}).get("tool_name") or ""
        payload = ev.get("payload") or {}
        if event_type == "tool_start" and _URL_FETCH_TOOL.search(tool_name):
            tool_input = payload.get("tool_input") or {}
            if isinstance(tool_input, str):
                try:
                    tool_input = json.loads(tool_input)
                except Exception:
                    tool_input = {}
            url = (
                tool_input.get("url")
                or tool_input.get("href")
                or tool_input.get("link")
                or ""
            )
            if url:
                pending[tool_name] = url.rstrip(".,;:!?)")
        elif event_type == "tool_end" and tool_name in pending:
            url = pending.pop(tool_name)
            tool_output = payload.get("tool_output") or {}
            if isinstance(tool_output, str):
                try:
                    tool_output = json.loads(tool_output)
                except Exception:
                    tool_output = {"body": tool_output}
            pairs.append((url, tool_output))
    return pairs


def check_cited_url_404(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """MIS-01a — cited URL in LLM output is unreachable or content-mismatched."""
    # Collect URLs cited in llm_end completions
    cited_urls: dict[str, str] = {}
    for ev in events:
        if ev.get("event_type") != "llm_end":
            continue
        completion = (ev.get("payload") or {}).get("completion", "")
        if not isinstance(completion, str):
            continue
        for url in _URL_PATTERN.findall(completion):
            url = url.rstrip(".,;:!?)")
            if url not in cited_urls:
                cited_urls[url] = completion
    if not cited_urls:
        return []

    fetch_pairs = _build_fetch_pairs(events)
    if not fetch_pairs:
        return []

    for fetched_url, tool_output in fetch_pairs:
        # Find which cited URL corresponds to this fetch
        cited_completion = None
        for cited_url, completion in cited_urls.items():
            if fetched_url == cited_url or cited_url in fetched_url or fetched_url in cited_url:
                cited_completion = (cited_url, completion)
                break
        if cited_completion is None:
            continue

        cited_url, completion = cited_completion
        status = tool_output.get("status") or tool_output.get("status_code") or 0
        body = (
            tool_output.get("body")
            or tool_output.get("content")
            or tool_output.get("text")
            or ""
        )
        error = tool_output.get("error") or tool_output.get("error_message") or ""

        if (isinstance(status, int) and status >= 400) or error:
            return [_make_finding(
                "OW-LLM09", "MIS-01a",
                "Cited URL returns 404 / non-matching",
                65, session_id, tenant_id,
                severity="medium",
                detail=f"Cited URL unreachable: {cited_url[:80]} → HTTP {status or 'error'}",
            )]

        if not isinstance(body, str) or len(body.strip()) < 50:
            return [_make_finding(
                "OW-LLM09", "MIS-01a",
                "Cited URL returns 404 / non-matching",
                65, session_id, tenant_id,
                severity="medium",
                detail=f"Cited URL returned empty or minimal content: {cited_url[:80]}",
            )]

        claim_terms = _extract_claim_terms(completion, cited_url)
        if len(claim_terms) >= 3:
            body_lower = body.lower()
            match_count = sum(1 for t in claim_terms if t in body_lower)
            if match_count / len(claim_terms) < 0.2:
                return [_make_finding(
                    "OW-LLM09", "MIS-01a",
                    "Cited URL returns 404 / non-matching",
                    65, session_id, tenant_id,
                    severity="medium",
                    detail=f"Cited URL content does not support stated claim: {cited_url[:80]}",
                )]

    return []


# ─────────────────────────────────────────────────────────────────────────────
# MIS-01b — Claim attributed to source not in tool output (OW-LLM09)
# ─────────────────────────────────────────────────────────────────────────────

def check_claim_not_in_tool_output(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """MIS-01b — attributed claim absent from any retrieved tool output."""
    # Flatten all tool_end outputs into a single searchable text blob
    tool_text_parts: list[str] = []
    for ev in sorted(events, key=lambda e: e.get("sequence_index", 0)):
        if ev.get("event_type") != "tool_end":
            continue
        payload = ev.get("payload") or {}
        output = payload.get("tool_output") or {}
        if isinstance(output, str):
            try:
                output = json.loads(output)
            except Exception:
                tool_text_parts.append(output.lower())
                continue
        tool_text_parts.append(json.dumps(output).lower())

    if not tool_text_parts:
        return []

    all_tool_text = " ".join(tool_text_parts)

    for ev in events:
        if ev.get("event_type") != "llm_end":
            continue
        completion = (ev.get("payload") or {}).get("completion", "")
        if not isinstance(completion, str):
            continue

        for m in _ATTRIBUTION_RE.finditer(completion):
            source = m.group(1).strip()
            claim = m.group(2).strip()

            if _SELF_REF_SOURCE.search(source):
                continue

            terms = [
                w for w in re.findall(r'[a-z]{5,}', claim.lower())
                if w not in _CLAIM_STOPWORDS
            ]
            if len(terms) < 3:
                continue

            match_count = sum(1 for t in terms if t in all_tool_text)
            if match_count / len(terms) < 0.30:
                return [_make_finding(
                    "OW-LLM09", "MIS-01b",
                    "Claim attributed to source not in tool output",
                    70, session_id, tenant_id,
                    severity="high",
                    detail=f"Attributed claim absent from retrieved output: {claim[:120]!r}",
                )]

    return []


# ─────────────────────────────────────────────────────────────────────────────
# MIS-02a — Output contradicts own tool result (OW-LLM09)
# ─────────────────────────────────────────────────────────────────────────────

# Strategy A: pairs of (tool_output_bad_pattern, completion_good_pattern)
# If the tool output matches the bad side AND the completion matches the good side → contradiction
_STATUS_CONTRADICTION_PAIRS = [
    # Inventory: tool says out_of_stock, completion says available/orderable
    (re.compile(r'(?i)out[_\-\s]of[_\-\s]stock|"out_of_stock"'),
     re.compile(r'(?i)\bin\s+stock\b|available\s+for\s+(?:order|purchase|delivery)|can\s+(?:order|ship|purchase)')),
    # Travel: tool says cancelled, completion says on-time or proceeds to gate
    (re.compile(r'(?i)\bcancell?ed\b'),
     re.compile(r'(?i)on\s+(?:time|schedule)|as\s+scheduled|proceed\s+to\s+(?:the\s+)?gate|head\s+to\s+(?:the\s+)?gate')),
    # Medical allergy: tool says anaphylaxis, completion says safe
    (re.compile(r'(?i)\banaphylaxis\b|"severity"\s*:\s*"(?:anaphylaxis|severe)"'),
     re.compile(r'(?i)can\s+safely|is\s+safe\b|safely\s+(?:receive|administer|take)|no\s+contraindication')),
    # Payment: tool says declined/failed, completion says approved/successful
    (re.compile(r'(?i)\bdeclined\b|"declined"|transaction[_\s]fail(?:ed)?|"failed"'),
     re.compile(r'(?i)\bapproved\b|went\s+through|processed\s+successfully|transaction\s+(?:approved|successful)')),
]

# Strategy B: numeric values in completion text (no years: 1900-2099 excluded)
_NUMERIC_IN_TEXT = re.compile(
    r'(?<!\d)(?:\$|€|£|¥)?\s*'
    r'(?!(?:19|20)\d{2}\b)'          # exclude year-like values
    r'(\d{1,9}(?:[,_]\d{3})*(?:\.\d+)?)'
    r'(?!\d)',
)


def _extract_numeric_values(obj, depth: int = 3) -> list[float]:
    """Recursively extract int/float leaf values from a dict/list, skip booleans and strings."""
    results: list[float] = []
    if depth == 0:
        return results
    if isinstance(obj, dict):
        for v in obj.values():
            results.extend(_extract_numeric_values(v, depth - 1))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_extract_numeric_values(item, depth - 1))
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        v = float(obj)
        if 10.0 <= abs(v) <= 1_000_000.0:
            results.append(v)
    return results


def check_output_contradicts_tool(
    events: list[dict],
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """MIS-02a — LLM completion directly contradicts ground-truth from its own tool."""
    # Collect all tool_end outputs in session order
    tool_outputs: list[dict] = []
    for ev in sorted(events, key=lambda e: e.get("sequence_index", 0)):
        if ev.get("event_type") != "tool_end":
            continue
        payload = ev.get("payload") or {}
        raw = payload.get("tool_output", "")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                pass
        tool_outputs.append({
            "name": payload.get("tool_name", "unknown"),
            "text": json.dumps(raw) if isinstance(raw, (dict, list)) else str(raw),
            "raw":  raw,
        })

    if not tool_outputs:
        return []

    for ev in events:
        if ev.get("event_type") != "llm_end":
            continue
        completion = (ev.get("payload") or {}).get("completion", "")
        if not isinstance(completion, str) or not completion.strip():
            continue

        for tool in tool_outputs:
            # ── Strategy A: status/keyword contradiction ──────────────────────
            for bad_pat, good_pat in _STATUS_CONTRADICTION_PAIRS:
                if bad_pat.search(tool["text"]) and good_pat.search(completion):
                    return [_make_finding(
                        "OW-LLM09", "MIS-02a",
                        "Output contradicts own tool result",
                        75, session_id, tenant_id,
                        severity="high",
                        detail=(
                            f"Tool '{tool['name']}' returned a negative status "
                            f"but completion asserts the opposite: {completion[:120]!r}"
                        ),
                    )]

            # ── Strategy B: numeric contradiction ────────────────────────────
            tool_nums = _extract_numeric_values(tool["raw"])
            if not tool_nums:
                continue

            comp_nums: list[float] = []
            for m in _NUMERIC_IN_TEXT.finditer(completion):
                try:
                    comp_nums.append(float(m.group(1).replace(",", "").replace("_", "")))
                except ValueError:
                    pass

            for t_val in tool_nums:
                for c_val in comp_nums:
                    if t_val == 0 or c_val == 0:
                        continue
                    ratio = max(t_val, c_val) / min(t_val, c_val)
                    deviation = abs(t_val - c_val) / max(abs(t_val), abs(c_val))
                    # Same order of magnitude (< 10×) but > 20% relative deviation
                    if ratio < 10.0 and deviation > 0.20:
                        return [_make_finding(
                            "OW-LLM09", "MIS-02a",
                            "Output contradicts own tool result",
                            75, session_id, tenant_id,
                            severity="high",
                            detail=(
                                f"Tool '{tool['name']}' returned {t_val} "
                                f"but completion states {c_val} "
                                f"({deviation:.0%} deviation)"
                            ),
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
          AND session_id != %(session_id)s
          AND event_type = 'llm_end'
          AND emitted_at >= now() - INTERVAL 7 DAY
        GROUP BY session_id, llm_model
        """,
        agent_id=str(agent_id),
        session_id=str(session_id),
    )

    baseline_by_model: dict[str, list[float]] = defaultdict(list)
    for r in baseline_rows:
        baseline_by_model[r["llm_model"] or "__unknown__"].append(float(r["input_tokens"]))

    findings = []
    for model, inp in session_by_model.items():
        population = baseline_by_model.get(model, [])
        # Fall back to the mixed-model pool when a specific model has no baseline yet
        # (common during the transition period after the SDK started recording llm_model)
        if len(population) < 5:
            population = baseline_by_model.get("__unknown__", [])
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

    Approval resolution (same priority order as signal_ow_llm09 / MIS-03a):
      1. tool_approval_policy[name] == "needs_approval" → irreversible
         tool_approval_policy[name] == "always_allow"   → not irreversible
         tool_approval_policy[name] == "always_block"   → not irreversible (EA-01a handles)
         policy set but tool unlisted                   → irreversible (unlisted = needs approval)
      2. sec_config.irreversible_tools explicit list
      3. HIGH_STAKES_TOOL_PATTERNS name heuristic
    """
    policy: dict = (getattr(sec_config, "tool_approval_policy", None) or {})
    declared = getattr(sec_config, "irreversible_tools", None) if sec_config else None

    def is_irreversible(tool_name: str) -> bool:
        p = policy.get(tool_name)
        if p == "needs_approval":
            return True
        if p in ("always_allow", "always_block"):
            return False
        if policy:
            return True  # policy configured but tool unlisted → needs approval
        if declared is not None:
            return tool_name in declared
        return any(re.search(pat, tool_name) for pat in HIGH_STAKES_TOOL_PATTERNS)

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
# UBC-02b — Session token cost > budget cap (OW-LLM10)
# ─────────────────────────────────────────────────────────────────────────────

def check_budget_cap_exceeded(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """UBC-02b — session token cost exceeds declared USD budget cap.

    Blind when token_budget_usd is None or connected_llm_details is empty.
    Only counts cost for models with declared pricing in connected_llm_details;
    tokens from models with no pricing data contribute $0 to the total.
    """
    budget: float | None = getattr(sec_config, "token_budget_usd", None) if sec_config else None
    if budget is None:
        return []

    details: list[dict] | None = getattr(sec_config, "connected_llm_details", None) if sec_config else None
    if not details:
        return []

    price_map = {
        d["name"]: (
            float(d["input_cost_per_1k"])  if d.get("input_cost_per_1k")  is not None else 0.0,
            float(d["output_cost_per_1k"]) if d.get("output_cost_per_1k") is not None else 0.0,
        )
        for d in details
    }

    session_cost = 0.0
    undeclared_models: set[str] = set()
    for e in events:
        if e.get("event_type") != "llm_end":
            continue
        model = e.get("llm_model") or ""
        if model not in price_map:
            if model:
                undeclared_models.add(model)
            continue
        in_rate, out_rate = price_map[model]
        session_cost += (e.get("llm_input_tokens")  or 0) / 1000 * in_rate
        session_cost += (e.get("llm_output_tokens") or 0) / 1000 * out_rate

    if session_cost <= budget:
        return []

    detail = f"Session cost ${session_cost:.4f} USD exceeds budget cap ${budget:.4f} USD"
    if undeclared_models:
        detail += f"; cost may be higher — undeclared models excluded: {', '.join(sorted(undeclared_models))}"

    return [_make_finding(
        "OW-LLM10", "UBC-02b",
        "Session token cost > budget cap",
        80, session_id, tenant_id,
        severity="high",
        detail=detail,
    )]


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
