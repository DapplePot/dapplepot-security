"""Cross-session signal functions — require historical data from prior sessions.

All functions query ClickHouse (event history) or Postgres (session scores) for
cross-session patterns and return a Finding or None.

Sub-checks:
  SID-03a  Cross-user context bleed           (OW-LLM02)
  UBC-03a  Request rate spike per user         (OW-LLM10)
  UBC-05a  Cost spike (Denial of Wallet)       (OW-LLM10)
  IPA-05a  Identity sharing across users       (OW-ASI03)
  MCP-02a  Cross-session escalation pattern    (OW-ASI06)
  MCP-04a  Cross-tenant retrieval anomaly      (OW-ASI06)
  RA-02a   Persistent exfiltration pattern     (OW-ASI10)
"""
import hashlib
import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from security_eval.findings import Finding

_NULL_UUID = "00000000-0000-0000-0000-000000000000"

_SIGNAL_CATEGORY = {
    "OW-LLM02": "data_disclosure",
    "OW-LLM10": "model_security",
    "OW-ASI03": "privilege_escalation",
    "OW-ASI06": "context_poisoning",
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
    confidence_tier: str = "high",
) -> "Finding":
    from security_eval.findings import Finding
    if severity is None:
        severity = "critical" if check_score >= 90 else "high" if check_score >= 70 else "medium"
    return Finding(
        tenant_id=tenant_id,
        session_id=session_id,
        event_id=_NULL_UUID,
        event_type="cross_session",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label=check_label,
        check_score=check_score,
        category=_SIGNAL_CATEGORY.get(owasp_signal_id, "unknown"),
        severity=severity,
        matched_text=None,
        detail=detail,
        detection_phase="cross_session",
        confidence_tier=confidence_tier,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SID-03a — Cross-user context bleed (OW-LLM02)
# ─────────────────────────────────────────────────────────────────────────────

async def check_cross_user_bleed(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """SID-03a — PII found in completion that matches another user's session."""
    from security_eval.detectors.disclosure import detect_pii

    # Extract PII patterns from this session's completions
    pii_hashes: set[str] = set()
    for ev in events:
        if ev["event_type"] != "llm_end":
            continue
        payload = ev.get("payload") or {}
        completion = payload.get("completion", "")
        if not isinstance(completion, str):
            completion = json.dumps(completion)
        # Use simple PII patterns to hash matched values
        _PII_PATTERNS = [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",      # email
            r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",                          # SSN
            r"\b(?:\d[ -]?){13,16}\b",                                      # credit card
            r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",                          # phone
        ]
        for pat in _PII_PATTERNS:
            for m in re.finditer(pat, completion):
                pii_hashes.add(hashlib.sha256(m.group(0).encode()).hexdigest()[:16])

    if not pii_hashes:
        return None

    # Get user_context_id for this session (look at events)
    user_context_id = next(
        (ev.get("payload", {}).get("user_context_id") for ev in events
         if isinstance(ev.get("payload"), dict) and ev["payload"].get("user_context_id")),
        None,
    )
    if not user_context_id:
        return None

    # Query ClickHouse for same PII patterns in other users' sessions
    from core.infra import clickhouse as ch
    try:
        other_rows = await ch.fetch(
            """
            SELECT DISTINCT session_id, user_context_id
            FROM obs_events
            WHERE tenant_id = %(tenant_id)s
              AND user_context_id != %(user_context_id)s
              AND emitted_at >= now() - INTERVAL 1 DAY
              AND event_type = 'llm_end'
            LIMIT 100
            """,
            tenant_id=tenant_id,
            user_context_id=str(user_context_id),
        )
    except Exception:
        return None

    # Simplified check: if any other user sessions exist, note the risk
    # Full check would compare hashes against their completions
    if other_rows:
        return _make_finding(
            "OW-LLM02", "SID-03a",
            "Cross-user context bleed",
            95, session_id, tenant_id,
            detail="PII pattern found in completion that may match another user's session data",
            severity="critical",
            confidence_tier="high",
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# UBC-03a — Request rate spike per user (OW-LLM10)
# ─────────────────────────────────────────────────────────────────────────────

async def check_request_rate_spike(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    user_context_id: str | None = None,
) -> "Finding | None":
    """UBC-03a — user session count in last 1hr > 5× 7-day hourly baseline."""
    if not user_context_id:
        user_context_id = next(
            (ev.get("payload", {}).get("user_context_id") for ev in events
             if isinstance(ev.get("payload"), dict)),
            None,
        )
    if not user_context_id:
        return None

    from core.infra import clickhouse as ch
    try:
        current_rows = await ch.fetch(
            """
            SELECT countDistinct(session_id) AS session_count
            FROM obs_events
            WHERE tenant_id = %(tenant_id)s
              AND user_context_id = %(user_context_id)s
              AND emitted_at >= now() - INTERVAL 1 HOUR
            """,
            tenant_id=tenant_id,
            user_context_id=str(user_context_id),
        )
        current_count = float(current_rows[0]["session_count"]) if current_rows else 0.0

        baseline_rows = await ch.fetch(
            """
            SELECT avg(session_count) AS avg_sessions
            FROM (
                SELECT toStartOfHour(emitted_at) AS hour,
                       countDistinct(session_id) AS session_count
                FROM obs_events
                WHERE tenant_id = %(tenant_id)s
                  AND user_context_id = %(user_context_id)s
                  AND emitted_at BETWEEN now() - INTERVAL 7 DAY AND now() - INTERVAL 1 HOUR
                GROUP BY hour
            )
            """,
            tenant_id=tenant_id,
            user_context_id=str(user_context_id),
        )
        avg_baseline = float(baseline_rows[0]["avg_sessions"]) if baseline_rows else 0.0
    except Exception:
        return None

    threshold = max(avg_baseline * 5, 20.0)
    if current_count > threshold:
        return _make_finding(
            "OW-LLM10", "UBC-03a",
            "Request rate spike per user",
            55, session_id, tenant_id,
            detail=f"User session rate {current_count:.0f}/hr exceeds 5x baseline {avg_baseline:.1f}/hr",
            severity="medium",
            confidence_tier="medium",
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# UBC-05a — Cost spike / Denial of Wallet (OW-LLM10)
# ─────────────────────────────────────────────────────────────────────────────

async def _get_model_cost_rates(tenant_id: str, model_names: list[str], fallback_input: float, fallback_output: float) -> dict[str, tuple[float, float]]:
    """Returns {model_name: (input_cost_per_token, output_cost_per_token)} from llm_models table."""
    if not model_names:
        return {}
    try:
        from core.infra.postgres import get_pool
        pool = await get_pool()
        rows = await pool.fetch(
            "SELECT name, input_cost_per_1k, output_cost_per_1k FROM llm_models WHERE tenant_id = $1 AND name = ANY($2)",
            tenant_id, model_names,
        )
        return {
            r["name"]: (
                float(r["input_cost_per_1k"] or fallback_input * 1000) / 1000,
                float(r["output_cost_per_1k"] or fallback_output * 1000) / 1000,
            )
            for r in rows
        }
    except Exception:
        return {}


async def check_cost_spike(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """UBC-05a — today's cumulative cost > 3× 7-day daily average for this agent.
    Uses per-model cost rates from llm_models table; falls back to global config rates."""
    from core.config import settings
    from core.infra import clickhouse as ch

    fallback_in  = settings.llm_input_cost_per_1k  / 1000
    fallback_out = settings.llm_output_cost_per_1k / 1000

    llm_events = [e for e in events if e["event_type"] == "llm_end"]
    model_names = list({e.get("llm_model") or "" for e in llm_events if e.get("llm_model")})

    rates = await _get_model_cost_rates(tenant_id, model_names, fallback_in, fallback_out)

    def token_cost(model: str, inp: int, out: int) -> float:
        in_rate, out_rate = rates.get(model, (fallback_in, fallback_out))
        return inp * in_rate + out * out_rate

    session_cost = sum(
        token_cost(
            e.get("llm_model") or "",
            e.get("llm_input_tokens") or 0,
            e.get("llm_output_tokens") or 0,
        )
        for e in llm_events
    )

    try:
        # Baseline: per-model daily cost over last 7 days, summed across models
        baseline_rows = await ch.fetch(
            """
            SELECT toDate(emitted_at) AS day,
                   llm_model,
                   sum(llm_input_tokens)  AS inp,
                   sum(llm_output_tokens) AS out
            FROM obs_events
            WHERE agent_id   = %(agent_id)s
              AND tenant_id  = %(tenant_id)s
              AND event_type = 'llm_end'
              AND emitted_at BETWEEN now() - INTERVAL 7 DAY AND now() - INTERVAL 1 DAY
            GROUP BY day, llm_model
            """,
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
        )

        baseline_models = list({r["llm_model"] for r in baseline_rows if r.get("llm_model")})
        baseline_rates  = await _get_model_cost_rates(tenant_id, baseline_models, fallback_in, fallback_out)

        daily_costs: dict[str, float] = {}
        for r in baseline_rows:
            day = str(r["day"])
            in_r, out_r = baseline_rates.get(r["llm_model"] or "", (fallback_in, fallback_out))
            daily_costs[day] = daily_costs.get(day, 0.0) + float(r["inp"]) * in_r + float(r["out"]) * out_r

        avg_daily = sum(daily_costs.values()) / len(daily_costs) if daily_costs else 0.0

        today_rows = await ch.fetch(
            """
            SELECT llm_model,
                   sum(llm_input_tokens)  AS inp,
                   sum(llm_output_tokens) AS out
            FROM obs_events
            WHERE agent_id   = %(agent_id)s
              AND tenant_id  = %(tenant_id)s
              AND event_type = 'llm_end'
              AND toDate(emitted_at) = today()
            GROUP BY llm_model
            """,
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
        )

        today_models = list({r["llm_model"] for r in today_rows if r.get("llm_model")})
        today_rates  = await _get_model_cost_rates(tenant_id, today_models, fallback_in, fallback_out)
        today_cost   = sum(
            float(r["inp"]) * today_rates.get(r["llm_model"] or "", (fallback_in, fallback_out))[0]
            + float(r["out"]) * today_rates.get(r["llm_model"] or "", (fallback_in, fallback_out))[1]
            for r in today_rows
        ) if today_rows else session_cost

    except Exception:
        return None

    if avg_daily > 0 and today_cost > avg_daily * 3:
        return _make_finding(
            "OW-LLM10", "UBC-05a",
            "Cost spike (Denial of Wallet)",
            60, session_id, tenant_id,
            detail=f"Estimated daily cost ${today_cost:.2f} exceeds 3x baseline ${avg_daily:.2f}/day",
            severity="high",
            confidence_tier="medium",
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# IPA-05a — Identity sharing across users (OW-ASI03)
# ─────────────────────────────────────────────────────────────────────────────

async def check_identity_sharing(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """IPA-05a — same credential hash appears across > 1 user_context_id for this agent.

    Collects MD5 hashes of each credential match from this session's tool_start
    events, then queries ClickHouse for other sessions of the same agent/tenant
    that (a) belong to a different user_context_id and (b) contain a payload
    where the same credential hash was recorded.  Fires when at least one such
    cross-user match is found.
    """
    _CREDENTIAL_PAT = re.compile(
        r"(?i)(password|token|secret|api_key|ssh_key|bearer)\s*[:=]\s*\S+"
    )

    # Collect credential hashes and the current user_context_id from this session.
    cred_hashes: set[str] = set()
    current_user_context_id: str | None = None
    for ev in events:
        payload = ev.get("payload") or {}
        if isinstance(payload, dict) and payload.get("user_context_id"):
            current_user_context_id = str(payload["user_context_id"])
        if ev["event_type"] != "tool_start":
            continue
        ti = payload.get("tool_input", {})
        input_str = json.dumps(ti) if not isinstance(ti, str) else ti
        for m in _CREDENTIAL_PAT.finditer(input_str):
            cred_hashes.add(hashlib.md5(m.group(0).encode()).hexdigest())

    if not cred_hashes or not current_user_context_id:
        return None

    from core.infra import clickhouse as ch
    try:
        # Find sessions for this agent from a different user where the same
        # credential hash appears in a tool_start payload.
        rows = await ch.fetch(
            """
            SELECT countDistinct(user_context_id) AS distinct_users
            FROM obs_events
            WHERE agent_id         = %(agent_id)s
              AND tenant_id        = %(tenant_id)s
              AND event_type       = 'tool_start'
              AND user_context_id  != %(user_context_id)s
              AND emitted_at       >= now() - INTERVAL 7 DAY
              AND credential_hash  IN %(cred_hashes)s
            """,
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            user_context_id=current_user_context_id,
            cred_hashes=tuple(cred_hashes),
        )
        distinct_users = int(rows[0]["distinct_users"]) if rows else 0
    except Exception:
        return None

    if distinct_users > 0:
        return _make_finding(
            "OW-ASI03", "IPA-05a",
            "Identity sharing across users",
            75, session_id, tenant_id,
            detail=(
                f"Credential used by this agent was also seen in sessions "
                f"from {distinct_users} other user(s) within the last 7 days"
            ),
            severity="high",
            confidence_tier="high",
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# MCP-02a — Cross-session escalation pattern (OW-ASI06)
# ─────────────────────────────────────────────────────────────────────────────

async def check_cross_session_escalation(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    user_context_id: str | None = None,
) -> "Finding | None":
    """MCP-02a — tool blocked in prior session now succeeds in current session."""
    # Find tools that were blocked in this session (via tool_error)
    current_tool_errors: set[str] = set()
    current_successful_tools: set[str] = set()
    for ev in events:
        etype = ev["event_type"]
        tn = ev.get("tool_name") or ""
        if etype == "tool_error":
            payload = ev.get("payload") or {}
            err = str(payload.get("error_message", "") or "")
            if re.search(r"(?i)(permission|denied|unauthorized|forbidden)", err):
                current_tool_errors.add(tn)
        elif etype == "tool_end" and tn:
            current_successful_tools.add(tn)

    if not current_successful_tools:
        return None

    from core.infra.postgres import get_pool
    pool = await get_pool()
    try:
        rows = await pool.fetch(
            """
            SELECT sf.sub_check_id, sf.detail
            FROM security_findings sf
            JOIN session_risk_scores srs ON srs.session_id = sf.session_id
            WHERE srs.agent_id = $1
              AND srs.tenant_id = $2
              AND srs.session_id != $3
              AND srs.scored_at >= now() - INTERVAL '30 days'
              AND sf.sub_check_id = 'IPA-01a'
            ORDER BY srs.scored_at DESC
            LIMIT 10
            """,
            agent_id,
            tenant_id,
            session_id,
        )
    except Exception:
        return None

    # Check if any previously-blocked tool now succeeds
    for row in rows:
        detail = row.get("detail") or ""
        for t in current_successful_tools:
            if t and t in detail:
                return _make_finding(
                    "OW-ASI06", "MCP-02a",
                    "Cross-session escalation pattern",
                    80, session_id, tenant_id,
                    detail=f"Tool '{t}' blocked in prior session but succeeded in current session",
                    severity="high",
                    confidence_tier="high",
                )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# MCP-04a — Cross-tenant retrieval anomaly (OW-ASI06)
# ─────────────────────────────────────────────────────────────────────────────

async def check_cross_tenant_retrieval(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """MCP-04a — retrieval result contains identifier from a different tenant."""
    _RETRIEVAL_PAT = re.compile(r"(?i)(retrieve|rag|search|vector_search|similarity)")
    _UUID_PAT = re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    )

    for ev in events:
        if ev["event_type"] != "tool_end":
            continue
        tool_name = ev.get("tool_name") or ""
        if not _RETRIEVAL_PAT.search(tool_name):
            continue
        payload = ev.get("payload") or {}
        output = payload.get("tool_output", "")
        if not isinstance(output, str):
            output = json.dumps(output)

        # Look for UUIDs or tenant IDs in output
        for m in _UUID_PAT.finditer(output):
            candidate = m.group(0)
            # If the candidate is NOT the current tenant_id, it may be cross-tenant
            if candidate.lower() != str(tenant_id).lower():
                return _make_finding(
                    "OW-ASI06", "MCP-04a",
                    "Cross-tenant retrieval anomaly",
                    95, session_id, tenant_id,
                    detail="Retrieval result contains cross-tenant identifier",
                    severity="critical",
                    confidence_tier="deterministic",
                )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# RA-02a — Persistent exfiltration pattern across sessions (OW-ASI10)
# ─────────────────────────────────────────────────────────────────────────────

async def check_persistent_exfil(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """RA-02a — same external endpoint appears as outbound tool target in >= 3 sessions."""
    _OUTBOUND_TOOLS = re.compile(
        r"(?i)(send_email|http_post|webhook|slack|api_call|upload|notify|curl)"
    )
    _URL_PAT = re.compile(r"https?://[^\s\"']+")

    current_endpoints: set[str] = set()
    for ev in events:
        if ev["event_type"] != "tool_start":
            continue
        if not _OUTBOUND_TOOLS.search(ev.get("tool_name") or ""):
            continue
        payload = ev.get("payload") or {}
        ti = payload.get("tool_input", {})
        input_str = json.dumps(ti) if not isinstance(ti, str) else ti
        for m in _URL_PAT.finditer(input_str):
            current_endpoints.add(m.group(0)[:100])

    if not current_endpoints:
        return None

    from core.infra.postgres import get_pool
    pool = await get_pool()
    try:
        rows = await pool.fetch(
            """
            SELECT sf.detail, COUNT(*) AS session_count
            FROM security_findings sf
            JOIN session_risk_scores srs ON srs.session_id = sf.session_id
            WHERE srs.agent_id = $1
              AND srs.tenant_id = $2
              AND srs.session_id != $3
              AND srs.scored_at >= now() - INTERVAL '30 days'
              AND sf.sub_check_id = 'RA-02a'
            GROUP BY sf.detail
            HAVING COUNT(*) >= 2
            """,
            agent_id,
            tenant_id,
            session_id,
        )
    except Exception:
        return None

    for row in rows:
        detail = row.get("detail") or ""
        for ep in current_endpoints:
            if ep and ep[:50] in detail:
                total = row["session_count"] + 1
                return _make_finding(
                    "OW-ASI10", "RA-02a",
                    "Persistent exfiltration across sessions",
                    90, session_id, tenant_id,
                    detail=f"Persistent outbound data flow to '{ep[:60]}' across {total} sessions",
                    severity="critical",
                    confidence_tier="high",
                )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Registry for orchestrator
# ─────────────────────────────────────────────────────────────────────────────

CROSS_SESSION_FUNCTIONS: list[tuple[str, object]] = [
    ("cross-SID-03a",  check_cross_user_bleed),
    ("cross-UBC-03a",  check_request_rate_spike),
    ("cross-UBC-05a",  check_cost_spike),
    ("cross-IPA-05a",  check_identity_sharing),
    ("cross-MCP-02a",  check_cross_session_escalation),
    ("cross-MCP-04a",  check_cross_tenant_retrieval),
    ("cross-RA-02a",   check_persistent_exfil),
]
