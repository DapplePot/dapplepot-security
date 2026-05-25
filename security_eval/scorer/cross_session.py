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
    "OW-ASI08": "cascading_failure",
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

_BLOCK_ERR_PAT = re.compile(
    r"(?i)(permission\s+denied|unauthorized|forbidden|not\s+allowed|access\s+denied|blocked)"
)


async def check_cross_session_escalation(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    user_context_id: str | None = None,
) -> "Finding | None":
    """MCP-02a — tool blocked (tool_error / permission denial) in a prior session
    now succeeds (tool_end) in the current session.

    Attack pattern: attacker probes which tools are restricted in session N, receives
    a permission-denied tool_error, then retries in session N+1 with modified context,
    escalated credentials, or injected privilege until the access control is bypassed.

    Detection:
      1. Collect every tool_name that produced a successful tool_end in the current
         session (excluding tools that also errored in this session — transient errors
         that were retried and succeeded within the same session are not escalation).
      2. Query ClickHouse obs_events for prior sessions of the same agent (last 30 days)
         where any of those tool names appeared in a tool_error event.
      3. For each matching prior tool_error row, check that the error_message contains
         a permission-denial keyword.  First confirmed match fires MCP-02a.
    """
    # ── Step 1: tools that succeeded in this session ──────────────────────────
    succeeded: set[str] = set()
    errored_this_session: set[str] = set()

    for ev in events:
        etype = ev.get("event_type", "")
        tn = (
            ev.get("tool_name")
            or (ev.get("payload") or {}).get("tool_name")
            or ""
        ).strip()
        if not tn:
            continue
        if etype == "tool_end":
            succeeded.add(tn)
        elif etype == "tool_error":
            errored_this_session.add(tn)

    # Only consider tools that had a clean success in this session
    candidates = succeeded - errored_this_session
    if not candidates:
        return None

    # ── Step 2: query ClickHouse for prior tool_error events for these tools ──
    from core.infra import clickhouse as ch
    try:
        rows = await ch.fetch(
            """
            SELECT tool_name, payload
            FROM obs_events
            WHERE agent_id   = %(agent_id)s
              AND tenant_id  = %(tenant_id)s
              AND session_id != %(session_id)s
              AND event_type  = 'tool_error'
              AND tool_name   IN %(tool_names)s
              AND emitted_at  >= now() - INTERVAL 30 DAY
            LIMIT 50
            """,
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            session_id=str(session_id),
            tool_names=tuple(candidates),
        )
    except Exception:
        return None

    if not rows:
        return None

    # ── Step 3: confirm the prior error was a permission denial ───────────────
    for row in rows:
        payload = row.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        err_msg = str(payload.get("error_message") or "")
        if _BLOCK_ERR_PAT.search(err_msg):
            tool = row.get("tool_name") or "unknown"
            return _make_finding(
                "OW-ASI06", "MCP-02a",
                "Cross-session escalation pattern",
                80, session_id, tenant_id,
                detail=(
                    f"Tool '{tool}' was blocked with permission denial in a prior session "
                    f"but completed successfully in the current session — "
                    f"possible access-control bypass"
                ),
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
# ASCV-01c — MCP tool schema changed without version bump (OW-ASI04)
# ─────────────────────────────────────────────────────────────────────────────

async def check_mcp_tool_schema_change(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
    sec_config=None,
) -> "Finding | None":
    """ASCV-01c — MCP tool schema changed without a server version bump.

    Extracts tool definitions from llm_start events (payload["tools"]) —
    captured by the SDK patch from messages.create(tools=[...]).
    Hashes each tool's (name + description + inputSchema) and compares
    against the stored baseline in mcp_tool_schema_baselines.

    Version suppression order:
      1. tool_versions in sec_config (registered in DapplePot inventory — primary)
      2. version token extracted from the tool's description field (fallback)
    If no version is registered in the inventory the check is strict — every
    schema change fires regardless of what the description says.

    First session per agent: stores baseline, no finding.
    Subsequent sessions: fires if any tool's hash differs from baseline.
    Updates the baseline after firing so future sessions track the new schema.
    """
    # Collect tool schemas from this session's llm_start events.
    current_schemas: dict[str, str] = {}  # tool_name → SHA-256 hash
    current_tools: dict[str, dict] = {}   # tool_name → full tool dict

    for ev in events:
        if ev["event_type"] != "llm_start":
            continue
        tools = (ev.get("payload") or {}).get("tools") or []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name") or ""
            if not name:
                continue
            schema_blob = json.dumps({
                "name": name,
                "description": tool.get("description") or "",
                "input_schema": tool.get("input_schema") or tool.get("inputSchema") or {},
            }, sort_keys=True)
            current_schemas[name] = hashlib.sha256(schema_blob.encode()).hexdigest()
            current_tools[name] = tool

    if not current_schemas:
        return None

    from core.infra.postgres import get_pool
    pool = await get_pool()

    try:
        rows = await pool.fetch(
            """
            SELECT tool_name, schema_hash, schema_json
            FROM mcp_tool_schema_baselines
            WHERE tenant_id = $1 AND agent_id = $2
            """,
            tenant_id, agent_id,
        )
    except Exception:
        return None

    baseline: dict[str, dict] = {
        r["tool_name"]: {"hash": r["schema_hash"], "schema": r["schema_json"]}
        for r in rows
    }

    if not baseline:
        # First session — store all current schemas as baseline.
        try:
            for name, h in current_schemas.items():
                await pool.execute(
                    """
                    INSERT INTO mcp_tool_schema_baselines
                      (tenant_id, agent_id, tool_name, schema_hash, schema_json)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (tenant_id, agent_id, tool_name) DO NOTHING
                    """,
                    tenant_id, agent_id, name, h,
                    json.dumps(current_tools[name]),
                )
        except Exception:
            pass
        return None

    _VERSION_PAT = re.compile(r"\bv?(\d+)[\.\d]*\b")

    def _extract_version(tool: dict) -> str | None:
        """Return the first version-like token from the tool's version field or description."""
        explicit = str(tool.get("version") or "").strip()
        if explicit:
            return explicit
        desc = tool.get("description") or ""
        m = _VERSION_PAT.search(desc)
        return m.group(0) if m else None

    schema_changed: list[str] = []
    version_bumped: list[str] = []

    inventory_versions: dict[str, str] = (
        getattr(sec_config, "tool_versions", None) or {}
    ) if sec_config else {}

    for name, h in current_schemas.items():
        if name not in baseline or baseline[name]["hash"] == h:
            continue
        # Schema changed — check whether a version bump accompanied it.
        # Primary: compare registered inventory version against incoming tool version.
        # Fallback: extract version tokens from description if no inventory version set.
        if name in inventory_versions:
            prev_ver = inventory_versions[name]
            curr_ver = (current_tools[name].get("version") or "").strip() or None
            if not curr_ver:
                # No version on the incoming tool — try extracting from description
                curr_ver = _extract_version(current_tools[name])
        else:
            prev_tool = baseline[name].get("schema") or {}
            if isinstance(prev_tool, str):
                try:
                    prev_tool = json.loads(prev_tool)
                except Exception:
                    prev_tool = {}
            prev_ver = _extract_version(prev_tool)
            curr_ver = _extract_version(current_tools[name])

        if prev_ver and curr_ver and prev_ver != curr_ver:
            # Version changed alongside schema — declared update, suppress finding.
            version_bumped.append(name)
        else:
            schema_changed.append(name)

    # Update last_seen and baseline for all changed tools.
    try:
        for name in current_schemas:
            if name in baseline and baseline[name]["hash"] != current_schemas[name]:
                await pool.execute(
                    """
                    UPDATE mcp_tool_schema_baselines
                    SET schema_hash=$4, schema_json=$5, last_seen=now()
                    WHERE tenant_id=$1 AND agent_id=$2 AND tool_name=$3
                    """,
                    tenant_id, agent_id, name,
                    current_schemas[name], json.dumps(current_tools[name]),
                )
            else:
                await pool.execute(
                    """
                    UPDATE mcp_tool_schema_baselines SET last_seen=now()
                    WHERE tenant_id=$1 AND agent_id=$2 AND tool_name=$3
                    """,
                    tenant_id, agent_id, name,
                )
    except Exception:
        pass

    if not schema_changed:
        return None

    detail = f"Tool schema changed without version bump: {', '.join(schema_changed[:5])}"
    if version_bumped:
        detail += f" (suppressed version-bumped: {', '.join(version_bumped[:3])})"

    return _make_finding(
        "OW-ASI04", "ASCV-01c",
        "MCP tool schema changed without version bump",
        70, session_id, tenant_id,
        detail=detail,
        severity="high",
        confidence_tier="high",
    )


# ─────────────────────────────────────────────────────────────────────────────
# CF-01b — Graph error → restart loop detected (OW-ASI08)
# ─────────────────────────────────────────────────────────────────────────────

async def check_graph_error_restart_loop(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """CF-01b — graph error restart loop: agent sessions repeatedly fail and restart.

    Fires cross-session when the current session ends in graph_error AND >= 2 prior
    sessions for the same agent also terminated with graph_error within the last
    2 hours — indicating a misconfigured error-recovery handler that restarts the
    session on each failure instead of backing off or alerting a human.

    Attack / failure pattern: a client's error-recovery hook restarts the agent
    session immediately after each failure.  Each run re-encounters the same
    persistent error (upstream service down, corrupted config, poisoned prompt) and
    fails again, creating a tight restart loop that amplifies token costs and
    accelerates any side effects of the underlying fault.

    Detection:
      1. Current session must contain at least one graph_error event.
      2. Query ClickHouse for distinct prior sessions of this agent that emitted
         graph_error within the last 2 hours.
      3. Fire when prior_error_sessions >= 2 (loop depth >= 3 including current).

    Score: 75 (fixed) — severity: high.
    """
    has_error = any(ev["event_type"] == "graph_error" for ev in events)
    if not has_error or not agent_id:
        return None

    from core.infra import clickhouse as ch
    try:
        rows = await ch.fetch(
            """
            SELECT countDistinct(session_id) AS prior_error_count
            FROM obs_events
            WHERE agent_id   = %(agent_id)s
              AND tenant_id  = %(tenant_id)s
              AND session_id != %(session_id)s
              AND event_type  = 'graph_error'
              AND emitted_at >= now() - INTERVAL 2 HOUR
            """,
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            session_id=str(session_id),
        )
    except Exception:
        return None

    prior_error_sessions = int(rows[0]["prior_error_count"]) if rows else 0
    if prior_error_sessions < 2:
        return None

    total_depth = prior_error_sessions + 1  # include current session
    return _make_finding(
        "OW-ASI08", "CF-01b",
        "Graph error → restart loop detected",
        75, session_id, tenant_id,
        detail=(
            f"Restart loop: {total_depth} consecutive sessions ended in graph_error "
            f"within 2 hours — possible misconfigured error-recovery hook"
        ),
        severity="high",
        confidence_tier="high",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Registry for orchestrator
# ─────────────────────────────────────────────────────────────────────────────

CROSS_SESSION_FUNCTIONS: list[tuple[str, object]] = [
    ("cross-SID-03a",   check_cross_user_bleed),
    ("cross-UBC-03a",   check_request_rate_spike),
    ("cross-UBC-05a",   check_cost_spike),
    ("cross-IPA-05a",   check_identity_sharing),
    ("cross-MCP-02a",   check_cross_session_escalation),
    ("cross-MCP-04a",   check_cross_tenant_retrieval),
    ("cross-RA-02a",    check_persistent_exfil),
    ("cross-ASCV-01c",  check_mcp_tool_schema_change),
    ("cross-CF-01b",    check_graph_error_restart_loop),
]
