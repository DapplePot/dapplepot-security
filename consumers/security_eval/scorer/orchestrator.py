"""Post-session scorer orchestrator — triggered on graph_end / graph_error.

v2 scoring model (§4.1):
  - Parent signal score = max(check_score) of its fired sub-checks.
  - Composite score = weighted avg: highest-score signal × 0.6 + rest × 0.4.
  - Alert fires when any individual signal score >= SIGNAL_ALERT_THRESHOLDS[signal]
    OR composite score >= COMPOSITE_ALERT_THRESHOLD.
"""
import json
from core.config import settings, SIGNAL_ALERT_THRESHOLDS, COMPOSITE_ALERT_THRESHOLD
from consumers.security_eval.scorer.llm_signals import (
    SIGNAL_ID_FUNCTIONS,
    SIGNAL_DESCRIPTION,
    check_multi_turn_jailbreak,
    check_rag_integrity,
    check_system_prompt_leakage,
    check_vector_integrity,
)
from consumers.security_eval.scorer.asi_signals import (
    AGENT_SIGNAL_ID_FUNCTIONS,
    AGENT_SIGNAL_DESCRIPTION,
    AGENT_SIGNAL_OWASP,
)

SCORER_VERSION = settings.scorer_version

# Overlap groups for dedup_key resolution
OVERLAP_GROUPS: dict[str, set[str]] = {
    "injection":        {"OW-LLM01", "OW-ASI01", "OW-ASI06"},
    "output_exec":      {"OW-LLM05", "OW-ASI05", "OW-ASI02"},
    "supply_chain":     {"OW-LLM03", "OW-ASI04"},
    "memory_vector":    {"OW-LLM08", "OW-ASI06"},
    "excessive_agency": {"OW-LLM06", "OW-ASI02", "OW-ASI10"},
    "pii_privilege":    {"OW-LLM02", "OW-ASI03"},
}


def resolve_overlap_group(fired_signal_ids: set[str]) -> str | None:
    """Return overlap group name if >= 2 signals from the same group fired."""
    for group_name, group_signals in OVERLAP_GROUPS.items():
        if len(fired_signal_ids & group_signals) >= 2:
            return group_name
    return None


def _band(score: int) -> str:
    if score < 20:
        return "clean"
    if score < 40:
        return "low"
    if score < 65:
        return "medium"
    if score < 85:
        return "high"
    return "critical"


def compute_ow_signal_score(fired_findings: list) -> dict[str, dict]:
    """
    Group findings by owasp_signal_id and compute per-signal score as the
    max check_score of all fired sub-checks.

    Returns:
    {
      "OW-LLM01": {
        "score": 92, "status": "fired",
        "sub_checks": {"PI-04b": {"status": "fired", "score": 92, "detail": "..."}}
      }, ...
    }
    """
    signal_map: dict[str, dict] = {}
    for f in fired_findings:
        sig = f.owasp_signal_id
        chk = f.sub_check_id
        score = f.check_score
        if sig not in signal_map:
            signal_map[sig] = {"score": 0, "status": "fired", "sub_checks": {}}
        signal_map[sig]["sub_checks"][chk] = {
            "status": "fired",
            "score": score,
            "label": f.check_label,
            "detail": f.detail or "",
        }
        signal_map[sig]["score"] = max(signal_map[sig]["score"], score)
    return signal_map


def compute_composite_score(signal_map: dict, framework: str) -> int:
    """
    Weighted composite 0–100 across all OW-{framework} signals that fired.
    Formula: highest-score signal × 60% + mean of rest × 40%.
    """
    prefix = f"OW-{framework}"
    fired = sorted(
        [signal_map[s]["score"] for s in signal_map
         if s.startswith(prefix) and signal_map[s]["status"] == "fired"],
        reverse=True,
    )
    if not fired:
        return 0
    if len(fired) == 1:
        return fired[0]
    primary   = fired[0] * 0.6
    secondary = (sum(fired[1:]) / len(fired[1:])) * 0.4
    return min(100, int(primary + secondary))


async def score_session(
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list,
) -> dict:
    """
    1. Fetch full event list for session from ClickHouse.
    2. Fetch session row from Postgres.
    3. Run all OW-LLM signal functions + sub-check helpers.
    4. Run all OW-ASI signal functions.
    5. Compute per-signal scores (max sub-check model) and composites.
    6. Write security_findings rows for post-session findings.
    7. Write session_risk_scores.
    8. Upsert agent_risk_scores.
    9. Alert if any signal >= its threshold OR composite >= COMPOSITE_ALERT_THRESHOLD.
    """
    from core.infra import clickhouse as ch
    from core.infra.postgres import get_pool

    events = await ch.fetch(
        """
        SELECT event_type, event_id, emitted_at, sequence_index,
               node_run_id, node_name, tool_name, llm_model,
               llm_input_tokens, llm_output_tokens, payload
        FROM obs_events
        WHERE tenant_id  = %(tenant_id)s
          AND session_id = %(session_id)s
        ORDER BY sequence_index ASC
        """,
        tenant_id=tenant_id,
        session_id=session_id,
    )

    pool = await get_pool()
    session_row = await pool.fetchrow(
        """
        SELECT initial_input, graph_state, graph_runs, duration_ms
        FROM sessions WHERE session_id = $1
        """,
        session_id,
    )
    session = dict(session_row) if session_row else {}

    # ─── OW-LLM01 through OW-LLM10 ───────────────────────────────────────────
    all_findings = list(online_findings)

    for signal_key, signal_fn in SIGNAL_ID_FUNCTIONS:
        finding = await signal_fn(
            events=events,
            session=session,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
            online_findings=online_findings,
        )
        if finding:
            all_findings.append(finding)

    # Additional sub-check helpers (return lists)
    all_findings.extend(check_multi_turn_jailbreak(events, session_id, tenant_id))
    all_findings.extend(check_rag_integrity(events, session_id, tenant_id, baseline={}))
    all_findings.extend(check_system_prompt_leakage(events, session_id, tenant_id))
    all_findings.extend(check_vector_integrity(events, session_id, tenant_id))

    # ─── OW-ASI01 through OW-ASI10 ───────────────────────────────────────────
    agent_findings: list = []

    for signal_key, signal_fn in AGENT_SIGNAL_ID_FUNCTIONS:
        finding = await signal_fn(
            events=events,
            session=session,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
            online_findings=online_findings,
        )
        if finding:
            agent_findings.append(finding)

    # ─── v2 scoring model ─────────────────────────────────────────────────────
    all_session_findings = all_findings + agent_findings

    llm_signal_map = compute_ow_signal_score(
        [f for f in all_session_findings if f.framework == "LLM"]
    )
    asi_signal_map = compute_ow_signal_score(
        [f for f in all_session_findings if f.framework == "ASI"]
    )

    llm_score = compute_composite_score(llm_signal_map, "LLM")
    asi_score  = compute_composite_score(asi_signal_map, "ASI")
    llm_band   = _band(llm_score)
    asi_band   = _band(asi_score)

    # ─── Persist post-session findings ───────────────────────────────────────
    from consumers.security_eval.findings import write_findings, write_agent_risk_score
    post_session_findings = [
        f for f in all_session_findings
        if f.detection_phase == "post_session"
    ]
    if post_session_findings:
        await write_findings(post_session_findings)

    # ─── Write session risk score ──────────────────────────────────────────────
    await pool.execute(
        """
        INSERT INTO session_risk_scores
            (session_id, tenant_id, agent_id,
             llm_score, llm_band, asi_score, asi_band,
             llm_signal_status, asi_signal_status,
             scorer_version, scored_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, now())
        ON CONFLICT (session_id) DO UPDATE SET
            llm_score          = EXCLUDED.llm_score,
            llm_band           = EXCLUDED.llm_band,
            asi_score          = EXCLUDED.asi_score,
            asi_band           = EXCLUDED.asi_band,
            llm_signal_status  = EXCLUDED.llm_signal_status,
            asi_signal_status  = EXCLUDED.asi_signal_status,
            scorer_version     = EXCLUDED.scorer_version,
            scored_at          = now()
        """,
        session_id,
        tenant_id,
        agent_id,
        llm_score,
        llm_band,
        asi_score,
        asi_band,
        json.dumps(llm_signal_map),
        json.dumps(asi_signal_map),
        SCORER_VERSION,
    )

    # ─── Upsert per-agent rolling aggregate ───────────────────────────────────
    if agent_id:
        await write_agent_risk_score(agent_id, tenant_id, llm_score, asi_score)

    score_row = {
        "session_id":         session_id,
        "tenant_id":          tenant_id,
        "agent_id":           agent_id,
        "llm_score":          llm_score,
        "llm_band":           llm_band,
        "asi_score":          asi_score,
        "asi_band":           asi_band,
        "llm_signal_status":  llm_signal_map,
        "asi_signal_status":  asi_signal_map,
        "scorer_version":     SCORER_VERSION,
    }

    # ─── Alert logic ──────────────────────────────────────────────────────────
    fired_llm_sigs = {s for s, d in llm_signal_map.items() if d["status"] == "fired"}
    fired_asi_sigs = {s for s, d in asi_signal_map.items() if d["status"] == "fired"}
    overlap_group  = resolve_overlap_group(fired_llm_sigs | fired_asi_sigs)
    score_row["dedup_key"] = (
        f"security:{session_id}:{overlap_group}"
        if overlap_group
        else f"security:{session_id}"
    )

    should_alert = llm_score >= COMPOSITE_ALERT_THRESHOLD or asi_score >= COMPOSITE_ALERT_THRESHOLD

    if not should_alert:
        for sig_id, sig_data in llm_signal_map.items():
            if sig_data["status"] == "fired":
                if sig_data["score"] >= SIGNAL_ALERT_THRESHOLDS.get(sig_id, 80):
                    should_alert = True
                    break

    if not should_alert:
        for sig_id, sig_data in asi_signal_map.items():
            if sig_data["status"] == "fired":
                if sig_data["score"] >= SIGNAL_ALERT_THRESHOLDS.get(sig_id, 80):
                    should_alert = True
                    break

    if should_alert:
        from consumers.security_eval.findings import produce_security_alert
        await produce_security_alert(score_row, all_session_findings)

    return score_row
