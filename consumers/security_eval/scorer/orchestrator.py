"""Post-session scorer orchestrator — triggered on graph_end / graph_error."""
import json
from core.config import settings
from core.infra import clickhouse as ch
from core.infra.postgres import get_pool
from consumers.security_eval.scorer.signals import (
    signal_s01,
    signal_s02,
    signal_s03,
    signal_s04,
    SIGNAL_FUNCTIONS,
)

SCORER_VERSION = settings.scorer_version


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


async def score_session(
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list,
) -> dict:
    """
    1. Fetch full event list for session from ClickHouse.
    2. Fetch session row from Postgres.
    3. Compute S-01–S-04 from online_findings, then S-05–S-10 from events.
    4. Sum signal points (capped per signal, total capped at 100).
    5. Write security_findings rows for post-session findings.
    6. Write session_risk_scores row.
    7. If score >= ALERT_ON_SCORE_GTE: produce to obs.alerts.v1.
    """
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
    session = await pool.fetchrow(
        """
        SELECT initial_input, graph_state, graph_runs, duration_ms
        FROM sessions WHERE session_id = $1
        """,
        session_id,
    )
    session = dict(session) if session else {}

    # S-01 through S-04 — derived from online_findings
    all_findings = list(online_findings)
    total_points = 0

    for signal_fn in (signal_s01, signal_s02, signal_s03, signal_s04):
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
            total_points = min(total_points + finding.score_contrib, 100)

    # S-05 through S-10 — require full event history
    for signal_fn in SIGNAL_FUNCTIONS:
        finding = await signal_fn(
            events=events,
            session=session,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
        )
        if finding:
            all_findings.append(finding)
            total_points = min(total_points + finding.score_contrib, 100)

    risk_score = min(total_points, 100)
    risk_band = _band(risk_score)

    # Write post-session findings (online findings already written during session)
    from consumers.security_eval.findings import write_findings
    post_session_findings = [f for f in all_findings if f.detection_phase == "post_session"]
    if post_session_findings:
        await write_findings(post_session_findings)

    # Write / upsert risk score
    await pool.execute(
        """
        INSERT INTO session_risk_scores
            (session_id, tenant_id, agent_id, risk_score, risk_band,
             signal_count, signal_ids, scorer_version, scored_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        ON CONFLICT (session_id) DO UPDATE SET
            risk_score     = EXCLUDED.risk_score,
            risk_band      = EXCLUDED.risk_band,
            signal_count   = EXCLUDED.signal_count,
            signal_ids     = EXCLUDED.signal_ids,
            scorer_version = EXCLUDED.scorer_version,
            scored_at      = now()
        """,
        session_id,
        tenant_id,
        agent_id,
        risk_score,
        risk_band,
        len(all_findings),
        [f.signal_id for f in all_findings],
        SCORER_VERSION,
    )

    score_row = {
        "session_id": session_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "signal_count": len(all_findings),
        "signal_ids": [f.signal_id for f in all_findings],
        "scorer_version": SCORER_VERSION,
    }

    if risk_score >= settings.alert_on_score_gte:
        from consumers.security_eval.findings import produce_security_alert
        await produce_security_alert(score_row, all_findings)

    return score_row
