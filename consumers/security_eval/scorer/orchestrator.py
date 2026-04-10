"""Post-session scorer orchestrator — triggered on graph_end / graph_error.

All detection (per-event and session-level) runs here after the full event
history is available from ClickHouse.

v3 scoring model:
  - Per-signal score = confidence-weighted max(check_score × confidence_weight).
  - Composite = highest-score signal × 60% + mean of rest × 40%.
  - Attack chain amplification: if multiple signals match a known attack chain,
    composite is multiplied by the chain's amplification factor (capped at 100).
  - Cross-session Bayesian agent trust: updated each session with temporal decay.
  - v2 columns still written for backward compatibility.
  - New v3_llm_composite / v3_asi_composite JSONB columns carry full v3 detail.
"""
import asyncio
import inspect as _inspect
import logging
import json

logger = logging.getLogger(__name__)
from core.config import (
    settings,
    SIGNAL_ALERT_THRESHOLDS,
    COMPOSITE_ALERT_THRESHOLD,
    SIGNAL_ALERT_THRESHOLDS_V3,
    COMPOSITE_ALERT_THRESHOLD_V3,
    CONFIDENCE_WEIGHTS,
    RISK_BANDS_V3,
    OVERLAP_GROUPS_V3,
    AGENT_TRUST_ALERT_THRESHOLD,
    AGENT_TRUST_CONSECUTIVE_SESSIONS,
)
from consumers.security_eval.scorer.llm_signals import (
    SIGNAL_ID_FUNCTIONS,
    SIGNAL_DESCRIPTION,
    check_multi_turn_jailbreak,
    check_rag_integrity,
    check_system_prompt_leakage,
    check_vector_integrity,
    check_payload_splitting,
    check_insecure_code_output,
    check_hallucinated_packages,
    check_ungrounded_high_stakes,
    check_input_size_anomaly,
)
from consumers.security_eval.scorer.asi_signals import (
    AGENT_SIGNAL_ID_FUNCTIONS,
    AGENT_SIGNAL_DESCRIPTION,
    AGENT_SIGNAL_OWASP,
)

SCORER_VERSION = settings.scorer_version


def resolve_overlap_group(fired_signal_ids: set[str]) -> str | None:
    """Return overlap group name if >= 2 signals from the same group fired."""
    for group_name, group_signals in OVERLAP_GROUPS_V3.items():
        if len(fired_signal_ids & group_signals) >= 2:
            return group_name
    return None


def _band(score: int) -> str:
    """v3 risk band (narrowed from v2)."""
    for band_name, (lo, hi) in RISK_BANDS_V3.items():
        if lo <= score <= hi:
            return band_name
    return "critical"


def compute_ow_signal_score(fired_findings: list) -> dict[str, dict]:
    """
    Group findings by owasp_signal_id and compute v3 per-signal scores.

    Returns per-signal dict with:
      raw_score, confidence_score, effective_score, confidence, status, sub_checks
    """
    signal_map: dict[str, dict] = {}
    for f in fired_findings:
        sig = f.owasp_signal_id
        chk = f.sub_check_id
        score = f.check_score
        conf = f.confidence
        tier = f.confidence_tier

        if sig not in signal_map:
            signal_map[sig] = {
                "raw_score": 0,
                "confidence_score": 0.0,
                "effective_score": 0,
                "confidence": 0.0,
                "score": 0,            # backward compat alias = raw_score
                "status": "fired",
                "sub_checks": {},
            }

        eff = score * conf
        if eff > signal_map[sig]["confidence_score"]:
            signal_map[sig]["confidence_score"] = eff
            signal_map[sig]["effective_score"] = round(eff)
            signal_map[sig]["confidence"] = conf

        signal_map[sig]["raw_score"] = max(signal_map[sig]["raw_score"], score)
        signal_map[sig]["score"] = signal_map[sig]["raw_score"]  # backward compat

        signal_map[sig]["sub_checks"][chk] = {
            "status": "fired",
            "score": score,
            "check_score": score,
            "confidence_tier": tier,
            "confidence": conf,
            "effective_score": round(eff),
            "check_label": f.check_label,
            "detail": f.detail or "",
            "event_id": str(f.event_id),
        }
    return signal_map


def compute_composite_score(signal_map: dict, framework: str) -> int:
    """
    v3 composite with confidence-weighted effective scores + attack chain amplification.

    Returns int 0-100.
    """
    from consumers.security_eval.scorer.attack_chains import detect_attack_chains

    prefix = f"OW-{framework}"
    fired = sorted(
        [
            (s, signal_map[s]["effective_score"], signal_map[s]["confidence"])
            for s in signal_map
            if s.startswith(prefix) and signal_map[s]["status"] == "fired"
        ],
        key=lambda x: x[1],
        reverse=True,
    )
    if not fired:
        return 0

    scores = [f[1] for f in fired]
    if len(scores) == 1:
        raw = scores[0]
    else:
        raw = scores[0] * 0.6 + (sum(scores[1:]) / len(scores[1:])) * 0.4

    # Attack chain amplification across all fired signals (both frameworks)
    all_fired = {f[0] for f in fired}
    _, amplification = detect_attack_chains(all_fired)

    return min(100, int(raw * amplification))


def compute_composite_score_v3(
    signal_map: dict,
    framework: str,
    all_fired_signal_ids: set[str],
) -> dict:
    """
    Full v3 composite result dict including amplification details.
    """
    from consumers.security_eval.scorer.attack_chains import detect_attack_chains

    prefix = f"OW-{framework}"
    fired = sorted(
        [
            (s, signal_map[s]["effective_score"], signal_map[s]["confidence"])
            for s in signal_map
            if s.startswith(prefix) and signal_map[s]["status"] == "fired"
        ],
        key=lambda x: x[1],
        reverse=True,
    )

    if not fired:
        return {
            "composite_score": 0,
            "raw_composite": 0.0,
            "amplification_factor": 1.0,
            "attack_chains_detected": [],
            "confidence_band": "high",
        }

    scores = [f[1] for f in fired]
    confidences = [f[2] for f in fired]

    raw = scores[0] if len(scores) == 1 else (
        scores[0] * 0.6 + (sum(scores[1:]) / len(scores[1:])) * 0.4
    )

    chains_detected, amplification = detect_attack_chains(
        {f[0] for f in fired} | all_fired_signal_ids
    )
    composite = min(100, int(raw * amplification))

    avg_conf = sum(confidences) / len(confidences)
    confidence_band = (
        "high" if avg_conf >= 0.85
        else "medium" if avg_conf >= 0.6
        else "low"
    )

    return {
        "composite_score": composite,
        "raw_composite": round(raw, 2),
        "amplification_factor": amplification,
        "attack_chains_detected": chains_detected,
        "confidence_band": confidence_band,
    }


async def _run_per_event_detectors(
    events: list[dict],
    tenant_id: str,
    session_id: str,
) -> list:
    """
    Replay the session event sequence and run all per-event detectors with
    in-memory cross-event context (replaces the Redis context used during
    online processing). All findings are tagged post_session.
    """
    from consumers.security_eval.detectors.injection import detect_injection
    from consumers.security_eval.detectors.passthrough import detect_passthrough
    from consumers.security_eval.detectors.disclosure import detect_pii
    from consumers.security_eval.detectors.agentic import (
        detect_agent_threats_on_tool_start,
        detect_agent_threats_on_tool_end,
        detect_agent_threats_on_llm_start,
    )
    from consumers.security_eval.detectors.prompt_guard import check_prompt_guard

    last_llm_output: dict[str, str] = {}   # node_run_id → completion
    last_tool_output: dict[str, str] = {}  # node_run_id → tool_output
    last_user_turn: str = ""
    findings: list = []

    for ev in events:
        etype = ev["event_type"]
        nid = ev.get("node_run_id") or ""
        payload = ev.get("payload") or {}
        ev_findings: list = []

        try:
            if etype == "llm_start":
                msgs = payload.get("messages", []) if isinstance(payload, dict) else []
                for m in reversed(msgs):
                    if isinstance(m, dict) and m.get("role") in ("user", "human"):
                        last_user_turn = str(m.get("content", ""))
                        break
                ev_findings += await detect_injection(
                    ev, last_tool_output=last_tool_output.get(nid, ""), tenant_id=tenant_id
                )
                ev_findings += detect_agent_threats_on_llm_start(ev)

            elif etype == "llm_end":
                completion = payload.get("completion", "") if isinstance(payload, dict) else ""
                last_llm_output[nid] = str(completion)
                ev_findings += detect_pii(ev)
                ev_findings += check_prompt_guard(
                    ev, session_ctx={"last_user_turn": last_user_turn}, agent_manifest={}
                )

            elif etype == "tool_start":
                ev_findings += await detect_passthrough(
                    ev, last_llm_output=last_llm_output.get(nid, "")
                )
                ev_findings += detect_agent_threats_on_tool_start(ev)

            elif etype == "tool_end":
                tool_output = payload.get("tool_output", "") if isinstance(payload, dict) else ""
                if not isinstance(tool_output, str):
                    tool_output = json.dumps(tool_output)
                last_tool_output[nid] = tool_output
                ev_findings += detect_pii(ev)
                ev_findings += detect_agent_threats_on_tool_end(ev)

        except Exception:
            logger.exception(
                '"per-event detector failed event_type=%s event_id=%s"',
                etype,
                ev.get("event_id"),
            )

        findings.extend(ev_findings)

    return findings


async def score_session(
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> dict:
    """
    1.  Fetch full event list for session from ClickHouse.
    2.  Fetch session row from Postgres.
    3.  Run per-event detectors (injection, PII, passthrough, agentic, prompt guard).
    4.  Run session-level OW-LLM signal functions + sub-check helpers.
    5.  Run session-level OW-ASI signal functions.
    6.  Run cross-session signals.                              (v3)
    7.  Compute per-signal scores (confidence-weighted).       (v3)
    8.  Detect attack chains.                                   (v3)
    9.  Compute composite scores (with amplification).         (v3)
    10. Write security_findings (with confidence fields).      (v3)
    11. Write session_risk_scores (v2 cols + v3 cols).        (v3)
    12. Compute Bayesian agent trust score.                    (v3)
    13. Upsert agent_risk_scores (with trust columns).        (v3)
    14. Resolve dedup_key.
    15. Alert if v3 thresholds breached.                      (v3)
    16. Alert if agent trust < threshold for N sessions.      (v3)
    """
    from core.infra import clickhouse as ch
    from core.infra.postgres import get_pool

    _CH_QUERY = """
        SELECT event_type, event_id, emitted_at, sequence_index,
               node_run_id, node_name, tool_name, llm_model,
               llm_input_tokens, llm_output_tokens, payload
        FROM obs_events
        WHERE tenant_id  = %(tenant_id)s
          AND session_id = %(session_id)s
        ORDER BY sequence_index ASC
    """
    # ClickHouse may lag behind the Kafka graph_end event by a few seconds.
    # Retry up to 3 times with increasing delays before giving up.
    _RETRY_DELAYS = [1, 3, 5]
    events = []
    for attempt, delay in enumerate(_RETRY_DELAYS):
        await asyncio.sleep(delay)
        events = await ch.fetch(_CH_QUERY, tenant_id=tenant_id, session_id=session_id)
        if events:
            break
        logger.warning(
            '"score_session no CH events yet session_id=%s attempt=%d/%d"',
            session_id,
            attempt + 1,
            len(_RETRY_DELAYS),
        )

    # ClickHouse returns payload as a JSON string — parse into dict for all signal functions.
    # UUID-typed columns (event_id, node_run_id) arrive as uuid.UUID objects; coerce to str.
    for ev in events:
        # Stamp tenant_id and session_id onto each event row (not stored in CH columns)
        ev.setdefault("tenant_id", tenant_id)
        ev.setdefault("session_id", session_id)
        for uuid_col in ("event_id", "node_run_id"):
            if ev.get(uuid_col) is not None:
                ev[uuid_col] = str(ev[uuid_col])
        p = ev.get("payload")
        if not p:
            ev["payload"] = {}
        elif isinstance(p, str):
            try:
                ev["payload"] = json.loads(p)
            except Exception:
                ev["payload"] = {}

    pool = await get_pool()
    session_row = await pool.fetchrow(
        """
        SELECT initial_input, graph_state, graph_runs, duration_ms
        FROM sessions WHERE session_id = $1
        """,
        session_id,
    )
    session = dict(session_row) if session_row else {}

    # ─── Per-event detectors (replayed post-session) ──────────────────────────
    all_findings = await _run_per_event_detectors(events, tenant_id, session_id)

    # ─── Session-level OW-LLM signals ────────────────────────────────────────
    for signal_key, signal_fn in SIGNAL_ID_FUNCTIONS:
        finding = await signal_fn(
            events=events,
            session=session,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
        )
        if finding:
            all_findings.append(finding)

    # Additional sub-check helpers (return lists)
    all_findings.extend(check_multi_turn_jailbreak(events, session_id, tenant_id))
    all_findings.extend(check_payload_splitting(events, session_id, tenant_id))
    all_findings.extend(check_rag_integrity(events, session_id, tenant_id, baseline={}))
    all_findings.extend(check_system_prompt_leakage(events, session_id, tenant_id))
    all_findings.extend(check_vector_integrity(events, session_id, tenant_id))
    all_findings.extend(check_insecure_code_output(events, session_id, tenant_id))
    all_findings.extend(check_hallucinated_packages(events, session_id, tenant_id))
    all_findings.extend(check_ungrounded_high_stakes(events, session_id, tenant_id))
    all_findings.extend(await check_input_size_anomaly(events, session_id, tenant_id, agent_id))

    # ─── Session-level OW-ASI signals ────────────────────────────────────────
    from consumers.security_eval.scorer.asi_signals import signal_a01
    # signal_a01 (goal hijack) correlates OW-ASI06 per-event detections with
    # write-tool behaviour — pass per-event findings so it can find them.
    a01_finding = await signal_a01(
        events=events,
        session=session,
        tenant_id=tenant_id,
        session_id=session_id,
        agent_id=agent_id,
        online_findings=all_findings,
    )
    if a01_finding:
        all_findings.append(a01_finding)

    for signal_key, signal_fn in AGENT_SIGNAL_ID_FUNCTIONS:
        import inspect as _inspect
        sig_params = set(_inspect.signature(signal_fn).parameters.keys())
        kwargs: dict = dict(
            events=events,
            session=session,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
        )
        if "all_findings" in sig_params:
            kwargs["all_findings"] = all_findings
        finding = await signal_fn(**kwargs)
        if finding:
            all_findings.append(finding)

    # ─── Cross-session signals ────────────────────────────────────────────────
    from consumers.security_eval.scorer.cross_session import CROSS_SESSION_FUNCTIONS
    for _cs_key, cs_fn in CROSS_SESSION_FUNCTIONS:
        try:
            cs_params = set(_inspect.signature(cs_fn).parameters.keys())
            cs_kwargs: dict = dict(
                events=events,
                session=session,
                tenant_id=tenant_id,
                session_id=session_id,
                agent_id=agent_id,
            )
            cs_finding = await cs_fn(**cs_kwargs)
            if cs_finding:
                all_findings.append(cs_finding)
        except Exception:
            logger.exception('"cross-session signal failed key=%s"', _cs_key)

    # ─── v3 scoring model ─────────────────────────────────────────────────────
    all_session_findings = all_findings

    llm_signal_map = compute_ow_signal_score(
        [f for f in all_session_findings if f.framework == "LLM"]
    )
    asi_signal_map = compute_ow_signal_score(
        [f for f in all_session_findings if f.framework == "ASI"]
    )

    all_fired_sigs = (
        {s for s, d in llm_signal_map.items() if d["status"] == "fired"}
        | {s for s, d in asi_signal_map.items() if d["status"] == "fired"}
    )

    v3_llm_composite = compute_composite_score_v3(llm_signal_map, "LLM", all_fired_sigs)
    v3_asi_composite = compute_composite_score_v3(asi_signal_map, "ASI", all_fired_sigs)

    llm_score = v3_llm_composite["composite_score"]
    asi_score  = v3_asi_composite["composite_score"]
    llm_band   = _band(llm_score)
    asi_band   = _band(asi_score)

    all_chains = list(
        set(v3_llm_composite["attack_chains_detected"])
        | set(v3_asi_composite["attack_chains_detected"])
    )
    confidence_band = (
        v3_llm_composite["confidence_band"]
        if llm_score >= asi_score
        else v3_asi_composite["confidence_band"]
    )

    # ─── Bayesian agent trust score ───────────────────────────────────────────
    trust_result = {"trust_score": 80.0, "trend": "stable", "trend_slope": 0.0,
                    "alpha": 2.0, "beta": 8.0}
    if agent_id:
        from consumers.security_eval.scorer.trust import compute_agent_trust_score
        historical_rows = await pool.fetch(
            """
            SELECT llm_score, asi_score, scored_at
            FROM session_risk_scores
            WHERE agent_id = $1 AND tenant_id = $2 AND session_id != $3
            ORDER BY scored_at DESC
            LIMIT 50
            """,
            agent_id,
            tenant_id,
            session_id,
        )
        historical_scores = [
            {
                "llm_score": r["llm_score"],
                "asi_score": r["asi_score"],
                "scored_at": r["scored_at"],
            }
            for r in historical_rows
        ]
        session_count = len(historical_scores)
        trust_result = compute_agent_trust_score(
            agent_id=agent_id,
            new_session_llm_score=llm_score,
            new_session_asi_score=asi_score,
            historical_scores=historical_scores,
            session_count=session_count,
        )

    # ─── Persist findings ─────────────────────────────────────────────────────
    from consumers.security_eval.findings import write_findings, write_agent_risk_score
    if all_session_findings:
        await write_findings(all_session_findings)

    # ─── Write session risk score (v2 cols + v3 cols) ─────────────────────────
    await pool.execute(
        """
        INSERT INTO session_risk_scores
            (session_id, tenant_id, agent_id,
             llm_score, llm_band, asi_score, asi_band,
             llm_signal_status, asi_signal_status,
             v3_llm_composite, v3_asi_composite,
             attack_chains_detected,
             scorer_version, scored_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7,
                $8::jsonb, $9::jsonb,
                $10::jsonb, $11::jsonb,
                $12,
                $13, now())
        ON CONFLICT (session_id) DO UPDATE SET
            llm_score              = EXCLUDED.llm_score,
            llm_band               = EXCLUDED.llm_band,
            asi_score              = EXCLUDED.asi_score,
            asi_band               = EXCLUDED.asi_band,
            llm_signal_status      = EXCLUDED.llm_signal_status,
            asi_signal_status      = EXCLUDED.asi_signal_status,
            v3_llm_composite       = EXCLUDED.v3_llm_composite,
            v3_asi_composite       = EXCLUDED.v3_asi_composite,
            attack_chains_detected = EXCLUDED.attack_chains_detected,
            scorer_version         = EXCLUDED.scorer_version,
            scored_at              = now()
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
        json.dumps(v3_llm_composite),
        json.dumps(v3_asi_composite),
        all_chains,
        SCORER_VERSION,
    )

    # ─── Upsert per-agent rolling aggregate (with trust) ─────────────────────
    if agent_id:
        await write_agent_risk_score(
            agent_id, tenant_id, llm_score, asi_score,
            trust_score=trust_result["trust_score"],
            trust_trend=trust_result["trend"],
            trust_trend_slope=trust_result["trend_slope"],
            trust_alpha=trust_result["alpha"],
            trust_beta=trust_result["beta"],
        )

    amplification = max(
        v3_llm_composite["amplification_factor"],
        v3_asi_composite["amplification_factor"],
    )

    score_row = {
        "session_id":              session_id,
        "tenant_id":               tenant_id,
        "agent_id":                agent_id,
        "llm_score":               llm_score,
        "llm_band":                llm_band,
        "asi_score":               asi_score,
        "asi_band":                asi_band,
        "llm_signal_status":       llm_signal_map,
        "asi_signal_status":       asi_signal_map,
        "v3_llm_composite":        v3_llm_composite,
        "v3_asi_composite":        v3_asi_composite,
        "attack_chains_detected":  all_chains,
        "amplification":           amplification,
        "confidence_band":         confidence_band,
        "trust_score":             trust_result["trust_score"],
        "trust_trend":             trust_result["trend"],
        "scorer_version":          SCORER_VERSION,
    }

    # ─── Alert logic (v3 thresholds) ─────────────────────────────────────────
    fired_llm_sigs = {s for s, d in llm_signal_map.items() if d["status"] == "fired"}
    fired_asi_sigs = {s for s, d in asi_signal_map.items() if d["status"] == "fired"}
    overlap_group  = resolve_overlap_group(fired_llm_sigs | fired_asi_sigs)
    score_row["dedup_key"] = (
        f"security:{session_id}:{overlap_group}"
        if overlap_group
        else f"security:{session_id}"
    )

    should_alert = (
        llm_score >= COMPOSITE_ALERT_THRESHOLD_V3
        or asi_score >= COMPOSITE_ALERT_THRESHOLD_V3
    )

    if not should_alert:
        for sig_id, sig_data in {**llm_signal_map, **asi_signal_map}.items():
            if sig_data["status"] == "fired":
                threshold = SIGNAL_ALERT_THRESHOLDS_V3.get(sig_id, 80)
                if sig_data["effective_score"] >= threshold:
                    should_alert = True
                    break

    # Sustained trust degradation alert
    if not should_alert and agent_id:
        if trust_result["trust_score"] < AGENT_TRUST_ALERT_THRESHOLD:
            try:
                recent_trust_rows = await pool.fetch(
                    """
                    SELECT trust_score
                    FROM agent_risk_scores
                    WHERE agent_id = $1
                    LIMIT 1
                    """,
                    agent_id,
                )
                if recent_trust_rows:
                    # Simple check: if current trust is below threshold, check consecutive
                    # sessions by looking at recent session risk scores
                    low_trust_sessions = await pool.fetch(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM (
                            SELECT scored_at
                            FROM session_risk_scores
                            WHERE agent_id = $1 AND tenant_id = $2
                            ORDER BY scored_at DESC
                            LIMIT %s
                        ) sub
                        """ % AGENT_TRUST_CONSECUTIVE_SESSIONS,
                        agent_id,
                        tenant_id,
                    )
                    # If we have enough sessions and trust is below threshold, alert
                    if low_trust_sessions and int(low_trust_sessions[0]["cnt"]) >= AGENT_TRUST_CONSECUTIVE_SESSIONS:
                        should_alert = True
            except Exception:
                pass

    if should_alert:
        from consumers.security_eval.findings import produce_security_alert
        await produce_security_alert(score_row, all_session_findings)

    return score_row
