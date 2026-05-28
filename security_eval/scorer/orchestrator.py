"""Post-session scorer orchestrator — triggered on graph_end / graph_error.

All detection (per-event and session-level) runs here after the full event
history is available from ClickHouse.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
v3 Scoring Model
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1.  Sub-check detection
    Each detector fires one Finding per triggered sub-check.  A Finding
    carries check_score (0–100, from signal_registry) and a confidence_tier.

2.  Confidence weighting
    confidence_weight = { deterministic:1.0, high:0.9, medium:0.7, low:0.5, skeletal:0.3 }
    effective_score = check_score × confidence_weight

3.  Per-signal score (compute_ow_signal_score)
    Findings are grouped by owasp_signal_id.
      raw_score       = max(check_score)          across fired sub-checks
      effective_score = max(check_score × weight) across fired sub-checks
    Both are stored so the UI can compare raw vs confidence-adjusted values.

4.  Composite score per framework (compute_composite_score_v3)
    Inputs: effective_score for each fired signal.
      raw_composite = top_signal × 0.60 + mean(rest) × 0.40   (if N ≥ 2)
                    = top_signal                               (if N = 1)
    The 60/40 split ensures a dominant signal drives the score while a
    cluster of supporting signals still raises it.

5.  Attack chain amplification
    detect_attack_chains() matches fired signal IDs against known multi-step
    attack patterns.  If ≥ 2 signals from a chain are present the composite
    is multiplied by the chain's factor (1.05–1.35, capped at 100).
      composite = min(100, int(raw_composite × amplification_factor))

6.  Risk bands
      clean 0–14 · low 15–34 · medium 35–59 · high 60–84 · critical 85–100

7.  Confidence band
    avg_conf of fired signals: ≥0.85 → high · ≥0.60 → medium · else low

8.  Bayesian agent trust (compute_agent_trust_score)
    Beta(α=2, β=8) prior → starting trust ≈ 80.
    Each session updates α (clean evidence) or β (risk evidence) weighted by
    temporal decay exp(−0.05 × days_old).
    trust_score = 100 × (1 − α / (α + β)).
    Alert when trust < 50 for 3+ consecutive sessions.

Notes:
  - v2 columns still written for backward compatibility.
  - v3_llm_composite / v3_asi_composite JSONB columns carry full v3 detail.
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
from security_eval.scorer.llm_signals import (
    SIGNAL_ID_FUNCTIONS,
    SIGNAL_DESCRIPTION,
    check_multi_turn_jailbreak,
    check_rag_integrity,
    check_rag_goal_shift,
    check_system_prompt_leakage,
    check_vector_integrity,
    check_payload_splitting,
    check_insecure_code_output,
    check_broken_sub_agent_output,
    check_cited_url_404,
    check_claim_not_in_tool_output,
    check_output_contradicts_tool,
    check_hallucinated_packages,
    check_ungrounded_high_stakes,
    check_input_size_anomaly,
    check_irreversible_without_gate,
    check_reads_outside_working_dir,
    check_network_not_in_allowlist,
    check_operating_hours,
    check_package_not_in_sbom,
    check_mcp_endpoint_anomaly,
    check_system_prompt_modification,
    check_undeclared_llm_used,
    check_context_window_stuffing,
    check_budget_cap_exceeded,
)
from security_eval.scorer.asi_signals import (
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

    Scoring model — per signal
    ──────────────────────────
    Each sub-check that fired contributes two values:
      • raw_score      = check_score  (0–100, defined in signal_registry)
      • effective_score = check_score × confidence_weight

    Confidence weights by tier:
      deterministic → 1.0   (pattern / regex match, no ambiguity)
      high          → 0.9   (strong heuristic or embeddings similarity)
      medium        → 0.7   (LLM judge, good recall)
      low           → 0.5   (weak heuristic, noisy)
      skeletal      → 0.3   (structural indicator only, no content match)

    The signal's headline figures are taken from the *best* sub-check:
      signal.raw_score       = max(check_score)          across fired sub-checks
      signal.effective_score = max(check_score × weight) across fired sub-checks

    All fired sub-checks are preserved in sub_checks{} so the UI can show
    which specific detection triggered and why.

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

        # effective = check_score × confidence_weight; track the best sub-check
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
    from security_eval.scorer.attack_chains import detect_attack_chains

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

    Composite formula (per framework — LLM or ASI)
    ───────────────────────────────────────────────
    Inputs: effective_score for each fired signal (0–100 after confidence weighting).

    Step 1 — weighted blend of fired signals
        If 1 signal fired:  composite_raw = effective_score[0]
        If N > 1 signals:   composite_raw = top_signal × 0.60
                                          + mean(rest)    × 0.40

    Rationale: the highest-severity signal dominates (60 %) but a cluster of
    lower signals still lifts the score (40 %), preventing a single noisy
    detector from drowning out a genuine multi-signal attack.

    Step 2 — attack chain amplification
        detect_attack_chains() checks whether the fired signal IDs match any
        known multi-step attack pattern (e.g. injection → exfiltration).
        Each chain carries an amplification factor (1.05–1.35).  The maximum
        factor across detected chains is applied:

            composite = min(100, int(composite_raw × amplification_factor))

        raw_composite (pre-amplification) is preserved so the UI can show
        "what the score would have been without the chain bonus".

    Step 3 — confidence band
        avg_conf = mean of per-signal confidence values for fired signals.
            ≥ 0.85  → "high"    (mostly deterministic / high-tier checks)
            ≥ 0.60  → "medium"
            <  0.60 → "low"

    Risk bands (applied to the final composite):
        clean    0–14
        low     15–34
        medium  35–59
        high    60–84
        critical 85–100
    """
    from security_eval.scorer.attack_chains import detect_attack_chains

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

    # Step 1: weighted blend — top signal × 60% + mean(rest) × 40%
    raw = scores[0] if len(scores) == 1 else (
        scores[0] * 0.6 + (sum(scores[1:]) / len(scores[1:])) * 0.4
    )

    # Step 2: attack chain amplification (pass both frameworks' fired IDs so
    # cross-framework chains like OW-LLM01 → OW-ASI06 are detected)
    chains_detected, amplification = detect_attack_chains(
        {f[0] for f in fired} | all_fired_signal_ids
    )
    composite = min(100, int(raw * amplification))

    # Step 3: confidence band from average signal confidence
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
    skip_sub_checks: frozenset[str] | None = None,
    sec_config=None,
) -> list:
    """
    Replay the session event sequence and run all per-event detectors with
    in-memory cross-event context (replaces the Redis context used during
    online processing). All findings are tagged post_session.

    skip_sub_checks: sub-check IDs that have already been handled by the
    SDK (online mode). Findings for these are filtered out to avoid
    double-counting when the scorer merges SDK findings later.
    """
    _skip = skip_sub_checks or frozenset()
    from security_eval.detectors.injection import detect_injection
    from security_eval.detectors.passthrough import detect_passthrough
    from security_eval.detectors.disclosure import detect_pii, detect_tool_params, detect_stack_trace, detect_cross_tenant_output
    from security_eval.detectors.agentic import (
        detect_agent_threats_on_tool_start,
        detect_agent_threats_on_tool_end,
        detect_agent_threats_on_llm_start,
    )
    from security_eval.detectors.prompt_guard import check_prompt_guard

    last_llm_output: dict[str, str] = {}   # node_run_id → completion
    last_tool_output: dict[str, str] = {}  # node_run_id → tool_output
    last_user_turn: str = ""
    user_tenant_id: str | None = None      # end-tenant for current session (SID-04b)
    findings: list = []

    for ev in events:
        etype = ev["event_type"]
        nid = ev.get("node_run_id") or ""
        payload = ev.get("payload") or {}
        ev_findings: list = []

        # Track user_tenant_id from session_start so SID-04b can compare tool outputs
        # ClickHouse normalises session_start → graph_start (toInternalType in session-writer.ts)
        if etype in ("session_start", "graph_start"):
            user_tenant_id = (
                ev.get("user_tenant_id")
                or (payload.get("user_tenant_id") if isinstance(payload, dict) else None)
            )

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
                ev_findings += detect_agent_threats_on_llm_start(ev, sec_config=sec_config)

            elif etype == "llm_end":
                completion = payload.get("completion", "") if isinstance(payload, dict) else ""
                last_llm_output[nid] = str(completion)
                ev_findings += detect_pii(ev)
                ev_findings += detect_stack_trace(ev)
                ev_findings += check_prompt_guard(
                    ev, session_ctx={"last_user_turn": last_user_turn}, agent_manifest={}
                )

            elif etype == "tool_start":
                ev_findings += await detect_passthrough(
                    ev, last_llm_output=last_llm_output.get(nid, "")
                )
                ev_findings += detect_agent_threats_on_tool_start(ev, sec_config=sec_config)
                ev_findings += detect_tool_params(ev)

            elif etype == "tool_end":
                tool_output = payload.get("tool_output", "") if isinstance(payload, dict) else ""
                if not isinstance(tool_output, str):
                    tool_output = json.dumps(tool_output)
                last_tool_output[nid] = tool_output
                ev_findings += detect_pii(ev)
                ev_findings += detect_cross_tenant_output(ev, user_tenant_id=user_tenant_id)
                ev_findings += detect_agent_threats_on_tool_end(ev)

        except Exception:
            logger.exception(
                '"per-event detector failed event_type=%s event_id=%s"',
                etype,
                ev.get("event_id"),
            )

        # Drop any finding whose sub_check_id is handled online by the SDK
        if _skip:
            ev_findings = [
                f for f in ev_findings
                if getattr(f, "sub_check_id", None) not in _skip
            ]
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
               llm_input_tokens, llm_output_tokens, user_context_id, payload
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
        SELECT initial_input, graph_state, graph_runs, duration_ms, started_at
        FROM sessions WHERE session_id = $1
        """,
        session_id,
    )
    session = dict(session_row) if session_row else {}

    # ─── Fetch / auto-init agent security config from Redis ───────────────────
    from core.infra.redis import get_redis
    from core.security_config import get_agent_security_config
    _redis = await get_redis()
    sec_config = await get_agent_security_config(_redis, tenant_id, agent_id)

    # ─── Load SDK online findings from Postgres ───────────────────────────────
    # Online findings were written directly to security_findings (detection_phase='online')
    # by the consumer when security_finding events arrived. Fetch them here so the
    # post-session scorer can skip their sub_check_ids and merge them into the final score.
    #
    # Use the set of sub-check IDs that *actually fired* (from DB rows) as the skip
    # set — not the config's online_subcheck_ids(). A sub-check may be toggled online
    # in config but have no SDK implementation, in which case no finding arrives and
    # the post-session scorer must still handle it.
    sdk_findings: list = []
    sdk_findings_all: list = []
    if sec_config.online_subcheck_ids():
        try:
            import dataclasses
            from security_eval.findings import Finding
            _init_fields = {f.name for f in dataclasses.fields(Finding) if f.init}
            rows = await pool.fetch(
                """
                SELECT tenant_id, session_id, event_id, event_type,
                       owasp_signal_id, sub_check_id, check_label, check_score,
                       category, severity, detection_phase,
                       matched_text, detail, confidence_tier
                FROM security_findings
                WHERE session_id = $1
                  AND detection_phase = 'online'
                """,
                session_id,
            )
            # Build two lists:
            # sdk_findings      — deduplicated by sub_check_id (for scoring only) so
            #                     multiple firings of the same check don't inflate scores.
            # sdk_findings_all  — every row, used for the combined online alert so all
            #                     firings (same sub-check, different events) are reported.
            _best: dict[str, Finding] = {}
            for row in rows:
                f = Finding(**{k: v for k, v in dict(row).items() if k in _init_fields})
                sdk_findings_all.append(f)
                existing = _best.get(f.sub_check_id)
                if existing is None or f.check_score > existing.check_score:
                    _best[f.sub_check_id] = f
            sdk_findings = list(_best.values())
            if sdk_findings:
                logger.info(
                    '"loaded %d SDK online findings (deduplicated) from Postgres session_id=%s"',
                    len(sdk_findings),
                    session_id,
                )
        except Exception:
            logger.exception('"failed to load online findings from Postgres session_id=%s"', session_id)

    # ─── Build action_map for online findings (sub_check_id → action_taken) ───
    # session_actions rows cover auditable actions (sanitize / terminate_session).
    # Findings absent from the map default to alert.
    online_action_map: dict[str, str] = {}
    if sdk_findings:
        try:
            action_rows = await pool.fetch(
                "SELECT sub_check_id, action_taken FROM session_actions WHERE session_id = $1",
                session_id,
            )
            online_action_map = {r["sub_check_id"]: r["action_taken"] for r in action_rows}
        except Exception:
            logger.exception('"failed to load session_actions session_id=%s"', session_id)

    # Build the skip set:
    # - Sub-checks configured as online AND with a known SDK implementation are always
    #   skipped post-session. The SDK handles them in real time and the security_finding
    #   event may not yet be persisted by the time the scorer runs (race condition between
    #   the async ingest pipeline and graph_end triggering score_session).
    # - Sub-checks configured as online but NOT in the SDK's implementation set are NOT
    #   skipped — no finding will arrive from the SDK for them so post-session must cover them.
    _SDK_ONLINE_CAPABLE = frozenset({
        'PI-01a', 'PI-01b', 'PI-01c', 'PI-02a', 'PI-05a', 'PI-08a',
        'SID-01a', 'SID-01c', 'SID-02a',
        'IOH-01a',
        'EA-01a', 'EA-02b',
    })
    config_online = sec_config.online_subcheck_ids() & _SDK_ONLINE_CAPABLE
    # Also include any sub-checks that actually fired online (already in DB) but
    # weren't covered by the config set (e.g. findings from older SDK versions).
    fired_online = frozenset(f.sub_check_id for f in sdk_findings)
    online_ids: frozenset[str] = config_online | fired_online

    # Sub-checks that have a dedicated session-level scorer in SIGNAL_ID_FUNCTIONS
    # and must not also fire per-event when running post-session — the per-event
    # detector exists only for online (real-time) detection. When not configured
    # online the session-level function produces the authoritative single finding.
    _SESSION_LEVEL_ONLY: frozenset[str] = frozenset({'EA-01a', 'EA-02b'})

    # ─── Per-event detectors (replayed post-session) ──────────────────────────
    # Skip sub-checks that the SDK already handled online — avoids double-counting.
    # Also skip sub-checks owned by session-level scorers when not in online mode.
    _per_event_skip = online_ids | (_SESSION_LEVEL_ONLY - config_online)
    all_findings = await _run_per_event_detectors(
        events, tenant_id, session_id, skip_sub_checks=_per_event_skip, sec_config=sec_config
    )
    # Merge SDK online findings in
    all_findings.extend(sdk_findings)

    # ─── Session-level OW-LLM signals ────────────────────────────────────────
    for signal_key, signal_fn in SIGNAL_ID_FUNCTIONS:
        sig_params = set(_inspect.signature(signal_fn).parameters.keys())
        kwargs: dict = dict(
            events=events,
            session=session,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_id=agent_id,
        )
        if "sec_config" in sig_params:
            kwargs["sec_config"] = sec_config
        finding = await signal_fn(**kwargs) if _inspect.iscoroutinefunction(signal_fn) else signal_fn(**kwargs)
        if finding:
            if getattr(finding, "sub_check_id", None) in online_ids:
                continue  # already handled online; action is the SDK-configured one
            # Respect per-signal enabled flag from config
            sig_id = getattr(finding, "owasp_signal_id", None)
            sig_cfg = sec_config.signals.get(sig_id) if sig_id else None
            if sig_cfg is None or sig_cfg.enabled:
                all_findings.append(finding)

    # Additional sub-check helpers (return lists) — filter by per-signal enabled flag.
    def _extend_if_enabled(findings: list) -> None:
        for f in findings:
            if getattr(f, "sub_check_id", None) in online_ids:
                continue  # already handled online
            sig_id  = getattr(f, "owasp_signal_id", None)
            sig_cfg = sec_config.signals.get(sig_id) if sig_id else None
            if sig_cfg is None or sig_cfg.enabled:
                all_findings.append(f)

    from security_eval.detectors.agentic import detect_ea_tool_call_limit, check_mcp_descriptor_poisoning
    _extend_if_enabled(detect_ea_tool_call_limit(events, sec_config, session_id, tenant_id))
    _extend_if_enabled(check_mcp_descriptor_poisoning(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_multi_turn_jailbreak(events, session_id, tenant_id))
    _extend_if_enabled(check_payload_splitting(events, session_id, tenant_id))
    _extend_if_enabled(check_rag_integrity(events, session_id, tenant_id, baseline={}))
    _extend_if_enabled(check_rag_goal_shift(events, session_id, tenant_id))
    _extend_if_enabled(check_system_prompt_leakage(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_vector_integrity(events, session_id, tenant_id))
    _extend_if_enabled(check_insecure_code_output(events, session_id, tenant_id))
    _extend_if_enabled(check_broken_sub_agent_output(events, session_id, tenant_id))
    _extend_if_enabled(check_cited_url_404(events, session_id, tenant_id))
    _extend_if_enabled(check_claim_not_in_tool_output(events, session_id, tenant_id))
    _extend_if_enabled(check_output_contradicts_tool(events, session_id, tenant_id))
    _extend_if_enabled(check_hallucinated_packages(events, session_id, tenant_id))
    _extend_if_enabled(check_ungrounded_high_stakes(events, session_id, tenant_id))
    _extend_if_enabled(await check_input_size_anomaly(events, session_id, tenant_id, agent_id))
    _extend_if_enabled(check_irreversible_without_gate(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_reads_outside_working_dir(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_network_not_in_allowlist(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_operating_hours(events, session, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_package_not_in_sbom(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_mcp_endpoint_anomaly(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_system_prompt_modification(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_undeclared_llm_used(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_context_window_stuffing(events, session_id, tenant_id, sec_config=sec_config))
    _extend_if_enabled(check_budget_cap_exceeded(events, session_id, tenant_id, sec_config=sec_config))

    # ─── Session-level OW-ASI signals ────────────────────────────────────────
    from security_eval.scorer.asi_signals import signal_a01
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
    if a01_finding and getattr(a01_finding, "sub_check_id", None) not in online_ids:
        all_findings.append(a01_finding)

    for signal_key, signal_fn in AGENT_SIGNAL_ID_FUNCTIONS:
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
        if "sec_config" in sig_params:
            kwargs["sec_config"] = sec_config
        finding = await signal_fn(**kwargs)
        if finding:
            if getattr(finding, "sub_check_id", None) in online_ids:
                continue  # already handled online; action is the SDK-configured one
            sig_id = getattr(finding, "owasp_signal_id", None)
            sig_cfg = sec_config.signals.get(sig_id) if sig_id else None
            if sig_cfg is None or sig_cfg.enabled:
                all_findings.append(finding)

    # ─── Cross-session signals ────────────────────────────────────────────────
    from security_eval.scorer.cross_session import CROSS_SESSION_FUNCTIONS
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
            if cs_finding and getattr(cs_finding, "sub_check_id", None) not in online_ids:
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
    # Model: Beta-Binomial with temporal decay.
    #
    # Prior: Beta(α=2, β=8) → starting trust ≈ 80 (trust = 1 − α/(α+β))
    #
    # Each scored session updates α and β:
    #   clean session   → α += decay_weight   (trust evidence)
    #   risky session   → β += decay_weight   (distrust evidence)
    #
    # Decay weight = exp(−λ × days_since_session), λ=0.05/day.
    # Sessions older than ~60 days contribute < 5 % of their original weight,
    # so recent behaviour dominates.
    #
    # Final trust_score = 100 × (1 − α / (α + β)), clamped to [0, 100].
    #
    # Trend is computed as the slope of the last N trust estimates (linear
    # regression over time).  Thresholds: improving ≥ +0.5/session,
    # degrading ≤ −0.5/session, otherwise stable.
    #
    # Alert fires when trust_score < AGENT_TRUST_ALERT_THRESHOLD (50) for
    # AGENT_TRUST_CONSECUTIVE_SESSIONS (3) consecutive sessions.
    trust_result = {"trust_score": 80.0, "trend": "stable", "trend_slope": 0.0,
                    "alpha": 2.0, "beta": 8.0}
    if agent_id:
        from security_eval.scorer.trust import compute_agent_trust_score
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
    from security_eval.findings import write_findings, write_agent_risk_score
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
             trust_score,
             scorer_version, scored_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7,
                $8::jsonb, $9::jsonb,
                $10::jsonb, $11::jsonb,
                $12,
                $13,
                $14, now())
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
            trust_score            = EXCLUDED.trust_score,
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
        trust_result["trust_score"],
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

    # Use per-framework thresholds; fall back to shared composite_alert_threshold
    _llm_threshold = sec_config.llm_composite_alert_threshold
    _asi_threshold = sec_config.asi_composite_alert_threshold

    should_alert = (
        llm_score >= _llm_threshold
        or asi_score >= _asi_threshold
    )
    trust_alert_triggered = False

    if not should_alert:
        for sig_id, sig_data in {**llm_signal_map, **asi_signal_map}.items():
            if sig_data["status"] == "fired":
                # Per-signal threshold: sec_config wins over platform default
                sig_cfg = sec_config.signals.get(sig_id)
                if sig_cfg is not None:
                    threshold = sig_cfg.alert_threshold
                else:
                    threshold = SIGNAL_ALERT_THRESHOLDS_V3.get(sig_id, 80)
                if sig_data["effective_score"] >= threshold:
                    should_alert = True
                    break

    # Collect every fired signal that individually crossed its alert threshold.
    # Built regardless of what triggered should_alert so the alert payload is complete.
    _threshold_signals: list[dict] = []
    for _sig_id, _sig_data in {**llm_signal_map, **asi_signal_map}.items():
        if _sig_data["status"] == "fired":
            _sig_cfg   = sec_config.signals.get(_sig_id)
            _sig_thr   = (
                _sig_cfg.alert_threshold if _sig_cfg is not None
                else SIGNAL_ALERT_THRESHOLDS_V3.get(_sig_id, 80)
            )
            if _sig_data["effective_score"] >= _sig_thr:
                _threshold_signals.append({
                    "sig_id":          _sig_id,
                    "effective_score": _sig_data["effective_score"],
                    "threshold":       _sig_thr,
                })

    _trigger_context = {
        "composite_llm_breached": llm_score >= _llm_threshold,
        "composite_asi_breached": asi_score >= _asi_threshold,
        "llm_score":              llm_score,
        "llm_threshold":          _llm_threshold,
        "asi_score":              asi_score,
        "asi_threshold":          _asi_threshold,
        "threshold_signals":      _threshold_signals,
    }

    # ─── Sustained trust degradation alert (evaluated independently) ─────────
    # Runs regardless of whether composite/signal alerts fired — trust degradation
    # is a separate signal and must not be silenced by the all_online suppression
    # that applies to per-session composite alerts.
    # Deduped per-agent per-day: fires at most once per 24 h window so a
    # persistently degraded agent does not spam one alert per session.
    if agent_id and trust_result["trust_score"] < AGENT_TRUST_ALERT_THRESHOLD:
        try:
            # Primary gate: agent has enough session history.
            # Uses agent_risk_scores.session_count — always available, no
            # dependency on migration 015.
            session_count_row = await pool.fetchrow(
                "SELECT session_count FROM agent_risk_scores WHERE agent_id = $1",
                agent_id,
            )
            has_enough_history = (
                session_count_row is not None
                and int(session_count_row["session_count"]) >= AGENT_TRUST_CONSECUTIVE_SESSIONS
            )

            if has_enough_history:
                # Secondary check: count how many recent sessions actually recorded
                # trust below the threshold. Using point-in-time snapshot scores
                # and checking all(< threshold) was too strict — Bayesian trust
                # converges gradually from its prior (~80) so early sessions for
                # a risky agent often have scores above threshold even when the
                # agent has been consistently bad. Filtering the query to only
                # sessions already below threshold and counting them correctly
                # captures "N sessions with confirmed low trust."
                # Exception path: column not yet migrated → trust the Bayesian score.
                try:
                    last_rows = await pool.fetch(
                        """
                        SELECT trust_score
                        FROM session_risk_scores
                        WHERE agent_id = $1 AND tenant_id = $2
                          AND trust_score IS NOT NULL
                        ORDER BY scored_at DESC
                        LIMIT $3
                        """,
                        agent_id,
                        tenant_id,
                        AGENT_TRUST_CONSECUTIVE_SESSIONS,
                    )
                    trust_alert_triggered = (
                        len(last_rows) >= AGENT_TRUST_CONSECUTIVE_SESSIONS
                        and all(
                            float(r["trust_score"]) < AGENT_TRUST_ALERT_THRESHOLD
                            for r in last_rows
                        )
                    )
                except Exception:
                    # Column not yet migrated — fall through to primary gate result.
                    trust_alert_triggered = True
        except Exception:
            logger.exception("failed to evaluate trust degradation alert agent_id=%s", agent_id)

    # ─── Combined online alert (one per session) ─────────────────────────────
    # Produced here — at session end — so all online findings are known and can
    # be bundled into a single alert (sanitize / terminate_session / alert actions).
    if sdk_findings:
        try:
            from security_eval.findings import produce_combined_online_alert
            _started_at = session.get("started_at")
            session_started_at = (
                _started_at.isoformat() if hasattr(_started_at, "isoformat") else str(_started_at)
                if _started_at else None
            )
            await produce_combined_online_alert(
                session_id=session_id,
                tenant_id=tenant_id,
                agent_id=agent_id,
                findings=sdk_findings_all,  # undeduped — show every firing in the alert
                action_map=online_action_map,
                session_started_at=session_started_at,
            )
        except Exception:
            logger.exception('"failed to produce combined online alert session_id=%s"', session_id)

    if should_alert:
        # Suppress the post-session risk-score alert when every finding was already
        # caught by the SDK online — the combined online alert above covers it.
        all_online = bool(all_session_findings) and all(
            f.detection_phase == "online" for f in all_session_findings
        )
        if not all_online:
            from security_eval.findings import produce_security_alert
            await produce_security_alert(score_row, all_session_findings, _trigger_context)

    if trust_alert_triggered:
        from security_eval.findings import produce_trust_alert
        await produce_trust_alert(score_row)

    return score_row
