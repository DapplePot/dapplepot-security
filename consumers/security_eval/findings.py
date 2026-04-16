"""Finding dataclass, Postgres batch writer, and alert producer."""
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.config import (
    settings,
    SIGNAL_ALERT_THRESHOLDS,
    COMPOSITE_ALERT_THRESHOLD,
    SIGNAL_ALERT_THRESHOLDS_V3,
    COMPOSITE_ALERT_THRESHOLD_V3,
    CONFIDENCE_WEIGHTS,
)

_producer = None


def _get_producer():
    global _producer
    if _producer is None:
        from core.infra.kafka import make_producer
        _producer = make_producer()
    return _producer


@dataclass
class Finding:
    tenant_id: str
    session_id: str
    event_id: str
    event_type: str
    owasp_signal_id: str    # canonical e.g. "OW-LLM01", "OW-ASI03"
    sub_check_id: str       # e.g. "PI-01a"
    check_label: str        # e.g. "Role-override phrase match"
    check_score: int        # per-sub-check weight 0–100
    category: str           # threat category e.g. "prompt_injection", "data_disclosure"
    severity: str           # critical | high | medium | low
    detection_phase: str    # online | post_session | cross_session
    matched_text: str | None = None
    detail: str | None = None
    # SDK event emission time — stored so the UI timeline uses the real event
    # timestamp rather than the DB insert time (created_at).
    emitted_at: str | None = None
    # v3 confidence fields
    confidence_tier: str = "high"   # deterministic | high | medium | low | skeletal
    confidence: float = field(init=False)
    # Derived in __post_init__ — not init params
    framework: str = field(init=False)  # "LLM" | "ASI" | future frameworks

    def __post_init__(self):
        # Derive framework from owasp_signal_id: "OW-LLM01" → "LLM", "OW-ASI03" → "ASI"
        parts = self.owasp_signal_id.split("-")
        self.framework = parts[1][:3] if len(parts) >= 2 else "LLM"
        # Derive confidence float from tier
        self.confidence = CONFIDENCE_WEIGHTS.get(self.confidence_tier, 0.9)


async def write_findings(findings: list[Finding]) -> None:
    if not findings:
        return
    from core.infra.postgres import get_pool
    pool = await get_pool()
    await pool.executemany(
        """
        INSERT INTO security_findings
            (tenant_id, session_id, event_id, event_type,
             framework, owasp_signal_id, sub_check_id, check_label, check_score,
             category, severity, detection_phase, matched_text, detail,
             confidence_tier, confidence, emitted_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        ON CONFLICT (session_id, sub_check_id) DO UPDATE SET
            check_score     = GREATEST(security_findings.check_score, EXCLUDED.check_score),
            severity        = CASE
                                WHEN ARRAY_POSITION(ARRAY['critical','high','medium','low'], EXCLUDED.severity)
                                   < ARRAY_POSITION(ARRAY['critical','high','medium','low'], security_findings.severity)
                                THEN EXCLUDED.severity
                                ELSE security_findings.severity
                              END,
            detection_phase = EXCLUDED.detection_phase,
            detail          = COALESCE(EXCLUDED.detail, security_findings.detail),
            matched_text    = COALESCE(security_findings.matched_text, EXCLUDED.matched_text),
            confidence_tier = EXCLUDED.confidence_tier,
            confidence      = EXCLUDED.confidence,
            emitted_at      = COALESCE(security_findings.emitted_at, EXCLUDED.emitted_at)
        WHERE EXCLUDED.check_score >= security_findings.check_score
        """,
        [
            (
                f.tenant_id,
                f.session_id,
                f.event_id,
                f.event_type,
                f.framework,
                f.owasp_signal_id,
                f.sub_check_id,
                f.check_label,
                f.check_score,
                f.category,
                f.severity,
                f.detection_phase,
                f.matched_text,
                f.detail,
                f.confidence_tier,
                f.confidence,
                datetime.fromisoformat(f.emitted_at.replace("Z", "+00:00")) if isinstance(f.emitted_at, str) else f.emitted_at,
            )
            for f in findings
        ],
    )


async def write_agent_risk_score(
    agent_id: str,
    tenant_id: str,
    llm_score: int,
    asi_score: int,
    trust_score: float = 80.0,
    trust_trend: str = "stable",
    trust_trend_slope: float = 0.0,
    trust_alpha: float = 2.0,
    trust_beta: float = 8.0,
) -> None:
    """Upsert per-agent aggregate risk in agent_risk_scores (rolling stats)."""
    from core.infra.postgres import get_pool
    pool = await get_pool()
    await pool.execute(
        """
        INSERT INTO agent_risk_scores
            (agent_id, tenant_id, session_count,
             avg_llm_score, avg_asi_score,
             max_llm_score, max_asi_score, last_scored_at,
             trust_score, trust_trend, trust_trend_slope,
             trust_alpha, trust_beta)
        VALUES ($1, $2, 1, $3, $4, $5, $6, now(), $7, $8, $9, $10, $11)
        ON CONFLICT (agent_id) DO UPDATE SET
            session_count       = agent_risk_scores.session_count + 1,
            avg_llm_score       = (
                agent_risk_scores.avg_llm_score * agent_risk_scores.session_count + $3
            ) / (agent_risk_scores.session_count + 1),
            avg_asi_score       = (
                agent_risk_scores.avg_asi_score * agent_risk_scores.session_count + $4
            ) / (agent_risk_scores.session_count + 1),
            max_llm_score       = GREATEST(agent_risk_scores.max_llm_score, $5),
            max_asi_score       = GREATEST(agent_risk_scores.max_asi_score, $6),
            last_scored_at      = now(),
            trust_score         = $7,
            trust_trend         = $8,
            trust_trend_slope   = $9,
            trust_alpha         = $10,
            trust_beta          = $11
        """,
        agent_id,
        tenant_id,
        float(llm_score),
        float(asi_score),
        llm_score,
        asi_score,
        trust_score,
        trust_trend,
        trust_trend_slope,
        trust_alpha,
        trust_beta,
    )


_SECURITY_RULE_ID    = "00000000-0000-0000-0000-000000000001"
_SECURITY_RULE_NAME  = "Security Risk Score"
_ONLINE_RULE_ID      = "00000000-0000-0000-0000-000000000002"
_ONLINE_RULE_NAME    = "Online Security Detection"

# Actions that warrant a combined alert from Zone 6 at session end.
_ALERTABLE_ACTIONS: frozenset[str] = frozenset({"alert", "sanitize", "terminate_session"})

# Actions that require an audit row in session_actions.
# sanitize is auditable because content was actively modified in-flight.
_AUDITABLE_ACTIONS: frozenset[str] = frozenset({"sanitize", "terminate_session"})

_RISK_BAND_TO_SEVERITY = {
    "clean":    "info",
    "low":      "info",
    "medium":   "medium",
    "high":     "warning",
    "critical": "critical",
}

_ACTION_TO_SEVERITY = {
    "alert":             "medium",
    "sanitize":          "medium",
    "terminate_session": "critical",
}


async def produce_security_alert(score_row: dict, findings: list[Finding], *, trust_triggered: bool = False) -> None:
    """Produce an alert to obs.alerts.v1 conforming to AlertMessage schema."""
    llm_band   = score_row.get("llm_band", "medium")
    severity   = _RISK_BAND_TO_SEVERITY.get(llm_band, "medium")
    session_id = score_row["session_id"]

    llm_status   = score_row.get("llm_signal_status", {})
    asi_status   = score_row.get("asi_signal_status", {})
    llm_fired    = sum(1 for v in llm_status.values() if v.get("status") == "fired")
    llm_clean    = sum(1 for v in llm_status.values() if v.get("status") == "clean")
    asi_fired    = sum(1 for v in asi_status.values() if v.get("status") == "fired")
    asi_clean    = sum(1 for v in asi_status.values() if v.get("status") == "clean")

    dedup_key = score_row.get("dedup_key", f"security:{session_id}")

    top_findings = [
        {
            "owasp_signal_id": f.owasp_signal_id,
            "sub_check_id":    f.sub_check_id,
            "check_label":     f.check_label,
            "check_score":     f.check_score,
            "effective_score": round(f.check_score * f.confidence),
            "confidence_tier": f.confidence_tier,
            "category":        f.category,
            "severity":        f.severity,
            "detail":          f.detail,
        }
        for f in sorted(findings, key=lambda x: x.check_score * x.confidence, reverse=True)[:5]
    ]

    alert = {
        "alert_id":      str(uuid.uuid4()),
        "tenant_id":     score_row["tenant_id"],
        "session_id":    session_id,
        "rule_id":       _SECURITY_RULE_ID,
        "rule_name":     _SECURITY_RULE_NAME,
        "severity":      severity,
        "triggered_at":  datetime.now(timezone.utc).isoformat(),
        "dedup_key":     dedup_key,
        "channels":      [],
        "channel_config": {},
        "payload": {
            "title":   (
                f"Agent Trust Alert: Score degrading ({int(score_row.get('trust_score', 0))}/100)"
                if trust_triggered else
                f"Security Risk: {llm_band.capitalize()} ({score_row['llm_score']}/100)"
            ),
            "message": (
                f"Agent trust score has been consistently below threshold across recent sessions · "
                f"Trust trend: {score_row.get('trust_trend', 'degrading')}"
                if trust_triggered else
                f"LLM: {llm_fired} signals fired · ASI: {asi_fired} signals fired"
            ),
            "rule_type":  "trust_degradation" if trust_triggered else "security_risk",
            "source":     "security",
            "agent_id":   score_row.get("agent_id"),
            # Composite scores
            "llm_score":  score_row["llm_score"],
            "llm_band":   llm_band,
            "asi_score":  score_row.get("asi_score", 0),
            "asi_band":   score_row.get("asi_band", "clean"),
            # Signal status maps (OW-canonical)
            "llm_signal_status": llm_status,
            "asi_signal_status": asi_status,
            # v3: attack chains, amplification, confidence, trust
            "attack_chains_detected": score_row.get("attack_chains_detected", []),
            "amplification":          score_row.get("amplification", 1.0),
            "confidence_band":        score_row.get("confidence_band", "high"),
            "trust_score":            score_row.get("trust_score"),
            "trust_trend":            score_row.get("trust_trend"),
            # Top findings
            "top_findings": top_findings,
            "summary": {
                "llm_signals_fired":    llm_fired,
                "llm_signals_clean":    llm_clean,
                "asi_signals_fired":    asi_fired,
                "asi_signals_clean":    asi_clean,
                # How many of these findings were already actioned online
                # (sanitize / terminate_session raised in real time).
                # Consumers can use this to de-duplicate notifications.
                "online_actioned_count": sum(
                    1 for f in findings if f.detection_phase == "online"
                ),
            },
            "signal_taxonomy_version": "3.0",
            "scorer_version": score_row["scorer_version"],
        },
    }
    producer = _get_producer()
    producer.produce(
        settings.kafka_alerts_topic,
        key=session_id.encode(),
        value=json.dumps(alert).encode(),
    )
    producer.flush()


async def write_session_action(
    finding: Finding, action_taken: str, agent_id: str | None = None
) -> None:
    """Persist an auditable online action (sanitize / terminate_session) to session_actions."""
    from core.infra.postgres import get_pool
    pool = await get_pool()
    await pool.execute(
        """
        INSERT INTO session_actions
            (session_id, tenant_id, agent_id,
             sub_check_id, owasp_signal_id, severity, action_taken)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        finding.session_id,
        finding.tenant_id,
        agent_id,
        finding.sub_check_id,
        finding.owasp_signal_id,
        finding.severity,
        action_taken,
    )


async def produce_combined_online_alert(
    session_id: str,
    tenant_id: str,
    agent_id: str | None,
    findings: list[Finding],
    action_map: dict[str, str],
) -> None:
    """Produce ONE combined alert for all online detections in a session.

    Called at session end (post-session scorer) so every online finding for the
    session is reported in a single alert instead of one per sub-check.

    action_map: sub_check_id → action_taken, built from session_actions rows
    (covers sanitize / terminate_session).  Findings absent from the map had
    action alert — session continued with an alert raised.
    """
    if not findings:
        return

    _severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    _action_rank   = {"terminate_session": 2, "sanitize": 1, "alert": 0}

    # Overall alert severity: highest of finding severity or action severity
    top_finding_sev = max(findings, key=lambda f: _severity_rank.get(f.severity, 0)).severity
    top_action      = max(action_map.values(), key=lambda a: _action_rank.get(a, 0)) \
                      if action_map else "alert"
    action_sev      = _ACTION_TO_SEVERITY.get(top_action, "medium")
    severity        = top_finding_sev \
                      if _severity_rank.get(top_finding_sev, 0) >= _severity_rank.get(action_sev, 0) \
                      else action_sev

    # Count by action bucket
    action_counts: dict[str, int] = {}
    for f in findings:
        bucket = action_map.get(f.sub_check_id, "alert")
        action_counts[bucket] = action_counts.get(bucket, 0) + 1

    detections = [
        {
            "sub_check_id":    f.sub_check_id,
            "owasp_signal_id": f.owasp_signal_id,
            "check_label":     f.check_label,
            "check_score":     f.check_score,
            "effective_score": round(f.check_score * f.confidence),
            "confidence_tier": f.confidence_tier,
            "severity":        f.severity,
            "category":        f.category,
            "action_taken":    action_map.get(f.sub_check_id, "alert"),
            "matched_text":    f.matched_text,
        }
        for f in findings
    ]

    n = len(findings)

    # Sorted detections list (highest effective score first) — used in message and payload
    sorted_detections = sorted(detections, key=lambda d: d["effective_score"], reverse=True)

    # Human-readable check lines: "PI-01a · Role-override phrase match [block_call, high]"
    check_lines = [
        f"{d['sub_check_id']} · {d['check_label']} [{d['action_taken']}, {d['severity']}]"
        for d in sorted_detections
    ]
    checks_text = "; ".join(check_lines)

    action_summary = ", ".join(
        f"{v} {k}" for k, v in action_counts.items() if v > 0
    )
    alert = {
        "alert_id":      str(uuid.uuid4()),
        "tenant_id":     tenant_id,
        "session_id":    session_id,
        "rule_id":       _ONLINE_RULE_ID,
        "rule_name":     _ONLINE_RULE_NAME,
        "severity":      severity,
        "triggered_at":  datetime.now(timezone.utc).isoformat(),
        # One dedup key per session — alert router discards duplicates if scorer retries.
        "dedup_key":     f"online_summary:{session_id}",
        "channels":      [],
        "channel_config": {},
        "payload": {
            "title":           f"Online Detections: {n} check{'s' if n != 1 else ''} fired",
            "message":         f"{checks_text}. Actions: {action_summary}.",
            "rule_type":       "online_security_summary",
            "source":          "security",
            "agent_id":        agent_id,
            "detection_count": n,
            "action_counts":   action_counts,
            "detections":      sorted_detections,
            "signal_taxonomy_version": "3.0",
        },
    }
    producer = _get_producer()
    producer.produce(
        settings.kafka_alerts_topic,
        key=session_id.encode(),
        value=json.dumps(alert).encode(),
    )
    producer.flush()
