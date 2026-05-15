"""Finding dataclass, Postgres batch writer, and alert delivery."""
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
        ON CONFLICT (session_id, sub_check_id, event_id) DO UPDATE SET
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
_TRUST_RULE_ID       = "00000000-0000-0000-0000-000000000002"
_TRUST_RULE_NAME     = "Agent Trust Degradation"
_ONLINE_RULE_ID      = "00000000-0000-0000-0000-000000000002"
_ONLINE_RULE_NAME    = "Online Security Detection"

# Actions that require an audit row in session_actions.
_AUDITABLE_ACTIONS: frozenset[str] = frozenset({"sanitize", "block_call", "terminate_session"})

_RISK_BAND_TO_SEVERITY = {
    "clean":    "info",
    "low":      "info",
    "medium":   "medium",
    "high":     "warning",
    "critical": "critical",
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _trust_status_label(score: float) -> str:
    if score >= 75: return "Trusted"
    if score >= 50: return "Caution"
    return "At risk"


async def produce_security_alert(
    score_row: dict,
    findings: list[Finding],
    trigger_context: dict | None = None,
) -> None:
    """Produce a security risk alert (composite / signal threshold crossed)."""
    llm_band   = score_row.get("llm_band", "medium")
    severity   = _RISK_BAND_TO_SEVERITY.get(llm_band, "medium")
    session_id = score_row["session_id"]

    llm_status = score_row.get("llm_signal_status", {})
    asi_status = score_row.get("asi_signal_status", {})
    llm_fired  = sum(1 for v in llm_status.values() if v.get("status") == "fired")
    llm_clean  = sum(1 for v in llm_status.values() if v.get("status") == "clean")
    asi_fired  = sum(1 for v in asi_status.values() if v.get("status") == "fired")
    asi_clean  = sum(1 for v in asi_status.values() if v.get("status") == "clean")

    trust_score = score_row.get("trust_score")

    ctx = trigger_context or {}
    if ctx.get("composite_llm_breached"):
        trigger_note = (
            f"LLM composite {ctx['llm_score']}/100 exceeded threshold {ctx['llm_threshold']}"
        )
    elif ctx.get("composite_asi_breached"):
        trigger_note = (
            f"ASI composite {ctx['asi_score']}/100 exceeded threshold {ctx['asi_threshold']}"
        )
    elif ctx.get("threshold_signals"):
        top = ctx["threshold_signals"][0]
        count = len(ctx["threshold_signals"])
        extra = f" (+{count - 1} more)" if count > 1 else ""
        trigger_note = (
            f"Signal '{top['sig_id']}' score {top['effective_score']} "
            f"exceeded threshold {top['threshold']}{extra}"
        )
    else:
        trigger_note = f"LLM: {llm_fired} signals fired · ASI: {asi_fired} signals fired"

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
        "alert_id":     str(uuid.uuid4()),
        "tenant_id":    score_row["tenant_id"],
        "session_id":   session_id,
        "rule_id":      _SECURITY_RULE_ID,
        "rule_name":    _SECURITY_RULE_NAME,
        "severity":     severity,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "dedup_key":    score_row.get("dedup_key", f"security:{session_id}"),
        "payload": {
            "title":     f"Security Risk: {llm_band.capitalize()} ({score_row['llm_score']}/100)",
            "message":   trigger_note,
            "rule_type": "security_risk",
            "source":    "security",
            "agent_id":  score_row.get("agent_id"),
            "llm_score": score_row["llm_score"],
            "llm_band":  llm_band,
            "asi_score": score_row.get("asi_score", 0),
            "asi_band":  score_row.get("asi_band", "clean"),
            "llm_signal_status":      llm_status,
            "asi_signal_status":      asi_status,
            "attack_chains_detected": score_row.get("attack_chains_detected", []),
            "amplification":          score_row.get("amplification", 1.0),
            "confidence_band":        score_row.get("confidence_band", "high"),
            "trust_score":            trust_score,
            "trust_trend":            score_row.get("trust_trend"),
            "top_findings":           top_findings,
            "summary": {
                "llm_signals_fired":     llm_fired,
                "llm_signals_clean":     llm_clean,
                "asi_signals_fired":     asi_fired,
                "asi_signals_clean":     asi_clean,
                "online_actioned_count": sum(1 for f in findings if f.detection_phase == "online"),
            },
            "trigger_context":          ctx,
            "signal_taxonomy_version": "3.0",
            "scorer_version":          score_row["scorer_version"],
        },
    }
    from server.alert_delivery import deliver_alert
    await deliver_alert(alert)


async def produce_trust_alert(score_row: dict) -> None:
    """Produce a standalone trust-degradation alert, separate from security risk alerts."""
    session_id  = score_row["session_id"]
    agent_id    = score_row.get("agent_id") or session_id
    trust_score = float(score_row.get("trust_score") or 0)
    trust_trend = score_row.get("trust_trend", "stable")

    day       = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dedup_key = f"trust:{agent_id}:{day}"

    alert = {
        "alert_id":     str(uuid.uuid4()),
        "tenant_id":    score_row["tenant_id"],
        "session_id":   session_id,
        "rule_id":      _TRUST_RULE_ID,
        "rule_name":    _TRUST_RULE_NAME,
        "severity":     "warning",
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "dedup_key":    dedup_key,
        "payload": {
            "title":       f"Agent Trust Degrading: {round(trust_score)}/100 ({_trust_status_label(trust_score)})",
            "message":     "Trust score below 50 for the last 3 consecutive sessions",
            "rule_type":   "trust_degradation",
            "source":      "security",
            "agent_id":    score_row.get("agent_id"),
            "trust_score": trust_score,
            "trust_trend": trust_trend,
            "scorer_version": score_row["scorer_version"],
        },
    }
    from server.alert_delivery import deliver_alert
    await deliver_alert(alert)


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
    session_started_at: str | None = None,
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

    severity = max(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0)).severity

    # Count by action bucket
    action_counts: dict[str, int] = {}
    for f in findings:
        bucket = action_map.get(f.sub_check_id, "alert")
        action_counts[bucket] = action_counts.get(bucket, 0) + 1

    detections = [
        {
            "sub_check_id":       f.sub_check_id,
            "owasp_signal_id":    f.owasp_signal_id,
            "check_label":        f.check_label,
            "check_score":        f.check_score,
            "effective_score":    round(f.check_score * f.confidence),
            "confidence_tier":    f.confidence_tier,
            "severity":           f.severity,
            "category":           f.category,
            "action_taken":       action_map.get(f.sub_check_id, "alert"),
            "matched_text":       f.matched_text,
            "trigger_event_id":   str(f.event_id),
            "trigger_event_type": f.event_type,
            "triggered_at":       f.emitted_at,
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
        "alert_id":     str(uuid.uuid4()),
        "tenant_id":    tenant_id,
        "session_id":   session_id,
        "rule_id":      _ONLINE_RULE_ID,
        "rule_name":    _ONLINE_RULE_NAME,
        "severity":     severity,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "dedup_key":    f"online_summary:{session_id}",
        "payload": {
            "title":           f"Online Detections: {n} check{'s' if n != 1 else ''} fired",
            "message":         f"{checks_text}. Actions: {action_summary}.",
            "rule_type":       "online_security_summary",
            "source":          "security",
            "agent_id":        agent_id,
            "detection_count":    n,
            "action_counts":      action_counts,
            "session_started_at": session_started_at,
            "detections":         sorted_detections,
            "signal_taxonomy_version": "3.0",
        },
    }
    from server.alert_delivery import deliver_alert
    await deliver_alert(alert)
