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
             confidence_tier, confidence)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
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
            confidence      = EXCLUDED.confidence
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


_SECURITY_RULE_ID   = "00000000-0000-0000-0000-000000000001"
_SECURITY_RULE_NAME = "Security Risk Score"

_RISK_BAND_TO_SEVERITY = {
    "clean":    "info",
    "low":      "info",
    "medium":   "medium",
    "high":     "warning",
    "critical": "critical",
}


async def produce_security_alert(score_row: dict, findings: list[Finding]) -> None:
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
            "title":   f"Security Risk: {llm_band.capitalize()} ({score_row['llm_score']}/100)",
            "message": f"LLM: {llm_fired} signals fired · ASI: {asi_fired} signals fired",
            "rule_type":  "security_risk",
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
                "llm_signals_fired": llm_fired,
                "llm_signals_clean": llm_clean,
                "asi_signals_fired": asi_fired,
                "asi_signals_clean": asi_clean,
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
