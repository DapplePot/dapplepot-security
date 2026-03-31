"""Finding dataclass, Postgres batch writer, and alert producer."""
import json
from dataclasses import dataclass, field
from typing import Any

from core.infra.kafka import make_producer
from core.infra.postgres import get_pool

_producer = None


def _get_producer():
    global _producer
    if _producer is None:
        _producer = make_producer()
    return _producer


@dataclass
class Finding:
    tenant_id: str
    session_id: str
    event_id: str
    event_type: str
    signal_id: str
    sig_type: str
    owasp_id: str
    severity: str
    score_contrib: int
    detection_phase: str
    matched_text: str | None = None
    detail: str | None = None


async def write_findings(findings: list[Finding]) -> None:
    if not findings:
        return
    pool = await get_pool()
    await pool.executemany(
        """
        INSERT INTO security_findings
            (tenant_id, session_id, event_id, event_type, signal_id, sig_type,
             owasp_id, severity, matched_text, detail, score_contrib, detection_phase)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        """,
        [
            (
                f.tenant_id,
                f.session_id,
                f.event_id,
                f.event_type,
                f.signal_id,
                f.sig_type,
                f.owasp_id,
                f.severity,
                f.matched_text,
                f.detail,
                f.score_contrib,
                f.detection_phase,
            )
            for f in findings
        ],
    )


async def produce_security_alert(score_row: dict, findings: list[Finding]) -> None:
    alert = {
        "alert_type": "security_risk",
        "session_id": score_row["session_id"],
        "tenant_id": score_row["tenant_id"],
        "agent_id": score_row.get("agent_id"),
        "risk_score": score_row["risk_score"],
        "risk_band": score_row["risk_band"],
        "signal_ids": score_row["signal_ids"],
        "top_findings": [
            {
                "signal_id": f.signal_id,
                "owasp_id": f.owasp_id,
                "severity": f.severity,
                "detail": f.detail,
            }
            for f in sorted(findings, key=lambda x: x.score_contrib, reverse=True)[:5]
        ],
        "scorer_version": score_row["scorer_version"],
    }
    producer = _get_producer()
    producer.produce(
        "obs.alerts.v1",
        key=score_row["session_id"].encode(),
        value=json.dumps(alert).encode(),
    )
    producer.poll(0)
