"""PII second-pass scanner — runs on llm_end and tool_end events."""
import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

PII_PATTERNS = [
    {
        "sig_id": "PII-001",
        "name": "Credit card",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "severity": "critical",
        "owasp_id": "LLM06",
    },
    {
        "sig_id": "PII-002",
        "name": "US SSN",
        "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "severity": "critical",
        "owasp_id": "LLM06",
    },
    {
        "sig_id": "PII-003",
        "name": "API key",
        "pattern": r"\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})\b",
        "severity": "critical",
        "owasp_id": "LLM06",
    },
    {
        "sig_id": "PII-006",
        "name": "JWT token",
        "pattern": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "severity": "critical",
        "owasp_id": "LLM06",
    },
    {
        "sig_id": "PII-004",
        "name": "Email address",
        "pattern": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        "severity": "warning",
        "owasp_id": "LLM06",
    },
    {
        "sig_id": "PII-005",
        "name": "Phone (E.164)",
        "pattern": r"\+?1?\s*[-.]?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "severity": "warning",
        "owasp_id": "LLM06",
    },
]


def _redact(matched: str) -> str:
    """Replace middle characters with * for safe storage."""
    if len(matched) <= 4:
        return "****"
    return matched[:2] + "*" * (len(matched) - 4) + matched[-2:]


def detect_pii(event: dict) -> list["Finding"]:
    # SDK payload fields differ by event type:
    #   llm_end  → "completion"
    #   tool_end → "tool_output"
    payload = event["payload"]
    if event["event_type"] == "llm_end":
        output_text = json.dumps(payload.get("completion", ""))
    else:  # tool_end
        output_text = json.dumps(payload.get("tool_output", ""))

    from consumers.security_eval.findings import Finding
    findings = []
    for sig in PII_PATTERNS:
        match = re.search(sig["pattern"], output_text)
        if match:
            findings.append(Finding(
                tenant_id=event["tenant_id"],
                session_id=event["session_id"],
                event_id=event["event_id"],
                event_type=event["event_type"],
                signal_id=sig["sig_id"],
                sig_type="pii",
                owasp_id=sig["owasp_id"],
                severity=sig["severity"],
                matched_text=_redact(match.group(0)),
                detail=sig["name"],
                score_contrib=0,  # S-04 score assigned in scorer
                detection_phase="online",
            ))
    return findings
