"""Output passthrough detector — runs on every tool_start event.

OW-LLM05 sub-checks emitted here:
  IOH-01a  Output contains shell command pattern
  IOH-01b  HTML/JS in output without escaping
  IOH-01c  SQL fragment in tool input from LLM output
  IOH-02a  Raw LLM output passed as tool param (LCS >= 0.9 or >= 0.6)
"""
import json
import re
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

# ─────────────────────────────────────────────────────────────────────────────
# IOH-01: Code / Script Injection in Output patterns
# ─────────────────────────────────────────────────────────────────────────────
_SHELL_PATTERNS = [
    r"(?i)\brm\s+-rf\b",
    r"(?i)curl\s+.*\|\s*(?:ba)?sh\b",
    r"(?i)python\s+-c\s+['\"]",
    r"(?i)\beval\s*\(",
    r"(?i)\bexec\s*\(",
    r"(?i)\bos\.system\s*\(",
    r"(?i)\bsubprocess\.",
]

_XSS_PATTERNS = [
    r"(?i)<script[\s>]",
    r"(?i)\bonerror\s*=",
    r"(?i)javascript\s*:",
]

_SQL_PATTERNS = [
    r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION)\b.{0,40}\b(FROM|INTO|TABLE|WHERE)\b",
]


def _lcs_ratio(a: str, b: str) -> float:
    """Longest common substring ratio relative to the shorter string."""
    if not a or not b:
        return 0.0
    a = re.sub(r'\s+', ' ', a.lower().strip())
    b = re.sub(r'\s+', ' ', b.lower().strip())
    return SequenceMatcher(None, a, b).ratio()


def _make_finding(event: dict, sub_check_id: str, check_label: str, check_score: int,
                  severity: str, matched_text: str, detail: str) -> "Finding":
    from consumers.security_eval.findings import Finding
    return Finding(
        tenant_id=event["tenant_id"],
        session_id=event["session_id"],
        event_id=event["event_id"],
        event_type=event["event_type"],
        owasp_signal_id="OW-LLM05",
        sub_check_id=sub_check_id,
        check_label=check_label,
        check_score=check_score,
        category="output_handling",
        severity=severity,
        matched_text=matched_text,
        detail=detail,
        detection_phase="post_session",
    )


async def detect_passthrough(
    event: dict,
    last_llm_output: str | None,
) -> list["Finding"]:
    findings: list["Finding"] = []
    payload = event.get("payload") or {}
    tool_input = json.dumps(payload.get("tool_input", {}))
    tool_input_str = tool_input

    # IOH-01a: Shell command patterns in tool input
    for pattern in _SHELL_PATTERNS:
        if re.search(pattern, tool_input_str):
            findings.append(_make_finding(
                event, "IOH-01a",
                check_label="Shell command pattern in output",
                check_score=90,
                severity="critical",
                matched_text=tool_input_str[:300],
                detail="Tool input contains shell execution pattern",
            ))
            break

    # IOH-01b: HTML/JS injection in tool input
    for pattern in _XSS_PATTERNS:
        if re.search(pattern, tool_input_str):
            findings.append(_make_finding(
                event, "IOH-01b",
                check_label="HTML/JS in output without escaping",
                check_score=85,
                severity="high",
                matched_text=tool_input_str[:300],
                detail="Tool input contains HTML/JS injection pattern",
            ))
            break

    # IOH-01c: SQL fragment in tool input
    for pattern in _SQL_PATTERNS:
        if re.search(pattern, tool_input_str):
            findings.append(_make_finding(
                event, "IOH-01c",
                check_label="SQL fragment in tool input from LLM output",
                check_score=90,
                severity="critical",
                matched_text=tool_input_str[:300],
                detail="Tool input contains SQL pattern that may originate from LLM completion",
            ))
            break

    # IOH-02a: Raw LLM output passed through to tool (LCS check)
    if last_llm_output:
        ratio = _lcs_ratio(tool_input, last_llm_output)
        if ratio >= 0.85:
            severity = "critical"
            check_score = 70
        elif ratio >= 0.60:
            severity = "high"
            check_score = 55
        else:
            ratio = None  # skip

        if ratio is not None:
            findings.append(_make_finding(
                event, "IOH-02a",
                check_label="Raw LLM output as tool param",
                check_score=check_score,
                severity=severity,
                matched_text=tool_input[:300],
                detail=f"tool_start input {ratio:.0%} similar to preceding llm_end output",
            ))

    return findings
