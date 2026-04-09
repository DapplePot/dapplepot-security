"""Output passthrough detector — runs on every tool_start event."""
import json
import re
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

SIGNAL_OWASP = "LLM02"


def _lcs_ratio(a: str, b: str) -> float:
    """Longest common substring ratio relative to the shorter string."""
    if not a or not b:
        return 0.0
    a = re.sub(r'\s+', ' ', a.lower().strip())
    b = re.sub(r'\s+', ' ', b.lower().strip())
    return SequenceMatcher(None, a, b).ratio()


async def detect_passthrough(
    event: dict,
    last_llm_output: str | None,
) -> "Finding | None":
    # SDK tool_start payload field is "tool_input"
    tool_input = json.dumps(event["payload"].get("tool_input", {}))

    if not last_llm_output:
        return None

    ratio = _lcs_ratio(tool_input, last_llm_output)

    if ratio >= 0.85:
        severity = "critical"
    elif ratio >= 0.60:
        severity = "warning"
    else:
        return None

    from consumers.security_eval.findings import Finding
    return Finding(
        tenant_id=event["tenant_id"],
        session_id=event["session_id"],
        event_id=event["event_id"],
        event_type=event["event_type"],
        signal_id="OUT-001",
        sig_type="passthrough",
        owasp_id=SIGNAL_OWASP,
        severity=severity,
        matched_text=tool_input[:300],
        detail=f"tool_start input {ratio:.0%} similar to preceding llm_end output",
        score_contrib=0,  # S-03 score assigned in scorer
        detection_phase="online",
    )
