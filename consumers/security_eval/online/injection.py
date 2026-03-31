"""Injection detector — runs on every llm_start event."""
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.config import settings
from core.infra.redis import get_redis

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

# Instruction-like patterns used by the indirect injection check (INJ-004)
INSTRUCTION_PATTERNS = [
    r"(?i)(ignore|disregard|forget).{0,30}(instruction|prompt|rule)",
    r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)",
    r"(?i)(new (instruction|task|directive|command))",
    r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)",
]

# OWASP mapping for injection signals
SIGNAL_OWASP = {
    "INJ-001": "LLM01",
    "INJ-002": "LLM01",
    "INJ-003": "LLM01",
    "INJ-004": "LLM01",
    "INJ-005": "LLM01",
}

# Hardcoded regex signatures (always active — not tenant-customisable)
REGEX_SIGNATURES = [
    {
        "sig_id": "INJ-001",
        "sig_type": "regex",
        "severity": "critical",
        "pattern": r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)",
    },
    {
        "sig_id": "INJ-002",
        "sig_type": "regex",
        "severity": "critical",
        "pattern": r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)",
    },
    {
        "sig_id": "INJ-005",
        "sig_type": "regex",
        "severity": "warning",
        "pattern": r"(?i)\[system\]|\<system\>|###\s*system",
    },
]

INDIRECT_SIGNATURE = {
    "sig_id": "INJ-004",
    "sig_type": "indirect",
    "severity": "warning",
    "min_overlap_chars": 80,
}


async def _load_blocklist(tenant_id: str | None) -> list[str]:
    """Load blocklist strings from Redis cache, keyed by tenant."""
    redis = await get_redis()
    cache_key = f"dp:sec:sigs:{tenant_id or 'global'}"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    # Fall back to Postgres if not cached
    from core.infra.postgres import get_pool
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT pattern FROM injection_signatures
        WHERE sig_type = 'blocklist'
          AND enabled = true
          AND (tenant_id IS NULL OR tenant_id = $1::uuid)
        """,
        tenant_id,
    )
    blocklist = [r["pattern"] for r in rows if r["pattern"]]
    await redis.setex(cache_key, settings.sig_cache_ttl_s, json.dumps(blocklist))
    return blocklist


def _blocklist_scan(content: str, blocklist: list[str]) -> str | None:
    content_lower = content.lower()
    for phrase in blocklist:
        if phrase.lower() in content_lower:
            return phrase
    return None


def _overlap_chars(a: str, b: str) -> int:
    """Count characters of longest common substring."""
    if not a or not b:
        return 0
    a_lower = a.lower()
    b_lower = b.lower()
    max_overlap = 0
    for i in range(len(a_lower)):
        for j in range(len(b_lower)):
            k = 0
            while (i + k < len(a_lower) and j + k < len(b_lower)
                   and a_lower[i + k] == b_lower[j + k]):
                k += 1
            if k > max_overlap:
                max_overlap = k
    return max_overlap


def _build_finding(event: dict, sig: dict, matched_text: str) -> "Finding":
    from consumers.security_eval.findings import Finding
    return Finding(
        tenant_id=event["tenant_id"],
        session_id=event["session_id"],
        event_id=event["event_id"],
        event_type=event["event_type"],
        signal_id=sig["sig_id"],
        sig_type=sig["sig_type"],
        owasp_id=SIGNAL_OWASP.get(sig["sig_id"], "LLM01"),
        severity=sig["severity"],
        matched_text=matched_text,
        detail=sig.get("detail"),
        score_contrib=0,  # S-01/S-02 score assigned in scorer
        detection_phase="online",
    )


async def detect_injection(
    event: dict,
    last_tool_output: str | None = None,
    tenant_id: str | None = None,
) -> list["Finding"]:
    findings = []
    messages = event["payload"].get("messages", [])
    blocklist = await _load_blocklist(tenant_id)

    for msg in messages:
        if msg.get("role") not in ("user", "tool"):
            continue
        content = str(msg.get("content", ""))

        # Regex signatures
        for sig in REGEX_SIGNATURES:
            if re.search(sig["pattern"], content):
                findings.append(_build_finding(event, sig, content[:200]))

        # Blocklist — INJ-003
        hit = _blocklist_scan(content, blocklist)
        if hit:
            findings.append(_build_finding(
                event,
                {"sig_id": "INJ-003", "sig_type": "blocklist", "severity": "critical"},
                hit[:200],
            ))

        # Indirect injection — INJ-004
        sig = INDIRECT_SIGNATURE
        if (last_tool_output
                and _overlap_chars(content, last_tool_output) >= sig["min_overlap_chars"]
                and any(re.search(p, content) for p in INSTRUCTION_PATTERNS)):
            findings.append(_build_finding(event, sig, content[:200]))

    return findings
