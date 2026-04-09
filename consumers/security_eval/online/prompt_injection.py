"""Injection detector — runs on every llm_start event.

OW-LLM01 sub-checks emitted here:
  PI-01a  Role-override phrase match          (INJ-001, INJ-002, blocklist)
  PI-01b  Delimiter smuggling                 (INJ-005)
  PI-02a  Web-fetched content with instruction (INJ-004 indirect injection)
"""
import json
import re
from typing import TYPE_CHECKING

from core.config import settings
from core.infra.redis import get_redis

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

# Instruction-like patterns used by the indirect injection check (PI-02a)
INSTRUCTION_PATTERNS = [
    r"(?i)(ignore|disregard|forget).{0,30}(instruction|prompt|rule)",
    r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)",
    r"(?i)(new (instruction|task|directive|command))",
    r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)",
]

# ─────────────────────────────────────────────────────────────────────────────
# Sub-check registry — maps each signature to its canonical OW-LLM01 sub-check
# ─────────────────────────────────────────────────────────────────────────────
_SUB_CHECKS = {
    "PI-01a": {
        "check_label": "Role-override phrase match",
        "check_score": 85,
        "severity": "high",
    },
    "PI-01b": {
        "check_label": "Delimiter smuggling",
        "check_score": 90,
        "severity": "critical",
    },
    "PI-02a": {
        "check_label": "Indirect injection in retrieved content",
        "check_score": 70,
        "severity": "high",
    },
}

# Hardcoded regex signatures
_REGEX_SIGNATURES = [
    {
        "sub_check_id": "PI-01a",
        "pattern": r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)",
    },
    {
        "sub_check_id": "PI-01a",
        "pattern": r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)",
    },
    {
        "sub_check_id": "PI-01b",
        "pattern": r"(?i)\[system\]|\<system\>|###\s*system|</s>|<\|im_start\|>|<\|im_end\|>",
    },
]

_INDIRECT_MIN_OVERLAP_CHARS = 80


async def _load_blocklist(tenant_id: str | None) -> list[str]:
    """Load blocklist strings from Redis cache, keyed by tenant."""
    redis = await get_redis()
    cache_key = f"dp:sec:sigs:{tenant_id or 'global'}"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    from core.infra.postgres import get_pool
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT pattern FROM injection_signatures
        WHERE pattern_type = 'blocklist'
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


def _build_finding(event: dict, sub_check_id: str, matched_text: str) -> "Finding":
    from consumers.security_eval.findings import Finding
    meta = _SUB_CHECKS[sub_check_id]
    return Finding(
        tenant_id=event["tenant_id"],
        session_id=event["session_id"],
        event_id=event["event_id"],
        event_type=event["event_type"],
        owasp_signal_id="OW-LLM01",
        sub_check_id=sub_check_id,
        check_label=meta["check_label"],
        check_score=meta["check_score"],
        category="prompt_injection",
        severity=meta["severity"],
        matched_text=matched_text,
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
        if msg.get("role") not in ("user", "human", "tool"):
            continue
        content = str(msg.get("content", ""))

        # Regex signatures → PI-01a and PI-01b
        for sig in _REGEX_SIGNATURES:
            if re.search(sig["pattern"], content):
                findings.append(_build_finding(event, sig["sub_check_id"], content[:200]))

        # Blocklist scan → PI-01a (role-override category)
        hit = _blocklist_scan(content, blocklist)
        if hit:
            findings.append(_build_finding(event, "PI-01a", hit[:200]))

        # Indirect injection — PI-02a
        if (last_tool_output
                and _overlap_chars(content, last_tool_output) >= _INDIRECT_MIN_OVERLAP_CHARS
                and any(re.search(p, content) for p in INSTRUCTION_PATTERNS)):
            findings.append(_build_finding(event, "PI-02a", content[:200]))

    return findings


def matches_injection_pattern(text: str) -> bool:
    """Utility: True if text matches any PI-01 injection pattern.

    Used by post-session checks (RAG integrity, multi-turn jailbreak).
    """
    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS
    return any(re.search(p, text) for p in all_patterns)


def has_partial_injection_signal(text: str) -> bool:
    """Utility: True if text contains a weaker injection fragment.

    A match here alone is sub-threshold; used by PI-04b accumulation check.
    """
    partial_patterns = [
        r"(?i)(ignore|forget|disregard).{0,20}(instruction|rule)",
        r"(?i)(act as|you are now|pretend)",
        r"(?i)(new task|new directive|override)",
    ]
    return any(re.search(p, text) for p in partial_patterns)
