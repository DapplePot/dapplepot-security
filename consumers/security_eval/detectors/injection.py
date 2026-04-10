"""Injection detector — runs on every llm_start event.

OW-LLM01 sub-checks emitted here:
  PI-01a  Role-override phrase match          (INJ-001, INJ-002, blocklist)
  PI-01b  Delimiter smuggling                 (INJ-005)
  PI-02a  Web-fetched content with instruction (INJ-004 indirect injection)
  PI-05a  Code injection pattern in prompt    (v3)
  PI-07a  Multimodal content with injection   (v3)
  PI-08a  Adversarial suffix / high-entropy   (v3)
  PI-09a  Obfuscated/encoded injection        (v3)
"""
import base64
import codecs
import json
import math
import re
import unicodedata
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
        "confidence_tier": "high",
    },
    "PI-01b": {
        "check_label": "Delimiter smuggling",
        "check_score": 90,
        "severity": "critical",
        "confidence_tier": "deterministic",
    },
    "PI-02a": {
        "check_label": "Indirect injection in retrieved content",
        "check_score": 70,
        "severity": "high",
        "confidence_tier": "high",
    },
    "PI-05a": {
        "check_label": "Code injection pattern in prompt",
        "check_score": 80,
        "severity": "high",
        "confidence_tier": "high",
    },
    "PI-07a": {
        "check_label": "Multimodal content with injection signal",
        "check_score": 60,
        "severity": "medium",
        "confidence_tier": "low",
    },
    "PI-08a": {
        "check_label": "Adversarial suffix (high-entropy tail)",
        "check_score": 75,
        "severity": "high",
        "confidence_tier": "medium",
    },
    "PI-09a": {
        "check_label": "Obfuscated/encoded injection",
        "check_score": 82,
        "severity": "high",
        "confidence_tier": "high",
    },
}

# PI-05a: Code injection patterns
_CODE_INJECTION_PATTERNS = [
    r"(?i)(import\s+os|import\s+subprocess|__import__|eval\s*\(|exec\s*\()",
    r"(?i)(os\.system|subprocess\.\w+|open\s*\(.+['\"]w['\"])",
    r"(?i)(require\s*\(\s*['\"]child_process|\.exec\s*\(|spawn\s*\()",
]

# PI-09a: Hex-encoded sequences
_HEX_PATTERN = re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.IGNORECASE)
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

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


def _build_finding(
    event: dict,
    sub_check_id: str,
    matched_text: str,
    detail: str | None = None,
) -> "Finding":
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
        detection_phase="post_session",
        confidence_tier=meta.get("confidence_tier", "high"),
        detail=detail,
    )


def _char_entropy(text: str) -> float:
    """Shannon entropy over character distribution."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    total = len(text)
    return -sum((v / total) * math.log2(v / total) for v in counts.values())


def _check_pi09a(content: str) -> str | None:
    """Return detection method name if obfuscated injection found, else None."""
    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS

    def matches_any(text: str) -> bool:
        return any(re.search(p, text) for p in all_patterns)

    # 1. Base64 decode candidates
    for m in _BASE64_CANDIDATE.finditer(content):
        candidate = m.group(0)
        # Pad to valid base64 length
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if matches_any(decoded):
                return "base64"
        except Exception:
            pass

    # 2. ROT13
    rot13 = codecs.encode(content, "rot_13")
    if matches_any(rot13):
        return "rot13"

    # 3. Unicode homoglyph normalization
    normalized = unicodedata.normalize("NFKC", content)
    if normalized != content and matches_any(normalized):
        return "homoglyph"

    # 4. Hex-encoded sequences
    hex_match = _HEX_PATTERN.search(content)
    if hex_match:
        try:
            decoded_hex = bytes.fromhex(hex_match.group(0).replace("\\x", "")).decode(
                "utf-8", errors="ignore"
            )
            if matches_any(decoded_hex):
                return "hex"
        except Exception:
            pass

    return None


async def detect_injection(
    event: dict,
    last_tool_output: str | None = None,
    tenant_id: str | None = None,
) -> list["Finding"]:
    findings = []
    messages = (event.get("payload") or {}).get("messages", [])
    if not isinstance(messages, list):
        messages = []
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

        # PI-05a — Code injection pattern in prompt (non-system messages only)
        if msg.get("role") not in ("system",):
            for pat in _CODE_INJECTION_PATTERNS:
                m = re.search(pat, content)
                if m:
                    findings.append(_build_finding(event, "PI-05a", content[:200]))
                    break

        # PI-07a — Multimodal content with injection signal
        raw_content = msg.get("content")
        if isinstance(raw_content, list):
            has_image = any(
                isinstance(part, dict) and part.get("type") in ("image_url", "image")
                for part in raw_content
            )
            if has_image and has_partial_injection_signal(content):
                findings.append(
                    _build_finding(
                        event,
                        "PI-07a",
                        content[:200],
                        detail="Multimodal message with injection-adjacent text",
                    )
                )

        # PI-08a — Adversarial suffix (high-entropy tail)
        tail = content[-100:]
        if len(tail) >= 40:
            H = _char_entropy(tail)
            non_ascii_or_special = bool(
                re.search(r"[^\x00-\x7F]", tail)
                or re.search(r"[!@#$%^&*()_+={}\[\]|\\:;\"'<>,.?/~`]{3,}", tail)
            )
            if H > 4.5 and non_ascii_or_special:
                findings.append(
                    _build_finding(
                        event,
                        "PI-08a",
                        tail[:200],
                        detail=f"High-entropy suffix detected (H={H:.2f})",
                    )
                )

        # PI-09a — Obfuscated/encoded injection
        method = _check_pi09a(content)
        if method:
            findings.append(
                _build_finding(
                    event,
                    "PI-09a",
                    content[:200],
                    detail=f"Obfuscated injection detected (method: {method})",
                )
            )

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
