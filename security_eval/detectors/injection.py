"""Injection detector — runs on llm_start and tool_end events.

OW-LLM01 sub-checks emitted here:
  PI-01a  Role-override phrase match          (INJ-001, INJ-002, blocklist)
  PI-01b  Delimiter smuggling                 (INJ-005)
  PI-01c  Encoded / obfuscated payload        (base64 + hex; post-session fallback)
  PI-02a  Web-fetched content with instruction (INJ-004 indirect injection)
  PI-02c  File / attachment payload injection  (document/file content blocks)
  PI-03a  API response carries directives      (tool_end; API/HTTP tool output)
  PI-03b  DB query result embeds prompt fragment (tool_end; DB/SQL tool output)
  PI-05a  Code injection pattern in prompt    (v3)
  PI-07a  Multimodal content with injection   (v3)
  PI-08a  Adversarial suffix / high-entropy   (v3)
  PI-09a  Obfuscated/encoded injection        (ROT13 + homoglyph; v3)

PI-01c vs PI-09a split:
  PI-01c  base64 decode → injection pattern match
          hex-escape (\\xNN x4+) → injection pattern match
  PI-09a  ROT13 transform → injection pattern match
          NFKC homoglyph normalisation → injection pattern match

PI-02a vs PI-02c vs PI-03a:
  PI-02a  injection in tool_end output echoed back into llm_start (80-char overlap)
  PI-02c  injection inside an uploaded document/file content block in the user message
  PI-03a  injection pattern found directly in an API/HTTP tool_end response body
  PI-03b  injection pattern found directly in a DB/SQL tool_end result row
          (both fire on the tool_end itself; no echo required)
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
    from security_eval.findings import Finding

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
    "PI-01c": {
        "check_label": "Encoded / obfuscated payload",
        "check_score": 75,
        "severity": "high",
        "confidence_tier": "high",
    },
    "PI-02c": {
        "check_label": "File / attachment payload injection",
        "check_score": 80,
        "severity": "high",
        "confidence_tier": "high",
    },
    "PI-03a": {
        "check_label": "API response carries directives",
        "check_score": 88,
        "severity": "high",
        "confidence_tier": "high",
    },
    "PI-03b": {
        "check_label": "DB query result embeds prompt fragment",
        "check_score": 82,
        "severity": "high",
        "confidence_tier": "high",
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
        "name": "Instruction suppression phrase",
        "pattern": r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)",
    },
    {
        "sub_check_id": "PI-01a",
        "name": "Persona override phrase",
        "pattern": r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)",
    },
    {
        "sub_check_id": "PI-01b",
        "name": "Delimiter / turn-separator token",
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
    from security_eval.findings import Finding
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


def _extract_document_texts(msg: dict) -> list[str]:
    """Extract text from document/file content blocks in a message (PI-02c).

    Handles:
      {"type": "document", "source": {"type": "text", "data": "<plaintext>"}}
      {"type": "document", "source": {"type": "base64", "data": "<b64>"}}
      {"type": "file", ...} — same structure
    Also extracts any standalone "text" parts that appear alongside a document
    block (common when an agent framework inlines parsed file content as a text
    part next to the original document block).
    """
    raw_content = msg.get("content")
    if not isinstance(raw_content, list):
        return []

    texts: list[str] = []
    has_doc = False

    for part in raw_content:
        if not isinstance(part, dict):
            continue
        ptype = part.get("type", "")

        if ptype in ("document", "file"):
            has_doc = True
            source = part.get("source") or {}
            src_type = source.get("type", "")
            data = source.get("data", "")

            if src_type == "text":
                texts.append(str(data))
            elif src_type == "base64":
                try:
                    texts.append(
                        base64.b64decode(data).decode("utf-8", errors="ignore")
                    )
                except Exception:
                    pass

            # Some frameworks put extracted text directly on the block
            if part.get("text"):
                texts.append(str(part["text"]))

    # Text parts that sit alongside a document block are likely parsed file output
    if has_doc:
        for part in raw_content:
            if isinstance(part, dict) and part.get("type") == "text":
                t = str(part.get("text", ""))
                if t and t not in texts:
                    texts.append(t)

    return texts


# PI-03a: tool names that indicate an outbound API/HTTP call
_API_TOOL_RE = re.compile(
    r"(?i)^(http|api|rest|fetch|request|get_|post_|put_|patch_|delete_|"
    r"call_|invoke_|url_|web_|curl|webhook|endpoint)"
)

# PI-03b: tool names that indicate a database query
_DB_TOOL_RE = re.compile(
    r"(?i)(sql|db_|database|query|execute_sql|run_query|select_|"
    r"pg_|postgres|mysql|sqlite|mongo|dynamo|bigquery|snowflake|"
    r"lookup|search_db|db_lookup|table_scan)"
)


def detect_api_response_injection(event: dict) -> list["Finding"]:
    """Scan tool_end output for injection patterns in API/HTTP response bodies (PI-03a).

    Fires when:
      1. The tool_name matches _API_TOOL_RE — indicating an outbound HTTP/API call.
      2. The tool_end output (the API response body) contains a role-override or
         instruction pattern from _REGEX_SIGNATURES + INSTRUCTION_PATTERNS.

    This catches cases where a third-party API endpoint (compromised or adversarial)
    embeds injection directives in its JSON/XML response body.  Unlike PI-02a, there
    is no overlap/echo requirement — the finding fires on the tool_end event directly
    when the response body contains the directive.
    """
    if event.get("event_type") != "tool_end":
        return []

    tool_name = event.get("tool_name") or (event.get("payload") or {}).get("tool_name", "")
    if not tool_name or not _API_TOOL_RE.search(str(tool_name)):
        return []

    payload = event.get("payload") or {}
    raw_output = payload.get("tool_output", "")
    output_text = json.dumps(raw_output) if isinstance(raw_output, dict) else str(raw_output)

    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS

    from security_eval.findings import Finding
    for pat in all_patterns:
        m = re.search(pat, output_text)
        if m:
            return [Finding(
                tenant_id=event.get("tenant_id", ""),
                session_id=event["session_id"],
                event_id=event["event_id"],
                event_type=event["event_type"],
                owasp_signal_id="OW-LLM01",
                sub_check_id="PI-03a",
                check_label="API response carries directives",
                check_score=88,
                category="prompt_injection",
                severity="high",
                matched_text=m.group(0)[:200],
                detail=f"Injection directive in API response body from tool {tool_name!r}: {m.group(0)[:80]}",
                detection_phase="post_session",
                confidence_tier="high",
            )]
    return []


def detect_db_result_injection(event: dict) -> list["Finding"]:
    """Scan tool_end output for injection patterns in DB/SQL query results (PI-03b).

    Fires when:
      1. The tool_name matches _DB_TOOL_RE — indicating a database query call.
      2. The tool_end output (query result rows) contains a role-override or
         instruction pattern from _REGEX_SIGNATURES + INSTRUCTION_PATTERNS.

    An attacker poisons a database row (via a prior write, SQL injection, or
    compromised seed data) with an injection directive stored as a column value.
    When the agent queries that table and the row is returned in tool_output,
    the directive is present in the agent's context and may be acted upon.

    Unlike PI-02a, there is no overlap/echo requirement — the finding fires
    directly on the tool_end event when the query result contains the directive.
    """
    if event.get("event_type") != "tool_end":
        return []

    tool_name = event.get("tool_name") or (event.get("payload") or {}).get("tool_name", "")
    if not tool_name or not _DB_TOOL_RE.search(str(tool_name)):
        return []

    payload = event.get("payload") or {}
    raw_output = payload.get("tool_output", "")
    output_text = json.dumps(raw_output) if isinstance(raw_output, (dict, list)) else str(raw_output)

    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS

    from security_eval.findings import Finding
    for pat in all_patterns:
        m = re.search(pat, output_text)
        if m:
            return [Finding(
                tenant_id=event.get("tenant_id", ""),
                session_id=event["session_id"],
                event_id=event["event_id"],
                event_type=event["event_type"],
                owasp_signal_id="OW-LLM01",
                sub_check_id="PI-03b",
                check_label="DB query result embeds prompt fragment",
                check_score=82,
                category="prompt_injection",
                severity="high",
                matched_text=m.group(0)[:200],
                detail=f"Injection directive in DB result from tool {tool_name!r}: {m.group(0)[:80]}",
                detection_phase="post_session",
                confidence_tier="high",
            )]
    return []


def _check_pi01c(content: str) -> str | None:
    """Return 'base64' or 'hex' if an encoded injection is found (PI-01c), else None.

    Only tests base64 decode and hex-escape decode — the two transforms that
    correspond to PI-01c in the signal registry and the online detector.
    ROT13 and homoglyph transforms belong to PI-09a.
    """
    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS

    def matches_any(text: str) -> bool:
        return any(re.search(p, text) for p in all_patterns)

    # 1. Base64 decode candidates
    for m in _BASE64_CANDIDATE.finditer(content):
        candidate = m.group(0)
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if matches_any(decoded):
                return "base64"
        except Exception:
            pass

    # 2. Hex-escape sequences (\xNN x4+)
    hex_match = _HEX_PATTERN.search(content)
    if hex_match:
        try:
            decoded_hex = bytes.fromhex(
                hex_match.group(0).replace("\\x", "")
            ).decode("utf-8", errors="ignore")
            if matches_any(decoded_hex):
                return "hex"
        except Exception:
            pass

    return None


def _check_pi09a(content: str) -> str | None:
    """Return 'rot13' or 'homoglyph' if an obfuscated injection is found (PI-09a), else None.

    Only tests ROT13 and Unicode homoglyph normalisation — the two transforms that
    distinguish PI-09a from PI-01c.  Base64 and hex-escape detection belong to
    PI-01c (_check_pi01c) and are intentionally excluded here to avoid duplicate
    findings for the same content.
    """
    all_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS

    def matches_any(text: str) -> bool:
        return any(re.search(p, text) for p in all_patterns)

    # 1. ROT13
    rot13 = codecs.encode(content, "rot_13")
    if matches_any(rot13):
        return "rot13"

    # 2. Unicode homoglyph normalization (NFKC)
    normalized = unicodedata.normalize("NFKC", content)
    if normalized != content and matches_any(normalized):
        return "homoglyph"

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
                findings.append(_build_finding(
                    event, sig["sub_check_id"], content[:200],
                    detail=sig.get("name"),
                ))

        # Blocklist scan → PI-01a (role-override category)
        hit = _blocklist_scan(content, blocklist)
        if hit:
            findings.append(_build_finding(
                event, "PI-01a", hit[:200],
                detail=f"Blocklist phrase matched: {hit[:80]}",
            ))

        # PI-01c — Encoded / obfuscated payload (base64 + hex; post-session fallback)
        pi01c_method = _check_pi01c(content)
        if pi01c_method:
            findings.append(
                _build_finding(
                    event,
                    "PI-01c",
                    content[:200],
                    detail=f"Encoded payload detected (method: {pi01c_method})",
                )
            )

        # Indirect injection — PI-02a
        if (last_tool_output
                and _overlap_chars(content, last_tool_output) >= _INDIRECT_MIN_OVERLAP_CHARS
                and any(re.search(p, content) for p in INSTRUCTION_PATTERNS)):
            findings.append(_build_finding(
                event, "PI-02a", content[:200],
                detail="Injection directive found in retrieved tool content",
            ))

        # PI-05a — Code injection pattern in prompt (non-system messages only)
        if msg.get("role") not in ("system",):
            for pat in _CODE_INJECTION_PATTERNS:
                m = re.search(pat, content)
                if m:
                    findings.append(_build_finding(
                        event, "PI-05a", content[:200],
                        detail=f"Code execution pattern: {m.group(0)[:80]}",
                    ))
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

        # PI-02c — File / attachment payload injection
        _all_injection_patterns = [sig["pattern"] for sig in _REGEX_SIGNATURES] + INSTRUCTION_PATTERNS
        for doc_text in _extract_document_texts(msg):
            for pat in _all_injection_patterns:
                m = re.search(pat, doc_text)
                if m:
                    findings.append(
                        _build_finding(
                            event,
                            "PI-02c",
                            doc_text[:200],
                            detail=f"Injection pattern in file/document content: {m.group(0)[:80]}",
                        )
                    )
                    break

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
