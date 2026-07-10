"""Online detectors — real-time threat detection for SDK.

Moved from SDK interceptor. Runs on events as they occur.
Supports redact_keys to prevent sensitive data exposure in findings.
"""
from __future__ import annotations

import base64
import codecs
import json as _json_mod
import math
import re
import unicodedata
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from security_eval.findings import Finding

from security_eval.patterns import (
    injection    as _pat_injection,
    obfuscation  as _pat_obfuscation,
    code_exec    as _pat_code,
    secrets      as _pat_secrets,
    pii          as _pat_pii,
)
from security_eval.registry import CHECK_BY_ID

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Pattern references — all definitions live in security_eval.patterns.*
# Local aliases keep the detector logic below unchanged.
# ─────────────────────────────────────────────────────────────────────────────

_ROLE_OVERRIDE_PATTERNS = _pat_injection.ROLE_OVERRIDE_PATTERNS
_INDIRECT_INJECTION    = _pat_injection.INSTRUCTION_PATTERNS
_DELIMITER_PATTERNS    = _pat_injection.DELIMITER_PATTERN
_HEX_PATTERN           = _pat_obfuscation.HEX_PATTERN
_BASE64_CANDIDATE      = _pat_obfuscation.BASE64_CANDIDATE
_SECRET_PATTERNS       = _pat_secrets.SECRET_PATTERNS
_JWT_PATTERN           = _pat_secrets.JWT_PATTERN
_PII_PATTERNS          = _pat_pii.PII_PATTERNS
_CODE_INJECTION        = _pat_code.CODE_INJECTION_PATTERNS_STRICT
_SHELL_PATTERNS        = _pat_code.SHELL_PATTERN

# Check metadata (label / score / severity / confidence_tier) is looked up from
# the registry (CHECK_BY_ID) at finding build time. Previously duplicated as
# `_SUB_CHECKS` here; the local copy drifted from the registry over time (e.g.
# SID-02a confidence_tier, IOH-04a confidence_tier, SID-03b label). Registry
# is source of truth; edit `registry/checks.yaml` and re-run gen_seed.py.

# ── Content-scan patterns (using the shared library where possible) ──
_HTML_JS_PATTERN = re.compile(
    r"(?i)(<script[\s>]|onerror\s*=|onload\s*=|javascript\s*:|<iframe[\s>])"
)
_SQL_FRAGMENT_PATTERN = re.compile(
    r"(?i)\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|"
    r"DROP\s+(TABLE|DATABASE|INDEX)|UNION\s+SELECT)\b"
)
# Financial identifier — Luhn-checkable card numbers (broader than the base pattern).
_FINANCIAL_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
)
# Health / biometric heuristics — SSN + medical terms proxy.
_HEALTH_SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)
_HEALTH_KEYWORDS = re.compile(
    r"(?i)\b(diagnosis|prescription|medical record|patient id|dob\b|biometric|"
    r"fingerprint|genotype|blood type|allergies|medications)\b"
)

# ─────────────────────────────────────────────────────────────────────────────
# Patterns for content-scan checks ported from session-analysis detectors.
# Mirrored 1:1 from the source implementation so a single tuning change lands
# in both pipelines when we consolidate later.
# ─────────────────────────────────────────────────────────────────────────────

# Combined "any injection directive" pattern set. Used by PI-02c, PI-03a, PI-03b,
# PI-09a — each fires when its own event-type / content-source predicate holds
# AND at least one of these patterns matches. Same union as
# `_REGEX_SIGNATURES + INSTRUCTION_PATTERNS` in security_eval/detectors/injection.py.
_INJECTION_ANY_PATTERNS: list = list(_ROLE_OVERRIDE_PATTERNS) + [_DELIMITER_PATTERNS] + list(_INDIRECT_INJECTION)

# PI-03a: tool names that indicate an outbound API/HTTP call.
_API_TOOL_RE = re.compile(
    r"(?i)^(http|api|rest|fetch|request|get_|post_|put_|patch_|delete_|"
    r"call_|invoke_|url_|web_|curl|webhook|endpoint)"
)
# PI-03b: tool names that indicate a database query.
_DB_TOOL_RE = re.compile(
    r"(?i)(sql|db_|database|query|execute_sql|run_query|select_|"
    r"pg_|postgres|mysql|sqlite|mongo|dynamo|bigquery|snowflake|"
    r"lookup|search_db|db_lookup|table_scan)"
)

# PI-07a: partial injection signal used for the multimodal check (weaker set
# than the full injection patterns — matches the source detector's
# `has_partial_injection_signal`).
_PARTIAL_INJECTION_PATTERNS = [
    re.compile(r"(?i)(ignore|forget|disregard).{0,20}(instruction|rule)"),
    re.compile(r"(?i)(act as|you are now|pretend)"),
    re.compile(r"(?i)(new task|new directive|override)"),
]

# SID-03b: stack trace / internal error signatures. Ported from
# security_eval/detectors/disclosure.py::_STACK_TRACE_PATTERNS.
_STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)"),                                 "Python traceback"),
    (re.compile(r"\bat (?:com|org|net|io|java|javax|sun|jdk)\.[a-zA-Z0-9_.]+\([A-Za-z0-9_]+\.java:\d+\)"), "Java/JVM stack frame"),
    (re.compile(r"System\.[A-Za-z]+Exception:"),                                         ".NET exception type"),
    (re.compile(r"\bat [A-Za-z_$][A-Za-z0-9_$.]*\s+\(/[^)]+\.js:\d+:\d+\)"),             "Node.js stack frame"),
    (re.compile(r"/(?:var/app|usr/local/lib|home/[^/\s\"\\]+|srv/app)/[^\s\"\\]{8,}"),   "Internal file path in error"),
    (re.compile(r"(?i)(?:psycopg2\.\w+Error|SQLSTATE\b|ORA-\d{4,}|SQLException\b|OperationalError:)"), "Database error code"),
]

# IOH-04a: insecure code patterns scanned inside fenced code blocks in
# generated output. Ported from security_eval/scorer/llm_signals.py.
_INSECURE_CODE_PATTERNS = [
    re.compile(r"eval\s*\("),
    re.compile(r"(?i)password\s*=\s*['\"][^'\"]+['\"]"),
    re.compile(r"(?i)verify\s*=\s*False"),
    re.compile(r"(?i)shell\s*=\s*True"),
    re.compile(r"(?i)innerHTML\s*="),
    re.compile(r"(?i)SELECT\s.+FROM\s.+WHERE\s.+['\"]?\s*\+\s*"),
    re.compile(r"(?i)pickle\.loads?\s*\("),
    re.compile(r"(?i)yaml\.load\s*\("),
]
_CODE_FENCE_PAT = re.compile(r"```[\s\S]*?```")


def _extract_document_texts(msg: dict) -> list[str]:
    """Extract text embedded inside document/file content parts of an
    LLM-start message (PI-02c source). Handles both `text` and base64
    `source.data`, plus adjacent `text` parts that sit alongside a doc block.
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
                    texts.append(base64.b64decode(data).decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            if part.get("text"):
                texts.append(str(part["text"]))
    if has_doc:
        for part in raw_content:
            if isinstance(part, dict) and part.get("type") == "text":
                t = str(part.get("text", ""))
                if t and t not in texts:
                    texts.append(t)
    return texts


def _has_partial_injection_signal(text: str) -> bool:
    return any(p.search(text) for p in _PARTIAL_INJECTION_PATTERNS)


def _matches_any_injection(text: str) -> bool:
    return any(p.search(text) for p in _INJECTION_ANY_PATTERNS)


def _check_pi09a(content: str) -> str | None:
    """Return 'rot13' or 'homoglyph' if an obfuscated injection is found,
    else None. Base64 and hex-escape belong to PI-01c and are excluded here.
    """
    rot13 = codecs.encode(content, "rot_13")
    if _matches_any_injection(rot13):
        return "rot13"
    normalized = unicodedata.normalize("NFKC", content)
    if normalized != content and _matches_any_injection(normalized):
        return "homoglyph"
    return None



def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    total = len(text)
    return -sum((v / total) * math.log2(v / total) for v in counts.values())


def _is_base64_encoded(text: str) -> bool:
    for m in _BASE64_CANDIDATE.finditer(text):
        candidate = m.group()
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if len(decoded) > 10 and any(p.search(decoded) for p in _ROLE_OVERRIDE_PATTERNS):
                return True
        except Exception:
            pass
    return False


def _extract_content(event_type: str, payload: dict[str, Any]) -> list[str]:
    """Extract text blobs to scan from the event payload."""
    texts: list[str] = []
    if event_type in ('llm_start', 'chat_model_start'):
        # `messages` in the compact llm_start shape is a 1-element list
        # containing only the current-turn input. In the legacy shape it's
        # the full accumulated history. Same iteration works for both.
        for msg in payload.get('messages') or []:
            content = msg.get('content', '') if isinstance(msg, dict) else str(msg)
            if content:
                texts.append(str(content))
    elif event_type == 'llm_end':
        c = payload.get('completion')
        if c:
            texts.append(str(c))
    elif event_type == 'tool_start':
        ti = payload.get('tool_input')
        if ti:
            texts.append(str(ti))
    elif event_type == 'tool_end':
        to = payload.get('tool_output')
        if to:
            texts.append(str(to))
    return texts


# Sub-check-prefix → category label (free-string field on Finding, not part
# of the registry taxonomy). Signal ID comes from the registry via CHECK_BY_ID.
_CATEGORY_BY_PREFIX: dict[str, str] = {
    'PI':  'prompt_injection',
    'SID': 'data_disclosure',
    'IOH': 'output_handling',
}


def _build_finding(
    event: dict,
    sub_check_id: str,
    matched_text: str,
    redact_keys: set | None = None,
) -> dict:
    """Build finding dict with optional redact_keys support."""
    meta = CHECK_BY_ID[sub_check_id]
    signal   = meta['signal_id']
    prefix   = sub_check_id.split('-', 1)[0]
    # Category is presentation-only ("prompt_injection", "data_disclosure",
    # "output_handling"); the registry doesn't track it, so keep the
    # prefix-derived mapping local.
    category = _CATEGORY_BY_PREFIX.get(prefix, 'output_handling')
    finding = {
        'owasp_signal_id': signal,
        'sub_check_id':    sub_check_id,
        'check_label':     meta['label'],
        'check_score':     meta['score'],
        'category':        category,
        'severity':        meta['severity'],
        'matched_text':    matched_text,
        'confidence_tier': meta.get('confidence_tier', 'high'),
        'detection_phase': 'online',
    }
    
    # Apply redact_keys if provided
    if redact_keys and isinstance(event.get('payload'), dict):
        payload = event['payload']
        for key in redact_keys:
            if key in payload:
                finding['matched_text'] = '[REDACTED]'
                break
    
    return finding


def detect_online(
    event: dict,
    redact_keys: set | None = None,
) -> list[dict]:
    """Run online checks on event. Returns list of findings."""
    findings = []
    et = event.get('event_type', '')
    payload = event.get('payload', {})
    
    texts = _extract_content(et, payload)
    if not texts:
        return findings
    
    for text in texts:
        # PI-01a: Role-override phrases
        for pat in _ROLE_OVERRIDE_PATTERNS:
            m = pat.search(text)
            if m:
                findings.append(_build_finding(event, 'PI-01a', m.group()[:200], redact_keys))
                break
        
        # PI-01b: Delimiter smuggling
        m = _DELIMITER_PATTERNS.search(text)
        if m:
            findings.append(_build_finding(event, 'PI-01b', m.group()[:200], redact_keys))
        
        # PI-01c: Encoded/obfuscated
        if _HEX_PATTERN.search(text) or _is_base64_encoded(text):
            findings.append(_build_finding(event, 'PI-01c', '[encoded content detected]', redact_keys))
        
        # PI-02a: Indirect injection
        for pat in _INDIRECT_INJECTION:
            m = pat.search(text)
            if m:
                findings.append(_build_finding(event, 'PI-02a', m.group()[:200], redact_keys))
                break
        
        # PI-05a: Code injection
        for pat in _CODE_INJECTION:
            m = pat.search(text)
            if m:
                findings.append(_build_finding(event, 'PI-05a', m.group()[:200], redact_keys))
                break
        
        # PI-08a: Adversarial suffix
        if len(text) > 80:
            tail = text[-60:]
            if _char_entropy(tail) > 4.5:
                findings.append(_build_finding(event, 'PI-08a', tail[:200], redact_keys))
        
        # SID-01a: API keys/tokens
        for pat in _SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                findings.append(_build_finding(event, 'SID-01a', m.group()[:200], redact_keys))
                break
        
        # SID-01c: JWT
        m = _JWT_PATTERN.search(text)
        if m:
            findings.append(_build_finding(event, 'SID-01c', m.group()[:200], redact_keys))
        
        # SID-02a: PII co-occurrence
        hits = sum(1 for pat in _PII_PATTERNS if pat.search(text))
        if hits >= 2:
            findings.append(_build_finding(event, 'SID-02a', '[multiple PII patterns detected]', redact_keys))
        
        # IOH-01a: Shell commands
        m = _SHELL_PATTERNS.search(text)
        if m:
            findings.append(_build_finding(event, 'IOH-01a', m.group()[:200], redact_keys))

        # ── Content signature checks ──

        # SID-01b: secret in tool call params (tool_start only)
        if et == 'tool_start':
            for pat in _SECRET_PATTERNS:
                m = pat.search(text)
                if m:
                    findings.append(_build_finding(event, 'SID-01b', m.group()[:200], redact_keys))
                    break

        # SID-02b: Financial identifiers in output
        if et in ('llm_end', 'tool_end'):
            m = _FINANCIAL_PATTERN.search(text)
            if m:
                findings.append(_build_finding(event, 'SID-02b', m.group()[:200], redact_keys))

        # SID-02c: Health / biometric data — SSN OR (health keyword + adjacent digit)
        if et in ('llm_end', 'tool_end'):
            m = _HEALTH_SSN_PATTERN.search(text)
            if m:
                findings.append(_build_finding(event, 'SID-02c', m.group()[:200], redact_keys))
            elif _HEALTH_KEYWORDS.search(text):
                # Secondary: health keyword + any number → likely PHI
                if re.search(r"\d{3,}", text):
                    findings.append(_build_finding(event, 'SID-02c', '[health context + numeric data]', redact_keys))

        # IOH-01b: HTML / JS in output without escaping
        if et in ('llm_end', 'tool_start'):
            m = _HTML_JS_PATTERN.search(text)
            if m:
                findings.append(_build_finding(event, 'IOH-01b', m.group()[:200], redact_keys))

        # IOH-01c: SQL fragment in output passed to DB
        if et == 'tool_start':
            m = _SQL_FRAGMENT_PATTERN.search(text)
            if m:
                findings.append(_build_finding(event, 'IOH-01c', m.group()[:200], redact_keys))

        # ── Content-scan ports from session-analysis detectors ──

        # PI-09a: obfuscated / encoded injection (ROT13 + homoglyph)
        # Only meaningful on incoming prompt content — fire on llm_start.
        if et in ('llm_start', 'chat_model_start'):
            method = _check_pi09a(text)
            if method:
                findings.append(_build_finding(event, 'PI-09a', text[:200], redact_keys))

        # SID-03b: stack trace / internal error in output
        if et == 'llm_end':
            for pat, _name in _STACK_TRACE_PATTERNS:
                m = pat.search(text)
                if m:
                    findings.append(_build_finding(event, 'SID-03b', m.group()[:200], redact_keys))
                    break

        # IOH-04a: insecure code pattern inside fenced code blocks
        if et == 'llm_end':
            for block in _CODE_FENCE_PAT.findall(text):
                _hit = None
                for pat in _INSECURE_CODE_PATTERNS:
                    m = pat.search(block)
                    if m:
                        _hit = m.group()[:200]
                        break
                if _hit:
                    findings.append(_build_finding(event, 'IOH-04a', _hit, redact_keys))
                    break

    # ── Message-structure checks — need raw payload, not extracted text ──
    # PI-02c and PI-07a inspect message parts (documents, multimodal blocks)
    # that _extract_content flattens into strings, so they read `payload`
    # directly here.
    if et in ('llm_start', 'chat_model_start'):
        messages = payload.get('messages') or []
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict) or msg.get('role') not in ('user', 'human', 'tool'):
                    continue

                # PI-02c: file / attachment payload injection
                for doc_text in _extract_document_texts(msg):
                    hit_pat = None
                    for pat in _INJECTION_ANY_PATTERNS:
                        m = pat.search(doc_text)
                        if m:
                            hit_pat = m.group()[:200]
                            break
                    if hit_pat:
                        findings.append(_build_finding(event, 'PI-02c', hit_pat, redact_keys))
                        break

                # PI-07a: multimodal content + weak injection signal
                raw = msg.get('content')
                if isinstance(raw, list):
                    has_image = any(
                        isinstance(part, dict) and part.get('type') in ('image_url', 'image')
                        for part in raw
                    )
                    if has_image:
                        # Flatten any text parts to run the partial-signal check.
                        text_parts = ' '.join(
                            str(p.get('text', '') if isinstance(p, dict) else p)
                            for p in raw
                        )
                        if _has_partial_injection_signal(text_parts):
                            findings.append(_build_finding(event, 'PI-07a', text_parts[:200], redact_keys))

    # PI-03a / PI-03b: injection directives inside tool_end output. Both are
    # gated by the tool name — API-shaped or DB-shaped names respectively.
    if et == 'tool_end':
        tool_name = str(payload.get('tool_name', '') or '')
        raw_output = payload.get('tool_output', '')
        output_text = _json_mod.dumps(raw_output) if isinstance(raw_output, (dict, list)) else str(raw_output)
        if output_text and tool_name:
            if _API_TOOL_RE.search(tool_name):
                for pat in _INJECTION_ANY_PATTERNS:
                    m = pat.search(output_text)
                    if m:
                        findings.append(_build_finding(event, 'PI-03a', m.group()[:200], redact_keys))
                        break
            if _DB_TOOL_RE.search(tool_name):
                for pat in _INJECTION_ANY_PATTERNS:
                    m = pat.search(output_text)
                    if m:
                        findings.append(_build_finding(event, 'PI-03b', m.group()[:200], redact_keys))
                        break

    return findings
