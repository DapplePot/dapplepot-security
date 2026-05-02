"""Online detectors — real-time threat detection for SDK.

Moved from SDK interceptor. Runs on events as they occur.
Supports redact_keys to prevent sensitive data exposure in findings.
"""
from __future__ import annotations

import base64
import math
import re
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from consumers.security_eval.findings import Finding

logger = logging.getLogger(__name__)

# Pattern constants (from SDK interceptor)
_ROLE_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)"),
    re.compile(r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]

_DELIMITER_PATTERNS = re.compile(
    r"(?i)\[system\]|\\<system\\>|###\s*system|</s>|<\|im_start\|>|<\|im_end\|>"
    r"|```\s*system|---\s*system\s*---|<<SYS>>|\[INST\]"
)

_HEX_PATTERN = re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.IGNORECASE)
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

_SECRET_PATTERNS = [
    re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35})"),
    re.compile(r"(?i)(password|passwd|secret|api[_\-]key)\s*[:=]\s*\S{8,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
]

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

_PII_PATTERNS = [
    re.compile(r"\b\d{3}[-.\\s]?\d{3}[-.\\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
]

_CODE_INJECTION = [
    re.compile(r"(?i)(import\s+os|import\s+subprocess|__import__|eval\s*\(|exec\s*\()"),
    re.compile(r"(?i)(require\s*\(\s*['\"]child_process|\.exec\s*\(|spawn\s*\()"),
]

_SHELL_PATTERNS = re.compile(
    r"(?i)(os\.system|subprocess\.\w+|eval\s*\(|exec\s*\(|\$\([^)]+\)|&&|\|\||;\s*\w)"
)

_INDIRECT_INJECTION = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(instruction|prompt|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]

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
    "PI-02a": {
        "check_label": "Web-fetched content with injection pattern",
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
    "PI-08a": {
        "check_label": "Adversarial suffix (high-entropy tail)",
        "check_score": 75,
        "severity": "high",
        "confidence_tier": "medium",
    },
    "SID-01a": {
        "check_label": "API key / token pattern in output",
        "check_score": 95,
        "severity": "critical",
        "confidence_tier": "deterministic",
    },
    "SID-01c": {
        "check_label": "JWT / session token in agent message",
        "check_score": 90,
        "severity": "critical",
        "confidence_tier": "deterministic",
    },
    "SID-02a": {
        "check_label": "Name + email + phone co-occurrence",
        "check_score": 75,
        "severity": "high",
        "confidence_tier": "high",
    },
    "IOH-01a": {
        "check_label": "Shell command pattern in output",
        "check_score": 90,
        "severity": "critical",
        "confidence_tier": "deterministic",
    },
}


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


def _build_finding(
    event: dict,
    sub_check_id: str,
    matched_text: str,
    redact_keys: set | None = None,
) -> dict:
    """Build finding dict with optional redact_keys support."""
    meta = _SUB_CHECKS[sub_check_id]
    finding = {
        'owasp_signal_id': 'OW-LLM01' if sub_check_id.startswith('PI') or sub_check_id.startswith('SID') else 'OW-LLM05',
        'sub_check_id': sub_check_id,
        'check_label': meta['check_label'],
        'check_score': meta['check_score'],
        'category': 'prompt_injection' if sub_check_id.startswith('PI') else ('data_disclosure' if sub_check_id.startswith('SID') else 'output_handling'),
        'severity': meta['severity'],
        'matched_text': matched_text,
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
    
    return findings
