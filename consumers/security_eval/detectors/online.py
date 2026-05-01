"""Online security checks — moved from dapplepot-sdk/interceptor.py.

All detection logic lives here. The SDK calls POST /v1/online-check on the
security service (via the API proxy) instead of running these checks locally.

Entry point: run_online_checks()
"""
from __future__ import annotations

import base64
import math
import re
from typing import Any

# ─── Patterns ─────────────────────────────────────────────────────────────────

_ROLE_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)"),
    re.compile(r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]

_DELIMITER_PATTERNS = re.compile(
    r"(?i)\[system\]|\<system\>|###\s*system|</s>|<\|im_start\|>|<\|im_end\|>"
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

_INDIRECT_INJECTION = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(instruction|prompt|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]

_CHECK_EVENT_TYPES: dict[str, frozenset[str]] = {
    'PI-01a': frozenset({'llm_start', 'tool_start'}),
    'PI-01b': frozenset({'llm_start', 'tool_start'}),
    'PI-01c': frozenset({'llm_start', 'tool_start'}),
    'PI-02a': frozenset({'tool_end'}),
    'PI-05a': frozenset({'llm_start', 'tool_start'}),
    'PI-08a': frozenset({'llm_start'}),
    'SID-01a': frozenset({'llm_end', 'tool_end'}),
    'SID-01c': frozenset({'llm_end', 'tool_end'}),
    'SID-02a': frozenset({'llm_end', 'tool_end'}),
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

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


# ─── Per-sub-check detectors ──────────────────────────────────────────────────

def _check_pi01a(content: str) -> dict | None:
    for pat in _ROLE_OVERRIDE_PATTERNS:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-01a',
                'check_label': 'Role-override phrase match', 'check_score': 85,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': m.group()[:200], 'confidence_tier': 'high',
            }
    return None


def _check_pi01b(content: str) -> dict | None:
    m = _DELIMITER_PATTERNS.search(content)
    if m:
        return {
            'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-01b',
            'check_label': 'Delimiter smuggling', 'check_score': 90,
            'category': 'prompt_injection', 'severity': 'critical',
            'matched_text': m.group()[:200], 'confidence_tier': 'deterministic',
        }
    return None


def _check_pi01c(content: str) -> dict | None:
    if _HEX_PATTERN.search(content) or _is_base64_encoded(content):
        return {
            'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-01c',
            'check_label': 'Encoded / obfuscated payload', 'check_score': 75,
            'category': 'prompt_injection', 'severity': 'high',
            'matched_text': '[encoded content detected]', 'confidence_tier': 'high',
        }
    return None


def _check_pi02a(content: str) -> dict | None:
    for pat in _INDIRECT_INJECTION:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-02a',
                'check_label': 'Web-fetched content with injection pattern', 'check_score': 70,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': m.group()[:200], 'confidence_tier': 'high',
            }
    return None


def _check_pi05a(content: str) -> dict | None:
    for pat in _CODE_INJECTION:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-05a',
                'check_label': 'Code injection pattern in prompt', 'check_score': 80,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': m.group()[:200], 'confidence_tier': 'high',
            }
    return None


def _check_pi08a(content: str) -> dict | None:
    if len(content) > 80:
        tail = content[-60:]
        if _char_entropy(tail) > 4.5:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-08a',
                'check_label': 'Adversarial suffix (high-entropy tail)', 'check_score': 75,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': tail[:200], 'confidence_tier': 'medium',
            }
    return None


def _check_sid01a(content: str) -> dict | None:
    for pat in _SECRET_PATTERNS:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM02', 'sub_check_id': 'SID-01a',
                'check_label': 'API key / token pattern in output', 'check_score': 95,
                'category': 'data_disclosure', 'severity': 'critical',
                'matched_text': m.group()[:200], 'confidence_tier': 'deterministic',
            }
    return None


def _check_sid01c(content: str) -> dict | None:
    m = _JWT_PATTERN.search(content)
    if m:
        return {
            'owasp_signal_id': 'OW-LLM02', 'sub_check_id': 'SID-01c',
            'check_label': 'JWT / session token in agent message', 'check_score': 90,
            'category': 'data_disclosure', 'severity': 'critical',
            'matched_text': m.group()[:200], 'confidence_tier': 'deterministic',
        }
    return None


def _check_sid02a(content: str) -> dict | None:
    hits = sum(1 for pat in _PII_PATTERNS if pat.search(content))
    if hits >= 2:
        return {
            'owasp_signal_id': 'OW-LLM02', 'sub_check_id': 'SID-02a',
            'check_label': 'Name + email + phone co-occurrence', 'check_score': 75,
            'category': 'data_disclosure', 'severity': 'high',
            'matched_text': '[multiple PII patterns detected]', 'confidence_tier': 'high',
        }
    return None


_CHECKER_MAP: dict[str, Any] = {
    'PI-01a':  _check_pi01a,
    'PI-01b':  _check_pi01b,
    'PI-01c':  _check_pi01c,
    'PI-02a':  _check_pi02a,
    'PI-05a':  _check_pi05a,
    'PI-08a':  _check_pi08a,
    'SID-01a': _check_sid01a,
    'SID-01c': _check_sid01c,
    'SID-02a': _check_sid02a,
}

# ─── Entry point ──────────────────────────────────────────────────────────────

def run_online_checks(
    event_type: str,
    payload: dict[str, Any],
    enabled_checks: dict[str, str],
    tool_manifest: list[str],
    max_tool_calls: int | None,
    tool_call_count: int,
) -> list[dict]:
    """Run all enabled online checks for one event.

    Returns list of finding dicts, each with an 'action' key added.
    Called directly by POST /v1/online-check in server/main.py.
    """
    results: list[dict] = []

    # EA-01a and EA-02b — tool-based checks
    if event_type == 'tool_start':
        ea01a_action = enabled_checks.get('EA-01a')
        if ea01a_action and tool_manifest:
            tool_name: str = payload.get('tool_name', '') or ''
            if tool_name and tool_name not in tool_manifest:
                results.append({
                    'owasp_signal_id': 'OW-LLM06', 'sub_check_id': 'EA-01a',
                    'check_label': 'Tool not in approved manifest invoked',
                    'check_score': 80, 'category': 'excessive_agency', 'severity': 'high',
                    'matched_text': tool_name[:200], 'confidence_tier': 'deterministic',
                    'detection_phase': 'online', 'action': ea01a_action,
                })

        ea02b_action = enabled_checks.get('EA-02b')
        if ea02b_action and max_tool_calls is not None and tool_call_count > max_tool_calls:
            excess = tool_call_count - max_tool_calls
            results.append({
                'owasp_signal_id': 'OW-LLM06', 'sub_check_id': 'EA-02b',
                'check_label': 'Tool calls exceed configured session limit',
                'check_score': min(65 + excess * 2, 85),
                'category': 'excessive_agency', 'severity': 'high',
                'matched_text': f'call #{tool_call_count} (limit: {max_tool_calls})',
                'confidence_tier': 'deterministic', 'detection_phase': 'online',
                'action': ea02b_action,
            })

    # Content-based checks
    content_checks = {
        sid: action for sid, action in enabled_checks.items()
        if sid in _CHECKER_MAP
    }
    if not content_checks:
        return results

    texts = _extract_content(event_type, payload)
    if not texts:
        return results

    for sub_check_id, action in content_checks.items():
        allowed = _CHECK_EVENT_TYPES.get(sub_check_id)
        if allowed and event_type not in allowed:
            continue
        checker = _CHECKER_MAP.get(sub_check_id)
        if not checker:
            continue
        for text in texts:
            finding = checker(text)
            if finding:
                finding['detection_phase'] = 'online'
                finding['action'] = action
                results.append(finding)
                break  # one finding per sub-check per event

    return results
