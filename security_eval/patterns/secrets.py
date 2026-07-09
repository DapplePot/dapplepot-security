"""Secret / credential / token patterns.

Used by SID-01a (API keys in output), SID-01b (secrets in tool params),
SID-01c (JWTs). The primary consumer today is `detectors/online.py`; the
extended record-based catalog in `detectors/disclosure.py` (`PII_PATTERNS`,
`_TOOL_PARAM_PATTERNS`) is metadata-rich and stays there — but its underlying
regexes come from here.
"""
from __future__ import annotations

import re

# ─────────────────────────────────────────────────────────────────────────────
# API keys / credential-shaped strings.
# ─────────────────────────────────────────────────────────────────────────────

# Provider-specific formats: OpenAI-ish `sk-`, AWS `AKIA`, Google `AIza`.
API_KEY_PROVIDER_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35})"
)

# Extended provider set — used by the disclosure detector's richer PII_PATTERNS
# list. Adds GitHub PATs and requires anchored word boundaries.
API_KEY_PROVIDER_EXTENDED: re.Pattern[str] = re.compile(
    r"\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16}|Bearer\s+[A-Za-z0-9\-._~+/]{32,})\b"
)

# Credential field pattern: `password: hunter2`, `api-key = ...`, etc.
CREDENTIAL_FIELD_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(password|passwd|secret|api[_\-]key)\s*[:=]\s*\S{8,}"
)

# OAuth / API bearer token (loose form — matches "Bearer <anything>" in output).
BEARER_TOKEN_PATTERN: re.Pattern[str] = re.compile(
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"
)

# ─────────────────────────────────────────────────────────────────────────────
# The three-regex list used by `detectors/online.py` for SID-01a real-time
# scanning. Kept as a list rather than a single alternation to preserve the
# per-pattern match-span semantics the online detector relies on.
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS: list[re.Pattern[str]] = [
    API_KEY_PROVIDER_PATTERN,
    CREDENTIAL_FIELD_PATTERN,
    BEARER_TOKEN_PATTERN,
]


# ─────────────────────────────────────────────────────────────────────────────
# JWT — three base64url segments joined by dots, first segment starts `eyJ`.
# Widely quoted; the length gate rejects the header alone.
# ─────────────────────────────────────────────────────────────────────────────

JWT_PATTERN: re.Pattern[str] = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)


# ─────────────────────────────────────────────────────────────────────────────
# Credentials embedded in tool input as JSON fields:
#   "password": "…"  /  "api_key": "…"  /  "auth_token": "…"
# Used by SID-01b.
# ─────────────────────────────────────────────────────────────────────────────

CREDENTIAL_JSON_FIELD_PATTERN: re.Pattern[str] = re.compile(
    r'(?i)"(?:password|passwd|secret|api[_\-]?key|auth(?:_token)?|access[_\-]?key|private[_\-]?key|token)"\s*:\s*"[^"]{8,}"'
)


# ─────────────────────────────────────────────────────────────────────────────
# Credentials embedded in URL — `postgresql://user:password@host`. SID-01b
# tool_input scan.
# ─────────────────────────────────────────────────────────────────────────────

URL_EMBEDDED_CREDENTIAL_PATTERN: re.Pattern[str] = re.compile(
    r'://[^:@\s"\']{1,}:[^@\s"\']{6,}@'
)


# ─────────────────────────────────────────────────────────────────────────────
# Credential-hash keyword pattern used by IPA-05a (identity sharing across
# users): matches "password=…", "token: …", "api_key := …" style in
# serialised tool_input.
# ─────────────────────────────────────────────────────────────────────────────

CREDENTIAL_KEYWORD_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(password|token|secret|api_key|ssh_key|bearer)\s*[:=]\s*\S+"
)
