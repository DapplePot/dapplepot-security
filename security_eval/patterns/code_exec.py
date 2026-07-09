"""Code-execution and shell-command patterns.

Two variants of `CODE_INJECTION_PATTERNS` are preserved. See the divergence
note at the end of this file.
"""
from __future__ import annotations

import re


# ─────────────────────────────────────────────────────────────────────────────
# Code-injection patterns (STRICT — 2 patterns)
#
# Original: `detectors/online.py` `_CODE_INJECTION`.
# Used online (SDK real-time) — narrower to keep the false-positive rate low
# on prompt content.
# ─────────────────────────────────────────────────────────────────────────────

CODE_INJECTION_PATTERNS_STRICT: list[re.Pattern[str]] = [
    re.compile(r"(?i)(import\s+os|import\s+subprocess|__import__|eval\s*\(|exec\s*\()"),
    re.compile(r"(?i)(require\s*\(\s*['\"]child_process|\.exec\s*\(|spawn\s*\()"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Code-injection patterns (EXTENDED — 3 patterns)
#
# Original: `detectors/injection.py` `_CODE_INJECTION_PATTERNS`.
# Superset of STRICT — adds `os.system`, `subprocess.\w+`, `open(…, 'w')`.
# Used post-session for PI-05a where the whole session is available and the
# lower precision is acceptable.
# ─────────────────────────────────────────────────────────────────────────────

CODE_INJECTION_PATTERNS_EXTENDED: list[re.Pattern[str]] = [
    re.compile(r"(?i)(import\s+os|import\s+subprocess|__import__|eval\s*\(|exec\s*\()"),
    re.compile(r"(?i)(os\.system|subprocess\.\w+|open\s*\(.+['\"]w['\"])"),
    re.compile(r"(?i)(require\s*\(\s*['\"]child_process|\.exec\s*\(|spawn\s*\()"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Shell command / metacharacter pattern.
#
# Original: `detectors/online.py` `_SHELL_PATTERNS`. Used for IOH-01a — shell
# command indicators in output being passed to a downstream tool.
# ─────────────────────────────────────────────────────────────────────────────

SHELL_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)(os\.system|subprocess\.\w+|eval\s*\(|exec\s*\(|\$\([^)]+\)|&&|\|\||;\s*\w)"
)


# ─────────────────────────────────────────────────────────────────────────────
# Divergence note
#
# STRICT vs EXTENDED differ only in the second-pattern superset (`os.system`,
# `subprocess.\w+`, `open(w)`). The strict variant runs live in Guard where
# false positives cause session termination; extended runs post-session where
# a finding produces an alert. Both retained deliberately.
#
# Convergence: once a calibrated model classifier subsumes the "regex fires
# but is legitimate code" case, both variants can collapse to EXTENDED with a
# model-verified precision threshold.
# ─────────────────────────────────────────────────────────────────────────────
