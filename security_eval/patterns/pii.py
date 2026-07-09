"""PII detection patterns — phone, email, SSN, credit card, DOB.

Two shapes exist:

* Bare regex list (this module) — used by `detectors/online.py` for real-time
  scanning where match-counting is enough to fire SID-02a (co-occurrence).
* Record catalogue with metadata — lives in `detectors/disclosure.py` as
  `PII_PATTERNS`, mapping each regex to a sub-check ID + label + severity.
  That structure uses the same underlying regex strings; extract as needed.
"""
from __future__ import annotations

import re


# North-American phone: NNN[- .]NNN[- .]NNNN with optional country/area
# groupings. Loose by design — SID-02a fires on co-occurrence, not on this
# alone.
PHONE_PATTERN: re.Pattern[str] = re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")


# Email — RFC-shape approximate. Deliberately anchored to word boundaries so
# short JSON-embedded strings don't fire.
EMAIL_PATTERN: re.Pattern[str] = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)


# US Social Security Number — SID-02c. Strict version (disclosure.py) excludes
# obvious placeholders (000-, 666-, 9xx-); the online.py variant is lenient
# for co-occurrence scanning.
SSN_PATTERN: re.Pattern[str] = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

SSN_STRICT_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)


# Credit card — Visa / Mastercard / Amex — Luhn not enforced (SID-02b relies
# on prefix + length; false positives are acceptable for co-occurrence).
CREDIT_CARD_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
)


# Date-of-birth — prefix-keyed to avoid every calendar date lighting up.
DOB_PATTERN: re.Pattern[str] = re.compile(r"(?i)\b(?:date\s+of\s+birth|dob)\s*[:\-]")


# North-American phone — E.164-ish variant. Broader than PHONE_PATTERN: accepts
# an optional country code, parens around the area code, and interior whitespace
# spans. Used by SID-02a's disclosure catalogue where a false positive is
# cheaper than a miss.
PHONE_E164_PATTERN: re.Pattern[str] = re.compile(
    r"\+?1?\s*[-.]?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)


# ─────────────────────────────────────────────────────────────────────────────
# The four-regex list used by SID-02a co-occurrence check in `online.py`.
# Fires when ≥ 2 of these match in the same text block.
# ─────────────────────────────────────────────────────────────────────────────

PII_PATTERNS: list[re.Pattern[str]] = [
    PHONE_PATTERN,
    EMAIL_PATTERN,
    SSN_PATTERN,
    CREDIT_CARD_PATTERN,
]
