"""Encoding-and-obfuscation patterns.

Runs of hex-escapes and base64-shaped candidate strings — cheap pre-filters
before attempting to decode and re-scan against injection patterns.
"""
from __future__ import annotations

import re

# Byte-string hex escape, four or more in a row (e.g. `\x69\x67\x6e...`).
# Used by PI-01c / PI-09a to flag encoded payloads before decoding.
HEX_PATTERN: re.Pattern[str] = re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.IGNORECASE)


# Base64 candidate — any run of 20+ base64-alphabet chars, optionally padded.
# Length gate is intentionally small: short candidates are decoded and
# discarded downstream if they don't yield readable text.
BASE64_CANDIDATE: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
