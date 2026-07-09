"""Prompt-injection patterns.

Two variants exist historically and are both preserved here — see the
divergence note below. Prefer the canonical variant for new code.
"""
from __future__ import annotations

import re

# ─────────────────────────────────────────────────────────────────────────────
# Instruction / directive patterns (canonical — was duplicated in
# online.py `_INDIRECT_INJECTION` and injection.py `INSTRUCTION_PATTERNS`)
# ─────────────────────────────────────────────────────────────────────────────

INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(instruction|prompt|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Role-override phrases (broader than INSTRUCTION_PATTERNS — specifically
# targets "ignore previous system instructions" and persona takeover phrases)
# ─────────────────────────────────────────────────────────────────────────────

ROLE_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    # "ignore previous/above/prior system instructions"
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)"),
    # "pretend / act / behave as … without restriction/limit/filter"
    re.compile(r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)"),
    # "you must/should/will do/execute/perform/run"
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    # "new instruction / new task / new directive / new command"
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    # "override / bypass / circumvent filter/restriction/policy"
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Delimiter smuggling — [system] tokens, chat template control tokens,
# system markers embedded in user content.
# ─────────────────────────────────────────────────────────────────────────────

DELIMITER_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)\[system\]|\\<system\\>|###\s*system|</s>|<\|im_start\|>|<\|im_end\|>"
    r"|```\s*system|---\s*system\s*---|<<SYS>>|\[INST\]"
)


# ─────────────────────────────────────────────────────────────────────────────
# Divergence note (see registry/overlaps.md)
#
# `INSTRUCTION_PATTERNS` (4 patterns) is a strict subset of
# `ROLE_OVERRIDE_PATTERNS` (5 patterns). Historically:
#   * `detectors/online.py` used the ROLE_OVERRIDE set for PI-01a and the
#     INSTRUCTION set for PI-02a (indirect injection through retrieved content)
#   * `detectors/injection.py` used the INSTRUCTION set as a generic
#     "instruction-like content" filter for AGH-04a and the encoded-injection
#     rescan (PI-01c / PI-09a)
#
# Both variants are retained under these names to preserve exact behaviour of
# the current codepaths. Convergence to a single canonical set is queued for
# when a calibrated model classifier lands — precise regex boundaries become
# less critical, and there we can pick one authoritative set with data support.
# ─────────────────────────────────────────────────────────────────────────────
