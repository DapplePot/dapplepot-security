"""Shared detection patterns.

Central home for regexes used across detectors and scorers. Prior to this
module the same patterns were copy-pasted across `detectors/online.py`,
`detectors/injection.py`, `detectors/disclosure.py`, and
`scorer/cross_session.py` — divergence was a real risk (PI-01a's role-override
list differed subtly between the online and post-session codepaths).

Layout:
    patterns/injection.py  — prompt-injection signatures (role override, delimiter smuggling, instruction directives)
    patterns/obfuscation.py — hex escape, base64 candidate
    patterns/code_exec.py  — code-execution primitives (eval/exec, subprocess, shell metacharacters)
    patterns/secrets.py    — API keys, JWTs, credential field names
    patterns/pii.py        — phone / email / SSN / credit-card patterns

Import style:
    from security_eval.patterns import injection as pat_injection
    if pat_injection.ROLE_OVERRIDE_PATTERNS[0].search(text):
        ...

Rule: any regex used by more than one detector belongs here. If a pattern is
truly local to one check, it stays in the detector file.
"""

from security_eval.patterns import (
    injection,
    obfuscation,
    code_exec,
    secrets,
    pii,
)

__all__ = ["injection", "obfuscation", "code_exec", "secrets", "pii"]
