#!/usr/bin/env python3
"""Verify the SDK's hardcoded _ONLINE_CAPABLE_SUB_CHECKS matches the registry.

Run manually when adding a new enforceable check, or as a CI step to prevent
silent drift. Exits 1 with a clear diff on mismatch.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Registry snapshot (generated from checks.yaml)
_HERE = Path(__file__).parent
_ROOT = _HERE.parent.parent
_SDK_INTERCEPTOR = _ROOT / "dapplepot-sdk" / "dapplepot_sdk" / "_interceptor.py"


def registry_set() -> set[str]:
    sys.path.insert(0, str(_ROOT / "dapplepot-security"))
    from security_eval.registry import ENFORCEABLE_SUBCHECK_IDS
    return set(ENFORCEABLE_SUBCHECK_IDS)


def sdk_hardcoded_set() -> set[str]:
    """Extract the SDK's frozenset literal by regex — safer than importing
    the SDK, which pulls in its whole dependency chain."""
    text = _SDK_INTERCEPTOR.read_text(encoding="utf-8")
    # Match the `_ONLINE_CAPABLE_SUB_CHECKS: frozenset[str] = frozenset({...})` block.
    m = re.search(
        r"_ONLINE_CAPABLE_SUB_CHECKS\s*:\s*frozenset\[str\]\s*=\s*frozenset\(\{([^}]*)\}\)",
        text,
        re.DOTALL,
    )
    if not m:
        raise RuntimeError(
            f"Could not find _ONLINE_CAPABLE_SUB_CHECKS literal in {_SDK_INTERCEPTOR}"
        )
    body = m.group(1)
    # Strip comments and pull out quoted identifiers.
    body = re.sub(r"#[^\n]*", "", body)
    ids = re.findall(r"'([A-Z]+-[0-9]+[a-z]?)'", body)
    return set(ids)


def main() -> int:
    reg = registry_set()
    sdk = sdk_hardcoded_set()

    only_reg = sorted(reg - sdk)
    only_sdk = sorted(sdk - reg)

    if not only_reg and not only_sdk:
        print(f"OK: SDK and registry agree on {len(reg)} enforceable checks.")
        return 0

    print(f"MISMATCH: registry has {len(reg)}, SDK hardcoded {len(sdk)}")
    if only_reg:
        print(f"  In registry, missing from SDK: {only_reg}")
        print("    → add these to _ONLINE_CAPABLE_SUB_CHECKS in dapplepot-sdk/dapplepot_sdk/_interceptor.py")
    if only_sdk:
        print(f"  In SDK, not in registry:       {only_sdk}")
        print("    → check registry/checks.yaml — either enforceable: true was reverted, or the SDK is ahead")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
