#!/usr/bin/env python3
"""Generate dapplepot-ui/src/data/signalRegistry.ts from checks.yaml.

The generated file is the customer-facing check catalog consumed by the UI.
DO NOT hand-edit the .ts file — edit checks.yaml and re-run this script.

Usage:
    python registry/gen_ts.py                # writes to default location
    python registry/gen_ts.py --check        # exit 1 if regeneration would change output (CI)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

REGISTRY_YAML = Path(__file__).parent / "checks.yaml"
DEFAULT_OUT   = (
    Path(__file__).parent.parent.parent
    / "dapplepot-ui" / "src" / "data" / "signalRegistry.ts"
)

HEADER = """\
/**
 * GENERATED FILE — DO NOT EDIT DIRECTLY.
 *
 * Source of truth: dapplepot-security/registry/checks.yaml
 * Regenerate with:  python dapplepot-security/registry/gen_ts.py
 *
 * The registry defines all 20 OWASP signals and 155 sub-checks with their
 * facets (scope, subject, mechanism), capabilities (enforceable, capable_modes,
 * capable_actions), and status.
 */

/**
 * `framework` is intentionally a string (not an enum) so new frameworks can be
 * added without a type change. Values carry their origin prefix so the value
 * is self-describing.
 *   Today:   'OW-LLM' (OWASP LLM Top 10), 'OW-ASI' (OWASP Agentic Top 10)
 *   Future:  'NIST-AI-RMF', 'MITRE-ATLAS', 'custom-*'
 */
export type Framework      = string
export type Scope          = 'event' | 'session' | 'history'
export type Subject        = 'agent' | 'user' | 'tenant'
export type Mechanism      = 'policy' | 'signature' | 'statistical' | 'behavioral' | 'model'
export type Mode           = 'observe' | 'detect' | 'enforce'
export type Action         = 'alert' | 'sanitize' | 'block_call' | 'terminate_session'
export type Severity       = 'critical' | 'high' | 'medium' | 'low'
export type ConfidenceTier = 'deterministic' | 'high' | 'medium' | 'low' | 'skeletal'
export type Status         = 'active' | 'coming-soon' | 'not-applicable'
export type EventType      =
  | 'session_start' | 'graph_start' | 'graph_end' | 'graph_error'
  | 'llm_start' | 'llm_end'
  | 'tool_start' | 'tool_end' | 'tool_error'

export interface SubCheck {
  id:               string
  label:            string
  signalId:         string      // parent signal (e.g. 'OW-LLM01'); flat for UI filters
  score:            number
  severity:         Severity
  confidenceTier:   ConfidenceTier
  scope:            Scope
  subject:          Subject
  mechanism:        Mechanism
  enforceable:      boolean
  capableModes:     Mode[]
  defaultMode:      Mode
  capableActions:   Action[]
  defaultAction?:   Action
  eventTypes:       EventType[]
  detector:         string | null
  requiresPolicyFields: string[]
  status:           Status
  statusReason?:    string
  matches?:         string[]
}

export interface SignalConfig {
  id:          string      // e.g. 'OW-LLM01' — prefix is convention, not enforced
  name:        string
  framework:   Framework   // e.g. 'LLM', 'ASI' today
  number:      number
  description: string
  subChecks:   SubCheck[]
}
"""

FOOTER = """
// ─── Derived helpers ─────────────────────────────────────────────────────────

export const ALL_SUBCHECKS: SubCheck[] = SIGNAL_REGISTRY.flatMap(s => s.subChecks)

export const LLM_SIGNALS = SIGNAL_REGISTRY.filter(s => s.framework === 'LLM')
export const ASI_SIGNALS = SIGNAL_REGISTRY.filter(s => s.framework === 'ASI')

export const ENFORCEABLE_SUBCHECK_IDS: ReadonlySet<string> = new Set(
  ALL_SUBCHECKS.filter(c => c.enforceable).map(c => c.id),
)

export function countByStatus(signal: SignalConfig, status: Status): number {
  return signal.subChecks.filter(c => c.status === status).length
}

export function countActive(signal: SignalConfig): number {
  return countByStatus(signal, 'active')
}

"""


def load_registry() -> dict:
    with REGISTRY_YAML.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _ts_string(s: str) -> str:
    """Render a Python string as a TS single-quoted string literal."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _ts_array(values: list[str], *, quote: bool = True) -> str:
    if not values:
        return "[]"
    inner = ", ".join(_ts_string(v) if quote else v for v in values)
    return f"[{inner}]"


def _emit_check(check: dict, signal_id: str, indent: str = "      ") -> str:
    lines: list[str] = []
    lines.append("{")
    lines.append(f"  id: {_ts_string(check['id'])},")
    lines.append(f"  label: {_ts_string(check['label'])},")
    lines.append(f"  signalId: {_ts_string(signal_id)},")
    lines.append(f"  score: {check['score']},")
    lines.append(f"  severity: {_ts_string(check['severity'])},")
    lines.append(f"  confidenceTier: {_ts_string(check['confidence_tier'])},")
    lines.append(f"  scope: {_ts_string(check['scope'])},")
    lines.append(f"  subject: {_ts_string(check['subject'])},")
    lines.append(f"  mechanism: {_ts_string(check['mechanism'])},")
    lines.append(f"  enforceable: {'true' if check['enforceable'] else 'false'},")
    lines.append(f"  capableModes: {_ts_array(check.get('capable_modes', []))},")
    lines.append(f"  defaultMode: {_ts_string(check['default_mode'])},")
    lines.append(f"  capableActions: {_ts_array(check.get('capable_actions', []))},")
    if check.get("default_action"):
        lines.append(f"  defaultAction: {_ts_string(check['default_action'])},")
    lines.append(f"  eventTypes: {_ts_array(check.get('event_types', []))},")
    detector = check.get("detector")
    lines.append(f"  detector: {'null' if detector is None else _ts_string(detector)},")
    lines.append(f"  requiresPolicyFields: {_ts_array(check.get('requires_policy_fields', []))},")
    lines.append(f"  status: {_ts_string(check['status'])},")
    if check.get("status_reason"):
        lines.append(f"  statusReason: {_ts_string(check['status_reason'])},")
    if check.get("matches"):
        lines.append("  matches: [")
        for m in check["matches"]:
            lines.append(f"    {_ts_string(m)},")
        lines.append("  ],")

    lines.append("}")
    return "\n".join(indent + ln if i > 0 else indent + ln for i, ln in enumerate(lines))


def emit_ts(registry: dict) -> str:
    out: list[str] = [HEADER]
    out.append("export const SIGNAL_REGISTRY: SignalConfig[] = [")
    for signal in registry["signals"]:
        desc = signal["description"].strip().replace("\n", " ")
        out.append("  {")
        out.append(f"    id: {_ts_string(signal['id'])},")
        out.append(f"    name: {_ts_string(signal['name'])},")
        out.append(f"    framework: {_ts_string(signal['framework'])},")
        out.append(f"    number: {signal['number']},")
        out.append(f"    description: {_ts_string(desc)},")
        out.append("    subChecks: [")
        for check in signal["checks"]:
            out.append(_emit_check(check, signal["id"]))
            out[-1] = out[-1].rstrip("\n") + ","
        out.append("    ],")
        out.append("  },")
    out.append("]")
    out.append(FOOTER)
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="output .ts file (default: dapplepot-ui/src/data/signalRegistry.ts)")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the file on disk differs from what would be generated")
    args = parser.parse_args()

    registry = load_registry()
    generated = emit_ts(registry)

    if args.check:
        if not args.out.exists():
            print(f"[gen_ts] {args.out} does not exist; expected it to be generated.", file=sys.stderr)
            return 1
        current = args.out.read_text(encoding="utf-8")
        if current != generated:
            print(f"[gen_ts] {args.out} is stale. Re-run: python registry/gen_ts.py", file=sys.stderr)
            return 1
        print(f"[gen_ts] {args.out} up to date.")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(generated, encoding="utf-8")

    n_signals = len(registry["signals"])
    n_checks  = sum(len(s["checks"]) for s in registry["signals"])
    n_enf     = sum(1 for s in registry["signals"] for c in s["checks"] if c["enforceable"])
    print(f"[gen_ts] wrote {args.out}")
    print(f"[gen_ts] {n_signals} signals · {n_checks} sub-checks · {n_enf} enforceable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
