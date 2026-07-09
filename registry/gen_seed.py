#!/usr/bin/env python3
"""Generate dapplepot-security/scripts/signal_registry_seed.py from checks.yaml.

The generated file is imported by run_migrations.py (or similar) to seed the
signal_registry table. It exposes SIGNALS + SUBCHECKS lists ready for insert.

Also emits a machine-readable JSON at scripts/registry_snapshot.json — useful
for gen_sdk.py (SDK enforceable-set generator) and for CI validation.

Usage:
    python registry/gen_seed.py
    python registry/gen_seed.py --check
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REGISTRY_YAML  = Path(__file__).parent / "checks.yaml"
DEFAULT_SEED   = Path(__file__).parent.parent / "scripts" / "signal_registry_seed.py"
DEFAULT_JSON   = Path(__file__).parent.parent / "scripts" / "registry_snapshot.json"

SEED_HEADER = '''\
"""GENERATED FILE — DO NOT EDIT DIRECTLY.

Source of truth: dapplepot-security/registry/checks.yaml
Regenerate with:  python dapplepot-security/registry/gen_seed.py

Consumed by DB seeding: reads SIGNALS + SUBCHECKS to upsert the
signal_registry table with platform defaults.
"""
from __future__ import annotations

from typing import TypedDict


class Signal(TypedDict):
    id:          str
    name:        str
    framework:   str
    number:      int
    description: str


class SubCheck(TypedDict, total=False):
    id:                     str
    signal_id:              str
    label:                  str
    score:                  int
    severity:               str
    confidence_tier:        str
    scope:                  str
    subject:                str
    mechanism:              str
    enforceable:            bool
    capable_modes:          list[str]
    default_mode:           str
    capable_actions:        list[str]
    default_action:         str
    event_types:            list[str]
    detector:               str | None
    requires_policy_fields: list[str]
    status:                 str
    status_reason:          str
    matches:                list[str]

'''


def load_registry() -> dict:
    with REGISTRY_YAML.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _py_repr(v):
    if v is None:
        return "None"
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_py_repr(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{_py_repr(k)}: {_py_repr(val)}" for k, val in v.items()) + "}"
    raise TypeError(f"cannot serialise {type(v)}")


def emit_seed(registry: dict) -> str:
    out = [SEED_HEADER]

    out.append("SIGNALS: list[Signal] = [")
    for s in registry["signals"]:
        desc = s["description"].strip().replace("\n", " ")
        out.append("    {")
        out.append(f"        'id':          {_py_repr(s['id'])},")
        out.append(f"        'name':        {_py_repr(s['name'])},")
        out.append(f"        'framework':   {_py_repr(s['framework'])},")
        out.append(f"        'number':      {s['number']},")
        out.append(f"        'description': {_py_repr(desc)},")
        out.append("    },")
    out.append("]")
    out.append("")

    out.append("SUBCHECKS: list[SubCheck] = [")
    for s in registry["signals"]:
        for c in s["checks"]:
            out.append("    {")
            out.append(f"        'id':                     {_py_repr(c['id'])},")
            out.append(f"        'signal_id':              {_py_repr(s['id'])},")
            out.append(f"        'label':                  {_py_repr(c['label'])},")
            out.append(f"        'score':                  {c['score']},")
            out.append(f"        'severity':               {_py_repr(c['severity'])},")
            out.append(f"        'confidence_tier':        {_py_repr(c['confidence_tier'])},")
            out.append(f"        'scope':                  {_py_repr(c['scope'])},")
            out.append(f"        'subject':                {_py_repr(c['subject'])},")
            out.append(f"        'mechanism':              {_py_repr(c['mechanism'])},")
            out.append(f"        'enforceable':            {_py_repr(c['enforceable'])},")
            out.append(f"        'capable_modes':          {_py_repr(c.get('capable_modes', []))},")
            out.append(f"        'default_mode':           {_py_repr(c['default_mode'])},")
            out.append(f"        'capable_actions':        {_py_repr(c.get('capable_actions', []))},")
            if c.get("default_action"):
                out.append(f"        'default_action':         {_py_repr(c['default_action'])},")
            out.append(f"        'event_types':            {_py_repr(c.get('event_types', []))},")
            out.append(f"        'detector':               {_py_repr(c.get('detector'))},")
            out.append(f"        'requires_policy_fields': {_py_repr(c.get('requires_policy_fields', []))},")
            out.append(f"        'status':                 {_py_repr(c['status'])},")
            if c.get("status_reason"):
                out.append(f"        'status_reason':          {_py_repr(c['status_reason'])},")
            if c.get("matches"):
                out.append(f"        'matches':                {_py_repr(c['matches'])},")
            out.append("    },")
    out.append("]")
    out.append("")

    # Derived sets for callers that need them without re-parsing.
    out.append("ENFORCEABLE_SUBCHECK_IDS: frozenset[str] = frozenset(")
    out.append("    c['id'] for c in SUBCHECKS if c.get('enforceable')")
    out.append(")")
    out.append("")

    return "\n".join(out) + "\n"


def emit_snapshot(registry: dict) -> str:
    """Machine-readable dump — canonical JSON for external consumers (SDK gen, CI)."""
    snapshot = {"signals": []}
    for s in registry["signals"]:
        signal_row = {
            "id":          s["id"],
            "name":        s["name"],
            "framework":   s["framework"],
            "number":      s["number"],
            "description": s["description"].strip().replace("\n", " "),
            "checks":      [],
        }
        for c in s["checks"]:
            row = {
                "id":                     c["id"],
                "signal_id":              s["id"],
                "label":                  c["label"],
                "score":                  c["score"],
                "severity":               c["severity"],
                "confidence_tier":        c["confidence_tier"],
                "scope":                  c["scope"],
                "subject":                c["subject"],
                "mechanism":              c["mechanism"],
                "enforceable":            c["enforceable"],
                "capable_modes":          c.get("capable_modes", []),
                "default_mode":           c["default_mode"],
                "capable_actions":        c.get("capable_actions", []),
                "event_types":            c.get("event_types", []),
                "detector":               c.get("detector"),
                "requires_policy_fields": c.get("requires_policy_fields", []),
                "status":                 c["status"],
            }
            if c.get("default_action"):
                row["default_action"] = c["default_action"]
            if c.get("status_reason"):
                row["status_reason"] = c["status_reason"]
            if c.get("matches"):
                row["matches"] = c["matches"]
            signal_row["checks"].append(row)
        snapshot["signals"].append(signal_row)
    return json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-out", type=Path, default=DEFAULT_SEED)
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    registry  = load_registry()
    seed_text = emit_seed(registry)
    json_text = emit_snapshot(registry)

    if args.check:
        rc = 0
        for path, generated in ((args.seed_out, seed_text), (args.json_out, json_text)):
            if not path.exists():
                print(f"[gen_seed] {path} missing; expected generated file.", file=sys.stderr)
                rc = 1
                continue
            if path.read_text(encoding="utf-8") != generated:
                print(f"[gen_seed] {path} stale. Re-run: python registry/gen_seed.py", file=sys.stderr)
                rc = 1
        if rc == 0:
            print("[gen_seed] seed + snapshot up to date.")
        return rc

    for path in (args.seed_out, args.json_out):
        path.parent.mkdir(parents=True, exist_ok=True)
    args.seed_out.write_text(seed_text, encoding="utf-8")
    args.json_out.write_text(json_text, encoding="utf-8")

    n_signals = len(registry["signals"])
    n_checks  = sum(len(s["checks"]) for s in registry["signals"])
    n_enf     = sum(1 for s in registry["signals"] for c in s["checks"] if c["enforceable"])
    print(f"[gen_seed] wrote {args.seed_out}")
    print(f"[gen_seed] wrote {args.json_out}")
    print(f"[gen_seed] {n_signals} signals · {n_checks} sub-checks · {n_enf} enforceable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
