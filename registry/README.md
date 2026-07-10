# Central Check Registry

**Source of truth** for all 20 OWASP signals and 155 sub-checks in DapplePot.

## Files in this folder

### Hand-maintained

| File | Role |
|---|---|
| `checks.yaml` | **The registry.** Every sub-check with its facets, capabilities, detector wiring, and status. Single source of truth. |
| `model_coverage.yaml` | Which sub-checks route to Reflex (fast classifier) vs Verdict (LLM judge). Orthogonal to `checks.yaml` so the model-service dimension doesn't touch every check definition. |
| `overlaps.md` | Intentional overlaps between sub-checks — partitioned families, corroborating families, and resolved-by-removal history (e.g. EA-01b deleted). Read this before proposing a "dedup" refactor. |
| `README.md` | This file. |

### Generators (code, not data)

| File | Role |
|---|---|
| `gen_ts.py` | Regenerates `dapplepot-ui/src/data/signalRegistry.ts` (customer-facing UI catalog). |
| `gen_seed.py` | Regenerates `dapplepot-security/scripts/signal_registry_seed.py` (DB seed) + `registry_snapshot.json` (machine-readable snapshot). |

### Generated (do NOT hand-edit)

- `dapplepot-ui/src/data/signalRegistry.ts`
- `dapplepot-security/scripts/signal_registry_seed.py`
- `dapplepot-security/scripts/registry_snapshot.json`

Any manual edit is overwritten by the next `gen_*.py` run. CI enforces this via `--check` flags.

### Runtime consumers

- `dapplepot-security/security_eval/registry.py` — loads the JSON snapshot + `model_coverage.yaml`, exposes derived sets (`ENFORCEABLE_SUBCHECK_IDS`, `EVENT_SCOPE_IDS`, `REFLEX_SUBCHECK_IDS`, `VERDICT_SUBCHECK_IDS`, etc.) and `coverage_report()`.
- `dapplepot-security/security_eval/models/` — Reflex + Verdict clients read `REFLEX_SUBCHECK_IDS`, `VERDICT_BY_CATEGORY`, and `CHECK_BY_ID` for dispatch, category grouping, and Finding metadata.
- `dapplepot-security/scripts/check_sdk_sync.py` — CI guard that cross-references the SDK's hardcoded `_ONLINE_CAPABLE_SUB_CHECKS` frozenset against the registry.

## How to add or change a check

1. Edit `checks.yaml` (see the schema block at the top of that file).
2. If the check should route to Reflex or Verdict, also add its ID to `model_coverage.yaml` under the appropriate service + category.
3. Regenerate downstream artifacts:
   ```bash
   python registry/gen_ts.py
   python registry/gen_seed.py
   ```
4. If you added/removed/renamed an **enforceable** check, update the SDK's `_ONLINE_CAPABLE_SUB_CHECKS` frozenset in `dapplepot-sdk/dapplepot_sdk/_interceptor.py` too, then verify:
   ```bash
   python scripts/check_sdk_sync.py
   ```
5. Commit the YAML edits + generated files in the same PR.

## Facet reference

Each check declares five facets that drive routing and UI:

| Facet | Read by |
|---|---|
| `scope` | Engine — routes checks to guard/analysis/history tiers |
| `subject` | UI — chip on finding cards when non-agent |
| `mechanism` | UI — chip; also selects between pattern-match and model implementations |
| `capable_modes` + `default_mode` | UI — mode ladder rungs shown; per-agent overrides live in Postgres |
| `capable_actions` + `default_action` | Guard — action space in `/v1/online-check`; UI — Enforce modal |

`enforceable` is a bool convenience: `true` iff `enforce` ∈ `capable_modes` and Runtime Guard has an implementation today.

## CI checks (all three must pass)

```bash
python registry/gen_ts.py   --check    # generated TS not stale
python registry/gen_seed.py --check    # generated seed + snapshot not stale
python scripts/check_sdk_sync.py       # SDK frozenset matches registry
```

Any of these exiting non-zero means the registry and its downstream artifacts are out of sync — do not merge.
