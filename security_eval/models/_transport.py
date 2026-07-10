"""Shared httpx client factory + owasp_signal_id → category map.

Both are cheap to compute; kept behind lazy accessors so import order doesn't
matter and so the httpx client is only constructed if a tier is actually
configured.
"""
from __future__ import annotations

import httpx

# Merged category map. Covers every OWASP signal a Reflex or Verdict finding
# can carry. Values match the free-string `category` field used by existing
# scorers (asi_signals._SIGNAL_CATEGORY, llm_signals._SIGNAL_CATEGORY,
# online._CATEGORY_BY_PREFIX) — so model findings look identical to
# rule-based findings downstream.
SIGNAL_CATEGORY: dict[str, str] = {
    "OW-LLM01": "prompt_injection",
    "OW-LLM02": "data_disclosure",
    "OW-LLM03": "supply_chain",
    "OW-LLM04": "supply_chain",
    "OW-LLM05": "output_handling",
    "OW-LLM06": "excessive_agency",
    "OW-LLM07": "system_prompt_leakage",
    "OW-LLM08": "vector_integrity",
    "OW-LLM09": "model_security",
    "OW-LLM10": "model_security",
    "OW-ASI01": "prompt_injection",
    "OW-ASI02": "excessive_agency",
    "OW-ASI03": "privilege_escalation",
    "OW-ASI04": "supply_chain",
    "OW-ASI05": "code_execution",
    "OW-ASI06": "context_poisoning",
    "OW-ASI07": "inter_agent_communication",
    "OW-ASI08": "cascading_failure",
    "OW-ASI09": "trust_exploitation",
    "OW-ASI10": "excessive_agency",
}


def make_client(timeout_ms: int) -> httpx.AsyncClient:
    """Fresh async client per call — callers use `async with`. Overhead is
    negligible next to the network round-trip we're about to do, and it
    keeps error handling and lifecycle strictly local.

    Timeout is applied to every phase (connect / read / write / pool) so a
    slow-to-refuse connect can't blow through the caller's latency budget."""
    total = timeout_ms / 1000.0
    return httpx.AsyncClient(
        timeout=httpx.Timeout(total, connect=total, read=total, write=total, pool=total)
    )
