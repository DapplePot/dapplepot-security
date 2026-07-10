"""Pluggable model backends for Reflex (fast classifier, Runtime Guard hot path)
and Verdict (LLM judge, post-session analysis).

Both entry points return an empty list — silent fallback — on any error,
including "not configured" (empty endpoint URL / API key). Callers should
merge the returned findings on top of, and only after having filtered out,
the corresponding rule-based results for the same sub-check IDs.
"""
from security_eval.models.reflex import reflex_classify
from security_eval.models.verdict import verdict_judge

__all__ = ["reflex_classify", "verdict_judge"]
