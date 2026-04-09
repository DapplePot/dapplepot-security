"""Unit tests for v2 scoring model: compute_ow_signal_score and compute_composite_score."""
import pytest

from tests.conftest import SESSION_ID, TENANT_ID, EVENT_ID
from consumers.security_eval.findings import Finding
from consumers.security_eval.scorer.orchestrator import (
    compute_ow_signal_score,
    compute_composite_score,
    resolve_overlap_group,
)


def _f(owasp_signal_id: str, sub_check_id: str, check_score: int) -> Finding:
    return Finding(
        tenant_id=TENANT_ID,
        session_id=SESSION_ID,
        event_id=EVENT_ID,
        event_type="post_session",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label="test",
        check_score=check_score,
        category="prompt_injection",
        severity="high",
        detection_phase="post_session",
    )


# ─────────────────────────────────────────────────────────────────────────────
# compute_ow_signal_score
# ─────────────────────────────────────────────────────────────────────────────
def test_signal_score_single_finding():
    findings = [_f("OW-LLM01", "PI-01a", 85)]
    result = compute_ow_signal_score(findings)
    assert result["OW-LLM01"]["score"] == 85
    assert result["OW-LLM01"]["status"] == "fired"
    assert "PI-01a" in result["OW-LLM01"]["sub_checks"]


def test_signal_score_takes_max_of_sub_checks():
    """Parent score = max(sub-check scores), not sum."""
    findings = [
        _f("OW-LLM01", "PI-01a", 85),
        _f("OW-LLM01", "PI-04b", 92),
    ]
    result = compute_ow_signal_score(findings)
    assert result["OW-LLM01"]["score"] == 92  # max, not 177


def test_signal_score_multiple_signals():
    findings = [
        _f("OW-LLM01", "PI-01a", 85),
        _f("OW-LLM02", "SID-01a", 95),
    ]
    result = compute_ow_signal_score(findings)
    assert result["OW-LLM01"]["score"] == 85
    assert result["OW-LLM02"]["score"] == 95


def test_signal_score_empty_is_empty():
    result = compute_ow_signal_score([])
    assert result == {}


# ─────────────────────────────────────────────────────────────────────────────
# compute_composite_score
# ─────────────────────────────────────────────────────────────────────────────
def test_composite_score_single_signal():
    signal_map = {"OW-LLM01": {"score": 90, "status": "fired"}}
    assert compute_composite_score(signal_map, "LLM") == 90


def test_composite_score_two_signals_weighted():
    signal_map = {
        "OW-LLM01": {"score": 90, "status": "fired"},
        "OW-LLM02": {"score": 60, "status": "fired"},
    }
    # primary=90×0.6=54, secondary=60×0.4=24 → 78
    score = compute_composite_score(signal_map, "LLM")
    assert score == 78


def test_composite_score_clean_signals_ignored():
    signal_map = {
        "OW-LLM01": {"score": 90, "status": "fired"},
        "OW-LLM02": {"score": 0,  "status": "clean"},
    }
    assert compute_composite_score(signal_map, "LLM") == 90


def test_composite_score_empty_returns_zero():
    assert compute_composite_score({}, "LLM") == 0
    assert compute_composite_score({}, "ASI") == 0


def test_composite_score_capped_at_100():
    signal_map = {
        "OW-ASI05": {"score": 98, "status": "fired"},
        "OW-ASI01": {"score": 92, "status": "fired"},
    }
    score = compute_composite_score(signal_map, "ASI")
    assert score <= 100


def test_composite_score_only_considers_correct_framework():
    signal_map = {
        "OW-LLM01": {"score": 80, "status": "fired"},
        "OW-ASI05": {"score": 98, "status": "fired"},
    }
    llm_score = compute_composite_score(signal_map, "LLM")
    asi_score = compute_composite_score(signal_map, "ASI")
    assert llm_score == 80
    assert asi_score == 98


# ─────────────────────────────────────────────────────────────────────────────
# resolve_overlap_group
# ─────────────────────────────────────────────────────────────────────────────
def test_overlap_injection_group():
    fired = {"OW-LLM01", "OW-ASI01"}
    assert resolve_overlap_group(fired) == "injection"


def test_overlap_output_exec_group():
    fired = {"OW-LLM05", "OW-ASI05"}
    assert resolve_overlap_group(fired) == "output_exec"


def test_overlap_none_for_single_signal():
    fired = {"OW-LLM01"}
    assert resolve_overlap_group(fired) is None


def test_overlap_none_for_unrelated_signals():
    fired = {"OW-LLM04", "OW-ASI07"}
    assert resolve_overlap_group(fired) is None
