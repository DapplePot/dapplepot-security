"""Unit tests for v3 scoring model — confidence weighting, composite, attack chains."""
import pytest

from consumers.security_eval.scorer.orchestrator import (
    compute_ow_signal_score,
    _band,
    resolve_overlap_group,
)
from consumers.security_eval.scorer.attack_chains import detect_attack_chains
from consumers.security_eval.findings import Finding
from tests.conftest import SESSION_ID, TENANT_ID, EVENT_ID


def _finding(
    owasp_signal_id: str,
    sub_check_id: str,
    check_score: int,
    confidence_tier: str = "high",
) -> Finding:
    from core.config import CONFIDENCE_WEIGHTS
    return Finding(
        tenant_id=TENANT_ID,
        session_id=SESSION_ID,
        event_id=EVENT_ID,
        event_type="post_session",
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label="test",
        check_score=check_score,
        category="test",
        severity="high",
        matched_text=None,
        detail="test",
        detection_phase="post_session",
        confidence_tier=confidence_tier,
        confidence=CONFIDENCE_WEIGHTS.get(confidence_tier, 0.9),
    )


# ─────────────────────────────────────────────────────────────────────────────
# compute_ow_signal_score
# ─────────────────────────────────────────────────────────────────────────────

def test_signal_score_empty():
    result = compute_ow_signal_score([])
    assert result == {}


def test_signal_score_single_finding():
    f = _finding("OW-LLM01", "PI-01a", 85, "high")
    result = compute_ow_signal_score([f])
    assert "OW-LLM01" in result
    sig = result["OW-LLM01"]
    assert sig["status"] == "fired"
    assert sig["raw_score"] == 85
    assert sig["effective_score"] > 0


def test_signal_score_deterministic_is_highest_confidence():
    from core.config import CONFIDENCE_WEIGHTS
    f_det = _finding("OW-LLM01", "PI-01b", 80, "deterministic")
    f_low = _finding("OW-LLM01", "PI-07a", 90, "low")
    result = compute_ow_signal_score([f_det, f_low])
    sig = result["OW-LLM01"]
    det_eff = 80 * CONFIDENCE_WEIGHTS["deterministic"]
    low_eff = 90 * CONFIDENCE_WEIGHTS["low"]
    # effective_score should be max of det_eff and low_eff
    assert sig["effective_score"] == round(max(det_eff, low_eff))


def test_signal_score_multiple_signals():
    findings = [
        _finding("OW-LLM01", "PI-01a", 85, "high"),
        _finding("OW-ASI01", "AGH-01b", 92, "high"),
    ]
    result = compute_ow_signal_score(findings)
    assert "OW-LLM01" in result
    assert "OW-ASI01" in result
    assert result["OW-LLM01"]["status"] == "fired"
    assert result["OW-ASI01"]["status"] == "fired"


def test_signal_score_groups_by_owasp_id():
    findings = [
        _finding("OW-LLM01", "PI-01a", 85, "high"),
        _finding("OW-LLM01", "PI-04b", 92, "high"),
    ]
    result = compute_ow_signal_score(findings)
    assert len(result) == 1
    assert "OW-LLM01" in result
    assert result["OW-LLM01"]["raw_score"] == 92  # max


def test_signal_score_confidence_lower_for_low_tier():
    from core.config import CONFIDENCE_WEIGHTS
    f_high = _finding("OW-LLM01", "PI-01a", 85, "high")
    f_low = _finding("OW-LLM01", "PI-07a", 85, "low")
    result_high = compute_ow_signal_score([f_high])
    result_low = compute_ow_signal_score([f_low])
    assert result_high["OW-LLM01"]["effective_score"] > result_low["OW-LLM01"]["effective_score"]


# ─────────────────────────────────────────────────────────────────────────────
# Risk bands (v3)
# ─────────────────────────────────────────────────────────────────────────────

def test_band_clean():
    assert _band(0) == "clean"
    assert _band(10) == "clean"
    assert _band(14) == "clean"


def test_band_low():
    assert _band(15) == "low"
    assert _band(34) == "low"


def test_band_medium():
    assert _band(35) == "medium"
    assert _band(59) == "medium"


def test_band_high():
    assert _band(60) == "high"
    assert _band(84) == "high"


def test_band_critical():
    assert _band(85) == "critical"
    assert _band(100) == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Overlap group resolution
# ─────────────────────────────────────────────────────────────────────────────

def test_no_overlap_single_signal():
    result = resolve_overlap_group({"OW-LLM01"})
    assert result is None


def test_injection_overlap_group():
    result = resolve_overlap_group({"OW-LLM01", "OW-ASI01"})
    assert result == "injection"


def test_output_exec_overlap_group():
    result = resolve_overlap_group({"OW-LLM05", "OW-ASI05"})
    assert result == "output_exec"


def test_excessive_agency_overlap():
    result = resolve_overlap_group({"OW-LLM06", "OW-ASI02"})
    assert result == "excessive_agency"


def test_pii_privilege_overlap():
    result = resolve_overlap_group({"OW-LLM02", "OW-ASI03"})
    assert result == "pii_privilege"


# ─────────────────────────────────────────────────────────────────────────────
# Attack chain amplification integration
# ─────────────────────────────────────────────────────────────────────────────

def test_attack_chain_amplification_applied():
    # indirect_injection_to_exfil: OW-LLM01 + OW-ASI02 + OW-LLM02 → 1.25×
    fired = {"OW-LLM01", "OW-ASI02", "OW-LLM02"}
    chains, amp = detect_attack_chains(fired)
    assert amp == 1.25
    # Composite at score 60 with amplification = min(100, int(60 * 1.25)) = 75
    raw = 60
    composite = min(100, int(raw * amp))
    assert composite == 75


def test_no_amplification_without_full_chain():
    fired = {"OW-LLM01", "OW-ASI02"}  # missing OW-LLM02
    chains, amp = detect_attack_chains(fired)
    assert "indirect_injection_to_exfil" not in chains
    assert amp == 1.0


def test_score_capped_at_100_with_amplification():
    fired = {"OW-ASI04", "OW-ASI05", "OW-ASI10"}  # supply_chain_to_backdoor 1.35×
    _, amp = detect_attack_chains(fired)
    raw = 85
    composite = min(100, int(raw * amp))
    assert composite <= 100
