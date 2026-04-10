"""Verify that scripts/seed_signal_registry.py defines >= 80 sub-checks
covering all OW-LLM01..10 and OW-ASI01..10 parent signals.

These tests run without a database — they validate the REGISTRY constant
in the seed script directly.
"""
import sys
import os

# Make the scripts package importable from the test runner root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from scripts.seed_signal_registry import REGISTRY

ALL_EXPECTED_SIGNALS = {
    "OW-LLM01", "OW-LLM02", "OW-LLM03", "OW-LLM04", "OW-LLM05",
    "OW-LLM06", "OW-LLM07", "OW-LLM08", "OW-LLM09", "OW-LLM10",
    "OW-ASI01", "OW-ASI02", "OW-ASI03", "OW-ASI04", "OW-ASI05",
    "OW-ASI06", "OW-ASI07", "OW-ASI08", "OW-ASI09", "OW-ASI10",
}


def test_registry_has_at_least_156_entries():
    assert len(REGISTRY) >= 156, f"Expected >= 156, got {len(REGISTRY)}"


def test_all_20_parent_signals_represented():
    present = {row[0] for row in REGISTRY}
    missing = ALL_EXPECTED_SIGNALS - present
    assert not missing, f"Missing parent signals: {missing}"


def test_sub_check_ids_are_unique_per_parent():
    seen: dict[tuple, int] = {}
    duplicates = []
    for row in REGISTRY:
        key = (row[0], row[1])  # (owasp_signal_id, sub_check_id)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            duplicates.append(key)
    assert not duplicates, f"Duplicate (owasp_signal_id, sub_check_id) pairs: {duplicates}"


def test_scores_are_in_valid_range():
    invalid = [(row[0], row[1], row[6]) for row in REGISTRY if not (0 <= row[6] <= 100)]
    assert not invalid, f"check_score out of range [0, 100]: {invalid}"


def test_severity_values_are_valid():
    valid_severities = {"critical", "high", "medium", "low"}
    invalid = [(row[0], row[1], row[7]) for row in REGISTRY if row[7] not in valid_severities]
    assert not invalid, f"Invalid severity values: {invalid}"


def test_categories_are_valid():
    invalid = [(row[0], row[3]) for row in REGISTRY if row[3] not in ("LLM", "ASI")]
    assert not invalid, f"Invalid owasp_category: {invalid}"


def test_detection_phases_are_valid():
    valid_phases = {"online", "post_session", "both", "excluded", "cross_session"}
    invalid = [(row[0], row[1], row[5]) for row in REGISTRY if row[5] not in valid_phases]
    assert not invalid, f"Invalid detection_phase: {invalid}"


def test_excluded_checks_have_reason():
    missing_reason = [
        (row[0], row[1])
        for row in REGISTRY
        if row[9] is True and not row[10]  # excluded=True but no exclusion_reason
    ]
    assert not missing_reason, f"Excluded checks without reason: {missing_reason}"


def test_llm03_is_excluded():
    llm03_entries = [row for row in REGISTRY if row[0] == "OW-LLM03"]
    assert llm03_entries, "OW-LLM03 must have at least one entry"
    assert all(row[9] for row in llm03_entries), "All OW-LLM03 entries must be excluded=True"


def test_dmp_and_vew_exclusions():
    """DMP-01a/c and VEW-01b/02a must be marked excluded (pre-runtime signals)."""
    expected_excluded = {"DMP-01a", "DMP-01c", "VEW-01b", "VEW-02a"}
    excluded_ids = {row[1] for row in REGISTRY if row[9] is True}
    missing = expected_excluded - excluded_ids
    assert not missing, f"Expected excluded sub-checks not found: {missing}"


def test_confidence_tier_values_are_valid():
    valid_tiers = {"deterministic", "high", "medium", "low", "skeletal"}
    invalid = [(row[0], row[1], row[8]) for row in REGISTRY if row[8] not in valid_tiers]
    assert not invalid, f"Invalid confidence_tier values: {invalid}"


def test_critical_sub_checks_have_high_scores():
    """All CRITICAL sub-checks should have check_score >= 85."""
    low_critical = [
        (row[0], row[1], row[6])
        for row in REGISTRY
        if row[7] == "critical" and row[6] < 85 and not row[9]
    ]
    assert not low_critical, f"Critical sub-checks with check_score < 85: {low_critical}"
