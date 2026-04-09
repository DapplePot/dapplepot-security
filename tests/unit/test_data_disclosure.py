"""Unit tests for the PII detector — no infra required."""
import pytest

from tests.conftest import make_event
from consumers.security_eval.online.pii import detect_pii, _redact


def _llm_end(completion: str) -> dict:
    return make_event("llm_end", {"completion": completion})


def _tool_end(tool_output) -> dict:
    return make_event("tool_end", {"tool_output": tool_output})


# --- _redact tests ---

def test_redact_short_string():
    assert _redact("ab") == "****"


def test_redact_card_number():
    result = _redact("4111111111111111")
    assert result.startswith("41")
    assert result.endswith("11")
    assert "*" in result
    assert "111111111111" not in result


def test_redact_preserves_length_indicator():
    original = "sk-abcdefghijklmnopqrstuvwxyz123456"
    redacted = _redact(original)
    assert redacted[:2] == "sk"
    assert redacted[-2:] == "56"


# --- detect_pii tests ---

def test_pii001_fires_on_visa_card():
    event = _llm_end("Your card ending in 4111111111111111 has been charged.")
    findings = detect_pii(event)
    assert any(f.signal_id == "PII-001" for f in findings)


def test_pii001_matched_text_is_redacted():
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    pii_finding = next(f for f in findings if f.signal_id == "PII-001")
    assert "4111111111111111" not in (pii_finding.matched_text or "")
    assert "*" in (pii_finding.matched_text or "")


def test_pii002_fires_on_ssn():
    event = _llm_end("SSN on file: 123-45-6789")
    findings = detect_pii(event)
    assert any(f.signal_id == "PII-002" for f in findings)


def test_pii003_fires_on_openai_api_key():
    event = _llm_end("Use this key: sk-" + "a" * 32)
    findings = detect_pii(event)
    assert any(f.signal_id == "PII-003" for f in findings)


def test_pii004_fires_on_email():
    event = _llm_end("Contact us at support@example.com for help.")
    findings = detect_pii(event)
    assert any(f.signal_id == "PII-004" for f in findings)


def test_pii004_severity_is_warning():
    event = _llm_end("Email: test@example.com")
    findings = detect_pii(event)
    email_finding = next((f for f in findings if f.signal_id == "PII-004"), None)
    assert email_finding is not None
    assert email_finding.severity == "warning"


def test_pii001_severity_is_critical():
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    card_finding = next((f for f in findings if f.signal_id == "PII-001"), None)
    assert card_finding is not None
    assert card_finding.severity == "critical"


def test_no_findings_on_clean_output():
    event = _llm_end("The weather today is sunny with a high of 72 degrees.")
    findings = detect_pii(event)
    assert findings == []


def test_tool_end_reads_tool_output_field():
    event = _tool_end("User email is test@example.com")
    findings = detect_pii(event)
    assert any(f.signal_id == "PII-004" for f in findings)


def test_detection_phase_is_online():
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    for f in findings:
        assert f.detection_phase == "online"
