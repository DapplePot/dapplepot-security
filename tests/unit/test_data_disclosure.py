"""Unit tests for the data disclosure (PII) detector — no infra required."""
import pytest

from tests.conftest import make_event
from consumers.security_eval.online.data_disclosure import detect_pii, _redact


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


# --- detect_pii tests (new OW-LLM02 signal IDs) ---

def test_sid02b_fires_on_visa_card():
    event = _llm_end("Your card ending in 4111111111111111 has been charged.")
    findings = detect_pii(event)
    assert any(f.sub_check_id == "SID-02b" for f in findings)
    assert any(f.owasp_signal_id == "OW-LLM02" for f in findings)


def test_sid02b_matched_text_is_redacted():
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    card_finding = next(f for f in findings if f.sub_check_id == "SID-02b")
    assert "4111111111111111" not in (card_finding.matched_text or "")
    assert "*" in (card_finding.matched_text or "")


def test_sid02c_fires_on_ssn():
    event = _llm_end("SSN on file: 123-45-6789")
    findings = detect_pii(event)
    assert any(f.sub_check_id == "SID-02c" for f in findings)


def test_sid01a_fires_on_openai_api_key():
    event = _llm_end("Use this key: sk-" + "a" * 32)
    findings = detect_pii(event)
    assert any(f.sub_check_id == "SID-01a" for f in findings)


def test_sid02a_fires_on_email():
    event = _llm_end("Contact us at support@example.com for help.")
    findings = detect_pii(event)
    assert any(f.sub_check_id == "SID-02a" for f in findings)


def test_sid02a_severity_is_high():
    event = _llm_end("Email: test@example.com")
    findings = detect_pii(event)
    email_finding = next((f for f in findings if f.sub_check_id == "SID-02a"), None)
    assert email_finding is not None
    assert email_finding.severity == "high"


def test_sid02b_severity_is_critical():
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    card_finding = next((f for f in findings if f.sub_check_id == "SID-02b"), None)
    assert card_finding is not None
    assert card_finding.severity == "critical"


def test_no_findings_on_clean_output():
    event = _llm_end("The weather today is sunny with a high of 72 degrees.")
    findings = detect_pii(event)
    assert findings == []


def test_tool_end_reads_tool_output_field():
    event = _tool_end("User email is test@example.com")
    findings = detect_pii(event)
    assert any(f.sub_check_id == "SID-02a" for f in findings)


def test_detection_phase_is_online():
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    for f in findings:
        assert f.detection_phase == "online"


def test_signal_id_format():
    """owasp_signal_id and sub_check_id must be set."""
    event = _llm_end("Card: 4111111111111111")
    findings = detect_pii(event)
    for f in findings:
        assert f.owasp_signal_id.startswith("OW-")
        assert f.sub_check_id
