from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from sentinelpi.events import Event, EventSource, Severity, severities_at_least
from sentinelpi.safety import REDACTED, clean_text, redact_text, sanitize_metadata

TS = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def make(**over):
    base = {
        "timestamp": TS,
        "source": EventSource.TEST,
        "event_type": "auth.ssh_failed_login",
        "severity": Severity.LOW,
        "summary": "Failed SSH login",
        "host": "pi",
    }
    base.update(over)
    return Event(**base)


# ---- redaction ----
def test_redacts_assignment_style_secrets():
    out = redact_text("login ok password=hunter2 token: abc123def")
    assert "hunter2" not in out and "abc123def" not in out
    assert out.count(REDACTED) == 2


def test_redacts_bearer_and_private_key():
    assert "abcdefgh12345" not in redact_text("Authorization: Bearer abcdefgh12345")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ndef\n-----END RSA PRIVATE KEY-----"
    out = redact_text(f"key {pem} end")
    assert "MIIabc" not in out and "end" in out


def test_ordinary_log_wording_is_not_mangled():
    text = "Failed password for invalid user admin from 203.0.113.9"
    assert redact_text(text) == text


def test_clean_text_blocks_log_injection_and_truncates():
    out = clean_text("bob\nFAKE: root logged in\x1b[31m\t!", 64)
    assert "\n" not in out and "\x1b" not in out
    assert len(clean_text("a" * 500, 64)) == 64


# ---- metadata ----
def test_secret_keys_are_redacted_not_stored():
    out = sanitize_metadata({"password": "x", "API_KEY": "y", "note": "fine", "n": 3})
    assert out == {"password": REDACTED, "API_KEY": REDACTED, "note": "fine", "n": 3}


def test_secrets_inside_string_values_are_redacted():
    out = sanitize_metadata({"detail": "connect password=hunter2"})
    assert "hunter2" not in out["detail"]


def test_nested_structures_allowed_within_limits():
    out = sanitize_metadata({"a": {"b": [1, 2, "x"]}})  # dict > dict > list = 3 levels
    assert out["a"]["b"][2] == "x"


@pytest.mark.parametrize(
    "bad",
    [
        {"bad key": 1},
        {"1abc": 1},
        {"k": {1, 2}},
        {"k": object()},
        {f"k{i}": 1 for i in range(51)},
        {"k": "x" * 256, "j": ["y" * 256] * 50},  # too large overall
        {"a": {"b": {"c": {"d": 1}}}},  # too deep
    ],
)
def test_malformed_metadata_rejected(bad):
    with pytest.raises(ValueError):
        sanitize_metadata(bad)


def test_non_finite_floats_become_none():
    assert sanitize_metadata({"x": float("nan"), "y": float("inf")}) == {"x": None, "y": None}


# ---- Event ----
def test_valid_event_and_api_shape():
    e = make(source_ip="203.0.113.5", username="root", metadata={"port": 22})
    api = e.to_api()
    assert api["timestamp"].endswith("Z")
    assert UUID(api["id"]) == e.id
    assert api["severity"] == "low" and api["source"] == "test"


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        make(timestamp=datetime(2026, 9, 28, 12, 0))


def test_timestamp_normalized_to_utc():
    plus2 = timezone(timedelta(hours=2))
    e = make(timestamp=datetime(2026, 9, 28, 14, 0, tzinfo=plus2))
    assert e.timestamp == TS and e.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize("bad_type", ["", "Has Caps", "1starts_digit", "x" * 65, "semi;colon"])
def test_bad_event_type_rejected(bad_type):
    with pytest.raises(ValidationError):
        make(event_type=bad_type)


def test_ip_validated_and_normalized():
    assert make(source_ip="2001:DB8:0:0:0:0:0:1").source_ip == "2001:db8::1"
    with pytest.raises(ValidationError):
        make(source_ip="999.1.1.1")
    with pytest.raises(ValidationError):
        make(source_ip="1.1.1.1; DROP TABLE events")


def test_empty_summary_and_unknown_fields_rejected():
    with pytest.raises(ValidationError):
        make(summary="   \n ")
    with pytest.raises(ValidationError):
        make(unexpected="x")


def test_attacker_controlled_fields_sanitized():
    e = make(username="root\nAccepted password for admin", summary="a\nb password=zzz")
    assert "\n" not in e.username and "\n" not in e.summary
    assert "zzz" not in e.summary


def test_metadata_redacted_through_model():
    assert make(metadata={"token": "abc"}).metadata == {"token": REDACTED}


def test_severity_ordering():
    assert Severity.HIGH.rank > Severity.LOW.rank
    assert severities_at_least(Severity.HIGH) == [Severity.HIGH, Severity.CRITICAL]
