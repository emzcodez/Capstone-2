import pytest

from analyzer.auth_events import AuthEventLog, auth_findings, make_event, summarize_auth, validate_event
from scripts.gen_auth_events import run


def test_schema_requires_fields_and_valid_values():
    with pytest.raises(ValueError):
        validate_event({"event_id": "AUTH-001"})
    with pytest.raises(ValueError):
        make_event("AUTH-001", "a", "b", "device", "mTLS", "MAYBE", "x")


def test_both_prototypes_share_one_format():
    ev = run().events
    assert {e["authentication_method"] for e in ev} == {"mTLS", "JWT"}
    assert all(set(("event_id", "source_identity", "target_identity", "identity_type",
                    "authentication_method", "result", "reason")) <= set(e) for e in ev)
    assert [e["event_id"] for e in ev][:2] == ["AUTH-001", "AUTH-002"]


def test_blocked_becomes_finding_allowed_does_not():
    log = AuthEventLog()
    log.record("a", "b", "device", "mTLS", "ALLOWED", "Valid certificate")
    assert auth_findings(log.events) == []
    log.record("x", "b", "device", "mTLS", "BLOCKED", "Revoked certificate")
    f = auth_findings(log.events)
    assert len(f) == 1 and f[0]["severity"] == "critical" and f[0]["identity"] == "x"


def test_repeated_failures_escalate():
    log = AuthEventLog()
    for _ in range(3):
        log.record("x", "b", "device", "mTLS", "BLOCKED", "Untrusted certificate (unknown issuer)")
    f = auth_findings(log.events)
    assert len(f) == 1 and f[0]["severity"] == "critical" and "probing" in f[0]["reason"]


def test_summary_counts():
    s = summarize_auth(run().events)
    assert s["total"] == 17 and s["allowed"] == 3 and s["blocked"] == 14
