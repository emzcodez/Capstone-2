import json
from pathlib import Path

from analyzer.auth_events import AuthEventLog
from scripts.import_prototype_logs import import_d2d, import_s2a


def test_s2a_jsonl_import_maps_outcomes(tmp_path):
    source = tmp_path / "s2a.jsonl"
    source.write_text(
        '{"outcome":"SUCCESS","agent_id":"agent-a","resource":"reports","reason":"OK"}\n'
        '{"outcome":"DENIED","agent_id":"agent-b","resource":"reports","reason":"NO_PERMISSION"}\n',
        encoding="utf-8")
    log = AuthEventLog()
    import_s2a(source, log)
    assert [e["result"] for e in log.events] == ["ALLOWED", "BLOCKED"]
    assert log.events[0]["authentication_method"] == "JWT"


def test_d2d_import_parses_peer_and_reason(tmp_path):
    source = tmp_path / "d2d.log"
    source.write_text(
        "2026-11-15 12:00:00 | WARNING | AUTH_FAILURE local=device-b role=server "
        "peer=device-a reason=CERT_EXPIRED detail=expired\n", encoding="utf-8")
    log = AuthEventLog()
    import_d2d(source, log)
    event = log.events[0]
    assert event["source_identity"] == "device-a"
    assert event["target_identity"] == "device-b"
    assert event["result"] == "BLOCKED"
    assert event["reason"] == "CERT_EXPIRED"
    assert event["timestamp"] == "2026-11-15T12:00:00+00:00"
