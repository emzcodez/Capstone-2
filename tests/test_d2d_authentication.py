"""Tests for the D2D mutual-TLS prototype (authentication/d2d)."""
import logging
from datetime import datetime, timedelta, timezone

import pytest

from authentication.d2d import certificate_manager as cm
from authentication.d2d import verifier as vf
from authentication.d2d.device_client import DeviceClient
from authentication.d2d.device_server import DeviceServer
from authentication.d2d.generate_certificates import generate_all

TRUSTED = {"device-a", "device-b"}


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    generate_all(d)
    return d


@pytest.fixture(autouse=True)
def quiet_logging():
    vf.setup_logging(None, console=False)


def connect(certs, client_stem, server_stem="device-b", client_id="device-a", allow=TRUSTED):
    """Start a server, connect one client, return (client_result, server_events)."""
    with DeviceServer("device-b", certs / f"{server_stem}.crt", certs / f"{server_stem}.key",
                      certs / "ca.crt", allowed_device_ids=allow) as server:
        client = DeviceClient(
            client_id, certs / "ca.crt",
            certs / f"{client_stem}.crt" if client_stem else None,
            certs / f"{client_stem}.key" if client_stem else None)
        result = client.connect("device-b", "127.0.0.1", server.port, "ping")
    return result, server.events


# ------------------------------------------------------------ certificate generation
def test_devices_have_separate_certificates_and_keys(certs):
    a, b = cm.load_cert(certs / "device-a.crt"), cm.load_cert(certs / "device-b.crt")
    assert a.serial_number != b.serial_number
    assert a.public_key().public_numbers() != b.public_key().public_numbers()
    assert (cm.device_id_of(a), cm.device_id_of(b)) == ("device-a", "device-b")


def test_expired_certificate_really_is_expired(certs):
    cert = cm.load_cert(certs / "device-a-expired.crt")
    assert cert.not_valid_after_utc < datetime.now(timezone.utc)


def test_private_keys_are_not_world_readable(certs):
    assert (certs / "device-a.key").stat().st_mode & 0o077 == 0


# ----------------------------------------------------------------- mTLS end to end
def test_trusted_devices_communicate(certs):
    result, events = connect(certs, "device-a")
    assert result.success and result.response["echo"] == "ping"
    assert events[0]["outcome"] == "success" and events[0]["peer"] == "device-a"


def test_reverse_direction_works(certs):
    with DeviceServer("device-a", certs / "device-a.crt", certs / "device-a.key", certs / "ca.crt") as s:
        c = DeviceClient("device-b", certs / "ca.crt", certs / "device-b.crt", certs / "device-b.key")
        assert c.connect("device-a", "127.0.0.1", s.port).success


def test_expired_client_certificate_is_blocked(certs):
    result, events = connect(certs, "device-a-expired")
    assert not result.success
    assert events[0]["outcome"] == "failure" and events[0]["reason"] == vf.EXPIRED


def test_untrusted_client_certificate_is_blocked(certs):
    result, events = connect(certs, "device-a-untrusted")
    assert not result.success
    assert events[0]["reason"] == vf.UNTRUSTED


def test_client_without_certificate_is_blocked(certs):
    result, events = connect(certs, None)
    assert not result.success
    assert events[0]["reason"] == vf.NO_CERTIFICATE


def test_valid_but_unauthorised_device_is_blocked(certs):
    result, events = connect(certs, "device-c", client_id="device-c")
    assert not result.success
    assert events[0]["reason"] == vf.NOT_AUTHORISED
    assert result.reason == vf.NOT_AUTHORISED


def test_client_rejects_expired_server(certs):
    result, _ = connect(certs, "device-a", server_stem="device-b-expired")
    assert not result.success and result.reason == vf.EXPIRED


def test_client_rejects_untrusted_server(certs):
    result, _ = connect(certs, "device-a", server_stem="device-b-untrusted")
    assert not result.success and result.reason == vf.UNTRUSTED


def test_no_application_data_reaches_blocked_peer(certs):
    # A blocked client must never get a reply payload.
    result, _ = connect(certs, "device-a-untrusted")
    assert result.response is None


# ------------------------------------------------------------------- verifier unit
def _verify(certs, stem, role="client", **kw):
    return vf.verify_certificate(cm.load_cert(certs / f"{stem}.crt"),
                                 cm.load_cert(certs / "ca.crt"), role=role, **kw)


def test_verifier_accepts_valid_cert(certs):
    r = _verify(certs, "device-a")
    assert r.ok and r.device_id == "device-a" and r.reason == vf.OK


def test_verifier_flags_expiry(certs):
    assert vf.EXPIRED in _verify(certs, "device-a-expired").codes


def test_verifier_flags_untrusted_issuer(certs):
    assert vf.UNTRUSTED in _verify(certs, "device-a-untrusted").codes


def test_verifier_flags_not_yet_valid(certs):
    r = _verify(certs, "device-a", now=datetime.now(timezone.utc) - timedelta(days=30))
    assert vf.NOT_YET_VALID in r.codes


def test_verifier_flags_revoked_serial(certs):
    serial = cm.load_cert(certs / "device-a.crt").serial_number
    assert vf.REVOKED in _verify(certs, "device-a", revoked_serials=[serial]).codes


def test_verifier_rejects_forged_signature(certs):
    # Same issuer name as the trusted CA, but signed with a different key.
    fake_key, fake_ca = cm.create_ca("D2D Root CA")
    _, forged = cm.issue_device_cert(fake_key, fake_ca, "device-a")
    r = vf.verify_certificate(forged, cm.load_cert(certs / "ca.crt"), role="client")
    assert not r.ok and vf.BAD_SIGNATURE in r.codes


def test_verifier_rejects_ca_used_as_device(certs):
    assert vf.WRONG_USAGE in _verify(certs, "ca").codes


# ----------------------------------------------------------------------- logging
def test_success_and_failure_are_logged(certs, tmp_path):
    log_file = tmp_path / "auth.log"
    logger = vf.setup_logging(log_file, console=False)
    with DeviceServer("device-b", certs / "device-b.crt", certs / "device-b.key", certs / "ca.crt",
                      logger=logger) as s:
        good = DeviceClient("device-a", certs / "ca.crt", certs / "device-a.crt", certs / "device-a.key", logger)
        bad = DeviceClient("device-a", certs / "ca.crt", certs / "device-a-expired.crt",
                           certs / "device-a-expired.key", logger)
        good.connect("device-b", "127.0.0.1", s.port)
        bad.connect("device-b", "127.0.0.1", s.port)
    for h in logger.handlers:
        h.flush()
    text = log_file.read_text()
    assert "AUTH_SUCCESS" in text and "AUTH_FAILURE" in text and "CERT_EXPIRED" in text
