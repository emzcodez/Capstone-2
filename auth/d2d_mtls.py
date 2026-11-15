"""D2D prototype: device-to-device mutual TLS credential verification (X.509 via `cryptography`).

Each side checks the peer certificate: signed by a trusted CA, not expired, not revoked, and the
certificate CN matches the claimed device identity. Every attempt is recorded in the common auth format.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from analyzer.auth_events import AuthEventLog


def make_ca(name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue_device_cert(ca_key, ca_cert, device: str, days_valid: int = 90, expired: bool = False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    start, end = (now - timedelta(days=30), now - timedelta(days=1)) if expired else (now - timedelta(minutes=1), now + timedelta(days=days_valid))
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _cn(name: x509.Name) -> str:
    return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


class D2DVerifier:
    """Verifier run by the *target* device. `trusted_cas` are CA certificates, `revoked` a set of serials."""

    def __init__(self, target: str, trusted_cas, revoked=(), log: AuthEventLog | None = None):
        self.target, self.trusted, self.revoked = target, list(trusted_cas), set(revoked)
        self.log = log if log is not None else AuthEventLog()

    def _check(self, claimed: str, cert) -> str | None:
        """Return a failure reason, or None if the certificate is acceptable."""
        if cert is None:
            return "Missing client certificate"
        issuer = next((ca for ca in self.trusted if ca.subject == cert.issuer), None)
        if issuer is None:
            return "Untrusted certificate (unknown issuer)"
        try:
            issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        except Exception:
            return "Invalid certificate signature"
        now = datetime.now(timezone.utc)
        if now > cert.not_valid_after_utc or now < cert.not_valid_before_utc:
            return "Expired certificate"
        if cert.serial_number in self.revoked:
            return "Revoked certificate"
        if _cn(cert.subject) != claimed:
            return f"Identity mismatch (certificate is for {_cn(cert.subject)})"
        return None

    def authenticate(self, claimed_source: str, cert) -> dict:
        reason = self._check(claimed_source, cert)
        return self.log.record(claimed_source, self.target, "device", "mTLS",
                               "BLOCKED" if reason else "ALLOWED", reason or "Valid certificate")
