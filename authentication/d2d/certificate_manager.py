"""
Certificate manager: creates keys / X.509 certificates and builds TLS contexts.

Everything cryptographic that the other modules need lives here:
  * create_ca()            - self-signed certificate authority
  * issue_device_cert()    - device certificate signed by a CA (any validity window,
                             which is how we manufacture *expired* certificates)
  * save_* / load_*        - PEM (de)serialisation
  * build_server_context() / build_client_context()
                           - ssl.SSLContext objects configured for mutual TLS
"""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2


# ------------------------------------------------------------------ keys / certs
def new_private_key() -> ec.EllipticCurvePrivateKey:
    """ECDSA P-256 keys: small, fast, and universally supported by TLS stacks."""
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str, org: str = "D2D Prototype") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def create_ca(common_name: str, days: int = 3650) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create a self-signed CA. Devices that chain to this CA are 'trusted'."""
    key = new_private_key()
    now = datetime.now(timezone.utc)
    subject = _name(common_name, org="D2D Prototype CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_device_cert(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    device_id: str,
    *,
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
    days: int = 365,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """
    Issue a device certificate signed by `ca_key`.

    The certificate is usable both as a TLS client and a TLS server certificate
    (EKU = clientAuth + serverAuth), which is what device-to-device mTLS needs
    because every device plays both roles. The device id is the Common Name and
    the DNS SAN is `<device_id>.local`.

    Pass `not_before` / `not_after` in the past to create an expired certificate.
    """
    key = new_private_key()
    now = datetime.now(timezone.utc)
    not_before = not_before or (now - timedelta(minutes=5))
    not_after = not_after or (now + timedelta(days=days))

    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(device_id, org="D2D Prototype Devices"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_encipherment=False,
                          content_commitment=False, data_encipherment=False,
                          key_agreement=True, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"{device_id}.local")]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


# --------------------------------------------------------------------- PEM I/O
def save_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path = Path(path)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    path.chmod(0o600)  # private keys must not be world-readable


def save_cert(cert: x509.Certificate, path: Path) -> None:
    Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def load_cert_der(der: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der)


def device_id_of(cert: x509.Certificate) -> str:
    """The device id is the certificate's Common Name."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "<no-common-name>"


# ------------------------------------------------------------------ TLS contexts
def build_server_context(cert_path: Path, key_path: Path, ca_path: Path) -> ssl.SSLContext:
    """
    TLS server context that DEMANDS a client certificate (CERT_REQUIRED) and only
    trusts client certificates chained to `ca_path`. That is what makes it *mutual* TLS.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = TLS_MIN_VERSION
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_path))
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def build_client_context(ca_path: Path, cert_path: Optional[Path] = None,
                         key_path: Optional[Path] = None) -> ssl.SSLContext:
    """
    TLS client context: verifies the server certificate against `ca_path` (including
    hostname) and presents its own certificate when one is supplied.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = TLS_MIN_VERSION
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca_path))
    if cert_path and key_path:
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx
