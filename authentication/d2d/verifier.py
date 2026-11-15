"""
Verifier: decides whether a peer certificate may be trusted, and explains why not.

Two layers protect a connection:

  1. The TLS stack (OpenSSL) already validates the chain, dates and hostname during
     the handshake. If that fails the handshake aborts; `classify_ssl_error()` turns
     the low-level error into a stable reason code for the logs.

  2. `verify_certificate()` below is an independent, explicit check run on the peer
     certificate *after* the handshake. It re-checks validity and trust, and adds
     policy OpenSSL knows nothing about: certificate usage (EKU), an allow-list of
     device ids and a revocation list. Defence in depth, and every decision is logged.
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from .certificate_manager import device_id_of, load_cert_der

# Stable reason codes (used in logs, tests and the demo output)
OK = "OK"
EXPIRED = "CERT_EXPIRED"
NOT_YET_VALID = "CERT_NOT_YET_VALID"
UNTRUSTED = "UNTRUSTED_ISSUER"
BAD_SIGNATURE = "BAD_SIGNATURE"
WRONG_USAGE = "WRONG_KEY_USAGE"
NOT_AUTHORISED = "DEVICE_NOT_AUTHORISED"
REVOKED = "CERT_REVOKED"
NO_CERTIFICATE = "NO_CLIENT_CERTIFICATE"
HOSTNAME_MISMATCH = "HOSTNAME_MISMATCH"
REJECTED_BY_PEER = "REJECTED_BY_PEER"
TLS_ERROR = "TLS_ERROR"


@dataclass
class VerificationResult:
    ok: bool
    device_id: str = "unknown"
    serial: str = "-"
    codes: List[str] = field(default_factory=list)      # empty when ok
    details: List[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return OK if self.ok else ",".join(self.codes)

    @property
    def detail(self) -> str:
        return "certificate trusted" if self.ok else "; ".join(self.details)


def verify_certificate(
    peer: "x509.Certificate | bytes",
    ca_cert: x509.Certificate,
    *,
    role: str,                                   # role of the PEER: "client" or "server"
    allowed_device_ids: Optional[Iterable[str]] = None,
    revoked_serials: Optional[Iterable[int]] = None,
    now: Optional[datetime] = None,
) -> VerificationResult:
    """Run every check and collect *all* failures (not just the first)."""
    if isinstance(peer, (bytes, bytearray)):
        peer = load_cert_der(bytes(peer))
    now = now or datetime.now(timezone.utc)
    result = VerificationResult(ok=True, device_id=device_id_of(peer), serial=format(peer.serial_number, "x")[:16])

    def fail(code: str, detail: str) -> None:
        result.ok = False
        result.codes.append(code)
        result.details.append(detail)

    # 1. Trust: issued by our CA and the signature really verifies.
    if peer.issuer != ca_cert.subject:
        fail(UNTRUSTED, f"issuer '{peer.issuer.rfc4514_string()}' is not the trusted CA")
    else:
        try:
            ca_cert.public_key().verify(
                peer.signature, peer.tbs_certificate_bytes,
                ec.ECDSA(peer.signature_hash_algorithm))
        except (InvalidSignature, TypeError, ValueError):
            fail(BAD_SIGNATURE, "certificate signature does not verify against the trusted CA")

    # 2. Validity window.
    if now > peer.not_valid_after_utc:
        fail(EXPIRED, f"expired on {peer.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")
    elif now < peer.not_valid_before_utc:
        fail(NOT_YET_VALID, f"not valid until {peer.not_valid_before_utc:%Y-%m-%d %H:%M} UTC")

    # 3. Certificate must be a leaf allowed for this TLS role.
    try:
        if peer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            fail(WRONG_USAGE, "a CA certificate cannot be used as a device certificate")
    except x509.ExtensionNotFound:
        pass
    wanted = ExtendedKeyUsageOID.CLIENT_AUTH if role == "client" else ExtendedKeyUsageOID.SERVER_AUTH
    try:
        eku = peer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if wanted not in eku:
            fail(WRONG_USAGE, f"certificate is not valid for TLS {role} authentication")
    except x509.ExtensionNotFound:
        fail(WRONG_USAGE, "certificate has no extendedKeyUsage extension")

    # 4. Policy: allow-list and revocation.
    if allowed_device_ids is not None and result.device_id not in set(allowed_device_ids):
        fail(NOT_AUTHORISED, f"device '{result.device_id}' is not on the allow-list")
    if revoked_serials is not None and peer.serial_number in set(revoked_serials):
        fail(REVOKED, "certificate serial number is on the revocation list")

    return result


# ------------------------------------------------------ TLS error classification
_CERT_VERIFY_CODES = {
    10: (EXPIRED, "certificate has expired"),
    9: (NOT_YET_VALID, "certificate is not yet valid"),
    18: (UNTRUSTED, "self-signed certificate"),
    19: (UNTRUSTED, "self-signed certificate in chain"),
    20: (UNTRUSTED, "issuer is not trusted"),
    21: (UNTRUSTED, "unable to verify the first certificate"),
    62: (HOSTNAME_MISMATCH, "certificate does not match the expected device name"),
}


def classify_ssl_error(exc: BaseException) -> Tuple[str, str]:
    """Map a TLS / socket exception to (reason_code, human readable detail)."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        code = getattr(exc, "verify_code", None)
        if code in _CERT_VERIFY_CODES:
            reason, text = _CERT_VERIFY_CODES[code]
            return reason, getattr(exc, "verify_message", None) or text
    text = str(exc)
    low = text.lower()
    if "expired" in low:
        return EXPIRED, text
    if "not yet valid" in low:
        return NOT_YET_VALID, text
    if any(s in low for s in ("unknown ca", "unknown_ca", "unable to get local issuer",
                              "self-signed", "self signed", "unable to verify")):
        return UNTRUSTED, text
    if any(s in low for s in ("peer did not return a certificate", "certificate required",
                              "certificate_required", "no certificate")):
        return NO_CERTIFICATE, text
    if "hostname" in low or "doesn't match" in low:
        return HOSTNAME_MISMATCH, text
    if any(s in low for s in ("bad certificate", "bad_certificate", "decrypt error")):
        return UNTRUSTED, text
    if any(s in low for s in ("eof occurred", "closed by peer", "connection reset", "broken pipe")):
        return REJECTED_BY_PEER, "peer closed the connection during/after authentication"
    return TLS_ERROR, text


# ------------------------------------------------------------------------ logging
LOGGER_NAME = "d2d.auth"
LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(message)s"


def setup_logging(log_file: Optional[Path] = None, console: bool = True,
                  level: int = logging.INFO) -> logging.Logger:
    """
    Configure the shared authentication logger. Every authentication decision is one line:

        <time> | INFO    | AUTH_SUCCESS local=device-b role=server peer=device-a serial=.. detail=..
        <time> | WARNING | AUTH_FAILURE local=device-b role=server peer=device-a reason=CERT_EXPIRED detail=..
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    fmt = logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(sh)
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def log_success(logger, local: str, role: str, peer: str, serial: str, detail: str = "") -> None:
    logger.info("AUTH_SUCCESS local=%s role=%s peer=%s serial=%s detail=%s", local, role, peer, serial, detail)


def log_failure(logger, local: str, role: str, peer: str, reason: str, detail: str = "") -> None:
    logger.warning("AUTH_FAILURE local=%s role=%s peer=%s reason=%s detail=%s", local, role, peer, reason, detail)
