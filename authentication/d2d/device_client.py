"""
Device client: the connecting side of a device. Presents its own certificate and
verifies the server's certificate before sending any application data.

Run standalone (a server must be listening):
    python -m authentication.d2d.device_client --device device-a --peer device-b --port 8443
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from . import certificate_manager as cm
from . import verifier as vf
from .generate_certificates import DEFAULT_CERT_DIR


@dataclass
class ConnectionResult:
    success: bool
    reason: str = vf.OK
    detail: str = ""
    response: Optional[dict] = None


class DeviceClient:
    def __init__(
        self,
        device_id: str,
        ca_path: Path,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
        logger=None,
    ):
        self.device_id = device_id
        self.log = logger or vf.get_logger()
        self.ca_cert = cm.load_cert(ca_path)
        self.context = cm.build_client_context(ca_path, cert_path, key_path)

    def connect(
        self,
        peer_id: str,
        host: str,
        port: int,
        message: str = "hello",
        allowed_server_ids: Optional[Iterable[str]] = None,
        timeout: float = 5.0,
    ) -> ConnectionResult:
        """
        Connect to `peer_id`, authenticate it, then send one message.
        Returns a ConnectionResult; failures are logged, never raised.
        """
        raw = None
        try:
            raw = socket.create_connection((host, port), timeout=timeout)

            # --- Layer 1: handshake. Server cert must chain to our CA, be in date and
            # --- carry the hostname '<peer_id>.local'. The server in turn demands OUR cert.
            try:
                conn = self.context.wrap_socket(raw, server_hostname=f"{peer_id}.local")
            except (ssl.SSLError, OSError) as exc:
                reason, detail = vf.classify_ssl_error(exc)
                return self._fail(peer_id, reason, f"server certificate rejected: {detail}")

            # --- Layer 2: explicit verification of the server certificate ----------------
            result = vf.verify_certificate(
                conn.getpeercert(binary_form=True), self.ca_cert, role="server",
                allowed_device_ids=set(allowed_server_ids) if allowed_server_ids else {peer_id})
            if not result.ok:
                conn.close()
                return self._fail(peer_id, result.reason, result.detail)

            # --- Application data. With TLS 1.3 the server validates OUR certificate only
            # --- after our handshake completes, so a rejection surfaces here as an alert.
            try:
                conn.sendall((json.dumps({"from": self.device_id, "message": message}) + "\n").encode())
                reply = self._read_line(conn)
            except (ssl.SSLError, OSError) as exc:
                reason, detail = vf.classify_ssl_error(exc)
                return self._fail(peer_id, reason, f"our certificate was rejected by the peer: {detail}")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

            if reply.get("status") != "ok":
                return self._fail(peer_id, reply.get("reason", "REJECTED"), "peer rejected our certificate")

            vf.log_success(self.log, self.device_id, "client", result.device_id, result.serial,
                           "mutual TLS established")
            return ConnectionResult(True, vf.OK, "mutual TLS established", reply)
        except (OSError, ValueError) as exc:
            return self._fail(peer_id, vf.TLS_ERROR, f"connection error: {exc}")
        finally:
            if raw:
                try:
                    raw.close()
                except OSError:
                    pass

    # ---------------------------------------------------------------- helpers
    def _fail(self, peer: str, reason: str, detail: str) -> ConnectionResult:
        vf.log_failure(self.log, self.device_id, "client", peer, reason, detail)
        return ConnectionResult(False, reason, detail)

    @staticmethod
    def _read_line(conn: ssl.SSLSocket) -> dict:
        data = b""
        while not data.endswith(b"\n") and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            raise ssl.SSLError("connection closed by peer before any response")
        return json.loads(data.decode())


# ------------------------------------------------------------------------- CLI
def main() -> None:
    p = argparse.ArgumentParser(description="Connect to a D2D device server (mutual TLS).")
    p.add_argument("--device", default="device-a", help="our device id")
    p.add_argument("--cert-name", help="certificate file stem to present (default: same as --device); "
                                       "use e.g. device-a-expired to demo a rejection")
    p.add_argument("--no-cert", action="store_true", help="connect without presenting a client certificate")
    p.add_argument("--peer", default="device-b", help="id of the device we expect to reach")
    p.add_argument("--certs", type=Path, default=DEFAULT_CERT_DIR)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--message", default="hello from the CLI")
    p.add_argument("--log-file", type=Path, default=Path(__file__).resolve().parent / "logs" / "auth.log")
    a = p.parse_args()

    if not (a.certs / "ca.crt").exists():
        raise SystemExit(f"No certificates in {a.certs}. Run: python -m authentication.d2d.generate_certificates")
    stem = a.cert_name or a.device
    logger = vf.setup_logging(a.log_file)
    client = DeviceClient(
        a.device, a.certs / "ca.crt",
        None if a.no_cert else a.certs / f"{stem}.crt",
        None if a.no_cert else a.certs / f"{stem}.key", logger)
    res = client.connect(a.peer, a.host, a.port, a.message)
    print("RESULT:", "SUCCESS" if res.success else f"BLOCKED ({res.reason})", res.response or "")
    raise SystemExit(0 if res.success else 1)


if __name__ == "__main__":
    main()
