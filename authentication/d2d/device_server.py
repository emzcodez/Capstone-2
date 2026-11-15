"""
Device server: the listening side of a device. Enforces mutual TLS.

A connection is accepted only if BOTH hold:
  * the TLS handshake succeeds (client presented a certificate that chains to the
    trusted CA and is within its validity period), and
  * verifier.verify_certificate() approves the peer certificate (usage, allow-list...).

Run standalone:
    python -m authentication.d2d.device_server --device device-b --port 8443
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import certificate_manager as cm
from . import verifier as vf
from .generate_certificates import DEFAULT_CERT_DIR


class DeviceServer:
    def __init__(
        self,
        device_id: str,
        cert_path: Path,
        key_path: Path,
        ca_path: Path,
        host: str = "127.0.0.1",
        port: int = 0,                                   # 0 = pick a free port
        allowed_device_ids: Optional[Iterable[str]] = None,
        revoked_serials: Optional[Iterable[int]] = None,
        logger=None,
    ):
        self.device_id = device_id
        self.host, self.port = host, port
        self.allowed_device_ids = set(allowed_device_ids) if allowed_device_ids is not None else None
        self.revoked_serials = set(revoked_serials) if revoked_serials is not None else None
        self.log = logger or vf.get_logger()
        self.ca_cert = cm.load_cert(ca_path)
        self.context = cm.build_server_context(cert_path, key_path, ca_path)
        self.events: List[Dict[str, str]] = []           # structured record of every decision
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> "DeviceServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name=f"{self.device_id}-server", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            self._sock.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------ serving
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw, addr), daemon=True).start()

    def _record(self, outcome: str, peer: str, reason: str, detail: str, serial: str = "-") -> None:
        with self._lock:
            self.events.append({"outcome": outcome, "peer": peer, "reason": reason, "detail": detail})
        if outcome == "success":
            vf.log_success(self.log, self.device_id, "server", peer, serial, detail)
        else:
            vf.log_failure(self.log, self.device_id, "server", peer, reason, detail)

    def _handle(self, raw: socket.socket, addr) -> None:
        raw.settimeout(5)
        conn = None
        try:
            # --- Layer 1: TLS handshake (chain, dates, client cert mandatory) ----------
            try:
                conn = self.context.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                reason, detail = vf.classify_ssl_error(exc)
                self._record("failure", "unknown", reason, f"handshake from {addr[0]}:{addr[1]} refused: {detail}")
                return

            # --- Layer 2: explicit verification of the peer certificate ----------------
            der = conn.getpeercert(binary_form=True)
            if not der:
                self._record("failure", "unknown", vf.NO_CERTIFICATE, "client presented no certificate")
                return
            result = vf.verify_certificate(
                der, self.ca_cert, role="client",
                allowed_device_ids=self.allowed_device_ids,
                revoked_serials=self.revoked_serials)
            if not result.ok:
                self._record("failure", result.device_id, result.reason, result.detail, result.serial)
                self._read_message(conn)  # drain the request so the rejection is not lost to a TCP reset
                self._reply(conn, {"status": "rejected", "from": self.device_id, "reason": result.reason})
                return

            self._record("success", result.device_id, vf.OK, "mutual TLS established", result.serial)

            # --- Trusted: application data may now flow ---------------------------------
            request = self._read_message(conn)
            self._reply(conn, {
                "status": "ok", "from": self.device_id, "to": result.device_id,
                "echo": request.get("message"), "time": time.strftime("%Y-%m-%dT%H:%M:%S")})
        except (OSError, ValueError):
            pass  # peer vanished / sent garbage - nothing more to do
        finally:
            try:
                (conn or raw).close()
            except OSError:
                pass

    @staticmethod
    def _read_message(conn: ssl.SSLSocket) -> dict:
        data = b""
        while not data.endswith(b"\n") and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        return json.loads(data.decode() or "{}")

    @staticmethod
    def _reply(conn: ssl.SSLSocket, payload: dict) -> None:
        try:
            conn.sendall((json.dumps(payload) + "\n").encode())
        except OSError:
            pass


# ------------------------------------------------------------------------- CLI
def main() -> None:
    p = argparse.ArgumentParser(description="Run a D2D device server (mutual TLS).")
    p.add_argument("--device", default="device-b", help="device id, e.g. device-b")
    p.add_argument("--cert-name", help="certificate file stem to present (default: same as --device)")
    p.add_argument("--certs", type=Path, default=DEFAULT_CERT_DIR)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--allow", nargs="*", help="device ids allowed to connect (default: any trusted device)")
    p.add_argument("--log-file", type=Path, default=Path(__file__).resolve().parent / "logs" / "auth.log")
    a = p.parse_args()

    if not (a.certs / "ca.crt").exists():
        raise SystemExit(f"No certificates in {a.certs}. Run: python -m authentication.d2d.generate_certificates")
    stem = a.cert_name or a.device
    logger = vf.setup_logging(a.log_file)
    server = DeviceServer(a.device, a.certs / f"{stem}.crt", a.certs / f"{stem}.key", a.certs / "ca.crt",
                          a.host, a.port, allowed_device_ids=a.allow, logger=logger).start()
    print(f"[{a.device}] listening on {a.host}:{server.port} (mutual TLS) - Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
