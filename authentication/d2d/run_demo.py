"""
End-to-end demo of the D2D mutual-TLS prototype.

    python -m authentication.d2d.run_demo

Generates fresh certificates, starts Device A and Device B servers on localhost and
runs a series of connection scenarios, printing whether each one was ALLOWED or
BLOCKED and whether that matches what a secure system should do. Every decision is
also written to authentication/d2d/logs/auth.log. Exit code 0 = all scenarios behaved correctly.
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from . import verifier as vf
from .device_client import DeviceClient
from .device_server import DeviceServer
from .generate_certificates import DEFAULT_CERT_DIR, generate_all

HERE = Path(__file__).resolve().parent
TRUSTED_DEVICES = {"device-a", "device-b"}


@dataclass
class Scenario:
    title: str
    client_id: str
    client_cert: Optional[str]          # cert file stem, None = present no certificate
    server_id: str
    server_cert: str                    # cert file stem the server presents
    expect_success: bool
    why: str


SCENARIOS: List[Scenario] = [
    Scenario("1. Device A -> Device B (both certificates valid)",
             "device-a", "device-a", "device-b", "device-b", True,
             "both devices hold valid certificates from the trusted CA"),
    Scenario("2. Device B -> Device A (reverse direction)",
             "device-b", "device-b", "device-a", "device-a", True,
             "authentication is mutual: either device can initiate"),
    Scenario("3. Device A with an EXPIRED certificate -> Device B",
             "device-a", "device-a-expired", "device-b", "device-b", False,
             "Device B must refuse an expired client certificate"),
    Scenario("4. Impostor 'device-a' signed by a ROGUE CA -> Device B",
             "device-a", "device-a-untrusted", "device-b", "device-b", False,
             "Device B must refuse a certificate from an untrusted CA"),
    Scenario("5. Device A with NO certificate -> Device B",
             "device-a", None, "device-b", "device-b", False,
             "mutual TLS requires the client to authenticate too"),
    Scenario("6. Device C (valid cert, but not authorised) -> Device B",
             "device-c", "device-c", "device-b", "device-b", False,
             "trusted CA but device is not on Device B's allow-list"),
    Scenario("7. Device A -> Device B presenting an EXPIRED certificate",
             "device-a", "device-a", "device-b", "device-b-expired", False,
             "Device A must refuse an expired server certificate"),
    Scenario("8. Device A -> impostor 'device-b' signed by a ROGUE CA",
             "device-a", "device-a", "device-b", "device-b-untrusted", False,
             "Device A must refuse a server certificate from an untrusted CA"),
]


def run(certs: Path = DEFAULT_CERT_DIR, verbose: bool = True) -> bool:
    certs = Path(certs)
    log_file = HERE / "logs" / "auth.log"
    log_file.parent.mkdir(exist_ok=True)
    log_file.write_text("")                                   # fresh log for each demo run
    logger = vf.setup_logging(log_file, console=False)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("      log> %(levelname)-7s %(message)s"))
    if verbose:
        logger.addHandler(console)

    print("Generating certificates ...")
    generate_all(certs)
    ca = certs / "ca.crt"

    results = []
    for sc in SCENARIOS:
        print(f"\n{sc.title}\n   expectation: {sc.why}")
        server = DeviceServer(
            sc.server_id, certs / f"{sc.server_cert}.crt", certs / f"{sc.server_cert}.key", ca,
            allowed_device_ids=TRUSTED_DEVICES, logger=logger)
        with server:
            client = DeviceClient(
                sc.client_id, ca,
                certs / f"{sc.client_cert}.crt" if sc.client_cert else None,
                certs / f"{sc.client_cert}.key" if sc.client_cert else None,
                logger)
            res = client.connect(sc.server_id, "127.0.0.1", server.port,
                                 message=f"ping from {sc.client_id}")
        outcome = "ALLOWED" if res.success else f"BLOCKED ({res.reason})"
        ok = res.success == sc.expect_success
        results.append(ok)
        extra = f"  reply: {res.response['echo']!r} from {res.response['from']}" if res.success else ""
        print(f"   RESULT: {outcome}{extra}  -> {'PASS' if ok else 'FAIL'}")

    passed = sum(results)
    print(f"\n{'=' * 60}\n{passed}/{len(results)} scenarios behaved as expected.")
    print(f"Authentication log: {log_file}")
    return all(results)


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
