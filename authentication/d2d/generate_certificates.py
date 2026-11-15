"""
Generate every certificate used by the D2D demo.

    python -m authentication.d2d.generate_certificates [--out authentication/d2d/certs]

Files written to the output directory (<name>.crt / <name>.key):

    ca                   trusted root CA (the one every device is configured to trust)
    rogue-ca             an attacker's CA - NOT trusted by anyone

    device-a             valid certificate for Device A, signed by `ca`
    device-b             valid certificate for Device B, signed by `ca`
    device-c             valid certificate for Device C, signed by `ca` (but not authorised)

    device-a-expired     Device A's certificate after it expired (signed by `ca`)
    device-b-expired     Device B's certificate after it expired (signed by `ca`)

    device-a-untrusted   impersonator of Device A, signed by `rogue-ca`
    device-b-untrusted   impersonator of Device B, signed by `rogue-ca`
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

from . import certificate_manager as cm

DEFAULT_CERT_DIR = Path(__file__).resolve().parent / "certs"


def generate_all(out_dir: Path = DEFAULT_CERT_DIR) -> Dict[str, Path]:
    """Create all demo certificates. Returns {name: directory-relative base path}."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    def write(name, key, cert):
        cm.save_key(key, out_dir / f"{name}.key")
        cm.save_cert(cert, out_dir / f"{name}.crt")

    # Two certificate authorities: one trusted, one attacker-controlled.
    ca_key, ca_cert = cm.create_ca("D2D Root CA")
    rogue_key, rogue_cert = cm.create_ca("Rogue CA")
    write("ca", ca_key, ca_cert)
    write("rogue-ca", rogue_key, rogue_cert)

    # Valid devices (separate key pair + certificate per device).
    for dev in ("device-a", "device-b", "device-c"):
        write(dev, *cm.issue_device_cert(ca_key, ca_cert, dev))

    # Expired: legitimate CA, legitimate identity, but validity ended yesterday.
    for dev in ("device-a", "device-b"):
        key, cert = cm.issue_device_cert(
            ca_key, ca_cert, dev,
            not_before=now - timedelta(days=90),
            not_after=now - timedelta(days=1))
        write(f"{dev}-expired", key, cert)

    # Untrusted: perfectly valid dates, but issued by the rogue CA.
    for dev in ("device-a", "device-b"):
        write(f"{dev}-untrusted", *cm.issue_device_cert(rogue_key, rogue_cert, dev))

    return {p.stem: p for p in sorted(out_dir.glob("*.crt"))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=DEFAULT_CERT_DIR, help="output directory")
    args = parser.parse_args()
    certs = generate_all(args.out)
    print(f"Generated {len(certs)} certificates in {args.out}:")
    for name in certs:
        cert = cm.load_cert(args.out / f"{name}.crt")
        print(f"  {name:20s} CN={cm.device_id_of(cert):10s} "
              f"valid {cert.not_valid_before_utc:%Y-%m-%d} -> {cert.not_valid_after_utc:%Y-%m-%d}")


if __name__ == "__main__":
    main()
