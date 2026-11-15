"""Run both prototypes through a fixed scenario and write data/sample_auth_events.json.
Usage: python scripts/gen_auth_events.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer.auth_events import AuthEventLog
from auth.d2d_mtls import D2DVerifier, issue_device_cert, make_ca
from auth.s2a_jwt import S2AVerifier, issue_token, make_keypair


def run() -> AuthEventLog:
    log = AuthEventLog()
    # ---- D2D (mTLS)
    ca_key, ca = make_ca("corp-device-ca")
    rogue_key, rogue = make_ca("rogue-ca")
    _, a = issue_device_cert(ca_key, ca, "device_A")
    _, c = issue_device_cert(ca_key, ca, "device_C")
    _, old = issue_device_cert(ca_key, ca, "device_old", expired=True)
    _, stolen = issue_device_cert(ca_key, ca, "device_stolen")
    _, evil = issue_device_cert(rogue_key, rogue, "device_X")
    d2d = D2DVerifier("device_B", [ca], revoked={stolen.serial_number}, log=log)
    d2d.authenticate("device_A", a)
    d2d.authenticate("device_C", c)
    d2d.authenticate("device_old", old)
    d2d.authenticate("device_stolen", stolen)
    d2d.authenticate("device_C", a)          # device_C presents device_A's cert
    for _ in range(3):                       # repeated probing with an attacker-issued cert
        d2d.authenticate("device_X", evil)
    d2d.authenticate("device_Y", None)
    # ---- S2A (JWT)
    idp_key, idp_pub = make_keypair()
    bad_key, _ = make_keypair()
    app = "payments-api"
    s2a = S2AVerifier(app, {"corp-idp": idp_pub}, required_scope="payments:write", revoked_subjects={"svc-legacy"}, log=log)
    s2a.authenticate("svc-billing", issue_token(idp_key, "svc-billing", "corp-idp", app, ["payments:write"]))
    s2a.authenticate("svc-reports", issue_token(idp_key, "svc-reports", "corp-idp", app, ["payments:read"]))
    s2a.authenticate("svc-batch", issue_token(idp_key, "svc-batch", "corp-idp", app, ["payments:write"], ttl=-60))
    s2a.authenticate("svc-web", issue_token(idp_key, "svc-web", "corp-idp", "other-api", ["payments:write"]))
    s2a.authenticate("svc-legacy", issue_token(idp_key, "svc-legacy", "corp-idp", app, ["payments:write"]))
    s2a.authenticate("svc-evil", issue_token(bad_key, "svc-evil", "corp-idp", app, ["payments:write"]))   # forged signature
    s2a.authenticate("svc-evil2", issue_token(bad_key, "svc-evil2", "attacker-idp", app, ["payments:write"]))
    s2a.authenticate("svc-ghost", None)
    return log


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "data" / "sample_auth_events.json"
    log = run()
    log.save(out)
    print(f"wrote {len(log.events)} events -> {out}")
