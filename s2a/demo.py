"""S2A demo: an authorized agent reaches a service; bad requests are rejected.

Run:  python -m s2a.demo
"""
from __future__ import annotations

import json
import time

import jwt

from .audit_log import AuditLog
from .registry import AgentRegistry
from .service import SimulatedService
from .token_issuer import ALGORITHM, IssuanceError, TokenIssuer, generate_keypair

ISSUER = "https://issuer.s2a.local"
SERVICE = "reports-service"
OTHER_SERVICE = "billing-service"


def build_environment(log_path="logs/s2a_audit.jsonl", echo=True):
    private_pem, public_pem = generate_keypair()
    registry = AgentRegistry()
    registry.register("agent-reader", "analytics-team", ["reports:read"], [SERVICE])
    registry.register("agent-writer", "ops-team", ["reports:read", "reports:write"], [SERVICE])
    registry.register("agent-billing", "finance-team", ["invoices:read"], [OTHER_SERVICE])
    registry.register("agent-retired", "legacy-team", ["reports:read"], [SERVICE])

    issuer = TokenIssuer(ISSUER, private_pem, registry, ttl_seconds=60)
    audit = AuditLog(log_path, echo=echo)
    service = SimulatedService(SERVICE, ISSUER, public_pem, registry, audit)
    service.route("GET", "/reports", "reports:read", lambda: ["Q1-report", "Q2-report"])
    service.route("POST", "/reports", "reports:write", lambda: {"created": "Q3-report"})
    service.route("DELETE", "/reports", "reports:delete", lambda: {"deleted": True})
    return registry, issuer, service, private_pem


def _forge(claims_override: dict, key, base_agent="agent-reader", aud=SERVICE, alg=ALGORITHM):
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": base_agent, "aud": aud, "iat": now, "nbf": now,
              "exp": now + 60, "jti": "forged", "permissions": ["reports:read"]}
    claims.update(claims_override)
    return jwt.encode(claims, key, algorithm=alg)


def main() -> None:
    registry, issuer, service, issuer_key = build_environment()
    attacker_key, _ = generate_keypair()
    results = []

    def attempt(title, expect_ok, method, path, token):
        print(f"\n> {title}")
        header = f"Bearer {token}" if token is not None else None
        res = service.handle_request(method, path, header, source_ip="10.0.0.5")
        print(f"    {method} {path}  ->  {res}")
        if res.data is not None:
            print(f"    response body: {res.data}")
        results.append((title, expect_ok, res.allowed))

    print("=" * 72 + "\nS2A - Service-to-Agent Authentication Demo\n" + "=" * 72)

    # ---- positive cases
    attempt("1. Authorized agent reads reports", True, "GET", "/reports",
            issuer.issue_token("agent-reader", SERVICE))
    attempt("2. Authorized agent writes reports", True, "POST", "/reports",
            issuer.issue_token("agent-writer", SERVICE))

    # ---- authorization failures
    attempt("3. Registered agent tries an action it was never granted (write)", False,
            "POST", "/reports", issuer.issue_token("agent-reader", SERVICE))
    attempt("4. Agent narrowed its own token, then asks for more than the token carries", False,
            "POST", "/reports", issuer.issue_token("agent-writer", SERVICE, permissions=["reports:read"]))
    attempt("5. Agent with a valid token attempts DELETE, a permission it was never granted", False,
            "DELETE", "/reports", issuer.issue_token("agent-writer", SERVICE))
    attempt("6. Agent registered only for billing-service, token (validly signed) aimed at reports-service", False,
            "GET", "/reports", _forge({"sub": "agent-billing", "permissions": ["reports:read"]}, issuer_key))

    # ---- token failures
    attempt("7. Expired token", False, "GET", "/reports",
            _forge({"iat": int(time.time()) - 120, "nbf": int(time.time()) - 120,
                    "exp": int(time.time()) - 60}, issuer_key))
    t = issuer.issue_token("agent-reader", SERVICE)
    head, payload, sig = t.split(".")
    attempt("8. Tampered token (signature corrupted)", False, "GET", "/reports",
            f"{head}.{payload}.{sig[:-4]}AAAA")
    attempt("9. Token signed with the attacker's own key", False, "GET", "/reports",
            _forge({}, attacker_key))
    attempt("10. Wrong issuer", False, "GET", "/reports",
            _forge({"iss": "https://evil.example"}, issuer_key))
    attempt("11. Token meant for a different service (wrong audience)", False, "GET", "/reports",
            issuer.issue_token("agent-billing", OTHER_SERVICE))
    attempt("12. 'alg: none' unsigned token", False, "GET", "/reports",
            jwt.encode({"iss": ISSUER, "sub": "agent-reader", "aud": SERVICE,
                        "iat": int(time.time()), "nbf": int(time.time()),
                        "exp": int(time.time()) + 60, "permissions": ["reports:read"]},
                       None, algorithm="none"))
    attempt("13. Garbage token", False, "GET", "/reports", "not.a.jwt")
    attempt("14. No token at all", False, "GET", "/reports", None)

    # ---- identity failures
    attempt("15. Validly signed token for an UNREGISTERED agent", False, "GET", "/reports",
            _forge({"sub": "agent-ghost"}, issuer_key))
    token_retired = issuer.issue_token("agent-retired", SERVICE)
    registry.revoke("agent-retired")
    attempt("16. Agent revoked after its token was issued", False, "GET", "/reports", token_retired)

    # ---- issuer-side refusals
    print("\n> 17. Issuer refuses to mint tokens for bad requests")
    for who, aud in [("agent-ghost", SERVICE), ("agent-retired", SERVICE), ("agent-reader", OTHER_SERVICE)]:
        try:
            issuer.issue_token(who, aud)
        except IssuanceError as e:
            print(f"    issuer refused: {e}")

    # ---- summary
    print("\n" + "=" * 72 + "\nSUMMARY\n" + "=" * 72)
    ok = 0
    for title, expect_ok, got in results:
        good = expect_ok == got
        ok += good
        print(f"  [{'PASS' if good else 'FAIL'}] {title}  (expected "
              f"{'allow' if expect_ok else 'reject'}, got {'allow' if got else 'reject'})")
    print(f"\n{ok}/{len(results)} scenarios behaved as expected.")
    print(f"Audit log: {service.audit.path}  ({len(service.audit.entries)} entries)")
    by = {}
    for e in service.audit.entries:
        by[e["outcome"]] = by.get(e["outcome"], 0) + 1
    print("Outcome counts:", json.dumps(by))


if __name__ == "__main__":
    main()
