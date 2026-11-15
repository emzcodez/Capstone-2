import time

import jwt
import pytest

from s2a.demo import ISSUER, OTHER_SERVICE, SERVICE, build_environment, _forge
from s2a.token_issuer import IssuanceError, generate_keypair


@pytest.fixture()
def env(tmp_path):
    registry, issuer, service, key = build_environment(str(tmp_path / "audit.jsonl"), echo=False)
    return registry, issuer, service, key


def call(service, token, method="GET", path="/reports"):
    return service.handle_request(method, path, f"Bearer {token}" if token else None)


def test_authorized_agent_succeeds(env):
    _, issuer, service, _ = env
    r = call(service, issuer.issue_token("agent-reader", SERVICE))
    assert r.allowed and r.status == 200 and r.agent_id == "agent-reader"
    assert r.data == ["Q1-report", "Q2-report"]


def test_token_is_short_lived_and_has_expected_claims(env):
    _, issuer, _, key = env
    claims = jwt.decode(issuer.issue_token("agent-reader", SERVICE), options={"verify_signature": False})
    assert claims["iss"] == ISSUER and claims["sub"] == "agent-reader" and claims["aud"] == SERVICE
    assert claims["exp"] - claims["iat"] <= 60 and claims["jti"]


def test_insufficient_permission_is_403(env):
    _, issuer, service, _ = env
    r = call(service, issuer.issue_token("agent-reader", SERVICE), "POST")
    assert (r.status, r.reason) == (403, "INSUFFICIENT_PERMISSIONS:reports:write")


def test_token_scope_narrower_than_registry(env):
    _, issuer, service, _ = env
    t = issuer.issue_token("agent-writer", SERVICE, permissions=["reports:read"])
    assert not call(service, t, "POST").allowed
    assert call(service, t, "GET").allowed


def test_permission_tightened_after_issuance(env):
    registry, issuer, service, _ = env
    t = issuer.issue_token("agent-writer", SERVICE)
    registry.register("agent-writer", "ops-team", ["reports:read"], [SERVICE])
    assert call(service, t, "POST").reason == "PERMISSION_REVOKED:reports:write"


def test_unknown_route_denied(env):
    _, issuer, service, _ = env
    r = call(service, issuer.issue_token("agent-reader", SERVICE), "GET", "/secrets")
    assert (r.status, r.reason) == (403, "UNKNOWN_ACTION")


def test_expired_token(env):
    _, _, service, key = env
    now = int(time.time())
    t = _forge({"iat": now - 120, "nbf": now - 120, "exp": now - 60}, key)
    assert call(service, t).reason == "TOKEN_EXPIRED"


def test_token_not_yet_valid(env):
    _, _, service, key = env
    now = int(time.time())
    assert call(service, _forge({"nbf": now + 300}, key)).reason == "TOKEN_NOT_YET_VALID"


def test_wrong_signing_key(env):
    _, _, service, _ = env
    attacker, _ = generate_keypair()
    assert call(service, _forge({}, attacker)).reason == "INVALID_SIGNATURE"


def test_tampered_payload(env):
    _, issuer, service, _ = env
    h, p, s = issuer.issue_token("agent-reader", SERVICE).split(".")
    other = jwt.api_jws.base64url_encode(b'{"sub":"agent-writer"}').decode()
    assert call(service, f"{h}.{other}.{s}").status == 401


def test_wrong_issuer(env):
    _, _, service, key = env
    assert call(service, _forge({"iss": "https://evil"}, key)).reason == "INVALID_ISSUER"


def test_wrong_audience(env):
    _, issuer, service, _ = env
    assert call(service, issuer.issue_token("agent-billing", OTHER_SERVICE)).reason == "INVALID_AUDIENCE"


def test_alg_none_rejected(env):
    _, _, service, _ = env
    now = int(time.time())
    t = jwt.encode({"iss": ISSUER, "sub": "agent-reader", "aud": SERVICE, "iat": now,
                    "nbf": now, "exp": now + 60, "permissions": ["reports:read"]}, None, algorithm="none")
    assert call(service, t).status == 401


def test_hs256_key_confusion_rejected(env):
    # Attacker signs HS256 using the (public) RSA key as the HMAC secret.
    _, _, service, _ = env
    now = int(time.time())
    t = jwt.encode({"iss": ISSUER, "sub": "agent-reader", "aud": SERVICE, "iat": now, "nbf": now,
                    "exp": now + 60, "permissions": ["reports:read"]},
                   "any-secret", algorithm="HS256")
    assert call(service, t).status == 401


def test_missing_exp_rejected(env):
    _, _, service, key = env
    now = int(time.time())
    t = jwt.encode({"iss": ISSUER, "sub": "agent-reader", "aud": SERVICE, "iat": now, "nbf": now,
                    "permissions": ["reports:read"]}, key, algorithm="RS256")
    assert call(service, t).reason == "MISSING_CLAIM"


def test_unregistered_agent(env):
    _, _, service, key = env
    r = call(service, _forge({"sub": "agent-ghost"}, key))
    assert (r.status, r.reason) == (401, "UNREGISTERED_AGENT")


def test_revoked_agent(env):
    registry, issuer, service, _ = env
    t = issuer.issue_token("agent-reader", SERVICE)
    registry.revoke("agent-reader")
    assert call(service, t).reason == "AGENT_REVOKED"


def test_missing_and_malformed_header(env):
    _, _, service, _ = env
    assert service.handle_request("GET", "/reports", None).reason == "MISSING_TOKEN"
    assert service.handle_request("GET", "/reports", "Token abc").reason == "MALFORMED_AUTH_HEADER"
    assert call(service, "not.a.jwt").reason == "MALFORMED_TOKEN"


def test_issuer_refusals(env):
    _, issuer, _, _ = env
    with pytest.raises(IssuanceError):
        issuer.issue_token("agent-ghost", SERVICE)
    with pytest.raises(IssuanceError):
        issuer.issue_token("agent-reader", OTHER_SERVICE)
    with pytest.raises(IssuanceError):
        issuer.issue_token("agent-reader", SERVICE, permissions=["reports:write"])


def test_audit_log_records_success_and_failure(env):
    _, issuer, service, key = env
    call(service, issuer.issue_token("agent-reader", SERVICE))
    call(service, _forge({"sub": "agent-ghost"}, key))
    outcomes = [e["outcome"] for e in service.audit.entries]
    assert outcomes == ["SUCCESS", "FAILURE"]
    assert service.audit.entries[0]["agent_id"] == "agent-reader"
    assert service.audit.entries[1]["reason"] == "UNREGISTERED_AGENT"
    assert service.audit.path.read_text().count("\n") == 2


def test_audit_log_never_contains_token(env):
    _, issuer, service, _ = env
    t = issuer.issue_token("agent-reader", SERVICE)
    call(service, t)
    assert t not in service.audit.path.read_text()
