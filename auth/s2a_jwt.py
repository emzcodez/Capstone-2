"""S2A prototype: service-to-application JWT verification (PyJWT, RS256).

The application checks signature, issuer, audience, expiry and required scope on a bearer token.
Every attempt is recorded in the common auth format.
"""
from __future__ import annotations

import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from analyzer.auth_events import AuthEventLog


def make_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def issue_token(private_key, service: str, issuer: str, audience: str, scopes=("read",), ttl: int = 300):
    now = int(time.time())
    claims = {"sub": service, "iss": issuer, "aud": audience, "scope": " ".join(scopes),
              "iat": now, "exp": now + ttl}
    return jwt.encode(claims, private_key, algorithm="RS256")


class S2AVerifier:
    """`trusted_issuers` maps issuer name -> public key. `revoked_subjects` are services whose tokens are denied."""

    def __init__(self, application: str, trusted_issuers: dict, required_scope: str = "read",
                 revoked_subjects=(), log: AuthEventLog | None = None):
        self.app, self.issuers, self.scope = application, trusted_issuers, required_scope
        self.revoked = set(revoked_subjects)
        self.log = log if log is not None else AuthEventLog()

    def _check(self, claimed: str, token: str | None) -> str | None:
        if not token:
            return "Missing token"
        try:
            iss = jwt.decode(token, options={"verify_signature": False}).get("iss")
        except jwt.PyJWTError:
            return "Invalid token signature (malformed token)"
        key = self.issuers.get(iss)
        if key is None:
            return f"Untrusted issuer ({iss})"
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.app)
        except jwt.ExpiredSignatureError:
            return "Expired token"
        except jwt.InvalidAudienceError:
            return "Wrong audience"
        except jwt.PyJWTError:
            return "Invalid token signature"
        if claims.get("sub") != claimed:
            return f"Identity mismatch (token is for {claims.get('sub')})"
        if claimed in self.revoked:
            return "Revoked service credential"
        if self.scope not in claims.get("scope", "").split():
            return f"Insufficient scope (needs {self.scope})"
        return None

    def authenticate(self, claimed_service: str, token: str | None) -> dict:
        reason = self._check(claimed_service, token)
        return self.log.record(claimed_service, self.app, "service", "JWT",
                               "BLOCKED" if reason else "ALLOWED", reason or "Valid token")
