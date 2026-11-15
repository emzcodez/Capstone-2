"""Token issuer: signs short-lived RS256 JWTs for registered agents only.

The issuer holds the PRIVATE key. Services only ever hold the PUBLIC key,
so a compromised service cannot mint tokens.
"""
from __future__ import annotations

import time
import uuid
from typing import Iterable, Optional, Tuple

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .registry import AgentRegistry

ALGORITHM = "RS256"
DEFAULT_TTL_SECONDS = 60


class IssuanceError(Exception):
    """Raised when the issuer refuses to mint a token."""


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


class TokenIssuer:
    def __init__(self, issuer: str, private_key_pem: bytes, registry: AgentRegistry,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.issuer = issuer
        self._private_key = private_key_pem
        self.registry = registry
        self.ttl_seconds = ttl_seconds

    def issue_token(self, agent_id: str, audience: str,
                    permissions: Optional[Iterable[str]] = None,
                    ttl_seconds: Optional[int] = None) -> str:
        agent = self.registry.get(agent_id)
        if agent is None:
            raise IssuanceError(f"agent '{agent_id}' is not registered")
        if not agent.active:
            raise IssuanceError(f"agent '{agent_id}' is revoked")
        if audience not in agent.allowed_audiences:
            raise IssuanceError(f"agent '{agent_id}' may not request tokens for '{audience}'")

        # Least privilege: a token can only carry a subset of the registered permissions.
        requested = set(permissions) if permissions is not None else set(agent.permissions)
        excess = requested - agent.permissions
        if excess:
            raise IssuanceError(f"permissions not granted to agent: {sorted(excess)}")

        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": agent_id,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + (ttl_seconds if ttl_seconds is not None else self.ttl_seconds),
            "jti": str(uuid.uuid4()),
            "permissions": sorted(requested),
        }
        return jwt.encode(claims, self._private_key, algorithm=ALGORITHM)
