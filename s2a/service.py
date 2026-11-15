"""Simulated service that authenticates agents before serving requests.

Validation pipeline (fail closed; first failure rejects the request):
  1. Bearer token present and well formed
  2. Signature valid, algorithm pinned to RS256 (blocks alg=none / HS256 confusion)
  3. Issuer (iss) is the trusted issuer
  4. Audience (aud) is THIS service
  5. Token lifetime: exp / nbf / iat present and valid
  6. Agent identity (sub) is registered and active
  7. Agent is allowed to call this service (registry audience list)
  8. Authorization: the route's permission is in the token AND still granted in the registry
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

import jwt

from .audit_log import AuditLog
from .registry import AgentRegistry
from .token_issuer import ALGORITHM

# Error taxonomy: reason code -> HTTP-style status
UNAUTHENTICATED, FORBIDDEN = 401, 403


@dataclass
class AuthResult:
    allowed: bool
    status: int
    reason: str
    agent_id: Optional[str] = None
    data: Any = None

    def __str__(self) -> str:
        verdict = "ALLOWED" if self.allowed else "REJECTED"
        return f"{self.status} {verdict} ({self.reason})"


class _Reject(Exception):
    def __init__(self, status: int, reason: str, claims: Optional[dict] = None):
        super().__init__(reason)
        self.status, self.reason, self.claims = status, reason, claims


# PyJWT exception -> (status, reason code). Order matters: most specific first.
_JWT_ERRORS = [
    (jwt.ExpiredSignatureError, "TOKEN_EXPIRED"),
    (jwt.ImmatureSignatureError, "TOKEN_NOT_YET_VALID"),
    (jwt.InvalidSignatureError, "INVALID_SIGNATURE"),
    (jwt.InvalidAudienceError, "INVALID_AUDIENCE"),
    (jwt.InvalidIssuerError, "INVALID_ISSUER"),
    (jwt.MissingRequiredClaimError, "MISSING_CLAIM"),
    (jwt.InvalidAlgorithmError, "INVALID_ALGORITHM"),
    (jwt.DecodeError, "MALFORMED_TOKEN"),
    (jwt.InvalidTokenError, "INVALID_TOKEN"),
]


class SimulatedService:
    def __init__(self, name: str, trusted_issuer: str, issuer_public_key_pem: bytes,
                 registry: AgentRegistry, audit_log: AuditLog, leeway_seconds: int = 0) -> None:
        self.name = name                      # this service's audience identifier
        self.trusted_issuer = trusted_issuer
        self._public_key = issuer_public_key_pem
        self.registry = registry
        self.audit = audit_log
        self.leeway = leeway_seconds
        # (method, path) -> (required permission, handler)
        self._routes: Dict[Tuple[str, str], Tuple[str, Callable[[], Any]]] = {}

    def route(self, method: str, path: str, permission: str, handler: Callable[[], Any]) -> None:
        self._routes[(method.upper(), path)] = (permission, handler)

    # ------------------------------------------------------------ public API
    def handle_request(self, method: str, path: str, authorization: Optional[str],
                       source_ip: Optional[str] = None) -> AuthResult:
        action = f"{method.upper()} {path}"
        unverified: Optional[dict] = None
        claims: Optional[dict] = None
        try:
            token = self._extract_bearer(authorization)
            unverified = self._peek(token)
            claims = self._verify_token(token)
            agent = self._check_agent(claims)
            permission, handler = self._lookup_route(method, path)
            self._authorize(claims, agent, permission)
        except _Reject as r:
            c = r.claims or claims or unverified or {}
            outcome = "DENIED" if r.status == FORBIDDEN else "FAILURE"
            self.audit.record(outcome=outcome, reason=r.reason, agent_id=c.get("sub"),
                              action=action, resource=self.name, jti=c.get("jti"),
                              source_ip=source_ip)
            return AuthResult(False, r.status, r.reason, c.get("sub") if r.status == FORBIDDEN else None)

        self.audit.record(outcome="SUCCESS", reason="AUTHENTICATED_AND_AUTHORIZED",
                          agent_id=claims["sub"], action=action, resource=self.name,
                          jti=claims.get("jti"), source_ip=source_ip)
        return AuthResult(True, 200, "AUTHENTICATED_AND_AUTHORIZED", claims["sub"], handler())

    # ------------------------------------------------------------ pipeline steps
    @staticmethod
    def _extract_bearer(header: Optional[str]) -> str:
        if not header:
            raise _Reject(UNAUTHENTICATED, "MISSING_TOKEN")
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise _Reject(UNAUTHENTICATED, "MALFORMED_AUTH_HEADER")
        return parts[1]

    @staticmethod
    def _peek(token: str) -> Optional[dict]:
        """Unverified claims, used ONLY to label audit entries - never for decisions."""
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return None

    def _verify_token(self, token: str) -> dict:
        try:
            return jwt.decode(
                token, self._public_key,
                algorithms=[ALGORITHM],                 # pinned: rejects alg=none / HS256
                audience=self.name, issuer=self.trusted_issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "nbf", "iss", "sub", "aud"]},
            )
        except jwt.PyJWTError as exc:
            for exc_type, reason in _JWT_ERRORS:
                if isinstance(exc, exc_type):
                    raise _Reject(UNAUTHENTICATED, reason)
            raise _Reject(UNAUTHENTICATED, "INVALID_TOKEN")

    def _check_agent(self, claims: dict):
        agent = self.registry.get(claims["sub"])
        if agent is None:
            raise _Reject(UNAUTHENTICATED, "UNREGISTERED_AGENT", claims)
        if not agent.active:
            raise _Reject(UNAUTHENTICATED, "AGENT_REVOKED", claims)
        if self.name not in agent.allowed_audiences:
            raise _Reject(FORBIDDEN, "AGENT_NOT_ALLOWED_FOR_SERVICE", claims)
        return agent

    def _lookup_route(self, method: str, path: str):
        route = self._routes.get((method.upper(), path))
        if route is None:
            raise _Reject(FORBIDDEN, "UNKNOWN_ACTION")
        return route

    @staticmethod
    def _authorize(claims: dict, agent, permission: str) -> None:
        if permission not in set(claims.get("permissions", [])):
            raise _Reject(FORBIDDEN, f"INSUFFICIENT_PERMISSIONS:{permission}", claims)
        if permission not in agent.permissions:      # registry may have been tightened since issuance
            raise _Reject(FORBIDDEN, f"PERMISSION_REVOKED:{permission}", claims)
