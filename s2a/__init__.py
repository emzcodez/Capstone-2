"""S2A - Service-to-Agent authentication prototype (Prototype 2)."""
from .registry import AgentRegistry, RegisteredAgent
from .token_issuer import TokenIssuer, generate_keypair
from .service import SimulatedService, AuthResult
from .audit_log import AuditLog

__all__ = ["AgentRegistry", "RegisteredAgent", "TokenIssuer", "generate_keypair",
           "SimulatedService", "AuthResult", "AuditLog"]
