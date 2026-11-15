"""Agent registry: the source of truth for which agents exist and what they may do."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, Optional


@dataclass(frozen=True)
class RegisteredAgent:
    agent_id: str
    owner: str
    permissions: FrozenSet[str]                 # e.g. {"reports:read"}
    allowed_audiences: FrozenSet[str]           # services this agent may call
    active: bool = True


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: Dict[str, RegisteredAgent] = {}

    def register(self, agent_id: str, owner: str, permissions: Iterable[str],
                 allowed_audiences: Iterable[str]) -> RegisteredAgent:
        agent = RegisteredAgent(agent_id, owner, frozenset(permissions),
                                frozenset(allowed_audiences))
        self._agents[agent_id] = agent
        return agent

    def get(self, agent_id: str) -> Optional[RegisteredAgent]:
        return self._agents.get(agent_id)

    def revoke(self, agent_id: str) -> None:
        a = self._agents.get(agent_id)
        if a:
            self._agents[agent_id] = RegisteredAgent(
                a.agent_id, a.owner, a.permissions, a.allowed_audiences, active=False)
