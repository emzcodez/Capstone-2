"""Audit log for authentication decisions (JSON Lines file + optional console echo)."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLog:
    def __init__(self, path: Optional[str] = "logs/s2a_audit.jsonl", echo: bool = False) -> None:
        self.path = Path(path) if path else None
        self.echo = echo
        self.entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, *, outcome: str, reason: str, agent_id: Optional[str],
               action: str, resource: str, jti: Optional[str] = None,
               source_ip: Optional[str] = None) -> Dict[str, Any]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "outcome": outcome,           # SUCCESS | DENIED | FAILURE
            "reason": reason,
            "agent_id": agent_id,         # unverified claim if auth failed - never trusted
            "action": action,
            "resource": resource,
            "jti": jti,
            "source_ip": source_ip,
        }
        with self._lock:
            self.entries.append(entry)
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
        if self.echo:
            print(f"    [audit] {entry['outcome']:<7} {reason}")
        return entry
