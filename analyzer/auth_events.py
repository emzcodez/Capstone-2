"""Common authentication-event format shared by the D2D (mTLS) and S2A (JWT) prototypes, plus the
conversion of failed/blocked attempts into identity-risk findings for the main framework.

Event (JSON):
  {"event_id": "AUTH-001", "timestamp": "...", "source_identity": "device_A", "target_identity": "device_B",
   "identity_type": "device" | "service" | "application", "authentication_method": "mTLS" | "JWT",
   "result": "ALLOWED" | "BLOCKED", "reason": "..."}
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

METHODS = {"mTLS", "JWT"}
RESULTS = {"ALLOWED", "BLOCKED"}
IDENTITY_TYPES = {"device", "service", "application"}
REQUIRED = ("event_id", "source_identity", "target_identity", "identity_type",
            "authentication_method", "result", "reason")

# failure reason -> (rule, severity, title, remediation). First substring match wins.
FAILURE_RULES = [
    ("revoked", "AUTH_REVOKED_CREDENTIAL", "critical", "Revoked credential still in use",
     "Treat the identity as compromised: rotate its credentials, review what it accessed, and keep it revoked."),
    ("signature", "AUTH_FORGED_CREDENTIAL", "critical", "Forged or tampered credential presented",
     "Investigate the source: invalid signatures mean a forged token/certificate. Rotate signing keys if exposed."),
    ("untrusted", "AUTH_UNTRUSTED_ISSUER", "high", "Credential from untrusted issuer",
     "Confirm the issuer is not an attacker-controlled CA/IdP; only add issuers through reviewed change control."),
    ("issuer", "AUTH_UNTRUSTED_ISSUER", "high", "Credential from untrusted issuer",
     "Confirm the issuer is not an attacker-controlled CA/IdP; only add issuers through reviewed change control."),
    ("identity mismatch", "AUTH_IDENTITY_MISMATCH", "high", "Credential does not match claimed identity",
     "Possible impersonation: verify which workload holds the credential and re-issue it."),
    ("audience", "AUTH_WRONG_AUDIENCE", "medium", "Token presented to the wrong audience",
     "Check for token replay/lateral movement; restrict tokens to a single audience."),
    ("scope", "AUTH_SCOPE_VIOLATION", "medium", "Token lacks the required scope",
     "Review the caller's granted scopes; an over-reach attempt may indicate probing."),
    ("expired", "AUTH_EXPIRED_CREDENTIAL", "low", "Expired credential used",
     "Automate rotation/renewal. Repeated use of expired credentials points to unmanaged identities."),
    ("missing", "AUTH_NO_CREDENTIAL", "medium", "Connection attempted without credentials",
     "Enforce mutual authentication on every endpoint; investigate the unauthenticated caller."),
]
DEFAULT_RULE = ("AUTH_FAILURE", "medium", "Authentication failure", "Review the failed authentication attempt.")
REPEAT_THRESHOLD = 3           # blocked attempts from one source -> probing, escalate one level
SEV_ORDER = ["low", "medium", "high", "critical"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_event(event_id: str, source: str, target: str, identity_type: str, method: str, result: str,
               reason: str, timestamp: Optional[str] = None, **extra) -> dict:
    ev = {"event_id": event_id, "timestamp": timestamp or now_iso(), "source_identity": source,
          "target_identity": target, "identity_type": identity_type, "authentication_method": method,
          "result": result.upper(), "reason": reason, **extra}
    validate_event(ev)
    return ev


def validate_event(ev: dict) -> dict:
    missing = [k for k in REQUIRED if k not in ev]
    if missing:
        raise ValueError(f"auth event missing fields: {missing}")
    if ev["authentication_method"] not in METHODS:
        raise ValueError(f"unknown authentication_method {ev['authentication_method']!r}")
    if ev["result"] not in RESULTS:
        raise ValueError(f"result must be ALLOWED or BLOCKED, got {ev['result']!r}")
    if ev["identity_type"] not in IDENTITY_TYPES:
        raise ValueError(f"unknown identity_type {ev['identity_type']!r}")
    return ev


class AuthEventLog:
    """Append-only recorder both prototypes write to. Assigns AUTH-001, AUTH-002, ..."""

    def __init__(self, events: Optional[Iterable[dict]] = None):
        self.events: List[dict] = [validate_event(dict(e)) for e in (events or [])]

    def record(self, source, target, identity_type, method, result, reason, **extra) -> dict:
        ev = make_event(f"AUTH-{len(self.events) + 1:03d}", source, target, identity_type, method,
                        result, reason, **extra)
        self.events.append(ev)
        return ev

    def save(self, path) -> None:
        Path(path).write_text(json.dumps(self.events, indent=2), encoding="utf-8")


def load_auth_events(path) -> List[dict]:
    with open(path, encoding="utf-8") as fh:
        return [validate_event(e) for e in json.load(fh)]


def summarize_auth(events: List[dict]) -> dict:
    by_method = defaultdict(lambda: {"ALLOWED": 0, "BLOCKED": 0})
    for e in events:
        by_method[e["authentication_method"]][e["result"]] += 1
    blocked = [e for e in events if e["result"] == "BLOCKED"]
    return {"total": len(events), "allowed": len(events) - len(blocked), "blocked": len(blocked),
            "by_method": dict(by_method), "top_failure_reasons": Counter(e["reason"] for e in blocked).most_common(5)}


def _rule_for(reason: str):
    r = (reason or "").lower()
    return next(((rule, sev, title, fix) for key, rule, sev, title, fix in FAILURE_RULES if key in r), DEFAULT_RULE)


def _bump(sev: str) -> str:
    return SEV_ORDER[min(SEV_ORDER.index(sev) + 1, len(SEV_ORDER) - 1)]


def auth_findings(events: List[dict], identities: Optional[List[dict]] = None) -> List[dict]:
    """Turn BLOCKED events into identity-risk findings in the same shape detect_risks() emits.

    One finding per (source, rule); repeated attempts are aggregated and escalated one severity level at
    REPEAT_THRESHOLD+ attempts (credential probing). ALLOWED events produce no finding.
    """
    known = {i.get("name"): i.get("arn") for i in (identities or [])}
    groups: Dict[tuple, List[dict]] = defaultdict(list)
    for e in events:
        if e["result"] == "BLOCKED":
            groups[(e["source_identity"], _rule_for(e["reason"])[0])].append(e)
    out = []
    for (source, rule), evs in groups.items():
        _, sev, title, fix = _rule_for(evs[0]["reason"])
        repeated = len(evs) >= REPEAT_THRESHOLD
        if repeated:
            sev = _bump(sev)
        targets = sorted({e["target_identity"] for e in evs})
        methods = sorted({e["authentication_method"] for e in evs})
        reason = (f"{len(evs)} blocked {'/'.join(methods)} attempt(s) by {source} -> {', '.join(targets)}: "
                  f"{evs[0]['reason']}" + (" (repeated attempts: possible probing)" if repeated else ""))
        out.append({"rule": rule, "severity": sev, "title": title, "identity": source,
                    "identity_arn": known.get(source), "resource": ", ".join(targets), "reason": reason,
                    "remediation": fix, "source": "authentication",
                    "evidence": {"auth_event_ids": [e["event_id"] for e in evs],
                                 "identity_type": evs[0]["identity_type"], "methods": methods}})
    return sorted(out, key=lambda f: -SEV_ORDER.index(f["severity"]))
