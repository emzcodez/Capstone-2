"""Import the standalone S2A and D2D prototype logs into the dashboard's common event schema.

Usage:
  python scripts/import_prototype_logs.py --s2a prototypes/s2a/demo_output.txt \
      --d2d prototypes/d2d/logs/auth.log --output data/sample_auth_events.json

The S2A input is the JSONL audit log (not the human-readable demo output).
The D2D input is the AUTH_SUCCESS/AUTH_FAILURE log emitted by the TLS demo.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzer.auth_events import AuthEventLog


D2D_RE = re.compile(
    r"AUTH_(SUCCESS|FAILURE)\s+local=(\S+)\s+role=(\S+)\s+peer=(\S+)"
    r"(?:\s+serial=(\S+))?(?:\s+reason=(\S+))?"
)


def import_s2a(path: Path, log: AuthEventLog) -> None:
    """Read S2A JSON Lines audit records."""
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
        outcome = str(row.get("outcome", "")).upper()
        result = "ALLOWED" if outcome == "SUCCESS" else "BLOCKED"
        reason = str(row.get("reason") or outcome or "Unknown S2A result")
        source = str(row.get("agent_id") or "unknown-agent")
        target = str(row.get("resource") or "unknown-service")
        log.record(source, target, "service", "JWT", result, reason,
                   prototype="S2A", action=row.get("action"), source_ip=row.get("source_ip"),
                   timestamp=row.get("timestamp"), jti=row.get("jti"))


def import_d2d(path: Path, log: AuthEventLog) -> None:
    """Read D2D TLS verifier logs; a peer authenticates to the local device."""
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = D2D_RE.search(line)
        if not match:
            continue
        outcome, local, role, peer, serial, reason = match.groups()
        result = "ALLOWED" if outcome == "SUCCESS" else "BLOCKED"
        timestamp = None
        try:
            timestamp = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
        log.record(peer, local, "device", "mTLS", result,
                   reason or ("Valid certificate" if result == "ALLOWED" else "TLS authentication failed"),
                   timestamp=timestamp, prototype="D2D", local_role=role,
                   certificate_serial=serial, raw_log=line.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s2a", type=Path, help="S2A JSONL audit log")
    parser.add_argument("--d2d", type=Path, help="D2D authentication log")
    parser.add_argument("--output", type=Path, default=ROOT / "data/sample_auth_events.json")
    args = parser.parse_args()
    if not args.s2a and not args.d2d:
        parser.error("provide at least one of --s2a or --d2d")
    log = AuthEventLog()
    if args.s2a:
        import_s2a(args.s2a, log)
    if args.d2d:
        import_d2d(args.d2d, log)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    log.save(args.output)
    print(f"Imported {len(log.events)} authentication events -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
