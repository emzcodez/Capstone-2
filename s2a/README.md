# S2A - Service-to-Agent Authentication (Prototype 2)

**Objective:** show how a service verifies an agent's identity *before* accepting its requests.

```
 Agent registry ──registers──▶ agents (id, owner, permissions, allowed services)
        │
 Token issuer  (PRIVATE key) ──signs short-lived RS256 JWT──▶ Agent
                                                               │  Authorization: Bearer <jwt>
                                                               ▼
 Simulated service (PUBLIC key only) ──validate──▶ authorize ──▶ handler
                                         │
                                         └──▶ audit log (JSON Lines) for every attempt
```

## Run
```bash
pip install -r requirements.txt      # needs PyJWT + cryptography (+ pytest for tests)
python -m s2a.demo                   # 16 scenarios + issuer refusals, writes logs/s2a_audit.jsonl
pytest tests/test_s2a.py -v          # 21 unit tests
```

## Files
| File | Role |
|---|---|
| `registry.py` | Registered agents: owner, permissions, services they may call, active/revoked |
| `token_issuer.py` | Mints RS256 JWTs (60 s default TTL) only for registered, active agents; permissions can only be narrowed, never widened |
| `service.py` | `SimulatedService.handle_request()` - the validation + authorization pipeline |
| `audit_log.py` | Append-only JSONL log of every success, denial and failure |
| `demo.py` | Runnable scenarios; `tests/test_s2a.py` covers the same plus edge cases |

## Token claims
`iss` issuer · `sub` agent id · `aud` target service · `iat`/`nbf`/`exp` (60 s) · `jti` unique id · `permissions` list

## Validation pipeline (fail closed, first failure rejects)
| # | Check | Reason code | Status |
|---|---|---|---|
| 1 | Bearer token present / well-formed | `MISSING_TOKEN`, `MALFORMED_AUTH_HEADER`, `MALFORMED_TOKEN` | 401 |
| 2 | Signature + algorithm pinned to RS256 | `INVALID_SIGNATURE`, `INVALID_ALGORITHM` (blocks `alg=none`, HS256 key confusion) | 401 |
| 3 | Issuer is the trusted issuer | `INVALID_ISSUER` | 401 |
| 4 | Audience is this service | `INVALID_AUDIENCE` | 401 |
| 5 | `exp`/`nbf`/`iat` present and valid | `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `MISSING_CLAIM` | 401 |
| 6 | Agent identity (`sub`) is registered and active | `UNREGISTERED_AGENT`, `AGENT_REVOKED` | 401 |
| 7 | Agent is allowed to call this service | `AGENT_NOT_ALLOWED_FOR_SERVICE` | 403 |
| 8 | Route permission is in the token **and** still in the registry | `INSUFFICIENT_PERMISSIONS:<perm>`, `PERMISSION_REVOKED:<perm>`, `UNKNOWN_ACTION` | 403 |

401 = could not authenticate; 403 = authenticated but not authorized.

## Audit log
One JSON object per attempt: `timestamp, outcome (SUCCESS|DENIED|FAILURE), reason, agent_id, action, resource, jti, source_ip`.
Tokens themselves are never logged. On failures, `agent_id` comes from *unverified* claims and is only a label for investigators.

## Design notes / limitations (prototype scope)
- Asymmetric keys: the service holds only the public key, so a compromised service cannot mint tokens.
- Keys are generated in memory per run. A real deployment would use a KMS/HSM, `kid` headers and key rotation (e.g. via JWKS).
- No replay protection: `jti` is logged but not tracked. Production would cache `jti` until `exp` or use mTLS / DPoP-style proof of possession.
- No rate limiting or lockout on repeated failures; the audit log gives the data to build it.
- The registry is in-memory; revocation takes effect immediately at the service because it re-checks the registry on each request.
