# Permission Analysis and Risk Detection 

```
iam_risk/
├── analyzer/policy_parser.py     # normalises IAM policies, action matching, action power levels
├── analyzer/risk_detector.py     # detect_risks(data) + the 5 rules + severity logic
├── tests/test_risk_detector.py   # pytest suite
├── tests/fixtures/*.json         # safe / risky / context / edge-case policies
└── data/sample_input.json        # example input in the agreed schema
```

Run: `pip install -r requirements.txt && pytest -v`
Demo: `python -m analyzer.risk_detector data/sample_input.json`

## Input / output contract
Input: `{"account_id", "sensitive_resources": [...], "identities": [{name, type, arn, classification,
trust_policy, attached_policies:[{name, document}], inline_policies:[...], group_policies:[{group, name, document}]}]}`

Output (sorted Critical -> Low): `identity, risk, reason, resource` (required by the brief) plus
`rule, policy, evidence` (for dashboard grouping and for Member 3's verification).

## Detection logic
1. **Parse**: every policy is flattened into statements (`Statement`/`Action`/`Resource`/`Principal` may be
   scalar or list; `NotAction`, `NotResource`, `Condition` are kept).
2. **Collect**: managed, inline and group policies for each identity are analysed together.
3. **Apply rules**
   | Rule | Flags | Base severity |
   |---|---|---|
   | WILDCARD_ACTION / ALLOW_NOT_ACTION | `*`, `iam:*`, `service:*`, Allow+NotAction | `*` on `*` Critical; `iam:*` Critical on `*`, High scoped; `s3:*` etc. High on `*`/sensitive, Medium scoped; other services Medium/Low |
   | UNRESTRICTED_RESOURCE | non-wildcard actions on `Resource:*` | permission/write High, read Medium, list Low; allow-list for actions that need `*` |
   | TRUST_* | public principal, external account, same-account root, web-identity/SAML without sub/aud | `Principal:*` Critical; external root w/o ExternalId/OrgID High; with it Low; same-account root Low |
   | SENSITIVE_RESOURCE_ACCESS | S3 actions reaching a configured sensitive resource | list Low, read Medium, write High, permission/admin Critical; +1 if via `Resource:*` |
   | PRIVILEGE_ESCALATION | curated action combinations across all of an identity's policies (PassRole+RunInstances, CreatePolicyVersion, Attach/Put policy, UpdateAssumeRolePolicy, ...) | per-combo High/Critical |
4. **Score context**: severity is lowered one level when mitigating conditions exist (`aws:SourceIp`,
   `aws:PrincipalOrgID`, `aws:RequestedRegion`, `sts:ExternalId`, ...), lowered for a PassRole scoped to
   specific roles, and raised for sensitive or unrestricted targets.
5. **Output**: de-duplicated, JSON-compatible findings, each with a reason.

## Limitations
- SCPs, permission boundaries and session policies are not evaluated; resource-based policies only partially.
- Conditions are judged heuristically from a fixed list of common keys, not evaluated.
- Explicit Deny statements are listed in `evidence.explicit_denies` but do not remove or lower findings.
- `NotAction`/`NotResource` are handled conservatively.
- Escalation detection covers a curated list of known paths only; sensitive resources must be configured.
- Static analysis shows what is permitted on paper; the IAM Policy Simulator (Member 3) confirms real access.

## Authentication integration (D2D mTLS + S2A JWT)
```
auth/d2d_mtls.py            # device-to-device mTLS: X.509 checks (CA, signature, expiry, revocation, CN match)
auth/s2a_jwt.py             # service-to-application JWT (RS256): signature, issuer, audience, expiry, scope
analyzer/auth_events.py     # common event format, recorder, BLOCKED -> risk-finding conversion
scripts/gen_auth_events.py  # runs both prototypes -> data/sample_auth_events.json
tests/test_auth_events.py
```
Event format: `event_id, timestamp, source_identity, target_identity, identity_type (device|service|application),
authentication_method (mTLS|JWT), result (ALLOWED|BLOCKED), reason`.

Run: `python scripts/gen_auth_events.py` then `python main.py --sample --auth-events data/sample_auth_events.json`;
the dashboard has an **Authentication (D2D / S2A)** tab and auth counts on the Overview.

Failure -> risk mapping (`FAILURE_RULES`): revoked / forged signature = critical; untrusted issuer / identity
mismatch = high; wrong audience / insufficient scope / missing credential = medium; expired = low.
3+ blocked attempts from one source escalate one level (probing). Findings join the normal findings list and
go through `score_findings`.


## Full standalone authentication prototypes (S2A + D2D)

The dashboard's `auth/` modules are lightweight verifier adapters used by the existing
common-event demo. The complete prototypes supplied separately are also retained under
`prototypes/`:

- `s2a/`: full Service-to-Agent implementation with registry, RS256 token
  issuer, service-side validation, JSONL audit log and 16-scenario demo.
- `authentication/d2d/`: end-to-end device-to-device mutual-TLS implementation with certificate
  generation, TLS client/server, certificate policy checks and runnable demo.

Run the full S2A demo from the repository root:
```bash
python -m s2a.demo
pytest -q tests/test_s2a.py
```

Run the full D2D demo from the repository root:
```bash
python -m authentication.d2d.run_demo
```

### Feed real prototype audit logs into the IAM dashboard

The dashboard already accepts the shared JSON event format through
`--auth-events` / the Authentication events uploader. To convert the standalone
prototype logs into that format, run:
```bash
python scripts/import_prototype_logs.py \
  --s2a logs/s2a_audit.jsonl \
  --d2d authentication/d2d/logs/auth.log \
  --output data/sample_auth_events.json

python main.py --sample --auth-events data/sample_auth_events.json
```
Both `--s2a` and `--d2d` are optional; provide whichever log(s) exist. The S2A input
must be the JSON Lines audit file, not the human-readable `demo_output.txt`.
The D2D input is the `AUTH_SUCCESS` / `AUTH_FAILURE` log produced by its demo.

The unified dashboard pipeline maps successful events to `ALLOWED` and denied/failed
events to `BLOCKED`; blocked events are converted into authentication risk findings
and included in the normal findings/scoring workflow. This is a log-import integration:
the standalone S2A service and D2D TLS server remain separately runnable prototypes,
not network services automatically started by Streamlit.
