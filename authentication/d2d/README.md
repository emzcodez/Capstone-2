# D2D – Device-to-Device Authentication Prototype (Prototype 1)

Shows how one device securely authenticates another **before** any application data is
exchanged, using **mutual TLS (mTLS)** with X.509 certificates. Two simulated devices
(Device A, Device B) each hold their own key pair and certificate issued by a shared,
trusted CA. Untrusted, expired, or unauthorised devices are rejected and every decision is logged.

## Quick start

```bash
pip install cryptography                         # only dependency (Python 3.9+)
python -m authentication.d2d.run_demo            # full demo, 8 scenarios, exit 0 if all correct
pytest tests/test_d2d_authentication.py -v       # 20 automated tests
```

Run the devices by hand in two terminals:

```bash
python -m authentication.d2d.generate_certificates
# terminal 1 - Device B listens (only device-a / device-b may connect)
python -m authentication.d2d.device_server --device device-b --port 8443 --allow device-a device-b
# terminal 2 - Device A connects
python -m authentication.d2d.device_client --device device-a --peer device-b --port 8443
# ...now try the attacks:
python -m authentication.d2d.device_client --device device-a --cert-name device-a-expired   --peer device-b --port 8443
python -m authentication.d2d.device_client --device device-a --cert-name device-a-untrusted --peer device-b --port 8443
python -m authentication.d2d.device_client --device device-a --no-cert                      --peer device-b --port 8443
```

## Modules

| File | Role |
|---|---|
| `generate_certificates.py` | Creates the trusted CA, a rogue CA, and all device certificates (valid, expired, untrusted) |
| `certificate_manager.py` | Key/cert creation (ECDSA P-256), PEM I/O, and the mTLS `SSLContext` builders |
| `device_server.py` | Listening device. Requires a client certificate (`CERT_REQUIRED`), then runs the verifier |
| `device_client.py` | Connecting device. Verifies the server cert + hostname, presents its own cert |
| `verifier.py` | Explicit certificate checks, TLS error -> reason-code mapping, and the auth logger |
| `run_demo.py` | Runs all scenarios and prints ALLOWED / BLOCKED per scenario |

## How authentication works

```
Device A (client)                                   Device B (server)
   |--- ClientHello ------------------------------------>|
   |<-- ServerHello + B's certificate + CertificateRequest|
   |  verify: chain -> trusted CA, dates, hostname,       |
   |          EKU=serverAuth, device on allow-list        |
   |--- A's certificate + proof of key possession ------->|
   |                       verify: chain -> trusted CA, dates (OpenSSL),
   |                               then verifier.py: signature, validity,
   |                               EKU=clientAuth, allow-list, revocation
   |<====== encrypted application data only if both sides pass ======>|
```

Two layers on each side: (1) the TLS handshake, and (2) `verifier.verify_certificate()`, an
independent post-handshake check that also enforces policy (certificate usage, device allow-list,
revocation list) which TLS alone does not.

## Demo scenarios

| # | Scenario | Expected | Reason code in log |
|---|---|---|---|
| 1 | A -> B, valid certificates | ALLOWED | - |
| 2 | B -> A (reverse) | ALLOWED | - |
| 3 | A presents an **expired** certificate | BLOCKED by B | `CERT_EXPIRED` |
| 4 | Impostor signed by a **rogue CA** | BLOCKED by B | `UNTRUSTED_ISSUER` |
| 5 | A presents **no** certificate | BLOCKED by B | `NO_CLIENT_CERTIFICATE` |
| 6 | Device C: valid cert, **not on allow-list** | BLOCKED by B | `DEVICE_NOT_AUTHORISED` |
| 7 | B presents an **expired** certificate | BLOCKED by A | `CERT_EXPIRED` |
| 8 | Impostor B signed by a **rogue CA** | BLOCKED by A | `UNTRUSTED_ISSUER` |

## Logging

Every decision is one line in `authentication/d2d/logs/auth.log` (and the console):

```
2026-11-15 12:04:30 | INFO    | AUTH_SUCCESS local=device-b role=server peer=device-a serial=6c30.. detail=mutual TLS established
2026-11-15 12:04:30 | WARNING | AUTH_FAILURE local=device-b role=server peer=unknown reason=CERT_EXPIRED detail=handshake ... certificate has expired
```

Note: with TLS 1.3 the client finishes its handshake *before* the server validates the client
certificate, so the connecting side may only see "peer closed the connection"
(`REJECTED_BY_PEER`). The **server-side log line always carries the precise reason**.

## Prototype limitations (and what production would add)

- Certificates and the CA key are generated locally and stored as files; production would use an
  HSM / device secure element and an enrolment protocol (e.g. EST/SCEP) for issuance.
- Revocation is a static serial list; production would use CRL/OCSP or short-lived certificates.
- `certs/` and `logs/` are git-ignored - never commit private keys.
