# Signed Sensor Events

Signed Sensor Events v1 adds a deterministic signature metadata layer for Falco-compatible runtime sensor events. It is intentionally small and demo-safe: it prepares the runtime path for stronger sensor authentication without implementing full mTLS, certificate issuance, or production key management.

## What is signed

The deterministic envelope contains safe metadata:

- sensor id;
- source system;
- external event type;
- event timestamp in UTC;
- nonce;
- signature algorithm;
- signature key id;
- canonical payload hash;
- signature status and verification reason.

Raw runtime payload JSON and raw `AdditionalDataJson` are not shown in UI or evidence. Signing material is never printed.

## Signature statuses

| Status | Meaning |
| --- | --- |
| `Valid` | Demo signature metadata verified and the normal `RTE-001` path can apply. |
| `Missing` | Required signature metadata is missing; `SIGN-001` is expected. |
| `Invalid` / `UnknownKey` | Signature metadata is invalid or cannot be verified; `SIGN-002` is expected. |
| `Stale` / `ReplayDetected` | Timestamp or nonce is stale/replayed; `SIGN-003` is expected. |
| `NotRequired` | Backward-compatible unsigned runtime events where v1 signing is not required. |

Persistent nonce storage is not added in v1. Replay detection is simulated deterministically for CI and demo validation; future certificate-bound enrollment or mTLS can add stronger transport and persistent replay controls.

## Local deterministic replay

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -DemoSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateMissingSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateInvalidSignature `
  -NoSubmit

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -SimulateStaleSignature `
  -NoSubmit
```

These commands do not require real Fedora/Falco, live Docker, live Trivy DB, external internet, certificates, private keys, real signing keys, or secrets.

## Evidence and operations

`Export-ConShieldDefenseEvidence.ps1` includes `Signed Sensor Event Evidence` with sanitized signature mode counts and related `SIGN-001` / `SIGN-002` / `SIGN-003` alerts/incidents. `/RuntimeSensors` shows compact signature status, key id, last signed timestamp, and related SIGN alert counts.

Do not commit real signing keys, private keys, certificates, passwords, API keys, tokens, connection strings, environment values, raw runtime payload JSON, raw `AdditionalDataJson`, Docker logs, screenshots, or generated local artifacts.
