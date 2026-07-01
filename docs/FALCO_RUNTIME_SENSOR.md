# Falco Linux Runtime Sensor Path v1

This path connects a Fedora/Linux Falco-compatible JSON alert to the existing ConShield external event pipeline without requiring Fedora for the default local demo.

## Flow

```text
Falco-compatible JSON line
-> ConShield.RuntimeCollector parser and mapping
-> /api/v1/security-events
-> SecurityEvent ExternalEvent
-> RTE-001 SIEM correlation
-> SIEM alert and linked incident
-> operator workflow and defense evidence export
```

## Local replay without Fedora

The default local defense scenario stays synthetic and does not require Fedora, Falco, kernel drivers, or Podman.

For a local collector replay against the running Web app, start ConShield first and then run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
```

To validate only parser and mapping behavior without submitting:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 -NoSubmit
```

To replay the filesystem fixture:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1 `
  -FixturePath .\tests\TestData\Falco\write-below-etc-container.json
```

The script prints only a safe summary: Web status, fixture name, sensor id, sensor trust status, signature status, signature key id, mapped runtime event type, source system, a short hash identifier, ingestion status, expected SIEM rules, and result. It does not print API keys, sensor credentials, connection strings, environment values, raw Falco payload JSON, raw additional data, signing material, logs, screenshots, or generated evidence artifacts.

## Runtime sensor stream collector

Runtime Sensor Stream Collector v1 adds a deterministic local stream command for Falco-compatible JSON-lines input:

```powershell
dotnet run --project .\src\ConShield.Cli -- sensor collect `
  --from-json-lines .\tests\TestData\Falco\falco-runtime-stream.jsonl `
  --demo-signature `
  --no-submit
```

The collector reads line by line, normalizes supported runtime events through the existing Falco mapping, applies sensor trust and signed-event metadata, skips malformed lines safely, and prints only counters, statuses, event types, and deterministic external event IDs. It does not dump the raw line, raw Falco JSON, raw runtime payload JSON, raw additional data, secrets, signing material, logs, screenshots, or generated artifacts.

Submit mode is available only as an explicit local action after Web/API and local ingestion credentials are configured:

```powershell
dotnet run --project .\src\ConShield.Cli -- sensor collect `
  --from-json-lines .\tests\TestData\Falco\falco-runtime-stream.jsonl `
  --demo-signature `
  --submit
```

Optional stdin mode is available for bounded local experiments without making real Falco/Fedora a CI dependency:

```powershell
Get-Content .\tests\TestData\Falco\falco-runtime-stream.jsonl |
  dotnet run --project .\src\ConShield.Cli -- sensor collect `
    --stdin `
    --demo-signature `
    --no-submit
```

Simulation flags cover trust and signature paths: `--simulate-unknown-sensor`, `--simulate-revoked-sensor`, `--simulate-disabled-sensor`, `--simulate-missing-signature`, `--simulate-invalid-signature`, `--simulate-stale-signature`, and `--simulate-replay-signature`. The fixture and options cover the `RTE-001`, `SENSOR-001`, `SENSOR-002`, `SIGN-001`, `SIGN-002`, and `SIGN-003` evidence paths without requiring real Fedora/Falco, live Docker, live Trivy, external internet, certificates, private keys, signing keys, or secrets.

## Signed sensor event replay

Signed Sensor Events v1 can be validated without real Fedora/Falco or real signing keys:

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

Expected SIEM signals are `RTE-001` for valid demo signatures, `SIGN-001` for missing signatures, `SIGN-002` for invalid signatures, and `SIGN-003` for stale or replayed signatures. Full mTLS is intentionally outside this PR.

## Sensor trust registry

The default local replay source `conshield.falco-linux-sensor` maps to `demo-falco-linux-01` in `config/sensor-registry.default.json` with `Trusted` status. Validate the registry before a demo:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ConShieldSensorRegistry.ps1
```

Unknown runtime sources are shown as `Unknown` in `/RuntimeSensors` and evidence. Revoked or disabled sources are represented safely by status only. This is a preparation layer for future mTLS and does not store or issue real certificates.

## Runtime Sensor Health

Open `/RuntimeSensors` after replay to verify Runtime Sensor Health. The page derives health from stored security events, SIEM alerts, and incidents; it does not require Fedora for local validation and does not read raw payload JSON.

The page shows:

- sensor id, source system, display name, environment, and trust status;
- signature status and signature key id;
- last seen UTC/Moscow time;
- runtime event count and latest event metadata;
- related `RTE-001` alert count;
- related `SIGN-001` / `SIGN-002` / `SIGN-003` alert count;
- related incident count;
- status: `Active` for events seen within 24 hours, `Stale` for older events, or `NoData` for known runtime sources without activity.

Useful local verification flow:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Start-ConShield.ps1 -StartApps -OpenRabbit
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Replay-ConShieldFalcoRuntimeEvent.ps1
```

Then open:

```text
http://127.0.0.1:5080/RuntimeSensors
```

## Credentials and source system

Local replay uses the non-reserved source system `conshield.falco-linux-sensor` with the normal local external ingestion key. This keeps the Windows-only verification path available without Fedora, Falco, or enrolled sensor headers.

The real Fedora collector keeps the reserved source system `conshield.falco-runtime-collector`. General external ingestion API keys must not submit that reserved source. Fedora deployment should use enrolled sensor headers, or the explicitly enabled local legacy runtime collector credential during controlled rollout only. Credentials are read from environment variables or ignored local files and are never echoed.

## Fedora collector helper

The tracked Fedora deployment kit includes `deploy/falco-linux/collect-falco-json.sh` for one-shot validation from a file or stdin:

```bash
sudo ./collect-falco-json.sh --file /var/log/conshield/falco-events.jsonl --no-submit
```

Submit mode validates `/etc/conshield/runtime-collector.env` ownership and permissions before invoking the collector. SELinux remains enforcing, and the helper does not install Falco, change kernel settings, or print protected environment values.

## Evidence export

`scripts/Export-ConShieldDefenseEvidence.ps1` includes `Runtime Sensor Evidence` and `Runtime Sensor Health` sections. They report safe aggregates, latest Falco-compatible rule names, source status, last seen time, event counts, and related `RTE-001`/incident counts only. If no events are present, the health section writes:

```text
No runtime sensor activity was found in the current evidence window.
```
