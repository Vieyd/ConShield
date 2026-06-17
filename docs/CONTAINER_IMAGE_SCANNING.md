# Container Image Scanning

## Purpose

ConShield container image scanning is the first working container-security vertical in the project:

```text
container image reference
-> Trivy
-> ConShield.ImageScanner
-> normalized external event
-> POST /api/v1/security-events
-> PostgreSQL
-> IMG-001 correlation
-> SIEM alert and incident
```

The scanner is designed for local portfolio and CI demonstrations. The `scan` command reports scan results into ConShield; the separate `gate` command evaluates a local policy and can optionally launch Docker after an Allow or acknowledged Warn decision.

## Architecture

- `ConShield.ImageScanner` is a standalone .NET 8 console project.
- The scanner starts local Trivy through `ProcessStartInfo` with `UseShellExecute = false`.
- Trivy JSON is parsed into a compact summary.
- Only normalized counts and metadata are submitted to the ingestion API.
- `ConShield.Web` does not start Trivy and does not run local process scans from MVC requests.

## Trust Boundaries

```text
user or CI
-> image reference
-> local Trivy executable
-> Trivy JSON report
-> ConShield.ImageScanner normalization
-> ingestion API with X-ConShield-Api-Key
-> PostgreSQL storage
-> SIEM correlation
```

Main risks and controls:

- Trivy executable spoofing: use `CONSHIELD_TRIVY_PATH` or PATH lookup; current directory is not searched implicitly.
- Command injection: image reference is passed as a single `ProcessStartInfo.ArgumentList` item; no shell is used.
- Huge output: stdout and stderr are size-limited.
- Timeout: scanner kills the process tree on timeout or cancellation.
- Credential leakage: API keys and registry credentials are not printed; credential-like image prefixes are redacted in output.
- Report tampering/replay: ConShield stores `externalEventId`, `reportSha256`, `sourceSystem`, and ingestion idempotency.
- Malformed JSON: parser rejects malformed reports and returns a nonzero exit code.
- Vulnerability database unavailable: Trivy nonzero exit is treated as scan failure, not as a vulnerability result.

## Installing Trivy

Windows:

1. Download the official `trivy_*_windows-64bit.zip` from the Trivy GitHub Releases page.
2. Extract it outside the repository.
3. Add `trivy.exe` to PATH or set `CONSHIELD_TRIVY_PATH` to the executable path.

Linux:

Use the official installation method from Trivy documentation for your distribution.

Do not commit the Trivy binary, archives, vulnerability databases, cache files, or full reports.

## Configuration

Environment variables:

```text
CONSHIELD_BASE_URL
CONSHIELD_API_KEY
CONSHIELD_TRIVY_PATH
```

Prefer `CONSHIELD_API_KEY` over `--api-key` so the key is not stored in shell history or process listings.

## CLI Examples

Scan and submit:

```powershell
$env:CONSHIELD_BASE_URL = "http://127.0.0.1:56895"
$env:CONSHIELD_API_KEY = "your-local-api-key"
$env:CONSHIELD_TRIVY_PATH = "C:\Tools\trivy\trivy.exe"
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20
```

Scan without submitting:

```powershell
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20 --no-submit
```

Idempotent retry:

```powershell
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20 --external-event-id "11111111-1111-1111-1111-111111111111"
dotnet run --project src/ConShield.ImageScanner -- scan --image alpine:3.20 --external-event-id "11111111-1111-1111-1111-111111111111"
```

## Exit Codes

```text
0 success
2 invalid arguments or config
3 Trivy unavailable
4 scan failed
5 report parsing failed
6 API rejected request
7 timeout or cancellation
```

Finding CVEs is not a technical failure. Trivy process failure, unavailable vulnerability database, malformed JSON, timeout, or API rejection are failures.

## Summary Schema

The scanner sends `sourceSystem = "conshield.image-scanner"` and `externalEventType = "container.image.scan.completed"`.

`additionalData` shape:

```json
{
  "schemaVersion": 1,
  "scanner": "trivy",
  "scannerVersion": "string",
  "imageReference": "string",
  "imageDigest": "string-or-null",
  "artifactType": "string-or-null",
  "scanStatus": "completed",
  "unknownCount": 0,
  "lowCount": 0,
  "mediumCount": 0,
  "highCount": 0,
  "criticalCount": 0,
  "totalCount": 0,
  "fixAvailableCount": 0,
  "affectedTargetCount": 0,
  "reportSha256": "lowercase-hex",
  "durationMs": 0
}
```

The full CVE list and full Trivy report are intentionally not submitted to ConShield.

## IMG-001

`IMG-001` creates a critical SIEM alert and incident when:

- event type is `SecurityEventType.ExternalEvent`;
- external event type is `container.image.scan.completed`;
- event severity is `Critical`;
- `additionalData` is a JSON object;
- `criticalCount >= 1`;
- `imageReference` is present.

Trigger key:

1. `imageDigest`, when present;
2. normalized `imageReference`, otherwise.

Malformed or incomplete scan events are ignored by `IMG-001` and do not break the correlation run.

## Limits

- No RabbitMQ/MongoDB event pipeline yet.
- No full policy language or remote policy distribution.
- No admission controller.
- No runtime monitoring.
- No Kubernetes/Falco integration.
- No registry credential UI.
- No automatic Trivy download.
- No full Trivy report storage in PostgreSQL.

## Troubleshooting

- `ExitCode=3`: install Trivy or set `CONSHIELD_TRIVY_PATH`.
- `ExitCode=4`: inspect the truncated safe stderr; Trivy DB/network problems commonly appear here.
- `ExitCode=5`: Trivy produced malformed or oversized JSON.
- `ExitCode=6`: check `CONSHIELD_BASE_URL`, ingestion API key, and Web application status.
- `ExitCode=7`: increase `--timeout-seconds` within the allowed range or check cancellation.

## Registry Credentials

Use Trivy's supported local registry authentication mechanisms outside this repository. Do not pass credentials in image references when possible. If a credential-like image reference is supplied, scanner console output redacts the prefix, but command history may still contain it.
