# Container Policy Gate

## Purpose

Container Policy Gate is the next container-security vertical in ConShield:

```text
image reference
-> Trivy scan summary
-> ContainerPolicy evaluation
-> scan audit event
-> policy audit event
-> optional hardened local docker run
-> POL-001 alert and incident when decision is Block
```

The gate demonstrates policy enforcement for a local portfolio scenario. It is not a production admission controller and does not block Kubernetes, registries, or remote runtimes.

## Architecture

- `ConShield.ContainerPolicy` is a pure .NET class library for policy loading, validation, hashing, and deterministic evaluation.
- `ConShield.ImageScanner gate` runs Trivy, evaluates the policy, submits audit events, and optionally starts Docker.
- `ConShield.Application` correlates Block policy decisions through `POL-001`.
- `ConShield.Web` does not start Trivy or Docker.

## Trust Boundaries

```text
user or CI
-> image reference
-> local Trivy executable
-> normalized scan summary
-> local policy JSON
-> policy decision
-> ingestion API
-> PostgreSQL
-> SIEM correlation
-> optional local Docker executable
```

Controls:

- no shell execution;
- all process arguments use `ProcessStartInfo.ArgumentList`;
- policy files are local only and limited to 64 KiB;
- invalid policy or invalid scan summary fails closed;
- Block has no CLI bypass;
- Docker launch is fixed to a hardened argument set;
- API keys, registry credentials, executable paths, and full reports are not submitted.

## Policy File

Baseline policy:

```text
config/policies/container-baseline-v1.json
```

Supported schema fields:

```json
{
  "schemaVersion": 1,
  "policyId": "container-baseline",
  "version": "1.0.0",
  "thresholds": {
    "criticalBlock": 1,
    "highBlock": 10,
    "totalBlock": 100,
    "highWarn": 1,
    "mediumWarn": 10,
    "unknownWarn": 1
  },
  "deniedImages": []
}
```

Unknown properties are rejected. Thresholds are optional, but when present they must be positive integers. `deniedImages` uses exact normalized image identity matching only; no wildcards or fuzzy matching are implemented.

Decision precedence:

1. denied image -> `Block`;
2. block thresholds -> `Block`;
3. warning thresholds -> `Warn`;
4. otherwise -> `Allow`.

Reason codes:

```text
IMAGE_DENIED
CRITICAL_THRESHOLD_REACHED
HIGH_BLOCK_THRESHOLD_REACHED
TOTAL_BLOCK_THRESHOLD_REACHED
HIGH_WARNING_THRESHOLD_REACHED
MEDIUM_WARNING_THRESHOLD_REACHED
UNKNOWN_WARNING_THRESHOLD_REACHED
WITHIN_POLICY
```

## CLI

Dry run:

```powershell
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json --no-submit
```

Submit audit events:

```powershell
$env:CONSHIELD_BASE_URL = "http://127.0.0.1:56895"
$env:CONSHIELD_API_KEY = "your-local-api-key"
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json
```

Execute only after an Allow decision:

```powershell
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json --execute
```

Execute after Warn requires explicit acknowledgement:

```powershell
dotnet run --project src/ConShield.ImageScanner -- gate --image alpine:3.20 --policy config/policies/container-baseline-v1.json --execute --accept-warning
```

Supported options:

```text
--image <value>
--policy <path>
--base-url <url> or CONSHIELD_BASE_URL
--api-key <value> or CONSHIELD_API_KEY
--trivy-path <path> or CONSHIELD_TRIVY_PATH
--docker-path <path> or CONSHIELD_DOCKER_PATH
--external-event-id <uuid>
--timeout-seconds <number>
--run-timeout-seconds <number>
--no-submit
--execute
--accept-warning
```

## Audit Events

The gate uses one `externalEventId` for two source systems:

- `conshield.image-scanner` / `container.image.scan.completed`;
- `conshield.container-guard` / `container.image.policy.evaluated`.

Policy event `additionalData` contains only summary data:

```json
{
  "schemaVersion": 1,
  "decision": "Block",
  "policyId": "container-baseline",
  "policyVersion": "1.0.0",
  "policySha256": "lowercase-hex",
  "imageReference": "repo/app:tag",
  "imageDigest": "repo/app@sha256:...",
  "reportSha256": "lowercase-hex",
  "unknownCount": 0,
  "lowCount": 0,
  "mediumCount": 0,
  "highCount": 0,
  "criticalCount": 0,
  "totalCount": 0,
  "reasonCodes": ["CRITICAL_THRESHOLD_REACHED"],
  "executionRequested": false,
  "warningAccepted": false
}
```

## POL-001

`POL-001` creates a critical alert and incident when:

- event type is `SecurityEventType.ExternalEvent`;
- external event type is `container.image.policy.evaluated`;
- `additionalData` is a JSON object;
- `schemaVersion == 1`;
- `decision == Block`;
- `policyId`, `policyVersion`, `policySha256`, and `imageReference` are valid.

Trigger key:

```text
POL-001:<policyId>:<policyVersion>:<imageDigest-or-normalized-reference>
```

Malformed policy events are ignored by `POL-001` and do not break the correlation run.

## Docker Launch Limits

Docker is launched only with `gate --execute`. The command is fixed:

```text
docker run --rm --pull=never --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=256m --cpus=0.5 --tmpfs=/tmp:rw,noexec,nosuid,size=64m <image-reference>
```

No arbitrary Docker arguments, host networking, host volumes, privileged mode, Docker socket mount, device mounts, or environment secret injection are supported.

When Trivy provides a valid sha256 digest reference, Docker launch uses that immutable digest reference. If no digest is available, launch uses the scanned image reference and the remaining tag TOCTOU limitation is documented rather than hidden.

## Exit Codes

```text
0 success
2 invalid arguments or config
3 Trivy unavailable
4 scan failed
5 report parsing failed
6 API rejected request
7 timeout or cancellation
10 Warn decision was not accepted
20 Block decision
21 invalid or malformed policy
22 policy evaluation failure
23 Docker unavailable
24 Docker launch failed
25 Docker timeout or cancellation
```

## Troubleshooting

- `21`: validate JSON shape, schema version, thresholds, and duplicate denied images.
- `20`: the policy worked as designed; do not add a bypass for Block.
- `10`: rerun with `--accept-warning` only if launching a Warn image is intentional.
- `23`: install Docker or set `CONSHIELD_DOCKER_PATH`.
- `6`: check Web, `CONSHIELD_BASE_URL`, and `CONSHIELD_API_KEY`.

## Not Implemented

- Kubernetes admission controller;
- registry-side enforcement;
- policy signing;
- waivers or exceptions;
- remote policy download;
- full policy engine language;
- runtime monitoring;
- Falco;
- RabbitMQ/MongoDB event pipeline.
