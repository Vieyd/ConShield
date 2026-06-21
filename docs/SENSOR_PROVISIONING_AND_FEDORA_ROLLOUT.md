# Sensor Provisioning and Fedora Rollout

## Scope and security boundary

`ConShield.SensorProvisioning` is a local operator-only console tool. It writes directly to the configured PostgreSQL database and does not expose an HTTP enrollment endpoint. It provisions only the reserved `conshield.falco-runtime-collector` source.

The tool generates 32 random bytes with the platform cryptographic RNG, encodes them as a Base64URL credential, and stores only its SHA-256 verifier. The plaintext credential is printed once to stdout so the operator can transfer it to the protected Fedora environment file. It is not accepted through command-line arguments and is not written to application logs.

Do this from the trusted Windows administration workstation. Do not run it in CI or paste its output into chat, tickets, shell transcripts, documentation, or tracked files.

## 1. Provision the sensor on Windows

Apply the current EF Core migrations before provisioning. Set the database connection through the current PowerShell process only; never pass it as an argument:

```powershell
$env:CONSHIELD_SENSOR_PROVISIONING_CONNECTION = "<local PostgreSQL connection string>"

dotnet run --project ./src/ConShield.SensorProvisioning -- `
  provision `
  --display-name "fedora-runtime-01" `
  --heartbeat-interval-seconds 60
```

The command fails closed if migrations are pending or the same normalized display name already exists for the runtime source. On success it prints exactly these four keys:

```text
CONSHIELD_SENSOR_ID=<public UUID>
CONSHIELD_SENSOR_CREDENTIAL_ID=<public UUID>
CONSHIELD_RUNTIME_COLLECTOR_API_KEY=<shown-once credential>
CONSHIELD_HEARTBEAT_INTERVAL_SECONDS=60
```

Copy the values directly into the Fedora staging file, clear the terminal when appropriate, and remove the connection variable from the PowerShell process:

```powershell
Remove-Item Env:CONSHIELD_SENSOR_PROVISIONING_CONNECTION
```

Running the command again with the same display name does not recover or reprint the credential. Lost credentials require a future controlled rotation/revocation workflow; do not create ambiguous duplicate records as a workaround.

## 2. Prepare the protected Fedora staging file

Keep SELinux enforcing and do not change the firewall boundary. On Fedora, create the installer staging location without putting the credential in shell history:

```bash
install -d -m 0700 /tmp/conshield-falco-secret
install -m 0600 /dev/null /tmp/conshield-falco-secret/runtime-collector.env
vi /tmp/conshield-falco-secret/runtime-collector.env
```

Populate the file in this exact five-line form:

```text
CONSHIELD_ENDPOINT=http://192.168.54.1:5080/api/v1/security-events
CONSHIELD_SENSOR_ID=<provisioned public UUID>
CONSHIELD_SENSOR_CREDENTIAL_ID=<provisioned public UUID>
CONSHIELD_RUNTIME_COLLECTOR_API_KEY=<shown-once credential>
CONSHIELD_HEARTBEAT_INTERVAL_SECONDS=60
```

Confirm ownership and modes without printing the file:

```bash
stat -c '%a %U %n' /tmp/conshield-falco-secret /tmp/conshield-falco-secret/runtime-collector.env
```

Expected modes are `700` for the directory and `600` for the file, both owned by the invoking user. Do not use `cat`, `set -x`, command-line assignments containing the credential, or environment dumps.

## 3. Preserve a bounded rollback and install

Before replacement, retain one root-only copy of the currently working legacy environment. Remove it after rollout acceptance:

```bash
sudo install -o root -g root -m 0600 \
  /etc/conshield/runtime-collector.env \
  /etc/conshield/runtime-collector.env.pre-enrollment

cd /tmp/conshield-falco-deploy
sudo ./install-fedora.sh
```

The installer validates the five keys, rejects placeholders, installs `/etc/conshield/runtime-collector.env` as `0600 root:root`, and removes the temporary staging file on exit. RuntimeCollector remains the non-root `conshield-runtime` service with an empty capability bounding set.

## 4. Verify service, heartbeat, and ingestion

Run the host checks without displaying environment contents:

```bash
cd /tmp/conshield-falco-deploy
sudo ./verify-host.sh
sudo systemctl is-active conshield-runtime-collector.service
sudo systemctl show conshield-runtime-collector.service \
  -p User -p Group -p NoNewPrivileges -p CapabilityBoundingSet -p NRestarts
```

Wait at least two configured heartbeat intervals. From the trusted Windows/PostgreSQL administration context, query only public inventory metadata:

```sql
SELECT "SensorId", "DisplayName", "SourceSystem", "LastSeenAtUtc", "RevokedAtUtc"
FROM "Sensors"
WHERE "SensorId" = '<provisioned sensor UUID>';
```

`LastSeenAtUtc` must be recent and continue advancing. Do not select `VerifierSha256`.

Verify the actual systemd collector path:

```bash
sudo ./verify-pipeline.sh
```

The script performs a no-submit parser check, validates only the presence of required environment keys, and appends the fixture to the protected Falco JSONL. The already-running non-root collector processes it with its protected EnvironmentFile. The script never extracts or passes the credential through argv.

On Windows, confirm the deterministic runtime events and normal Outbox/RabbitMQ/Mongo/Inbox path. Re-running the fixture may report duplicates; this is expected idempotency behavior.

## 5. Disable the legacy fallback

Disable the fallback only after all of the following are true:

- RuntimeCollector is active with no restart loop;
- `LastSeenAtUtc` advances for the provisioned Sensor;
- fixture or safe Falco events are accepted;
- the general ingestion key still cannot submit the reserved runtime source;
- no new relevant SELinux AVC is present;
- the central pipeline is healthy.

Set the central Web configuration to:

```json
"ExternalEventIngestion": {
  "AllowLegacyRuntimeCollectorCredential": false
}
```

Restart only the central Web application, wait for another heartbeat, then run `verify-pipeline.sh` again. Successful heartbeat and ingestion with fallback disabled prove that the enrolled path is in use. After an observation period, remove the obsolete shared runtime key from central configuration and securely delete the Fedora rollback copy:

```bash
sudo rm -f /etc/conshield/runtime-collector.env.pre-enrollment
```

## 6. Roll back safely

If heartbeat or ingestion fails, re-enable `AllowLegacyRuntimeCollectorCredential`, restart the central Web application, and restore the protected legacy Fedora environment:

```bash
sudo install -o root -g root -m 0600 \
  /etc/conshield/runtime-collector.env.pre-enrollment \
  /etc/conshield/runtime-collector.env
sudo restorecon /etc/conshield/runtime-collector.env
sudo systemctl restart conshield-runtime-collector.service
sudo systemctl is-active conshield-runtime-collector.service
```

Do not disable SELinux, Secure Boot, Windows Firewall, or service hardening to make rollout pass. Preserve the failed Sensor record for review. Credential revocation and rotation are intentionally deferred to a follow-up PR.

## Safety checklist

- Do not commit either staging or installed environment files.
- Do not send the credential through chat, issue trackers, PR text, argv, or logs.
- Do not add a public enrollment endpoint or expose PostgreSQL beyond its current boundary.
- Keep SELinux `Enforcing`, Secure Boot unchanged, and Windows Firewall scoped to the Fedora host-only address.
- Keep RuntimeCollector non-root with no added capabilities.
- Do not add Kubernetes, mTLS/PKI automation, fleet UI, or automatic response.
- Delete temporary and rollback credential copies after successful acceptance.
