# ConShield Fedora Falco Sensor

This kit deploys a real Falco sensor on a Fedora 44 VM while Windows remains the primary developer workstation and central ConShield server. The Fedora VM represents a protected Linux node; clients do not need to replace Windows desktops.

## Security boundaries

- SELinux stays `Enforcing`; Secure Boot is not changed.
- Falco uses the BTF-based `modern_ebpf` engine.
- Existing Podman is reused. Kubernetes is not installed.
- Falco writes bounded JSONL to `/var/log/conshield/falco-events.jsonl`.
- `conshield-runtime` is a non-login account and runs only the collector.
- The source-specific runtime API key exists only in `/etc/conshield/runtime-collector.env` (`0600 root:root`).
- Sensor and credential IDs are public selectors; the credential is bound to the enrolled sensor and its reserved source system.
- The collector sends a bounded heartbeat that updates inventory state without creating SIEM events.
- The endpoint is HTTP only on the isolated VMware host-only network.

## Staging expected by the installer

```text
/tmp/conshield-falco-deploy/       this deployment kit
/tmp/runtime-collector-linux-x64/  self-contained collector artifact
/tmp/conshield-falco-secret/       invoking-user owned directory, mode 0700
  runtime-collector.env            temporary secret environment, mode 0600
```

Install:

```bash
cd /tmp/conshield-falco-deploy
sudo ./install-fedora.sh
sudo ./verify-host.sh
sudo ./verify-pipeline.sh
./demo-safe.sh
```

The installer rejects symlinks and weak ownership/modes for secret staging, creates a timestamped backup of `/etc/falco/falco.yaml`, applies only the required engine/output keys, validates Falco and systemd configuration, and deletes the temporary secret copy on exit.

Create the staging file from `conshield-runtime-collector.env.example` only after the corresponding sensor credential has been provisioned in the central database. It must contain exactly the endpoint, sensor ID, credential ID, credential, and heartbeat interval entries shown by the example. Do not pass the credential through command-line arguments.

Use the local operator tool and follow the complete staged rollout, verification, fallback-disablement, and rollback procedure in [`docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md`](../../docs/SENSOR_PROVISIONING_AND_FEDORA_ROLLOUT.md). `verify-pipeline.sh` submits through the running systemd collector and never extracts the credential from its protected environment file.

## Rollback

```bash
cd /tmp/conshield-falco-deploy
sudo ./uninstall-fedora.sh
```

Rollback stops and removes the collector, restores the newest pre-install Falco configuration backup, and deliberately retains the Falco package and `/var/log/conshield` for review. No container storage or Windows Docker volume is removed.
