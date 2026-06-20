# ConShield Fedora Falco Sensor

This kit deploys a real Falco sensor on a Fedora 44 VM while Windows remains the primary developer workstation and central ConShield server. The Fedora VM represents a protected Linux node; clients do not need to replace Windows desktops.

## Security boundaries

- SELinux stays `Enforcing`; Secure Boot is not changed.
- Falco uses the BTF-based `modern_ebpf` engine.
- Existing Podman is reused. Kubernetes is not installed.
- Falco writes bounded JSONL to `/var/log/conshield/falco-events.jsonl`.
- `conshield-runtime` is a non-login account and runs only the collector.
- The API key exists only in `/etc/conshield/runtime-collector.env` (`0600 root:root`).
- The endpoint is HTTP only on the isolated VMware host-only network.

## Staging expected by the installer

```text
/tmp/conshield-falco-deploy/       this deployment kit
/tmp/runtime-collector-linux-x64/  self-contained collector artifact
/tmp/fedora-runtime-collector.env  temporary secret environment
```

Install:

```bash
cd /tmp/conshield-falco-deploy
sudo ./install-fedora.sh
sudo ./verify-host.sh
sudo ./verify-pipeline.sh
./demo-safe.sh
```

The installer creates a timestamped backup of `/etc/falco/falco.yaml`, applies only the required engine/output keys, validates Falco and systemd configuration, and deletes the temporary secret copy.

## Rollback

```bash
cd /tmp/conshield-falco-deploy
sudo ./uninstall-fedora.sh
```

Rollback stops and removes the collector, restores the newest pre-install Falco configuration backup, and deliberately retains the Falco package and `/var/log/conshield` for review. No container storage or Windows Docker volume is removed.
