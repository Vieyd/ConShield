#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo ./install-fedora.sh" >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
collector_source=${CONSHIELD_COLLECTOR_SOURCE:-/tmp/runtime-collector-linux-x64}
secret_source=${CONSHIELD_SECRET_SOURCE:-/tmp/conshield-falco-secret/runtime-collector.env}
falco_repo_url=https://falco.org/repo/falcosecurity-rpm.repo
falco_key_url=https://falco.org/repo/falcosecurity-packages.asc
tmp_dir=$(mktemp -d /tmp/conshield-falco-install.XXXXXX)
chmod 0700 "$tmp_dir"
umask 077
cleanup() {
  rm -rf -- "$tmp_dir"
  if [[ -f $secret_source && ! -L $secret_source ]]; then
    rm -f -- "$secret_source"
  fi
}
trap cleanup EXIT

grep -q '^VERSION_ID=44' /etc/os-release || {
  echo "This deployment kit is validated for Fedora 44." >&2
  exit 1
}
[[ $(getenforce) == Enforcing ]] || {
  echo "SELinux must remain Enforcing." >&2
  exit 1
}
[[ -r /sys/kernel/btf/vmlinux ]] || {
  echo "Kernel BTF is required for modern_ebpf." >&2
  exit 1
}
[[ -d $collector_source && -x $collector_source/ConShield.RuntimeCollector ]] || {
  echo "RuntimeCollector artifact is missing from $collector_source." >&2
  exit 1
}
[[ -f $secret_source && ! -L $secret_source ]] || {
  echo "RuntimeCollector environment file is missing from $secret_source." >&2
  exit 1
}
secret_dir=$(dirname -- "$secret_source")
[[ -d $secret_dir && ! -L $secret_dir ]] || {
  echo "RuntimeCollector secret directory must be a real directory." >&2
  exit 1
}
expected_uid=${SUDO_UID:-0}
[[ $(stat -c '%u' "$secret_dir") == "$expected_uid" && $(stat -c '%a' "$secret_dir") == 700 ]] || {
  echo "RuntimeCollector secret directory must be owned by the invoking user with mode 0700." >&2
  exit 1
}
[[ $(stat -c '%u' "$secret_source") == "$expected_uid" && $(stat -c '%a' "$secret_source") == 600 ]] || {
  echo "RuntimeCollector environment file must be owned by the invoking user with mode 0600." >&2
  exit 1
}

dnf install -y curl jq openssl ca-certificates policycoreutils-python-utils bpftool logrotate ShellCheck podman

curl --proto '=https' --tlsv1.2 --fail --show-error --location --output "$tmp_dir/falco.asc" "$falco_key_url"
curl --proto '=https' --tlsv1.2 --fail --show-error --location --output "$tmp_dir/falcosecurity.repo" "$falco_repo_url"
rpm --import "$tmp_dir/falco.asc"
install -o root -g root -m 0644 "$tmp_dir/falcosecurity.repo" /etc/yum.repos.d/falcosecurity.repo
dnf -q makecache --refresh
dnf install -y falco

if ! getent passwd conshield-runtime >/dev/null; then
  useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin conshield-runtime
fi

install -d -o root -g root -m 0755 /opt/conshield
rm -rf -- /opt/conshield/runtime-collector.new
install -d -o root -g root -m 0755 /opt/conshield/runtime-collector.new
cp -a -- "$collector_source/." /opt/conshield/runtime-collector.new/
chown -R root:root /opt/conshield/runtime-collector.new
find /opt/conshield/runtime-collector.new -type d -exec chmod 0755 {} +
find /opt/conshield/runtime-collector.new -type f -exec chmod 0644 {} +
chmod 0755 /opt/conshield/runtime-collector.new/ConShield.RuntimeCollector
if [[ -d /opt/conshield/runtime-collector ]]; then
  rm -rf -- /opt/conshield/runtime-collector.previous
  mv -- /opt/conshield/runtime-collector /opt/conshield/runtime-collector.previous
fi
mv -- /opt/conshield/runtime-collector.new /opt/conshield/runtime-collector

tr -d '\r' < "$secret_source" > "$tmp_dir/runtime-collector.env"
[[ $(wc -l < "$tmp_dir/runtime-collector.env") -eq 2 ]] || {
  echo "RuntimeCollector environment must contain exactly two lines." >&2
  exit 1
}
grep -Eq '^CONSHIELD_ENDPOINT=http://192\.168\.54\.1:5080/api/v1/security-events$' "$tmp_dir/runtime-collector.env" || {
  echo "RuntimeCollector endpoint is invalid." >&2
  exit 1
}
grep -Eq '^CONSHIELD_RUNTIME_COLLECTOR_API_KEY=[[:graph:]]+$' "$tmp_dir/runtime-collector.env" || {
  echo "RuntimeCollector API key line is invalid." >&2
  exit 1
}
install -d -o root -g root -m 0755 /etc/conshield
install -o root -g root -m 0600 "$tmp_dir/runtime-collector.env" /etc/conshield/runtime-collector.env

install -d -o root -g conshield-runtime -m 0750 /var/log/conshield
touch /var/log/conshield/falco-events.jsonl
chown root:conshield-runtime /var/log/conshield/falco-events.jsonl
chmod 0640 /var/log/conshield/falco-events.jsonl
restorecon -RF /var/log/conshield /etc/conshield /opt/conshield

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
if ! find /etc/falco -maxdepth 1 -type f -name 'falco.yaml.conshield-backup.*' -print -quit | grep -q .; then
  cp -a -- /etc/falco/falco.yaml "/etc/falco/falco.yaml.conshield-backup.$timestamp"
fi
install -o root -g root -m 0644 "$script_dir/falco.yaml.fragment" /etc/falco/conshield.yaml.fragment
install -o root -g root -m 0644 "$script_dir/falco_rules.local.yaml" /etc/falco/falco_rules.local.yaml

python3 - /etc/falco/falco.yaml <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

def replace_top_level_scalar(data: str, key: str, value: str) -> str:
    pattern = rf"(?m)^{re.escape(key)}:\s*.*$"
    updated, count = re.subn(pattern, f"{key}: {value}", data, count=1)
    if count != 1:
        raise SystemExit(f"Expected one top-level key: {key}")
    return updated

def replace_section_scalar(data: str, section: str, key: str, value: str) -> str:
    lines = data.splitlines()
    in_section = False
    changed = False
    for index, line in enumerate(lines):
        if re.match(rf"^{re.escape(section)}:\s*$", line):
            in_section = True
            continue
        if in_section and line and not line.startswith((" ", "\t", "#")):
            break
        if in_section and re.match(rf"^  {re.escape(key)}:\s*", line):
            lines[index] = f"  {key}: {value}"
            changed = True
            break
    if not changed:
        raise SystemExit(f"Expected {section}.{key} in Falco configuration")
    return "\n".join(lines) + "\n"

text = replace_top_level_scalar(text, "json_output", "true")
text = replace_section_scalar(text, "engine", "kind", "modern_ebpf")
text = replace_section_scalar(text, "file_output", "enabled", "true")
text = replace_section_scalar(text, "file_output", "keep_alive", "true")
text = replace_section_scalar(text, "file_output", "filename", "/var/log/conshield/falco-events.jsonl")
text = replace_section_scalar(text, "webserver", "enabled", "false")
path.write_text(text, encoding="utf-8")
PY

falco -c /etc/falco/falco.yaml \
  --validate /etc/falco/falco_rules.yaml \
  --validate /etc/falco/falco_rules.local.yaml
install -o root -g root -m 0644 "$script_dir/conshield-runtime-collector.service" /etc/systemd/system/conshield-runtime-collector.service
install -o root -g root -m 0644 "$script_dir/logrotate-conshield-falco" /etc/logrotate.d/conshield-falco
systemd-analyze verify /etc/systemd/system/conshield-runtime-collector.service
logrotate -d /etc/logrotate.d/conshield-falco >/dev/null

falco_service=
for candidate in falco-modern-bpf.service falco.service; do
  if systemctl list-unit-files "$candidate" --no-legend 2>/dev/null | grep -q "$candidate"; then
    falco_service=$candidate
    break
  fi
done
[[ -n $falco_service ]] || {
  echo "No Falco systemd service was installed." >&2
  exit 1
}

systemctl daemon-reload
systemctl enable "$falco_service"
systemctl restart "$falco_service"
systemctl enable --now conshield-runtime-collector.service
systemctl is-active --quiet "$falco_service"
systemctl is-active --quiet conshield-runtime-collector.service

echo "Falco and ConShield RuntimeCollector installed."
echo "Falco service: $falco_service"
falco --version | head -n 1
echo "Driver: modern_ebpf"
