#!/usr/bin/env bash
set -euo pipefail

collector=${CONSHIELD_RUNTIME_COLLECTOR_BIN:-/opt/conshield/runtime-collector/ConShield.RuntimeCollector}
mapping=${CONSHIELD_RUNTIME_MAPPING:-/opt/conshield/runtime-collector/config/falco-mapping-v1.json}
environment_file=${CONSHIELD_RUNTIME_ENV_FILE:-/etc/conshield/runtime-collector.env}
input_file=
stdin=false
no_submit=false
max_event_age_days=30

usage() {
  cat >&2 <<'USAGE'
Usage:
  collect-falco-json.sh --file <path> [--no-submit]
  collect-falco-json.sh --stdin [--no-submit]

Reads one Falco-compatible JSON object per line and invokes ConShield.RuntimeCollector.
Secrets must be provided through the protected RuntimeCollector environment file, not arguments.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)
      [[ $# -ge 2 ]] || {
        usage
        exit 2
      }
      input_file=$2
      shift 2
      ;;
    --stdin)
      stdin=true
      shift
      ;;
    --no-submit|--dry-run|--validate)
      no_submit=true
      shift
      ;;
    --max-event-age-days)
      [[ $# -ge 2 && $2 =~ ^[0-9]+$ && $2 -ge 1 && $2 -le 3650 ]] || {
        usage
        exit 2
      }
      max_event_age_days=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ $stdin == true && -n $input_file ]] || [[ $stdin == false && -z $input_file ]]; then
  usage
  exit 2
fi

[[ -x $collector ]] || {
  echo "RuntimeCollector binary is unavailable." >&2
  exit 1
}

[[ -f $mapping && ! -L $mapping ]] || {
  echo "RuntimeCollector mapping is unavailable." >&2
  exit 1
}

args=(collect --mapping "$mapping" --max-event-age-days "$max_event_age_days")
if [[ $stdin == true ]]; then
  args+=(--stdin)
else
  [[ -f $input_file && ! -L $input_file ]] || {
    echo "Input file is unavailable." >&2
    exit 1
  }
  args+=(--file "$input_file")
fi

if [[ $no_submit == true ]]; then
  args+=(--no-submit)
  if [[ ${EUID} -eq 0 ]] && id -u conshield-runtime >/dev/null 2>&1; then
    exec runuser -u conshield-runtime -- "$collector" "${args[@]}"
  fi
  exec "$collector" "${args[@]}"
fi

[[ -f $environment_file && ! -L $environment_file ]] || {
  echo "RuntimeCollector environment file is unavailable." >&2
  exit 1
}

env_mode=$(stat -c '%a' "$environment_file")
env_owner=$(stat -c '%U:%G' "$environment_file")
[[ $env_mode == 600 && $env_owner == root:root ]] || {
  echo "RuntimeCollector environment file has unsafe permissions." >&2
  exit 1
}

if [[ ${EUID} -eq 0 ]] && id -u conshield-runtime >/dev/null 2>&1; then
  # shellcheck disable=SC2016
  exec runuser -u conshield-runtime -- bash -c '
    set -euo pipefail
    set -a
    # shellcheck source=/dev/null
    source "$1"
    set +a
    for variable in CONSHIELD_ENDPOINT CONSHIELD_SENSOR_ID CONSHIELD_SENSOR_CREDENTIAL_ID CONSHIELD_RUNTIME_COLLECTOR_API_KEY; do
      [[ -n ${!variable:-} ]] || {
        echo "RuntimeCollector environment is incomplete." >&2
        exit 1
      }
    done
    exec "$2" "${@:3}"
  ' bash "$environment_file" "$collector" "${args[@]}"
fi

set -a
# shellcheck source=/dev/null
source "$environment_file"
set +a
for variable in CONSHIELD_ENDPOINT CONSHIELD_SENSOR_ID CONSHIELD_SENSOR_CREDENTIAL_ID CONSHIELD_RUNTIME_COLLECTOR_API_KEY; do
  [[ -n ${!variable:-} ]] || {
    echo "RuntimeCollector environment is incomplete." >&2
    exit 1
  }
done
exec "$collector" "${args[@]}"
