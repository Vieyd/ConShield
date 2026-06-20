#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo ./verify-pipeline.sh" >&2
  exit 1
fi

collector=/opt/conshield/runtime-collector/ConShield.RuntimeCollector
fixture=/opt/conshield/runtime-collector/samples/runtime-demo.jsonl
mapping=/opt/conshield/runtime-collector/config/falco-mapping-v1.json

runuser -u conshield-runtime -- "$collector" collect --file "$fixture" --mapping "$mapping" --no-submit

set -a
# shellcheck disable=SC1091
source /etc/conshield/runtime-collector.env
set +a
runuser --preserve-environment -u conshield-runtime -- "$collector" collect --file "$fixture" --mapping "$mapping"

echo "Fixture verification completed; inspect Windows pipeline counters by deterministic externalEventId."
