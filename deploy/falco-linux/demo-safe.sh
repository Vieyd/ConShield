#!/usr/bin/env bash
set -euo pipefail

if command -v podman >/dev/null; then
  runtime=podman
elif command -v docker >/dev/null; then
  runtime=docker
else
  echo "No supported container runtime found." >&2
  exit 1
fi

"$runtime" run --rm --name conshield-falco-demo docker.io/library/alpine:3.20 sh -c 'echo conshield-falco-demo'
echo "Safe non-privileged container demonstration completed."
