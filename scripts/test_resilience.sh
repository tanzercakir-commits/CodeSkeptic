#!/usr/bin/env bash
# Explicit already-built local artifacts only. Never builds or downloads.
set -euo pipefail
repo=$(git rev-parse --show-toplevel)
exec python3 -B "$repo/fuzz/run_resilience.py" "$@"
