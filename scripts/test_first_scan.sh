#!/usr/bin/env bash
# Direct T1 entry point; no build, network access or hosted commissioning.
set -euo pipefail
test_binary="${1:?usage: test_first_scan.sh <codeskeptic-binary> [unittest options]}"
shift
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B "$script_dir/../tests/FirstScanTest.py" "$test_binary" "$@"
