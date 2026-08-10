#!/usr/bin/env python3
"""Fail-closed compatibility entry point for the real-world manifest."""

from __future__ import annotations

import sys
from pathlib import Path

from run_realworld_campaign import CampaignError, load_manifest, validate_manifest


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).with_name(
        "realworld_manifest.json"
    )
    if len(sys.argv) > 2:
        print(
            "REALWORLD_LEDGER_FAIL usage: check_realworld_ledger.py [manifest-path]",
            file=sys.stderr,
        )
        return 2
    try:
        manifest = validate_manifest(load_manifest(path))
    except CampaignError as error:
        print(f"REALWORLD_LEDGER_FAIL {error}", file=sys.stderr)
        return 2
    print(
        f"REALWORLD_LEDGER_OK projects={len(manifest['projects'])} "
        f"campaigns={len(manifest['campaigns'])} path={path.as_posix()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
