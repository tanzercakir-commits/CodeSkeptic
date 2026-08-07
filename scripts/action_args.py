#!/usr/bin/env python3
"""Parse the composite Action's extra-args without executing shell code."""

import os
import shlex
import sys


def parse(value: str) -> list[str]:
    """Split shell-style quoting, then expand environment variables as data."""
    return [os.path.expandvars(arg) for arg in shlex.split(value, posix=True)]


def main() -> int:
    value = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        args = parse(value)
    except ValueError as error:
        print(f"::error::invalid extra-args: {error}", file=sys.stderr)
        return 2

    for arg in args:
        sys.stdout.buffer.write(os.fsencode(arg) + b"\0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
