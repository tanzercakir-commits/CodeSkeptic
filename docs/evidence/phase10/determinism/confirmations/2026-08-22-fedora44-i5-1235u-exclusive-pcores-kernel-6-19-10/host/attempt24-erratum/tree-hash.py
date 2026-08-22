#!/usr/bin/env python3
"""Compute a strict canonical identity for an immutable directory tree."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: tree-hash.py ROOT")
    root = Path(sys.argv[1]).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("tree root is not a directory")
    entries: list[dict[str, str]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        base = Path(directory)
        for name in [*names, *files]:
            path = base / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                entries.append({"path": relative, "type": "directory"})
            elif stat.S_ISREG(mode):
                entries.append({
                    "path": relative,
                    "sha256": sha256_file(path),
                    "type": "regular",
                })
            elif stat.S_ISLNK(mode):
                target = os.readlink(path)
                if "\x00" in target:
                    raise RuntimeError("symlink target contains NUL")
                entries.append({
                    "path": relative,
                    "target": target,
                    "type": "symlink",
                })
            else:
                raise RuntimeError(f"unsupported tree entry: {relative}")
    raw = json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    print(json.dumps({
        "entry_count": len(entries),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
