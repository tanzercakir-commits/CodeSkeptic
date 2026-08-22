#!/usr/bin/env python3
"""Read-only preflight for the frozen P10.7 qualification environment."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo = Path("/work")
    build = repo / "build-p10-07-v6-release"
    expected_os = "Linux 6.19.10-300.fc44.x86_64"
    observed_os = f"{platform.system()} {platform.release()}"
    if observed_os != expected_os:
        raise RuntimeError("host kernel differs from the frozen V7 authority")
    sys.path.insert(0, str(repo / "scripts"))
    import run_determinism_qualification as qualification

    manifest = qualification.load_manifest(
        repo / "scripts" / "determinism_workloads.json"
    )
    source = qualification.source_manifest(repo)
    toolchain = qualification.toolchain_identity(
        build / "src" / "codeskeptic",
        Path("/usr/bin/clang-20").resolve(strict=True),
        Path("/usr/bin/time").resolve(strict=True),
        Path("/usr/bin/cmake").resolve(strict=True),
        Path("/usr/bin/ninja").resolve(strict=True),
        Path("/usr/bin/clang-20").resolve(strict=True),
        Path("/usr/bin/clang++-20").resolve(strict=True),
    )
    build_identity = qualification._build_toolchain_identity(
        build,
        repo,
        Path("/usr/bin/cmake").resolve(strict=True),
        Path("/usr/bin/ninja").resolve(strict=True),
        Path("/usr/bin/clang-20").resolve(strict=True),
        Path("/usr/bin/clang++-20").resolve(strict=True),
    )
    mirror = subprocess.run(
        ["git", "-C", "/mirror", "rev-parse", "HEAD"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    mirror_bare = subprocess.run(
        ["git", "-C", "/mirror", "rev-parse", "--is-bare-repository"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if mirror_bare != "true":
        raise RuntimeError("llama authority mirror is not bare")
    subprocess.run(
        ["git", "-C", "/mirror", "cat-file", "-e", f"{mirror}^{{commit}}"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "-C", "/mirror", "fsck", "--full", "--no-dangling"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    output = {
        "analyzer_sha256": toolchain["analyzer"]["sha256"],
        "analyzer_version": toolchain["analyzer"]["version"],
        "manifest_sha256": qualification.digest_json(manifest),
        "mirror_revision": mirror,
        "source": source,
        "build_identity_sha256": qualification.digest_json(build_identity),
        "toolchain_sha256": qualification.digest_json(toolchain),
    }
    expected = {
        "analyzer_sha256": (
            "2fdca181e7c881de7a20472c78cf807e0b1f1b984747e9d860eb2119af049562"
        ),
        "analyzer_version": "CodeSkeptic 0.4.9-dev",
        "manifest_sha256": (
            "90cd7f03db2c50b851f4900ab628057a524045372d19c103258785b0d7861ac4"
        ),
        "build_identity_sha256": (
            "e26f3b0001f9b89c60250612fe81fb6070cccead5f061f74e6a1d88ee0581c82"
        ),
        "mirror_revision": "4dee52f82dc455a035e900fed6a40cb45cd7a454",
        "source": {
            "file_count": 386,
            "manifest_sha256": (
                "b8c4b7235c1c8704304dd5fe4de90728e6cd0b4ab020526b76f1e4731b3e0d9b"
            ),
            "revision": "88e369b21675e64e0a92842b0ce22f0c8148745e",
        },
        "toolchain_sha256": (
            "63c01694379ed68b8aa875ac414a08718001fc67d6bf7594b21332cf55a88120"
        ),
    }
    for key, value in expected.items():
        if output[key] != value:
            raise RuntimeError(f"frozen preflight mismatch: {key}")
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
