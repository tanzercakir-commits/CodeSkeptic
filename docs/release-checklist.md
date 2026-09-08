# Linux artifact qualification

This is the CH06-S01-U001 package work, not a published or signed release.
Only independently reviewed, actual artifact executions establish support.
Windows/macOS, Container/Action parity and full SBOM/provenance remain separate
FIFO units. Protected source/test inventories and CMake files stay unchanged.

## Assembly profile

Run `bash scripts/package_release.sh /absolute/build/src/codeskeptic /fresh/output clang-20`
on the Debian/Ubuntu build host that owns the matching LLVM installation.
Build-host tools are Bash, Python 3.8+, `ldd`, `readelf`, `dpkg-query`, and the
matching Clang. The script performs no downloads or privilege elevation.
The initial Linux profile requires dynamic LLVM; unknown dependencies, missing
licenses, mismatched resource majors and a missing transitive RPATH fail closed.

The archive and expanded directory retain the binary's full version, including
development source suffixes. Existing artifacts are not overwritten. A failure
during final publication may leave an artifact or partial expanded tree, but
never reports `PACKAGE_RESULT`; preserve/inspect it and retry in a fresh output
directory. Assembly success alone is not qualification success.

The expanded tree contains `bin/`, Clang intrinsic headers, non-core shared
libraries, project LICENSE/README, and `licenses/INDEX.tsv`. Each redistributed
component maps to its installed package copyright notice; referenced installed
common license texts are also copied. These are distribution-provided notices,
not a legal review or a signed provenance attestation. Keep the complete tree.
Full SBOM/version-source/provenance work follows in CH06-S02-U001.

The ELF loader, glibc and linked libstdc++/libgcc remain host requirements;
`DEPENDENCIES.txt` names them. A tarball is not an all-Linux portability promise:
the build host's ABI floor still applies. Runtime needs no Python, compiler,
package manager or sudo. Analysis needs the target's development headers,
compile commands and any project dependencies; these are not bundled.

## Required T3 evidence

1. Focused packager regressions: `python3 -B scripts/test_package.py`. Synthetic
   executable/loader/package-metadata fixtures test rejection and preservation;
   they do **not** prove a real ELF artifact runs. These direct script tests are
   intentionally outside the frozen `tests/` namespace, not CTest registrations.
2. One exact-source Linux build and package in the cached offline toolchain.
   Preserve revision, commands, binary/archive hashes, dependency and license
   inventory. Do not relabel an earlier build as current.
3. Non-root, offline unpacking into a fresh path containing spaces, with no
   source/build mount or LLVM installation visible. Confirm all bundled DSOs
   resolve inside the unpacked tree; intrinsic headers must resolve there too.
4. Real C and C++ first scans. Compare source-build and unpacked CLI results on
   identical fixtures across console, JSON, SARIF and HTML, preserving exit,
   finding, coverage and completeness semantics. Run relevant existing CLI and
   resource regressions without modifying their assertions.
5. Queue/catalog checks and exact-head independent review before any POP or
   feature-only publication. No hosted CI, release, signature, main merge or
   broader platform success is implied by local results.

## Local qualification — 2026-09-08

Measured source: `a23cf319264847c752a4fdc55ce2f3cadb196f78`;
binary identity: `0.4.9-dev+ga23cf3192648`. The later documentation checkpoint
does not rebuild or relabel this artifact. This is the existing unoptimized
development CMake profile, not a performance-qualified production release.

- Binary SHA-256: `5272baff931cae3dbd21c51409dd129a607df983a69e851b3f6cf57e5e845677`.
- Archive: `codeskeptic-v0.4.9-dev+ga23cf3192648-linux-x86_64.tar.gz`.
- Archive SHA-256: `25fca8890ddab665670ec2d68ac2df7534ed83f296edd07ebd585f7ce27b8416`.
- Build/assembly image: `25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5`
  (Ubuntu, LLVM/Clang 20.1.2). Clean runtime image:
  `045183670ef29ce21bc22a8d4f62511ce472679ca8fc9774f04181f7f383ca62`
  (Ubuntu 24.04.4, x86_64). Both were cached; no download or sudo was used.
- Assembly and runtime: non-root, offline, read-only inputs/root filesystem,
  zero kernel capability sets, 2 CPUs, 6 GiB memory, 256 PIDs, 1 GiB temporary
  filesystem. Configured swap allowance is another 6 GiB, not a 6-GiB combined
  memory-plus-swap bound. Both containers exited 0 and were removed successfully.

The seven initial synthetic regressions failed against the former packager;
all 21 expanded regressions passed locally and in the build image. Existing
OutputParity CLI tests passed 5/5, FirstScan recipes 12/12 and ResourceDir tests
9/9. FirstScan's binary-only installation test is **not** the isolation proof.
All 124 protected quality inputs remain unchanged.

Actual source-versus-package qualification ran 6 scenarios × 4 formats on each
binary (48 runs): clean C/C++, blocking C/C++, report-only, incomplete,
explicitly accepted partial coverage, and explicitly accepted recovery.
All 24 comparisons preserve the complete structured report, exit, findings,
coverage, completeness, version and capability discovery. Console and HTML
visible findings, notes, CWE labels and verdicts also match; only the one
HTML header's wall-clock generation minute is normalized. Dates inside finding
messages are not changed. Existing format parsing is pinned to protected
`tests/OutputParityCliTest.py` SHA-256
`a49ee42d2b9b3cc880bf4ad8fb118e0b0d0953374579f182e8f089dd06559c7d`.

The real runtime unpacked into a path with spaces, with no source/build mount,
LLVM installation or Python. Both C and C++ fixtures include packaged
`stddef.h`. Temporarily removing intrinsic headers makes the scan fail with
exit 2; removing the package's LLVM makes the loader fail with exit 127.
Both negatives only touch the disposable extraction and restore the files;
the original archive is preserved. Final archive, expanded and restored-tree
inventories and file hashes agree exactly. All 12 non-core DSOs resolve inside
the package; host dependency rows reconcile with the complete actual loader
closure. Equivalent loader `../` segments are normalized to exact package paths,
not accepted by a loose substring match.

The 13 component entries cover the intrinsic headers and 12 bundled libraries.
A separate read-only check reconciles original installed owners/versions,
every header and library byte, project LICENSE/README, distribution copyright
notices and referenced common license texts. This evidence covers this actual
dynamic-runtime artifact; it is not an audit of every possible static-link or
third-party build configuration, or a substitute for the later SBOM unit.

Raw local evidence lives under
`/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH06-S01-U001/`:
the `a23cf319264847c752a4fdc55ce2f3cadb196f78/` directory contains `build.log`,
`assembly.log`, `runtime.log`, both raw scan matrices, container inspections and
cleanup records, `origin-audit.log`, `reconciliation-final.log`, and artifacts.
`helpers/` contains the bounded reproducing scripts and report reconciler.
Earlier unsuccessful reconciler logs remain failures: they caught the generated
HTML minute, equivalent loader paths and Podman's removed cidfile; no analyzer
result, acceptance threshold or historical receipt was rewritten to hide them.

This is local Ubuntu x86_64 artifact evidence only. It does not establish older
glibc compatibility, all-Linux portability, another Python version, Docker/
Action execution, Windows/macOS support, hosted CI, signature or publication.
Final exact-head independent review and the FIFO ledger transition are required
before this unit is complete.
