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

## Current evidence

Qualification pending: the implementation and focused regressions are being
prepared. No current artifact execution or new support claim is recorded yet.
