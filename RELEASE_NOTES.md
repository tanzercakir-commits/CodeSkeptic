# CodeSkeptic v0.4.5 — native Windows

The first release with a native Windows binary:
`codeskeptic-windows-x86_64.zip` — a static-CRT MSVC build carrying its
own Clang intrinsic headers, smoke-tested on the release runner with
the build LLVM renamed away and the entire vcvars environment stripped
(the same exit-1-with-findings contract the Linux clean-container
smoke enforces).

## Native Windows, staged honestly (docs/windows-support.md)

- **Tier 1 — MSVC port:** the engine compiles and links with MSVC
  against the official LLVM 20.1.8 windows-msvc dev tarball, and the
  full 682-test unit suite runs green on `windows-latest` on every
  push (windows.yml — the ratchet). Portability layer verified before
  landing: the `__builtin_*_overflow` / `__int128` arithmetic was
  replaced by shared checked-int64 helpers proven behavior-identical
  to the builtins over the int64 edge matrix plus 40M random pairs.
- **Tier 2 — "point at a directory" anywhere:** closed by measurement,
  not code. With the entire 28-variable vcvars family stripped, clang's
  MSVC toolchain still locates Visual Studio (COM setup-API/registry)
  and the Windows SDK (registry) on its own; a dedicated CI step guards
  exactly that behavior from here on.
- **Packaging:** `package_release.sh` gained a Windows branch (zip,
  `codeskeptic.exe`, bundled `lib/clang/20/include`, no dynamic libs to
  carry — the official LLVM Windows dist is static). The release lane
  builds, tests, version-checks, packages, relocation-smokes and
  uploads the zip alongside the Linux/macOS tarballs; `sha256sums.txt`
  covers all three.

Requirement, stated plainly: analyzing code on Windows needs an MSVC
toolset + Windows SDK installed (any Visual Studio or Build Tools
install) — analyzed code resolves real system headers, as with any
compiler. `compile_commands.json` mode and MCP stdio (now binary-mode,
CRLF-tolerant) work as on Linux/macOS.

## Engine

No intended behavior changes. The only engine-adjacent change is the
checked-arithmetic substitution above, pinned by IntervalTest on every
platform and equivalence-fuzzed against the GCC/Clang builtins before
merge. All existing floors stay green: 682 unit tests on three
platforms, NIST Juliet, the real-world corpus, the thesis gate, and
the self-scan dogfood gate.
