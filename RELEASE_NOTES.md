# CodeSkeptic v0.4.4 — the trust-chain round

No engine changes. This release closes the reproducibility and
supply-chain gaps the second external critique identified — the gap
between LOOKING pinned and BEING pinned.

## GitHub Action: pinning the action now pins the analyzer

- `uses: tanzercakir-commits/CodeSkeptic@v0.4.4` previously downloaded
  the LATEST release binary regardless of the pinned ref — the
  analyzer could drift under a "pinned" workflow. The `version` input
  now defaults to the action's own ref: pin the action, and that exact
  release binary is what analyzes your code. Explicit `version:
  latest` still floats for those who want it.
- The action now verifies the downloaded tarball against the
  `sha256sums.txt` published with the release — a mismatch (or a
  missing checksum file) fails the job.
- The action self-test gained a pinned lane: after every release it
  runs the action pinned to the fresh tag and asserts the analyzer
  that answers is exactly that version.

## Self-contained releases: now proven, not just claimed

The clean-container release smoke used to install `libzstd1`,
`zlib1g` and `libtinfo6` before running the packaged binary — which
would MASK a broken bundle (the critique's sharpest catch). The smoke
now installs only `libc6-dev` (the demo's libc headers), asserts
`ldd` reports no missing libraries, and asserts the bundled runtime
libraries (LLVM, zstd, zlib, tinfo) resolve from the PACKAGE lib
directory, not the host.

## Docs and templates

- README examples pin versions (`@v0.4.4`, `ghcr.io/...:v0.4.4`)
  with `:latest` noted as the explicit floating choice.
- `docs/evaluate.md` prerequisites rewritten for the binary/Docker
  era: Option A (release binary), B (Docker), C (build from source —
  only C needs LLVM dev libraries), with your project's
  `compile_commands.json` explained as a separate concern.
- New issue templates: **false-positive report** (traces welcome —
  every FP family so far became an engine feature) and **evaluation
  report** (independent evaluations are the most valuable
  contribution this project can receive).

## Windows, honestly framed

No native binary yet — and the README now says exactly that while
giving Windows users two working paths: WSL2 (best for Linux-targeted
projects; with the `#ifdef _WIN32`-branches-are-invisible caveat
stated up front, because the analyzer sees the compiler's view) and
Docker Desktop (fastest trial). The WSL path is exercised by a new CI
smoke on a windows-latest runner — the support table claims only what
that job proves. Native MSVC analysis remains a separately planned
effort (docs/windows-support.md).

Full engine history: docs/devlog/changelog.md.
