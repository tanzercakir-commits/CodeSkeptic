# CodeSkeptic v0.4.0 — the onboarding release

v0.3 asked "do we catch the bugs an AI writes?"; v0.4 asks the question
an external reviewer put to us bluntly: *can a stranger try this in
five minutes?* Until now the honest answer was no — source build only,
LLVM dev libraries required, a 742-line README. This release is the
response, built point by point from that review.

## Try it in one command

**Binary** (no LLVM install needed — the tarball bundles the Clang
intrinsic headers and every non-glibc shared library, found
exe-relative at runtime):

```bash
curl -sL https://github.com/tanzercakir-commits/CodeSkeptic/releases/latest/download/codeskeptic-linux-x86_64.tar.gz | tar xz
./codeskeptic-v*/bin/codeskeptic path/to/your.c
```

macOS (Apple Silicon): `codeskeptic-darwin-arm64.tar.gz`, same layout.

**Docker:**

```bash
docker run --rm -v "$PWD:/work" ghcr.io/tanzercakir-commits/codeskeptic src/ --sarif out.sarif
```

**GitHub Action** — report-only by default (findings inform; blocking
is an explicit opt-in after an adoption week, as our own evaluation
guide recommends):

```yaml
- uses: tanzercakir-commits/CodeSkeptic@v0.4.0
  with:
    path: src/
    build-path: build
```

Every release asset is smoke-tested before publishing: the tarball is
extracted in clean containers (Ubuntu 22.04 + 24.04, no LLVM) and must
find the demo bugs with exactly exit code 1.

## What changed

- **Relocatable binaries.** The Clang resource dir is resolved at
  runtime (env override → exe-relative `lib/clang/<N>` → the build
  machine's baked path), with the resolution order unit-tested. The
  executable carries a transitive `DT_RPATH` to its bundled libraries.
- **README re-architecture** (742 → ~250 lines). Quickstart first;
  explicit "What it won't catch" and "Use it alongside, not instead"
  sections; deep content layered into `docs/` (usage, integrations,
  benchmarks, comparison, engine internals). Nothing was deleted.
- **`docs/evaluate.md`** — the reviewer's own trial protocol, adopted
  as our recommended evaluation: 10–30 of *your* TUs, real
  `compile_commands.json`, memory-leak scored separately, traces
  verified by hand, report-only CI for week one, gate only after
  7–8/10 findings hold up.
- **SARIF Windows-path fix**: drive-letter (`C:\`) and UNC paths are
  now emitted as proper `file:///` URIs (closes
  `docs/windows-support.md` §4; Windows support itself remains
  plan-only, staged honestly).
- **CI guards for the front door**: the README's quickstart block is
  extracted verbatim and executed on a clean runner on every docs
  change — copy-paste installability is proven, not assumed. It
  caught its first real bug (a missing `clang-20` in the install line)
  on its maiden run.
- `CODESKEPTIC_BUILD_TESTS` CMake option (hermetic artifact builds);
  Docker image with an LLVM-free runtime stage; release/docker/action
  pipelines with per-job status mirroring.

## Unchanged, on purpose

The analysis engine is v0.3's: six Juliet CWE floors hold (rule
precision 1.000 on five of six; the honest recall bounds and their
reasons are in [docs/benchmarks.md](docs/benchmarks.md)), the blind
AI-corpus recall gate stands at 0.625 @ precision 1.000, and the
real-world corpus pins are untouched. Rule-quality work (memory-leak
FP taxonomy, div-by-zero recall classification) is the next round —
see [docs/PLAN-v0.4.md](docs/PLAN-v0.4.md).
