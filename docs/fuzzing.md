# Parser fuzzing

Phase 10 fuzzing is limited to four existing production input surfaces:
project configuration, `compile_commands.json`, strict versioned text
summaries/models, and MCP JSON-RPC messages. The harnesses call the same parser
entry points as the product. They do not add a second grammar, invoke the
analyzer, discover projects, or broaden rule semantics.

## Dedicated build

Fuzz targets are opt-in and cannot be combined with the unit-test build. Use a
Clang toolchain with libFuzzer:

```sh
cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCODESKEPTIC_BUILD_TESTS=OFF \
  -DCODESKEPTIC_BUILD_FUZZERS=ON
cmake --build build-fuzz --target \
  codeskeptic_fuzz_config \
  codeskeptic_fuzz_compile_database \
  codeskeptic_fuzz_summary \
  codeskeptic_fuzz_mcp_json_rpc
```

On systems where LLVM is installed in a versioned prefix, also pass the same
`CMAKE_PREFIX_PATH` used by the normal CodeSkeptic build. macOS developers who
use Homebrew LLVM should select its `clang` and `clang++` explicitly.

## Reproducible campaigns

`fuzz/campaign.json` is the canonical target, seed, input-size, per-input
timeout, 2 GiB per-process RSS ceiling, run-count, and wall-time budget.
`fuzz/corpus/SHA256SUMS` binds every
retained seed. The runner verifies that manifest before and after execution,
copies seeds into a temporary mutable corpus, and never teaches the canonical
corpus in place.

The CI smoke gate runs 256 inputs per target:

```sh
python3 scripts/run_fuzz_campaign.py \
  --build-dir build-fuzz \
  --mode smoke \
  --output /tmp/codeskeptic-fuzz-smoke
```

The extended local gate runs 10,000 inputs per target:

```sh
python3 scripts/run_fuzz_campaign.py \
  --build-dir build-fuzz \
  --mode extended \
  --output docs/evidence/phase10/fuzz/<date>-<host>
```

The output directory must be new or empty, so prior evidence cannot be
silently overwritten. Every target has a complete log and log SHA-256 in
`receipt.json`; `receipt.json.sha256` detects accidental or partial receipt
corruption. Authenticity comes from the Git object that ultimately reaches
protected main, not from a co-located checksum. The receipt also binds the
production/fuzz source input manifest (including
uncommitted worktree bytes), source commit, corpus and campaign manifests,
toolchain identity, binary hashes, exact normalized commands, budgets,
durations, exits, and crash artifacts. Any non-zero exit, wall timeout, crash
artifact, checksum drift, missing binary, or malformed manifest rejects the
campaign.

The recorded source commit is the worktree's base commit at campaign time. The
verifier accepts a later descendant HEAD only when the exact production/fuzz
source manifest still matches, avoiding an impossible self-referential receipt
while rejecting unrelated history or changed parser bytes.

Retained repository evidence also has a `SHA256SUMS` one level above its dated
directory. That manifest covers the receipt and every complete log; once the
change reaches protected main, the protected Git object is the external
authority for those digests.

Clang's production compilation-database parser emits diagnostics for malformed
JSON. Those messages are expected in the compile-database log; acceptance is
determined by the bounded target exit and absence of crash artifacts, not by a
quiet log.

Verify any retained receipt, including every log hash and current source/corpus
binding, with:

```sh
python3 scripts/run_fuzz_campaign.py \
  --build-dir build-fuzz \
  --verify-receipt docs/evidence/phase10/fuzz/<date>-<host>
```

The CI workflow uploads its checksummed smoke receipt for 14 days. A branch
receipt proves only the tested implementation bytes; task completion still
comes from the protected-main lifecycle defined in `docs/PLAN.md` and
`CONTRIBUTING.md`.
