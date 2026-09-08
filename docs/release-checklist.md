# Candidate acceptance and artifact qualification

## Candidate acceptance matrix

This CH07 dossier assembles independently accepted development profiles; it
does **not** claim a fresh same-source cross-platform release. The documentation
review SHA is recorded by the CH07 receipt in `BOOK.json` / `PROGRESS.md` after
independent acceptance. It is not any executable's source identity. All PASS
entries below mean the stated bounded measurement passed, not universal feature
or platform coverage. There is no public candidate download, new tag or main merge.

| Delivery promise | Exact measured identity | Accepted PASS evidence and boundary |
|---|---|---|
| Linux installation, isolation and output parity | **L**: source/binary/archive below | CH06-S01-U001: actual non-root/offline package execution without a host LLVM installation or Python; bundled LLVM is present. 48 source/package analyses, 24 four-format comparisons, two dependency negatives. Ubuntu x86_64 ABI profile only. |
| First C/C++ scan, doctor repair, baseline and report-only recipe | **L**, byte-identical installed binary | Same unit's `assembly.log` and terminal invocation: 12/12 FirstScan tests, including real marked recipes and static/mock negatives. Not 12 end-to-end runs; archive isolation is the separate row above. |
| Local CLI/container/Action parity | **L** archive; implementation review **I** | CH06-S01-U002: six scenarios / 19 actual analyses with complete SARIF/exit parity. Report-only wrapper exit 0 retains analyzer exit 1. Local Action only; no hosted Action or source-rebuild qualification. |
| Triage, baseline, suppression and PR delta | **T** | CH03-S02-U001: actual delta/shift/rename, gate ladder, assumption delta, suppression audit, baseline v3 and malformed-input negatives. Triage decisions do not establish clean code. |
| Output, discovery and verdict contract | **O** | CH03-S01-U002: 52 output-parity checks, capabilities/producer selection and CWE metadata. Later **L** four-format artifact parity and **N** native 0/1/2 scans are additional, separately bound evidence. |
| Declared models and sidecar validation | **M** | CH02-S02-U001: 45 JSON, two SARIF and four same-process MCP checks plus malformed/framing/transaction negatives. Validation is not proof that user-supplied semantic declarations are true. |
| Supported/experimental CWE qualification | **Q** | CH05-S01-U003: seven supported and five experimental family sample sets; frozen positive/safe/boundary checks pass. These narrow samples do not promote experimental rules or establish family-wide precision/recall. |
| Real-project measurement and noise disclosure | **R** | CH05-S02-U002: retained measured results and independent adjudication; passing the measurement process does not mean a clean scan or that every usability target was achieved. Actual limitations below. |
| Linux inventory/provenance sidecars | **L** archive; generator review **S** | CH06-S02-U001: unchanged archive, 328 files / 13 licensed-component entries, schema/checksum validation and negative controls. Unsigned and incomplete composition; no native-package SBOM claim. |
| Native Windows/macOS support; Linux and ordinary Windows CI | **N** | CH06-S02-U002: actual native run 34243269691 attempt 1, ordinary Windows 34243269775 attempt 1, Linux 34243269733 attempt 2 all SUCCESS. Raw artifact and test/skip audits retained. Native first scans preserve clean/finding/unavailable 0/1/2; profiles and exclusions below. |

Identity keys are exact source commits unless explicitly marked as an
implementation/documentation review. The Linux archive and both native packages
retain different actual binary/version identities; they are not repackaged here.

| Key | Full identity | Artifact or primary measurement |
|---|---|---|
| L | `a23cf319264847c752a4fdc55ce2f3cadb196f78` | [Linux archive and executable hashes](#local-qualification--2026-09-08) |
| I | `9070e9ba17c07f8c5438709675fb4c9d24da52c5` (implementation review, not binary source) | [Local integration evidence](integrations.md#qualified-artifact-integration-profiles) uses L |
| T | `3a222ffee8343d567318530c49ce27ba02b1ee98` | CH03-S02-U001 exact-source `cli-smoke.log` |
| O | `184a30cdef4c33f4b70394d15fa771f823fd8c13` | CH03-S01-U002 exact-source `cli-smoke-v2.log` |
| M | `574fa3158093782407118e93b36caa252c1be09e` | CH02-S02-U001 `574fa31/cli.log` |
| Q | `157724b079803c2fbe28d1de8e2c1032eb8f703f` | [Frozen sample results](quality_results.md), supported/experimental `results.json` |
| R | `c4fa60864f2e5853581c2f8a0dd66a3fc967239b` | CH05-S02-U002 exact-source `measurement/results.json` and `adjudication-summary.json` |
| S | `f0f348faa3944a3c152173f9ef027a81f90f6422` (generator/documentation review, not binary source) | L archive plus [inventory/provenance profile](#ch06-s02-u001--unsigned-inventory-and-provenance) |
| N | `e83b641be32665740e8637cbb1368346e82ea471` | [Native archive/executable hashes and actual jobs](#hosted-native-measurement--2026-09-08); independent final review `85cbb8fbbc725dd0a0192dd83f0ac851d47c74be` is documentation-only |

### Evidence retention and reproducibility

Each task row resolves to its completed `BOOK.json` record: the full contract,
exact review SHA, distinct implementer/verifier, PASS with zero findings, and
named check commands/absolute evidence paths/SHA-256 digests. `PROGRESS.md`
exposes the same review and check digests. These are procedural independent
receipts, not signatures or external producer attestations. Source histories,
archives, raw results and failed attempts are preserved, not replaced by this
summary. Durable local evidence root:
`/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/`.
CH07 qualification rechecks the bound bytes and documented identities without
claiming to rerun historical/native binaries at the new documentation HEAD.

Canonical completed receipt digests (SHA-256 of JSON+LF) bind every original
required check **and** additional source/evidence-continuity checks. Older
three-check contracts are not reduced to CH07's two check names.

| Matrix key | Canonical independent PASS receipt SHA-256 |
|---|---|
| L | `787972bea8f66d4b0b922ea254f164ef1f57c70c5d65869017427521bfec0100` |
| I | `abb0a7eb9a9d6023fa869d718181530d3f546261280f2da79de67b559ecb7ef1` |
| T | `efc7ebfdf8fc030f5ad06604e5ab3b2298e0e3af453f066baacc0e4ace2cccba` |
| O | `0e560f735aaf5e4a8878a9cc480752a44fd04bfa2606588f91b769392b65a3fb` |
| M | `97f30d8eca4131882b3e9fcc959536e6c4afb8af7a021ad6ba6978c4c1d90dc8` |
| Q | `2b2dd8f058732b7dbdfb2b490099119fa6e902b60686d07c025e86b27f9c8bf5` |
| R | `188c77e1452c035e5674ff98c57b27d63f08bfe66d660e3866d192a17f4432f8` |
| S | `8c672e2dbaf4c78aabb521f65d1eef6c7df7e26dae249d9a0520dccbbae60a19` |
| N | `09cfa0a998fdd9ce715bc760b86539038ea6c3779421cdaf79dec0bd028174d7` |

The L first-scan binding is specifically its `a23cf319.../assembly.log`
(SHA-256 `9ae85946389d96f8942f881591e9daf34f7e65e0adedcd7e63af9bfc0e369bb4`),
which records the installed/source version and byte-equal executable hash,
plus `container-assembly-afkwrQ/terminal-inspect.json` under the same source
directory (SHA-256 `5d1fd23517a09083f5eb2fec67f8499f9819923401d256f9e471bd28648145d7`)
recording the actual `FirstScanTest.py` invocation and terminal exit 0.
Marked walkthrough recipes are unchanged from L. This is output/coverage
contract evidence, not a separate first-use demonstration of function contracts.

### Candidate limits and publication boundary

The R measurement has cJSON 34/76 analyzed translation units, with 42 broken;
its adjudication is 39 false positives, nine true positives and six unknowns.
GoogleTest covers only four library translation units (not its tests/examples),
with three false positives. tinyxml2 covers three translation units, with five
false positives and four unknowns. These are measured limitations, not clean
projects, a low-noise guarantee, or a reason to lower quality floors. Q's seeded
sample precision/recall success is not a substitute for this project evidence.
Earlier README benchmark/token and v0.4.8 campaign numbers remain historical.

Native profiles have explicit [unexecuted platform assertions and prerequisites](windows-support.md#actual-tests-and-unexecuted-platform-coverage).
Linux's absolute address-space, Windows's Job Object committed-memory and
macOS's one-time startup-virtual-size-plus-budget cap are different contracts;
see [worker budgets](usage.md#worker-resource-limits-and-cancellation). Native CI success does not
prove older OS/ABI/SDK compatibility, Windows-host WSL execution, native SBOMs,
publisher signing, macOS notarization/Gatekeeper download-install, or a public
release. GitHub artifacts' 14-day retention is not permanent distribution.

Linux CI attempt 1 was cancelled at its 30-minute limit after slow dependency
download; its interrupted and unexecuted gates remain failures/unexecuted.
Only the independently diagnosed, fresh same-source attempt 2 supplies the
complete Linux PASS. Earlier failed native jobs and the c4fd06b accounting gap
also remain failed/incomplete; none is relabeled by this matrix.

Acceptance here is limited to the documented local candidate dossier and retained
unsigned artifacts. A unified new-source release, missing broader qualification,
main integration, tag/release publication or signing requires separate work and
exact-candidate owner authority where applicable. No such external action is
required to deliver this explicitly local dossier; the final FIFO unit must
still verify and record that distinction before declaring the queue terminal.

## Linux artifact qualification

This is the CH06-S01-U001 package work, not a published or signed release.
Only independently reviewed, actual artifact executions establish support.
Windows/macOS support is recorded in the separate measured profile below. Container/Action parity is
recorded in `docs/integrations.md`; the CH06-S02-U001 inventory/provenance profile
below builds on this exact artifact. Protected source/test inventories and CMake
files stay unchanged.

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
Machine-readable inventory/version/provenance sidecars are described below.

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

## CH06-S02-U001 — unsigned inventory and provenance

This profile accepts only the previously qualified Linux x86_64, dynamic-LLVM,
dpkg-notice tarball layout. It adds sidecars without changing or executing the
archive. Python 3.9+ on Linux is required for this **metadata mode**; the earlier
assembly-only interface retains its Python 3.8+ requirement. No runtime user
needs Python. Nothing is downloaded, installed, signed or published by the tool.

`CMakeLists.txt` remains the sole authored product-version source. The generator
reads it and the native report/capability schema declarations from the **artifact
source commit**, not from its own checkout. A clean development identity must
match that commit's next-patch/version suffix; a release identity needs the exact
matching local tag. Dirty, unbound and arbitrary version overrides are rejected.
Native JSON and capabilities evidence must agree with this identity. These two
files are identity inputs, not a replacement for the actual first-scan gates.

Provide a producer-owned `codeskeptic-build-evidence/v1` JSON document with exactly:

- `schema`, `source_sha` (full commit), `archive_sha256`, `binary_sha256`.
- `report` and `capabilities`: each has `path` and `sha256` for saved native output.
- `recipe`: exactly `source_sha`, `toolchain`, `commands`, `inputs`.
  `source_sha` must agree; `toolchain` is a nonempty string-to-string map of the
  observed tool versions/profile; `commands` is a nonempty list of reproduction
  command strings, **recorded as data and never executed**. `inputs` is a nonempty
  list of `{name, path, sha256}` records for retained build logs, cache, recipe
  scripts or workflow. Names are unique; input files are bounded regular files.

Paths resolve from the caller's working directory; absolute paths are simplest.
No environment or credential inventory is taken. Prepare evidence deliberately:
do not include secrets in logs/commands. Report/recipe/manifest SHA-256 bindings
detect later inconsistency but cannot prove an honest producer, or prove that
the asserted recipe actually produced the binary. The original build evidence
and independent review remain necessary. Missing records are not fabricated.

With a clean, committed generator and its two imported helpers:

```bash
bash scripts/package_release.sh --provenance /path/codeskeptic-vVERSION-linux-x86_64.tar.gz /path/build-evidence.json /fresh/sidecars
python3 -B scripts/generate_sbom.py verify /path/codeskeptic-vVERSION-linux-x86_64.tar.gz /fresh/sidecars --source-sha FULL_SOURCE_SHA --version VERSION
```

The output directory must not exist, and its parent must already exist. Sidecars
are named after the full archive filename: `.sbom.json`, `.provenance.json`, plus
`sha256sums.txt` binding both JSON files and the unchanged archive. Keep the
archive and sidecars together; the checksum file can be checked in that combined
directory. Existing outputs are never overwritten. A late I/O failure can leave
partial owned evidence, but never prints `PROVENANCE_OK`; preserve it and retry
in a fresh directory. Verification does not modify supplied artifacts or sidecars;
it uses temporary extraction files and checks the archived bytes, not merely
internally consistent JSON hashes. The exact checksum companion is required.
Only release aggregation may explicitly use `--pending-checksums` while preparing
the combined checksum file; an existing inconsistent companion is never ignored.

The SBOM uses [CycloneDX 1.6 JSON](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json).
It inventories bundled libraries and Clang headers by installed package/version,
with exact distribution-notice references and hashes. License URLs are relative
to the unpacked artifact root; keep `licenses/` including referenced common
texts. Notice names are deliberately **unclassified**, not invented SPDX license
conclusions. The provenance also inventories every packaged file by path, size
and SHA-256. Missing/duplicate/extra INDEX entries, conflicting package versions,
missing notices, unclassified files, dependency/LLVM mismatches and unsafe archive
members fail closed. Host libraries are named but their versions/licenses are
unknown. Static source dependencies are not fully resolved: CycloneDX composition
is explicitly `incomplete`, not a complete-all-dependencies or legal-review claim.

The custom `codeskeptic-provenance/v1` record is unsigned. It separates original
artifact source SHA, authored/tool/schema versions, binary/archive hashes and
recorded recipe from the metadata-generator HEAD and source-file hashes. Build
input names/digests are retained without publishing their local filesystem paths.
This is neither a SLSA attestation nor proof of bit-for-bit reproducibility.
In particular, the earlier a23cf319 package reused a development build cache;
recording its procedure does not turn it into a fresh Release/clean-room build.

The tag-only Release workflow prepares Linux sidecars after packaging, rechecks
them against the archive, uploads them to the existing shared draft, and checks
them again before combined checksums/publication. Checksums include sidecars.
Existing platform smoke gates remain mandatory. This change does not run that
workflow, grant release authority or claim equivalent macOS/Windows SBOM coverage;
those native profiles are recorded separately below.

T3 qualification requires focused `scripts/test_generate_sbom.py` negatives,
existing package/release-workflow guards, actual unchanged qualified-archive
generation and re-verification, and validation against the official CycloneDX
schema with a separately recorded schema/validator version. Only then may an
independent exact-head PASS and real FIFO POP complete this unit.

## Native platform qualification — CH06-S02-U002

The separate `candidate-native` jobs in `release.yml` build/test/package Windows
x86_64 and macOS arm64 on the exact candidate branch. They never enter the
tag-only prepare/upload/publish or legacy ref-writing jobs. Branch/path filters
avoid rerunning expensive native builds for a ledger-only POP; changed native
source, package/helper/tests or workflow select a fresh run. A changed source
commit invalidates previous package identity; never stamp it onto an old binary.

Before support is recorded, require each actual native job's full test gates,
six C/C++ packaged first scans, final successful conclusion and retained exact
archive/JSON/command metadata. `scripts/platform_first_scan.py` accepts only the
two native architectures, checks full source/version, executes the freshly
unpacked trusted archive with the caller's build LLVM hidden, and preserves
clean/finding/unavailable semantics and Unicode paths. Windows packaged binary
bytes equal the source executable; macOS load-path/ad-hoc-signature changes can
change those bytes, so both hashes and matching version are recorded explicitly.

The package/scan artifact and separate build diagnostics are uploaded with an
exact source/run/attempt name even when a job fails. Missing evidence or a failed
step is not success. Restore LLVM before final job success. Retain downloaded
catalog/run/job records and raw archive digests outside the worktree for an
independent audit; a self-authored helper result is not external qualification.

Local `python3 -B scripts/test_platform_workflow.py` checks version preservation,
candidate/tag boundaries, bounded archive handling and negative report/runner
evidence. Its checkpoint-tick regression also compiles a small C++17 program
with an already-installed wide-integer-capable compiler, covering signed minima
and high bits without narrowing. No compiler is downloaded. This local check
does not run native Windows/macOS binaries. Existing frozen
`tests/WorkflowPolicyTest.py`, `tests/ReleaseWorkflowTest.py` and package/SBOM
regressions remain unchanged. A profile is qualified only by actual retained
hosted evidence, with unexecuted platform assertions disclosed separately.

## Hosted native measurement — 2026-09-08

Measured source: `e83b641be32665740e8637cbb1368346e82ea471`; native binary identity:
`0.4.9-dev+ge83b641be326`. This later documentation-only checkpoint does not
rebuild or relabel the executables, archives or their embedded README files.
The existing Linux package remains the separately identified `a23cf319` artifact
above; these measurements do not produce a new Linux tarball.

Actual native [run 34243269691](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34243269691),
attempt 1, finished SUCCESS. Both native jobs completed full CTest, named
compilation-input accounting, separate single-process tests, packaging, six
first scans and final LLVM restoration. Read-only independent audits inspected
the actual downloaded artifacts and raw logs, not only self-authored results.

| Profile | Actual job | Outer retained artifact | Outer bytes |
|---|---|---|---:|
| macOS arm64 | [102118622191](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34243269691/job/102118622191) | `10063258404` | 61,519,331 |
| Windows x86_64 | [102118622475](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34243269691/job/102118622475) | `10063711096` | 20,334,058 |

The outer GitHub ZIP is the retained evidence container, not the nested
installable package. Its catalog name binds target/full source/run/attempt.
All digests below are SHA-256, independently recomputed from retained bytes.

macOS:

- Outer ZIP: `cf118758acdafbbdda548f8fc91fb97c04c0386a8df1f648b75b9724fcfd4b42`.
- Package: `codeskeptic-v0.4.9-dev+ge83b641be326-darwin-arm64.tar.gz`, 56,354,213 bytes;
  `a2d81c883c3e7d87d2ea661a294bf51300efd53a206fab4233ee2e5e9d27b0fc`.
- Packaged executable: `7a33f5851a0ff124231b98719baa180c3b508b9621f7cd1430b5abe934af4c7c`.
- Source-build executable: `13a81a8301a5b572a2189d39ce25cb5de59ff0cb53a732ef7e64192e0c9ff2f7`.
  Actual Mach-O arm64 load-path rewriting/ad-hoc signing changes the bytes;
  equal native version and separate source/accounting binding are verified.

Windows:

- Outer ZIP: `de8c77dc670270b5ef3b951067e5e5df3e75d95d2cec6df879061cdf3d7d717f`.
- Package: `codeskeptic-v0.4.9-dev+ge83b641be326-windows-x86_64.zip`, 15,106,441 bytes;
  `bb510deece8ab475a467a155dfe501c4b943c13948fa0e00beacf38cd8d98348`.
- Packaged and source-build executable, byte-identical PE AMD64:
  `c7c2f701e4ef5fe4478958e03b825b76d6987556ae6c4ecdc7749d0237b4a886`.

For each language, the retained packaged scans show complete clean exit 0,
one supported blocking null-dereference/exit 1, and missing-header incomplete
exit 2. Source, compilation database, report, command and stdout/stderr hashes
reconcile. No partial-coverage or recovery acceptance is enabled. The actual
runner/test totals, exact skipped identities, dependencies and memory-contract
limits are [recorded together](windows-support.md#actual-tests-and-unexecuted-platform-coverage).
Skipped assertions are not counted as passing or hidden behind green wrappers.

The separate ordinary Windows [run 34243269775](https://github.com/tanzercakir-commits/CodeSkeptic/actions/runs/34243269775),
attempt 1, job `102118622584`, also succeeded with its unchanged SDK-discovery,
normal packaging, real 7-Zip-masked PowerShell fallback and LLVM-hidden
relocation gates. Diagnostic artifact `10063891996` is 11,991 bytes, SHA-256
`9cb15cd01eb603e4a71603ab1b30efb467e336aed76df36efd4aaf2d5d81d992`.
It does not retain that ordinary job's package bytes; do not attribute the
native candidate's binary/ZIP checksums to it.

Native artifact first-scan mode makes no downloads and runs no compiler.
The separate build-stage `--ctest-accounting` mode runs unchanged registered
tests and may invoke their compiler. Its `CAPTURED` marker does not classify
skips: independent review reconciles the original full CTest log with the named
repeat, exact source/script/binary, interpreter, compiler, CWD and temporary
environment. The earlier `c4fd06b` accounting gap is not retroactively erased.

Raw evidence is retained outside the worktree under
`/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH06-S02-U002/`:
`e83b641-native-final-run.json`, `e83b641-native-final-catalog.json`, exact
`macos-e83b641-*` / `windows-e83b641-*` archives and job logs, ordinary Windows
records, and independent `macos-review-e83b641.md` / `windows-review-e83b641.md`.
Native ZIPs include `codeskeptic-platform/` raw scan/package records and
`codeskeptic-native-build/` full CTest/single-process/build/accounting evidence.
GitHub's 14-day artifact retention is not permanent distribution.

This qualifies only these unsigned candidate profiles. Publisher signing,
notarization/Gatekeeper download-install qualification, native SBOM coverage,
public release and main integration remain unperformed or unauthorized. Missing
signer/release authority is an explicit blocker to those broader claims, not
success. No tag, release, PR or main merge is created by this qualification.
