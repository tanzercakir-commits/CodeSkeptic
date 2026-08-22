# Attempt23 physical-run preflight

- Frozen at: `2026-08-22T15:02:32Z`
- Primary repository: `main@7dfd37596414c9512316093ff4fb6b039673f55f` (clean; unchanged)
- Feature authority: `phase-determinism-kernel-bound-authority@88e369b21675e64e0a92842b0ce22f0c8148745e` (clean)
- Attempt22 result: safe pre-controller rejection (`payload_exit=2`, transaction safe, graphical restore `0`). No snapshot, qualification evidence, or measured workload was started.
- Attempt22 last durable step: `coredump-handoff-verified`; all root-staging files were copied before the fail-closed hash comparison stopped the run.
- Attempt22 packaging defect: the authorizer retained four stale literal hashes for `snapshot-builder.sh`, `run-static-preflight.sh`, `static-preflight.py`, and `run-confirmation.sh`. This was an operator packaging error, not a user command error or CodeSkeptic measurement failure.
- Regression proof: a new exact-byte manifest/authorizer test failed against the stale wiring before the correction.
- Attempt23 correction: the core manifest, cgroup launcher, root controller, authorizer, guided wrapper, short launcher, and renamed stress fixtures were rebound bottom-up to current bytes.
- Attempt23 core manifest SHA-256: `77866c8182fd1e55166e3c50e4694e2b1d10e5ae5ed25e7b2ec750054e584fac`
- Attempt23 operator tree: `entry_count=26`, `manifest_sha256=e20c4212ddb0f572a634e2efe499d8f5ac50a6a0f13e04d46f1b40c91493278f`
- Snapshot builder SHA-256: `00c90dd9feb9e068719a72ba29936cf5e5c9c70f198b526b04b1e66cfd271718`
- Cgroup launcher SHA-256: `c64daad1f663bf86f204b5ebdd5bbf5c0827e6524e28639f0937386258712296`
- Root controller SHA-256: `8f3da3404f6d86b07852fef066206a109252c5d6c8c28f5cb75bec2ba0d3857e`
- Authorizer SHA-256: `f67c16911f53419f09b204cd68869c2ab17bbdf18507bc528575225de73bd400`
- Guided wrapper SHA-256: `3eca12183c25015573c17c4f25cf45f35b2f8632ad93dcb448ad5114f66a3ee7`
- Short launcher SHA-256: `5dd1bb26ee348d780e7055eaf75283dec363f8b9ad896c3b1308a2fd860a6d85`
- Shell syntax and Python AST parsing: PASS
- Core `SHA256SUMS`: PASS (`9/9`)
- Operator regression suite with live host access: PASS (`64/64`)
- Production-shaped root-staging emulation: PASS. Root ownership, exact modes, all nine manifested bytes, VSCode helper, and root controller were independently restaged and reverified in a temporary user namespace.
- Installed shortcut `/home/tanzer/a23`: mode `0555`; byte-identical to the frozen launcher.
- GUI invocation check: expected fail-closed physical-TTY rejection; no Attempt23 evidence path was created.
- Stale Attempt21/Attempt22 identity scan: empty.
- Attempt23 authority, result, log, pre-controller, helper, snapshot, and evidence paths: absent and available.
- Source qualification inherited unchanged from `88e369b`: determinism regressions `56/56`, workflow regressions `4/4`, full LLVM/Clang 20 package `1299/1299`, retained stress matrix `9 x 2`, receipt/checksum verification PASS.
- Independent agents were not used at the user's request. A separated primary-agent audit added the missing cross-hash and short-launcher regressions and re-ran all operator checks.

Physical TTY confirmation is the only remaining Attempt23 action. Run only `~/a23`; never rerun `~/a22`.
