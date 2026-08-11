# Phase 8.3 hosted qualification contract

Status: locked before implementation on 2026-08-10.

## Purpose and authority

This lane measures release-candidate recipes before the canonical real-world
factory accepts them. It is observational only. A qualification receipt is
never an accepted campaign receipt, never a blocking product verdict, and
never authority to update `scripts/realworld_manifest.json` without a later
locked implementation boundary and repeat evidence.

The only candidates are llama.cpp, shadPS4, and the production TensorFlow Lite
library surface required by Phase 8.3. Each candidate uses an immutable
40-hex upstream commit. Qualification may refine build flags and source roots
when a recorded hosted observation disproves a proposed recipe; it may not
replace a named project with an easier project or silently narrow a production
surface.

## File boundary

Qualification implementation is limited to:

- `.github/workflows/phase83-qualification.yml`;
- `scripts/phase83_qualification.py`;
- `scripts/phase83_candidates.json`;
- `tests/Phase83QualificationTest.py` and its CTest registration;
- this contract and the canonical TODO/changelog status records.

The canonical manifest, campaign runner, expected ledger, production workflow,
analyzer source, grammar, and accepted contract semantics stay unchanged until
qualification is complete and the Phase 8.3 implementation boundary is locked.

## Input contract

1. The candidate document has a closed schema and exactly the three named
   candidates. Repository URLs are exact GitHub HTTPS clone URLs and revisions
   are immutable commits.
2. Commands are token arrays. No shell command string, script interpreter,
   command substitution, environment placeholder, or executable outside the
   existing CMake command family is admitted.
3. Paths and source roots are repository-relative and cannot escape their
   declared roots. Translation units are the exact intersection of the real
   compile database and the named Ninja production target's command closure;
   configured-but-unbuilt sources and dependency sources are excluded. There
   is no fallback glob.
4. shadPS4 alone may request recursive submodules. Every recursive submodule
   must be initialized at the superproject-pinned gitlink revision. The receipt
   records a canonical path/revision list, count, and SHA-256 identity. Checkout
   permits HTTPS transport only.
5. Candidate builds and scans use at most two build jobs, a per-candidate
   deadline, and the declared process address-space ceiling.

## Output contract

1. Every invocation writes a JSON receipt and SHA-256 sidecar, including a
   fail-closed `unavailable` receipt when checkout, build, identity derivation,
   or analysis fails.
2. A successful observation binds the candidate recipe digest, checked-out
   revision, analyzer SHA-256, submodule identity, exact sorted translation-unit
   count and digest, complete analyzer coverage, exit classification, finding
   count, ordered fingerprints, and fingerprint digest.
3. `observed` requires analyzer exit 0 or 1, a complete report, attempted TU
   count equal to the derived TU count, zero broken TUs, zero incomplete
   functions, and internally consistent finding fingerprints. Anything else is
   `unavailable` and cannot seed a factory expectation.
4. Logs, TU lists, reports, receipts, and sidecars are uploaded even when the
   observation is unavailable. The hosted workflow has read-only repository
   permission, no secrets, no `continue-on-error`, and no privileged event.
5. One observation is insufficient for acceptance. The canonical factory still
   requires the later locked expectations and three independent identical
   semantic receipts.

## Contract-first shadow report

No C++ function is created or materially changed in this qualification slice,
so contract-first shadow dogfood is not applicable. Functions considered: 0;
proposals: 0; eligible: 0; rejected: 0; unsupported: 0. No `cs: ai` proposal can
become accepted intent. Native pointer and owned-memory parity remain deferred
to executable A7 fixtures.
