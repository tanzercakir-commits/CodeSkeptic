# Feasibility: Typestate — protocol/ordering intent verification

Status: **feasibility report only** (no engine code). Decision gate at the
end. Written 2026-07-18 on `claude/typestate-feasibility`.

## 0. What this is and why now

The recall series (#92/#94/#95/#96/#97/#98) exhausted the tractable
*value* intents (null / zero / range / unbounded-copy). The remaining
real-world bugs — the ones surfaced by the bitcoin/VeraCrypt issue triage
and the thesis-v3 misses — are *ordering / lifecycle* intents:

- bitcoin #33940: an IPC object whose `destroy()` is never called.
- VeraCrypt #1819: a file lock never released.
- thesis-v3 m04/m08: use-after-free across a loop / function.
- The universal shapes: use-after-close, double-close, missing-close,
  "init before use", "lock before access".

These are not predicates over a value; they are **"the operations on this
object happened in a forbidden order (or a required one never happened)."**
The mathematical object for that is a **typestate**: a finite automaton
per tracked object.

This is the concrete, checkable form of the "intent verification" idea —
intent as a *protocol*, verified by the existing dataflow engine.

## 1. The load-bearing fact: we already ship a typestate

`src/rules/MemoryLeakRule_Ex.cpp` defines

```cpp
enum class AllocState { None, Allocated, Freed, Escaped };
```

and drives it over the shared `DataflowEngine` (worklist + fixpoint +
assume-edges + two-phase reporting). That IS a typestate automaton for
the heap-object protocol:

```
None ──alloc──▶ Allocated ──free──▶ Freed
                    │                  │
                  (end)              use / free   ⟹ leak / UAF / double-free
                    ▼                  ▼
                  LEAK              violation
        (Escaped = the object left our sight ⟹ ⊤, stay silent)
```

It is guarded today by the NIST Juliet floors **CWE401 (leak), CWE415
(double-free), CWE416 (use-after-free)** at rprecision **1.000** (see
`scripts/juliet_expected.txt`). So:

- The engine already supports a typestate lattice, precisely, at scale.
- The precision hazards of typestate — **aliasing, escape, conditional
  transitions** — are already handled for the memory protocol (the
  `Escaped` ⊤-state, the sole-definition discipline, guarded disjuncts).
- There is already a **ratchet** proving a typestate rule holds precision.

**Conclusion: this is a generalization of a proven, guarded mechanism —
not a new research bet.** That is the single most important feasibility
finding.

## 2. The formal object (what makes it programmable)

A protocol P is a finite automaton `(Q, Σ, δ, q0, F)`:

- `Q`: object states (`Unopened, Open, Closed`).
- `Σ`: the operations we recognize on the object (`open, use, close`).
- `δ: Q × Σ → Q ∪ {⊥}`. A transition **undefined** in δ is a *violation*
  (use-after-close, double-close).
- `q0`: initial state; `F`: accepting states an object MUST reach by
  end-of-scope (else *leak* / resource not released).

The analysis lattice per tracked object is `Q ∪ {⊤}` (⊤ = unknown /
escaped / aliased — the sound "give up" element). The engine hooks map
1:1 to what we already implement:

| Engine hook | Typestate meaning |
|---|---|
| `initialState` | every tracked object at `q0` (or ⊤ if it enters opaque) |
| `transfer(stmt)` | apply δ on the operation `stmt` performs; undefined δ → record a **violation** |
| `merge` (join) | states disagree on two paths → least-upper-bound (→ ⊤ unless equal) |
| `refineOnEdge` | a guard (`if (f)`, `if (fd >= 0)`) refines the state on that edge |
| `latticeHeight` | `|Q| + 1` (finite → convergence guaranteed) |
| `onStatement` | post-fixpoint: report forbidden transitions; report objects not in `F` at scope end |

Three-valued output falls straight out of the abstraction (already the
house style): **proven violation** (every path takes the forbidden
transition) = error; **possible** (some path) = warning; **⊤** =
unknown, silent.

## 3. Where the protocol (the intent) comes from — the three sources

Per the intent-verification discipline (extracted intent is a
*hypothesis*, never trusted as truth):

1. **Universal / built-in** — a small library of hard-coded protocols for
   std APIs whose contract is intrinsic and unambiguous:
   `FILE*` (`fopen`→use→`fclose`), POSIX fd (`open`→…→`close`),
   `pthread_mutex` (`lock`→`unlock`). No author input; always on. This is
   the direct analogue of `isIntrinsicNullSource` — key on the callee's
   contract, never on caller data.
2. **Declared** — the author (or the AI, via MCP) writes a protocol in a
   `.csk` sidecar (the CONTRACTS.md DSL already exists). This is where a
   *custom* object's lifecycle (the bitcoin `BlockTemplate`
   create/destroy) gets checked.
3. **Inferred-as-question** — names betray protocol roles
   (`Open`/`Close`/`Init`/`Shutdown`/`Acquire`/`Release`). The analyzer
   may PROPOSE a protocol from names, but only surfaces a violation as
   *"this looks like a use-after-close of a resource opened at L; is that
   the intended protocol?"* — never a hard bug. (This reuses the
   AssumptionRule #64 "where is this verified?" posture.)

v1 uses only source (1). Sources (2) and (3) are follow-ups that need no
new engine — only a new φ-source feeding the same verifier.

## 4. Minimal v1 scope (smallest real + guardable thing)

**Protocol: `FILE*` lifecycle.** `fopen`/`freopen`/`fdopen`/`tmpfile`
(already recognized as intrinsic null sources in #98) is the `open`; a
successful (non-null) result is `Open`; `fclose` is `close`; passing it
to `fread`/`fwrite`/`fgets`/`fprintf`/`fseek` is `use`.

Detected violations:
- **use-after-fclose** (CWE-416 shape on a FILE*).
- **double fclose** (CWE-415 shape).
- **missing fclose** on an owned handle at scope end (CWE-775 / CWE-404 —
  file-descriptor / resource leak).

Why `FILE*` first:
- Intrinsic source+sink (fopen/fclose) — no caller-dependence, same
  precision discipline as every recall rule we shipped.
- It is *structurally identical* to the existing heap-object typestate
  (open≈alloc, close≈free, use-after-close≈UAF), so v1 can be built by
  **generalizing `AllocState` to carry a protocol id**, reusing the leak
  rule's escape/alias handling wholesale — lowest-risk path.
- It maps to real NIST Juliet CWEs (CWE-775, CWE-404) → a ready-made
  guard corpus (see §5).

Explicitly **out of v1** (documented, deferred): custom `.csk` protocols
(source 2), name-inferred protocols (source 3), cross-function handle
ownership (needs a typestate summary — the interprocedural version),
alias sets beyond the sole-definition discipline.

## 5. Test & guard plan — the non-negotiable part

A new mechanism ships **with executable guards or not at all** (the
constitution). Concretely, before any `FILE*` typestate merges:

**(a) Unit pins** (gtest, shuffle-stable), mirroring the leak/UAF pins:
- `fopen`→`fread`→`fclose` → clean.
- `fclose` then `fread` → use-after-close **error**.
- `fclose` twice → double-close **error**.
- `fopen` then early-return without `fclose` → leak **warning**.
- conditional `if (f) fclose(f)` on all paths → clean (path-sensitivity).
- handle escapes to a callee (`register(f)`) → ⊤ → **silent** (the
  anti-FP contract).

**(b) A new Juliet floor** in `scripts/juliet_expected.txt`, gated in CI
exactly like CWE190 was:
- Add `CWE775_Missing_Release_of_File_Descriptor` (and/or CWE404) to the
  `CWES` array in `scripts/run_juliet.sh` and the `CWE_RULES` map in
  `scripts/juliet_eval.py`.
- Pin `rprecision`/`rhitrate` **from the measured sampled run**, with the
  same margin discipline (0.95 precision floor for a clean rule; a
  conservative recall floor that catches total collapse).
- **The existing five/six floors must stay green and fp=0** — especially
  CWE416/415/401, because a `FILE*` typestate must not perturb the heap
  typestate it shares machinery with.

**(c) Real-corpus FP gate**: cJSON / tinyxml2 pinned counts unchanged
(these do real `fopen`/`fclose` — the precision tripwire).

**(d) Determinism**: 12-seed gtest-shuffle stability, as standing.

**The floor IS the go/no-go instrument.** If the `FILE*` typestate cannot
clear a ≥0.95 precision floor on Juliet CWE775/404 without weakening any
existing floor, the increment is **shelved** — not merged with a lowered
bar. (This is the "ilerleyemezsek askıya alırız" clause, made executable.)

## 6. Honest risks & kill criteria

| Risk | Mitigation | Kill criterion |
|---|---|---|
| **Aliasing** — two vars, one handle; close via alias 1, use via alias 2 | Reuse the leak rule's sole-definition + escape discipline; unhandled alias → ⊤ (silent, not FP) | If real corpora show alias-driven FPs that ⊤ can't absorb → shelve |
| **Escape** — handle stored in a struct / returned / passed to opaque fn | `Escaped`/⊤ exactly as AllocState does today | (already tolerated by the shipped leak rule) |
| **Ownership ambiguity** — is this function the closer, or the caller? | v1: only intra-scope handles opened AND owned locally; escape → silent | If most real `fopen`s escape → recall ≈ 0 → the value case fails, shelve or pivot to declared-protocol |
| **`fdopen`/`freopen` aliasing a fd** | Treat conservatively (transition to ⊤) in v1 | n/a (silent is safe) |
| **General-protocol scope creep** | v1 is `FILE*` ONLY, structurally = heap typestate; the general declarable engine is a *separate* later gate | If v1 can't clear its floor, the general engine is moot |

## 7. Effort & phasing

- **Phase 0 (this doc):** feasibility. ✅
- **Phase 1 — `FILE*` typestate, built-in:** generalize the alloc
  typestate to a protocol id; add fopen/fclose/use recognition; unit
  pins; Juliet CWE775/404 floor; corpus gate. Estimate: comparable to one
  recall PR (#95/#96 scale). This is the real go/no-go.
- **Phase 2 — declarable protocols (`.csk`):** a protocol DSL over the
  existing contract parser; no engine change. Only if Phase 1 clears.
- **Phase 3 — name-inferred protocols (question-with-proof):** the
  AssumptionRule posture applied to protocols. Only if Phases 1–2 hold.
- **Phase 4 — interprocedural (typestate summaries):** cross-function
  ownership; the hardest, deferred until there is demand + a corpus.

## 8. Recommendation

**GO on Phase 1** (`FILE*` typestate, built-in), because:
1. It is a *generalization of a shipped, Juliet-guarded mechanism*, not a
   new bet — the precision hazards are already solved for the sibling
   heap protocol.
2. It has an intrinsic, caller-independent source+sink (fopen/fclose) —
   the same discipline that kept every recall rule at 1.000 precision.
3. It has a ready-made executable guard (Juliet CWE775/404) — the
   constitution's requirement is satisfiable up front.
4. It is the smallest step that makes "intent verification as protocol"
   real and measurable, and it directly targets a real bug class
   (resource-lifecycle) seen in the issue triage.

**Shelve** the moment Phase 1 cannot clear a ≥0.95 precision floor on its
CWE corpus without weakening an existing floor, or if real-corpus
measurement shows escape/aliasing FPs the ⊤ element cannot absorb.

The general declarable-protocol vision (Phases 2–4) is **not** approved by
this report — it is gated behind Phase 1's measured success.
