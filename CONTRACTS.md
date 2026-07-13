# ZeroDefect Contracts — Design Specification (v1)

Status: AGREED (co-design session 2026-07-13). This document is the
spec the implementation is written against. Grammar and semantics
changes go through this file first.

## 1. Why

Every rule shipped so far hunts UNIVERSAL bugs (null dereference,
leaks, UB). The founding pain — "we said it was done, and the release
crashed anyway" — is about INTENT: the code silently stopped doing
what it was supposed to do. Contracts close that gap:

> The author (human or LLM) states intent next to the code;
> ZeroDefect verifies the code against the stated intent,
> deterministically, on every change.

The key architectural insight: **a contract is a declared function
summary.** The engine already INFERS summaries (return nullness,
zeroness, parameter effects) and already diffs them as contracts
(`--summary-diff`, WEAKENED = CI gate). Contracts replace "inferred
vs inferred" with "declared vs inferred": the declaration pins the
intent, the dataflow engine checks the pin.

## 2. Surface syntax

### 2.1 Primary: structured line comments

```c
// zd: ensures return != null if n != 0
// zd: requires p != null
// zd: owns(cfg)
char *find_config(struct Cfg *cfg, const char *dir, size_t n);
```

- Works on every codebase (C89 included), no build-system impact,
  cheap for an LLM to emit next to the code it writes.
- One clause per line; multiple `zd:` lines may precede one function.
- Contract lines attach to the NEXT function declaration or
  definition; intervening blank lines and ordinary comments are
  allowed, but another declaration ends the attachment window.

### 2.2 Machine-proposed contracts

```c
// zd:ai ensures return != null
```

`zd:ai` marks a contract proposed by a tool/LLM but not yet adopted
by a human. Same grammar; different failure severity (§5).

There is deliberately NO `zd:trust` tag: the bare form already means
human-authored, and "trust(ed)" reads as "assume WITHOUT checking" in
analyzer vocabulary — the opposite of what we do.

### 2.3 Policies

```c
// zd:policy no-absolute-paths
```

Policies are pattern prohibitions (AST-level), not dataflow claims —
a different verification engine under a shared surface. The bare
`zd:` form is reserved for dataflow contracts (the overwhelmingly
common case pays no disambiguation tax); policies carry the explicit
`policy` tag. A policy comment at file top scopes to the file;
project-wide policies belong in the idiom profile
(`zerodefect.conf`, `policy = no-absolute-paths`), with file comments
usable for local additions.

### 2.4 Sidecar files (third-party code)

For code you cannot annotate, contracts live in a sidecar:
`src/core.c` → `src/core.c.zdc`. Entries are **explicitly anchored**
— every line names its function:

```
find_config: ensures return != null if n != 0
git_commit_create: requires repo != null
```

Anchors are function names (qualified for C++; an optional `/arity`
suffix disambiguates overloads: `push_back/2`). Order-based or
position-based mapping is forbidden by design: a silently shifted
mapping would attach guarantees to the wrong functions, and a wrong
assurance is worse than any missed finding.

### 2.5 Out of v1 (recorded, not promised)

- `[[zd::...]]` C++ attributes — possible future sugar over the same
  clauses.
- Compiler-integrated checking (a clang plugin surfacing findings at
  build time) — a distribution question (ROADMAP §4.C), not a syntax
  question.
- IDE affordances (accept/fix buttons for `zd:ai` proposals) — needs
  the deferred VS Code extension; v1 surfaces the same events through
  CLI/CI reports.

## 3. Grammar (v1)

```
contract-line := "zd:" [ "ai" ] clause
clause  := "requires" pred
         | "ensures" pred [ "if" pred ]
         | "owns" "(" param-name ")"
         | "borrows" "(" param-name ")"
         | "returns" "owned"
         | "policy" policy-name

pred    := or-expr
or-expr := and-expr { "||" and-expr }
and-expr:= unary { "&&" unary }
unary   := "!" unary | atom
atom    := "(" pred ")" | operand relop operand | operand
operand := "return" | param-name | integer-literal | "null"
relop   := "==" | "!=" | "<" | "<=" | ">" | ">="
```

Design notes:

- `ensures return != null` (not `returns nonnull`): one expression
  grammar serves pre- and postconditions; `return` is an ordinary
  operand. Same for zeroness: `ensures return != 0`.
- Ownership clauses (`owns`, `borrows`, `returns owned`) are EFFECT
  declarations, not value predicates — forcing them into the
  expression grammar would be artificial. They stay keyword forms and
  map onto the existing parameter-effect summary lattice
  (Frees/Stores vs ReadsOnly).
- The grammar is deliberately tiny (a dozen productions). It is
  parsed by a small hand-written recursive-descent parser inside the
  analyzer; the binding design constraint is not parser technology
  but §4: every construct must map onto the fact machinery.

## 4. Verifiable subset (v1) — honesty at the syntax boundary

A contract the engine cannot check is a false comfort. v1 enforces
the boundary explicitly:

- **Syntax error** in a `zd:` line → analyzer error (`contract-syntax`).
  Never silently skipped.
- **Parseable but outside the v1 checkable subset** → explicit
  diagnostic (`contract-unsupported`, warning): the contract is
  reported as NOT verified and otherwise ignored. Never silently
  treated as checked.

The v1 checkable subset, defined by what the dataflow engine can
prove today:

| Clause | Checked against | Notes |
|--------|-----------------|-------|
| `ensures return != null` / `== null` | return-nullness dataflow (per-path) | violation carries the offending return's trace |
| `ensures return != 0` / `== 0` | return-zeroness dataflow | integer returns |
| `ensures ... if <guard>` | per-disjunct return states | guard must be FACT-KEYABLE: parameter/enum/template-constant vs integer constant, `&&`/`||`/`!`, unsigned zero-identities — exactly `conditionFact`'s domain |
| `requires p != null` | (a) callee side: `p` seeds as NonNull — derefs of `p` stop warning, the contract carries the proof burden; (b) caller side: passing a maybe-null argument at a visible call site is a violation | |
| `requires <relational>` e.g. `p != null \|\| n == 0` | caller side, fact-keyable guards | the systemd/fprime assert shape, now as a declared contract |
| `owns(p)` / `borrows(p)` / `returns owned` | parameter-effect / return-ownership summaries | `owns` also suppresses caller-side leak reports for that argument |

Everything else (arithmetic between variables, `strlen(...)` calls in
predicates, quantifiers) is `contract-unsupported` in v1 and becomes
checkable only when the engine genuinely learns it (ROADMAP §4.B
explicitly ties the engine-evolution decision to what this table
needs next).

## 5. Failure semantics

| Event | Severity | CI effect |
|-------|----------|-----------|
| Declared (`zd:`) contract violated by the code | **error** | fails (exit 1) |
| Machine-proposed (`zd:ai`) contract violated | warning | reported, does not fail |
| `contract-syntax` (unparseable zd: line) | error | fails |
| `contract-unsupported` (outside v1 subset) | warning | reported |
| Inferred summary WEAKENED, no declared contract (`--summary-diff`) | configurable gate | default remains exit 1; projects may relax to warn during adoption |

Rationale (resolving the drift question): a violated DECLARED
contract must break CI — that friction is the product. The exit is
always explicit and always visible in the diff: either fix the code
or change the `zd:` line, and a changed `zd:` line in review IS the
audit trail of "intent changed deliberately". The softer
"don't block the team" instinct applies to the INFERRED layer
(summary-diff without declarations), where the gate becomes a
per-project choice instead of an absolute rule.

`zd:ai` is the adoption ramp: tools propose, humans promote a line to
bare `zd:` by deleting three characters — the cheapest possible
"reviewed and adopted" gesture.

## 6. Violation output (LLM self-repair fuel)

A contract finding always carries: the violated clause verbatim, the
contract's source location, the violating site, and the dataflow
trace showing the path (e.g. which return may be null and why). The
message format is designed to be pasted back into the model that
wrote the code:

```
core.c:41: error: contract violated: 'ensures return != null if n != 0'
  declared at core.c:37
  -> core.c:39: 'buf' assigned null here
  -> core.c:41: returned here on the n != 0 path (n > 0 recorded)
```

## 7. Implementation plan (each round = one PR, three referees green)

- **B — parser + unconditional postconditions**: comment scanner +
  clause parser + attachment; `ensures return != null / != 0` checked
  against the existing return dataflow; `zd:ai` severity split;
  `contract-syntax` / `contract-unsupported` diagnostics; tests.
- **C — preconditions**: `requires p != null` callee seeding +
  caller-side checking; relational `requires` (fact-keyable).
- **D — conditional postconditions + effects**: `ensures ... if g`
  per-disjunct checking; `owns/borrows/returns owned` vs the effect
  summaries.
- **E — policies + sidecars**: `zd:policy no-absolute-paths` as the
  first policy (the founding Ruledsl incident, immortalized); `.zdc`
  sidecar loading with anchored entries; profile-level policies.

Rule id: `contract` (one rule, clause carried in the message).
Message table entries appended per the i18n order invariant.
