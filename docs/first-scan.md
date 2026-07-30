# Your first scan on a real codebase

The first run on a mature C/C++ project surfaces a few well-known
families of findings. This is the map: recognise the family, apply the
lever. **Every lever below is precision — a fact you hand the analyzer,
not a mute button.** You are refining the proof, never hiding output;
that is why the findings that remain stay trustworthy.

## Start here: baseline

Adopting CodeSkeptic on an existing project? Snapshot today's findings
and gate only what's NEW, so you get PR-gating without triaging history
up front:

```
codeskeptic src/ --build-path build --baseline .codeskeptic-baseline.json
```

This is the single most important first move. Tune the families below
second — with a baseline in place, none of them block you meanwhile.
(Details: docs/usage.md#baseline-workflow.)

## The families and their levers

| You see a lot of… | It is this class | Do this |
|---|---|---|
| `null-deref` right after `assert(p)` | assert-family | Usually already silent — the engine recovers `assert` even when `NDEBUG` compiled it out. Custom spelling? `--assert-macros CHECK_PTR`. A macro that asserts a pointer IS null (`assert_null`)? `--negative-assert-macros`. |
| `null-deref` after a custom abort — `error()`, `panic()`, `Fatal()` | a fatal handler not marked `noreturn` | `--fatal-asserts error,panic` — tells the engine that path really does terminate. |
| `null-deref` on accessor results — `obj->get(id)->field` | accessor-nullability (the "assumption" class) | Honest **may** warnings: the accessor's summary says it can return null. Put a contract on it (`cs: ensures` — see CONTRACTS.md), or baseline. |
| `null-deref` after an unchecked `malloc`, used immediately | the embedded "alloc failure is fatal anyway" convention | A contract on your allocator (`cs: ensures` non-null), or baseline. |
| leak / double-free findings are **zero** on a wrapper-heavy codebase | the leak domain is blind to your wrappers | `--alloc-functions git__malloc,zmalloc --free-functions git__free` — turns the whole leak/UAF domain on. |
| a field-subject assert — `DEBUGASSERT(data->conn)` — doesn't silence its deref | a known v1 gap (member-subject recovery) | Baseline for now; the plain-variable and custom-abort cases above cover most of it. |

## Opt-in rules (silent unless you ask)

Some rules need you to declare your project's untrusted inputs — they
report nothing until you do:

```
# parsers: enables sign-conversion (CWE-195) + alloc-size-overflow
# (CWE-131) on lengths/counts read off the wire or a file
codeskeptic src/ --build-path build \
  --untrusted-int-sources read_u16,packet_len,tud_cdc_read
```

Provenance is never guessed — an ordinary length parameter stays silent;
only a value you declared untrusted, that can wrap or go negative into a
size, is reported.

## Reading a finding before deciding it's noise

- **Every finding carries a trace.** Follow it — allocated here, may be
  null here, dereferenced here — before calling it a false positive.
- **Severity tells you the claim.** `[error]` = definite on some path;
  `[warning]` = may. An honest "may" on an accessor is not the tool
  guessing — it is the tool declining to assume.
- **Want the shipped-build view instead?** `--no-assert-recovery`
  reports the code exactly as the `NDEBUG` build runs it, with no
  recovered assumptions at all.

## The short version

Baseline first, tune second. Each lever states a fact the compiler
already relies on — that a handler aborts, that a pointer is non-null,
that a wrapper allocates. You are not silencing the analyzer; you are
finishing the proof it started.
