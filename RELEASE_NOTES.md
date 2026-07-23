# CodeSkeptic v0.4.7 — two engine slices: untrusted lengths reach the bounds rule, zeroness flows through wrapper chains

The first engine-capability release since the v0.4.3 false-positive
round (v0.4.4–v0.4.6 were trust-chain, platform and correctness-of-
delivery work). Two long-deferred slices land, both recall moves with
the precision story pinned in CI.

## Untrusted length -> possible buffer overflow (CWE-120)

The engine's declared untrusted-integer sources — the `atoi`/`strtol`
family, `scanf`-filled outputs, and your project's own
`--untrusted-int-sources` functions (wire lengths, packet fields) —
now feed the sized-copy check. When a `memcpy`/`memmove`/`memset`/
`strncpy` length *derives* from such a source and its proven finite
range can exceed the destination's capacity, that is reported as a
possible buffer overflow. Reachability is by construction: the source
contract says external input picks the value.

The proof doctrine is unchanged on both sides of the line:

- a guard (`if (len <= sizeof(buf))`) narrows the range on its own
  edge and silences the warning;
- an unknown length (no declared source) never reports — provenance
  is opt-in, never guessed, so ordinary size parameters stay silent;
- a width-bounded `%2d` keeps its narrowed range and warns only
  against a destination it can actually exceed.

`strncpy` also joins the definite arm: it pads to exactly `n` bytes,
so a constant `n` past the capacity is a definite overflow (CWE-787),
same as `memcpy`.

## Zeroness through wrapper chains (div-by-zero recall)

`int id(int x) { return x; }` used to erase what the analyzer knew
about `x`: `r = id(d); 100 / r` lost `d`'s possibly-zero state at the
call boundary. Function summaries now carry a zero-passthrough claim —
"the result is zero only if argument #k is zero" — harvested when
every return path is either proven never-zero or returns an unmodified
parameter. Consumption flows the argument's state through the call
(`r = id(d)` behaves exactly like `r = d`), chains compose across
hops, and guards on the result refine as usual.

Width discipline guards both directions: any narrowing conversion in
the chain blocks the claim, because a truncated nonzero can become
zero — which would otherwise fabricate a warning or, worse, silently
suppress a real one.

## The honest numbers

- libgit2 v1.9.0 (201 files): **34 findings — identical** to the
  documented v0.4.3 core; the new arms produced zero new reports on
  real C.
- rtp2httpd: **0**, Catch2 deep corpus: **0**.
- NIST Juliet: every gated floor holds (CWE369/190/476/415/416 at
  sampled rprecision 1.000; CWE401 0.714 ≥ its 0.68 floor). The
  CWE369 sampled hitrate did NOT move (0.108): Juliet's remaining
  misses there are function-pointer and multi-hop-parameter shapes,
  not identity wrappers — the passthrough gain lives in real-world
  wrapper code and in the 22 new pinned tests, and we report it that
  way rather than claiming a benchmark bump.
- 717 unit tests (Linux; the Windows lane runs the same suite minus
  one Linux-only case), thesis gate 0 FP / 9-of-9 in scope.

## Summary file format v4

Persisted cross-run summaries gain the zero-passthrough column;
v1–v3 files load unchanged (the claim defaults to absent).

No platform or packaging changes — the v0.4.5 native Windows zip, the
v0.4.6 macOS SDK resolution and fail-loud exit policy, and the
checksum-verified GitHub Action all carry forward unchanged.
