---
name: False positive
about: CodeSkeptic flagged code that is actually correct
title: "[FP] "
labels: false-positive
---

**The finding** (paste the console output *including the dataflow
trace* — the `->` lines; or attach the SARIF/HTML report):

```
```

**The code** (a minimal snippet if you can extract one; otherwise a
link/description of the flagged pattern):

```c
```

**Why it's actually correct** (the invariant the analyzer missed —
e.g. "the two guards are correlated", "ownership transfers to X"):

**Project vocabulary** (did you declare custom allocators /
fatal asserts / owning pointers? See `profiles/` — if the FP disappears
with a profile, tell us that too; the profile may be the fix):

**Version** (`codeskeptic --version`) and platform:

<!-- Every confirmed FP family becomes an engine feature with a pinned
regression test — this template exists because that pipeline works. -->
