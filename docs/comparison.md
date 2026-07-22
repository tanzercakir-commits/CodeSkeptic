# How does CodeSkeptic compare?

Three findings from [`demo.c`](demo.c) and [`custom.c`](custom.c), run
through the mainstream C/C++ tools. The interesting part isn't that
CodeSkeptic wins a row — it's that **no single mainstream tool catches
all three, and for the two null cases the good static analyzers disagree
with each other**:

| Finding | `-Wall -Wextra` | gcc `-fanalyzer` | clang `--analyze` | CodeSkeptic |
|---------|:---:|:---:|:---:|:---:|
| null-deref via `getenv` (a library contract) | — | — | ✅ | ✅ + trace |
| null-deref via your own null-returning function | — | ✅ | — | ✅ + trace |
| int-overflow from `atoi` | — | — | — | ✅ + trace |

Clang's analyzer models `getenv` as nullable but doesn't follow the
hand-written function; gcc's `-fanalyzer` does the exact opposite; the
everyday `-Wall -Wextra` warnings flag none of them. CodeSkeptic covers
the class — a library-contract source, an interprocedural custom return,
and the runtime overflow — each with a dataflow trace. This isn't
"nobody else can": it's that the everyday warning net has a real gap
here, and analyzer coverage is uneven — which is exactly the surface
CodeSkeptic is built for.

Note the `n * 4096` case: `gcc -O2 -Wall -Wextra -Woverflow` and
`clang -Winteger-overflow` are both silent, because `-Woverflow` only
fires on compile-time-*constant* overflow, not a value that arrives
from `atoi` at runtime.

<sub>Reproduced with gcc 13.3 and clang 18.1 on the two files above. MSVC
2022 (`/W4` and `/analyze`) and cppcheck 2.17 (`--enable=all`) were also
checked by hand on the `getenv` case and stayed silent.</sub>

## Positioning, honestly

CodeSkeptic is **precision-first**: it speaks only when the dataflow
proves something, so its recall is bounded by design. It is a
complementary layer, not a replacement — keep your compiler warnings,
sanitizers, clang static analyzer / `-fanalyzer`, CodeQL-style broad
analysis, fuzzing, and tests, and add CodeSkeptic where those are
weakest: low-noise, trace-backed gating of *new* changes (human or
AI-generated). The full "what it won't catch" list is in the
[README](../README.md#what-it-wont-catch); how to measure it on your
own code is in [evaluate.md](evaluate.md).
