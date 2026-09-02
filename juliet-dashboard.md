## Rule quality dashboard

Reference: analyzer tree `7decb6b09ac2ee3c09a03bb37eebf17df71e97d5`, workflow run `31242561307`.

| Rule | Precision (base → head, Δ) | Recall (base → head, Δ) | F1 (base → head, Δ) | TP / FP | Misses A / M / O |
|---|---:|---:|---:|---:|---:|
| `null-deref` | 1.000 → 1.000 (+0.000) | 0.347 → 0.347 (+0.000) | 0.516 → 0.516 (+0.000) | 140 / 0 | 35 / 226 / 0 |
| `memory-leak` | 0.714 → 0.880 (+0.166) | 0.193 → 0.249 (+0.056) | 0.306 → 0.388 (+0.082) | 103 / 14 | 61 / 237 / 0 |
| `double-free` | 1.000 → 1.000 (+0.000) | 0.242 → 0.298 (+0.056) | 0.390 → 0.459 (+0.069) | 119 / 0 | 20 / 260 / 0 |
| `use-after-free` | 1.000 → 1.000 (+0.000) | 0.496 → 0.534 (+0.038) | 0.663 → 0.696 (+0.033) | 212 / 0 | 78 / 107 / 0 |
| `div-by-zero` | 1.000 → 1.000 (+0.000) | 0.108 → 0.108 (+0.000) | 0.195 → 0.195 (+0.000) | 43 / 0 | 10 / 105 / 239 |
| `int-overflow` | 1.000 → 1.000 (+0.000) | 0.052 → 0.057 (+0.005) | 0.100 → 0.108 (+0.008) | 23 / 0 | 56 / 143 / 179 |

Miss classes: **A** addressable, **M** engine/model gap, **O** intentionally out of scope.

Benchmark runtime: 322.380s; peak RSS: 128260 KiB.
