## Rule quality dashboard

Reference: analyzer tree `7decb6b09ac2ee3c09a03bb37eebf17df71e97d5`, workflow run `31242561307`.

| Rule | Precision (base → head, Δ) | Recall (base → head, Δ) | F1 (base → head, Δ) | TP / FP | Misses A / M / O |
|---|---:|---:|---:|---:|---:|
| `null-deref` | 1.000 → 1.000 (+0.000) | 0.347 → 0.347 (+0.000) | 0.516 → 0.516 (+0.000) | 140 / 0 | 67 / 194 / 0 |
| `memory-leak` | 0.714 → 0.714 (+0.000) | 0.193 → 0.193 (+0.000) | 0.306 → 0.306 (+0.000) | 80 / 32 | 119 / 203 / 0 |
| `double-free` | 1.000 → 1.000 (+0.000) | 0.242 → 0.242 (+0.000) | 0.390 → 0.390 (+0.000) | 97 / 0 | 92 / 211 / 0 |
| `use-after-free` | 1.000 → 1.000 (+0.000) | 0.496 → 0.496 (+0.000) | 0.663 → 0.663 (+0.000) | 198 / 0 | 96 / 105 / 0 |
| `div-by-zero` | 1.000 → 1.000 (+0.000) | 0.108 → 0.108 (+0.000) | 0.195 → 0.195 (+0.000) | 43 / 0 | 36 / 81 / 239 |
| `int-overflow` | 1.000 → 1.000 (+0.000) | 0.052 → 0.052 (+0.000) | 0.100 → 0.100 (+0.000) | 21 / 0 | 82 / 119 / 179 |

Miss classes: **A** addressable, **M** engine/model gap, **O** intentionally out of scope.

Benchmark runtime: 96.360s; peak RSS: 110588 KiB.
