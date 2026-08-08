## Rule quality dashboard

Reference: analyzer tree `7decb6b09ac2ee3c09a03bb37eebf17df71e97d5`, workflow run `31242561307`.

| Rule | Precision (base → head, Δ) | Recall (base → head, Δ) | F1 (base → head, Δ) | TP / FP | Misses A / M / O |
|---|---:|---:|---:|---:|---:|
| `null-deref` | 1.000 → 1.000 (+0.000) | 0.347 → 0.347 (+0.000) | 0.516 → 0.516 (+0.000) | 140 / 0 | 67 / 194 / 0 |
| `memory-leak` | 0.714 → 0.876 (+0.162) | 0.193 → 0.223 (+0.030) | 0.306 → 0.355 (+0.049) | 92 / 13 | 119 / 191 / 0 |
| `double-free` | 1.000 → 1.000 (+0.000) | 0.242 → 0.273 (+0.031) | 0.390 → 0.428 (+0.038) | 109 / 0 | 88 / 203 / 0 |
| `use-after-free` | 1.000 → 1.000 (+0.000) | 0.496 → 0.531 (+0.035) | 0.663 → 0.694 (+0.031) | 212 / 0 | 82 / 105 / 0 |
| `div-by-zero` | 1.000 → 1.000 (+0.000) | 0.108 → 0.108 (+0.000) | 0.195 → 0.195 (+0.000) | 43 / 0 | 36 / 81 / 239 |
| `int-overflow` | 1.000 → 1.000 (+0.000) | 0.052 → 0.057 (+0.005) | 0.100 → 0.108 (+0.008) | 23 / 0 | 80 / 119 / 179 |

Miss classes: **A** addressable, **M** engine/model gap, **O** intentionally out of scope.

Benchmark runtime: 188.030s; peak RSS: 133868 KiB.
