## Rule quality dashboard

Reference: analyzer tree `7decb6b09ac2ee3c09a03bb37eebf17df71e97d5`, workflow run `31242561307`.

| Rule | Precision (base → head, Δ) | Recall (base → head, Δ) | F1 (base → head, Δ) | TP / FP | Misses A / M / O |
|---|---:|---:|---:|---:|---:|
| `null-deref` | 1.000 → 1.000 (+0.000) | 0.347 → 0.349 (+0.002) | 0.516 → 0.518 (+0.002) | 163 / 0 | 80 / 222 / 0 |
| `memory-leak` | 0.714 → 0.862 (+0.148) | 0.193 → 0.251 (+0.058) | 0.306 → 0.389 (+0.083) | 417 / 67 | 438 / 760 / 0 |
| `double-free` | 1.000 → 1.000 (+0.000) | 0.242 → 0.303 (+0.061) | 0.390 → 0.465 (+0.075) | 425 / 0 | 280 / 697 / 0 |
| `use-after-free` | 1.000 → 1.000 (+0.000) | 0.496 → 0.528 (+0.032) | 0.663 → 0.691 (+0.028) | 236 / 0 | 92 / 119 / 0 |
| `div-by-zero` | 1.000 → 1.000 (+0.000) | 0.108 → 0.107 (-0.001) | 0.195 → 0.193 (-0.002) | 88 / 0 | 72 / 172 / 492 |
| `int-overflow` | 1.000 → 1.000 (+0.000) | 0.052 → 0.053 (+0.001) | 0.100 → 0.100 (+0.000) | 84 / 0 | 323 / 474 / 713 |

Miss classes: **A** addressable, **M** engine/model gap, **O** intentionally out of scope.

Benchmark runtime: 396.070s; peak RSS: 139560 KiB.
