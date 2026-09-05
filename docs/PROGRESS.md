# CodeSkeptic — PROGRESS

Yalnız bağımsız doğrulanmış yerel tamamlamalar; GitHub yayını veya release anlamına gelmez. Eski programın kayıtları referans arşivinde korunmuştur.

## CS3-CH01-S01-U003 — Checked-add overflow sonucunun kullanımını izle

- Commit: `da35862435e1991ae673e5a5053022eade6e347c`
- Dal: `agent/cs3-ch01-s01-u003-checked-add`
- Implementer: `root-cs3-ch01-s01-u003-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s01-u003-da35862-20260905`
- İnceleme SHA-256: `12af8cc2f84d537e9a419c3b7d5806009897a23a4cd980c888e1ab9094cd10c6`
- Tarih: 2026-09-05T00:44:00.157780+00:00
- Sonuç: Checked-add çağrısının başarısızlık sonucu yok sayıldığında güvensiz boyut kullanımı yakalanır.
- focused-tests: PASS; SHA-256 `eb08b1edace2bac91c96e096d1855b0519c20290d131e63c7b656fd7bc37133e`; `bash scripts/local_test.sh focused 'AllocSizeOverflowRuleTest.*:IntOverflowRuleTest.*:IntervalTest.*:IntervalAnalysisTest.*'`
- cli-smoke: PASS; SHA-256 `2d6cd22b2aaee34282b6b4907360acc65da71f1d03b6230ac7426123893401b0`; `PYTHONDONTWRITEBYTECODE=1 python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S01-U003/cli_smoke.py && bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `a39c62d003baca5278332e49c1cd77acc47c752353a69259a41fc68f01aa034b`; `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py check && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base 8a45e888765c9aa94982ee7f90e4d2cb069b61f9`

## CS3-CH01-S01-U002 — 64-bit allocation-size toplamayı denetle

- Commit: `a3fb412a19dfdc34e853fce7f6fc0e7c2c18c1d1`
- Dal: `agent/cs3-ch01-s01-u002-uint64-allocation-add`
- Implementer: `root-cs3-ch01-s01-u002-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s01-u002-a3fb412-20260905`
- İnceleme SHA-256: `bf3008ea32e9ae80f903152edfbf99ca19296b3e06823159c373aa11545175c7`
- Tarih: 2026-09-04T23:13:45.092195+00:00
- Sonuç: n+header gibi allocation boyutlarında unsigned sarma mevcut çarpım modeline eklenir.
- focused-tests: PASS; SHA-256 `b172ca3588ebafaf4855996f4d6e79354ce52af740c367741ce3ddd26c8fb1d3`; `bash scripts/local_test.sh build && bash scripts/local_test.sh focused 'AllocSizeOverflowRuleTest.*:IntOverflowRuleTest.*:IntervalTest.*:IntervalAnalysisTest.*'`
- cli-smoke: PASS; SHA-256 `6d512174c7cb3060dfce35913b39f8b2bf4dc68edf775c0316bdf0d80e39bbc9`; `PYTHONDONTWRITEBYTECODE=1 python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S01-U002/cli_smoke.py && bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `28d25eca46741baae51482f751501db7d40ed1038a138a506307c7a7fe2c21a3`; `PYTHONDONTWRITEBYTECODE=1 bash scripts/check_docs_sync.sh && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base 200054c898836137f9247676eb82beaf89393293`

## CS3-CH01-S01-U001 — 64-bit signed çıkarma taşmasını doğru hesapla

- Commit: `ae6ced3c2f1c4efba2a2208a7f1c288266f229f5`
- Dal: `agent/cs3-ch01-s01-u001-int64-subtraction`
- Implementer: `root-cs3-ch01-s01-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s01-u001-ae6ced3-20260905`
- İnceleme SHA-256: `e3a4af4a0d99f7567863dac1e7dda890bc9d851f31a8af7ed543151a7ae080b3`
- Tarih: 2026-09-04T22:20:38.489790+00:00
- Sonuç: Çıkarma toplama gibi hesaplanmaz; kanıtlanabilir 64-bit overflow/underflow doğru raporlanır.
- focused-tests: PASS; SHA-256 `1507cdc33967f09f93a280f10e3c1b703ff8118e6674ddc514f32611dfc87ae1`; `bash scripts/local_test.sh build && bash scripts/local_test.sh focused 'IntOverflowRuleTest.*:ReadmeCompareTest.DemoC_AtoiOverflow:UntrustedIntSourceTest.*:IntervalTest.*'`
- cli-smoke: PASS; SHA-256 `fee9031e76a57ddfd9f1a77b86c1e146cdaab1fc12f82996f5a39015fc88fecb`; `bash scripts/local_test.sh smoke && bash scripts/local_test.sh int64-smoke`
- queue-check: PASS; SHA-256 `b5050a02ffdbe6f4f57cf7c4c9084649bb40c9f740fac2a6d95eee6f397a8ddb`; `PYTHONDONTWRITEBYTECODE=1 bash scripts/check_docs_sync.sh && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base d6b266e9701984e7d276b8af8aeb90502f19dabf`

## CS3-CH00-S01-U001 — Main tabanlı kitabı ve çalışan FIFO/POP sistemini kur

- Commit: `977cdf84cb20a937cdf0bb41beabd283a44be5df`
- Dal: `governance/cwe-product-restart`
- Implementer: `root-cwe-restart-20260905`
- Bağımsız denetçi: `independent-cwe-bootstrap-verifier-977cdf8-20260905`
- İnceleme SHA-256: `2ca7e7f490370275b9da6bac4a8c546358f34dc4c7f3066d53af3d1b0059bad6`
- Tarih: 2026-09-04T22:08:22.440117+00:00
- Sonuç: Eski dallar referans olarak saklanır; bağımsız doğrulama olmadan kuyruk ilerleyemez.
- queue-tests: PASS; SHA-256 `58f9d4d60ffeb67d8d8601acb8e1480d97aced7512c4dc86645822db0549a83e`; `PYTHONDONTWRITEBYTECODE=1 python3 -B tests/test_project_queue.py && PYTHONDONTWRITEBYTECODE=1 python3 -B tests/StatusAutomationTest.py`
- queue-check: PASS; SHA-256 `8c876dc68cd1d0df6a7b248f008afd9fb01e7a3f41755dc2c44fa765ba2fa20f`; `PYTHONDONTWRITEBYTECODE=1 bash scripts/check_docs_sync.sh && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base 7dfd37596414c9512316093ff4fb6b039673f55f`
