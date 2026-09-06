# CodeSkeptic — PROGRESS

Yalnız bağımsız doğrulanmış yerel tamamlamalar; GitHub yayını veya release anlamına gelmez. Eski programın kayıtları referans arşivinde korunmuştur.

## CS3-CH04-S02-U003 — Checkpoint yalnız aynı geçerli analizi sürdürsün

- Commit: `8551582173200c13fbe6b935786b0c0ce141d6b3`
- Dal: `agent/cs3-ch04-s02-u003-checkpoint-resume`
- Implementer: `root-cwe-ch04-s02-u003-20260906`
- Bağımsız denetçi: `independent-cwe-ch04-s02-u003-composite-8551582-cache-exact-verifier-20260907`
- İnceleme SHA-256: `d2f0f1882d3695f5188416f986f00d4c8ff3090fa444141ac0f6492d47e21c1f`
- Tarih: 2026-09-06T22:28:33.344664+00:00
- Sonuç: Kesilen çalışma tam girdi kimliği doğrulandıktan sonra devam eder.
- linux-suite: PASS; SHA-256 `512f7bf2a508095a78d577675ace49d4dc4388bf73b58a7c7c28c3e58c86172f`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U003/qualify.sh b3ce9d8820edcb9c5804b30820e96acfeef8dae6`
- relevant-corpus: PASS; SHA-256 `2dcf072a96332c1e88df525c0df62d9e08482c71263df96e56a0aa37d70b1887`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U003/qualify.sh b3ce9d8820edcb9c5804b30820e96acfeef8dae6`
- queue-check: PASS; SHA-256 `835f636e5e3a069d751a91da90cb8bca1e13a66417c4b52cb9e36db2ffaaa028`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base b3ce9d8820edcb9c5804b30820e96acfeef8dae6 && bash scripts/check_docs_sync.sh && python3 -B scripts/check_capabilities_sync.py && git diff --check && git status --short --branch && git rev-parse HEAD main`
- artifact-equivalence: PASS; SHA-256 `8d8bd35c7e0946bf8d0d0b9c4c8480f06f9d319d3689293196356ebde1f6e44d`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U003/verify_ledger_artifact.py`
- cli-smoke: PASS; SHA-256 `ef422ca62075269d5ee1dad2ea172d280fd674a3df59a0c7578a8b5d67976be2`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U003/qualify.sh b3ce9d8820edcb9c5804b30820e96acfeef8dae6`

## CS3-CH04-S02-U002 — Cache yazımı ve saklama sınırını güvenli yap

- Commit: `481c19f079d3007df64151ce0e2254285dafedb1`
- Dal: `agent/cs3-ch04-s02-u002-cache-storage`
- Implementer: `root-cwe-ch04-s02-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch04-s02-u002-product-481c19f-cache-exact-verifier-20260906`
- İnceleme SHA-256: `6da2cdb626ec8360806944f8a74f9fcd9c1fee05441d168d463e28c8c330fa45`
- Tarih: 2026-09-06T20:34:33.804747+00:00
- Sonuç: Kısmi/bozuk/symlink kayıt kullanılmaz; disk kullanımı tanımlı tavanda kalır.
- linux-suite: PASS; SHA-256 `2dc9f47e063881c3a829d6877a16a3938f905db5fe7ff937d4d3de46d96dfbea`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U002/qualify.sh 481c19f079d3007df64151ce0e2254285dafedb1`
- relevant-corpus: PASS; SHA-256 `f2f04e56ddfe600263fbfe8661d7c4e828826e1e6eeb49766cb41294febbe5b0`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U002/qualify.sh 481c19f079d3007df64151ce0e2254285dafedb1`
- queue-check: PASS; SHA-256 `091f21ee8878ec1890b4c93b5f22648672b96aeb14bae03b98b78d971a11d3f9`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U002/qualify.sh 481c19f079d3007df64151ce0e2254285dafedb1`

## CS3-CH04-S02-U001 — Cache kimliğini gerçek girdilere bağla

- Commit: `490205087393f5a3c9215e9efda4ea48d0bcdad5`
- Dal: `agent/cs3-ch04-s02-u001-cache-identity`
- Implementer: `root-cwe-ch04-s02-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch04-s02-u001-product-4902050-cache-exact-verifier-20260906`
- İnceleme SHA-256: `4d2664bf768b99f3000f3c0314037c796176b43cc3773bae1e89934b108c383e`
- Tarih: 2026-09-06T19:34:47.329135+00:00
- Sonuç: Cache yalnız aynı araç/ayar/girdi/header bağımlılıkları için kullanılabilir.
- focused-tests: PASS; SHA-256 `da1313bc5cb38862be5566900d9e706c6dda6b578dbeadf8a6df8103cd98c80f`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U001/qualify.sh 490205087393f5a3c9215e9efda4ea48d0bcdad5`
- cli-smoke: PASS; SHA-256 `990fac6f6e6c1f5c8de1f838ca7a5b86824624bb06034d68ff89e188f112c986`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U001/qualify.sh 490205087393f5a3c9215e9efda4ea48d0bcdad5`
- queue-check: PASS; SHA-256 `6314ef412b3401459c07f507905cc7d3b2555c1a7bb59cec57eec6bec23d9538`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S02-U001/qualify.sh 490205087393f5a3c9215e9efda4ea48d0bcdad5`

## CS3-CH04-S01-U002 — Timeout/bellek/iptal bütçesini uygula

- Commit: `81f1d505854e57e4b222860d7a469db494326200`
- Dal: `agent/cs3-ch04-s01-u002-resource-budgets`
- Implementer: `root-cwe-ch04-s01-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch04-s01-u002-product-81f1d505-20260906`
- İnceleme SHA-256: `468487aee0dd24bc7f3f73dc9beda19c5e7c304b692f16cfec916112436ce2d9`
- Tarih: 2026-09-06T17:12:35.558702+00:00
- Sonuç: Kaynak bütçesi aşan worker sonlandırılır; süreç ve descriptor sızıntısı bırakılmaz.
- linux-suite: PASS; SHA-256 `3c9480bbf2b94ae0af3680e106322d84d1617af4672ca0b73ccfde1a6fc3d603`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U002/qualify.sh 81f1d505854e57e4b222860d7a469db494326200`
- relevant-corpus: PASS; SHA-256 `2dcf072a96332c1e88df525c0df62d9e08482c71263df96e56a0aa37d70b1887`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U002/qualify.sh 81f1d505854e57e4b222860d7a469db494326200`
- queue-check: PASS; SHA-256 `4f2efecadc7397deed831d0817c79ed7f33e05cc715632ec78de64853168d9cf`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U002/qualify.sh 81f1d505854e57e4b222860d7a469db494326200`
- resource-lifecycle-focused: PASS; SHA-256 `a3daf005965ee9c58f3099e640a066093ea64f5119e807b1d2601bd7d7b1f558`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U002/qualify.sh 81f1d505854e57e4b222860d7a469db494326200`
- cli-smoke: PASS; SHA-256 `801bf938848126844f74b4dbcadb2a935c0f5823d5b6d0d25c07f0e88a6ead23`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U002/qualify.sh 81f1d505854e57e4b222860d7a469db494326200`

## CS3-CH04-S01-U001 — Dosya başına taşınabilir worker protokolü kur

- Commit: `3e0627ecd3fa5740875456619e702403f377b4b5`
- Dal: `agent/cs3-ch04-s01-u001-worker-protocol`
- Implementer: `root-cwe-ch04-s01-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch04-s01-u001-product-3e0627e-20260906`
- İnceleme SHA-256: `58534a357b0dec5b30a2ae472f5186eb2c1a455499044321daf3f6da481dfbda`
- Tarih: 2026-09-06T16:22:19.370072+00:00
- Sonuç: Bir dosyanın çökmesi diğer dosyaların sonuçlarını kaybettirmez.
- linux-suite: PASS; SHA-256 `960e6c25dc85e853c060878b92b00218f0e81493d58a123a9abf1d1a0fa6e38b`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U001/qualify.sh 3e0627ecd3fa5740875456619e702403f377b4b5`
- relevant-corpus: PASS; SHA-256 `2dcf072a96332c1e88df525c0df62d9e08482c71263df96e56a0aa37d70b1887`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U001/qualify.sh 3e0627ecd3fa5740875456619e702403f377b4b5`
- queue-check: PASS; SHA-256 `59f0ccead4c09f9c2755e0cc096bc7115366aaf6b53e02e791f098688ae77cea`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U001/qualify.sh 3e0627ecd3fa5740875456619e702403f377b4b5`
- worker-and-reporter-regressions: PASS; SHA-256 `b12b342db8cfdb7fe56f70577fc4764e098db9f3e8b10488bed6195b66e6b560`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH04-S01-U001/qualify.sh 3e0627ecd3fa5740875456619e702403f377b4b5`

## CS3-CH03-S02-U002 — Minimal ilk tarama ve CI kullanımını doğrula

- Commit: `4e283ddea28a0f47c671f7a7d37baee37aa7fa56`
- Dal: `agent/cs3-ch03-s02-u002-first-scan`
- Implementer: `root-cwe-ch03-s02-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch03-s02-u002-product-4e283dd-20260906`
- İnceleme SHA-256: `4e5e8693a07ae346109efe718f80dc58b60611a6223cc01398537c0a4f330cf0`
- Tarih: 2026-09-06T15:20:05.704259+00:00
- Sonuç: Temiz bir örnek projede kurulmuş araçla ilk tarama ve rapor-only CI akışı tekrarlanır.
- focused-tests: PASS; SHA-256 `0357be461d1611c3c1fb988d6a2006a7b485bbe4a073b254ea8334f89ebeff0f`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U002/qualify.sh`
- cli-smoke: PASS; SHA-256 `53abaa221e86934690e3611c4aa6dd50df172b13b673c3209c34b5423f37f2e7`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U002/qualify.sh`
- queue-check: PASS; SHA-256 `0851f93f0b6cea990902124ec7b7fd357a7a95867f9162538d6a92b7c4111a90`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U002/qualify.sh`
- binary-provenance: PASS; SHA-256 `0e1d4cadf9e89bb403e62776891f9d82db1906c0c9fdaf83bec4f5cd6438eefe`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U002/qualify.sh`

## CS3-CH03-S02-U001 — Baseline/suppression ile yalnız yeni bulguyu ayır

- Commit: `3a222ffee8343d567318530c49ce27ba02b1ee98`
- Dal: `agent/cs3-ch03-s02-u001-baseline-suppression`
- Implementer: `root-cwe-ch03-s02-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch03-s02-u001-product-3a222ff-20260906`
- İnceleme SHA-256: `efc7ebfdf8fc030f5ad06604e5ab3b2298e0e3af453f066baacc0e4ace2cccba`
- Tarih: 2026-09-06T14:56:02.794058+00:00
- Sonuç: Yeni kod kontrolü legacy bulguları gizlice yeni veya yok sayılmış göstermeden çalışır.
- focused-tests: PASS; SHA-256 `8bbe39a3b2ea7ebcb01c6bebc636bc3de310ce8c60f890a7bcec363fe9ffc72a`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U001/qualify_final.sh`
- cli-smoke: PASS; SHA-256 `1e8049ba4e403ddfdb3f88c0c4cf7ac043b809da35065be84cfda3ae637829d3`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U001/qualify_final.sh`
- queue-check: PASS; SHA-256 `a85956e2226b895f34366d5d725f0ad226ee251fb2f67ec9c15f5072f0238a2c`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U001/qualify_final.sh`
- exact-version: PASS; SHA-256 `0bd23d5fbbbd062a63192cb74893adf6fcd4d77e155649b6f79f4d6fa250166d`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S02-U001/run_offline.sh /workspace/build/src/codeskeptic --version`

## CS3-CH03-S01-U002 — CLI/JSON/SARIF/HTML bulgu ve verdict tutarlılığını sabitle

- Commit: `184a30cdef4c33f4b70394d15fa771f823fd8c13`
- Dal: `agent/cs3-ch03-s01-u002-output-parity`
- Implementer: `root-cwe-ch03-s01-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch03-s01-u002-product-184a30c-20260906`
- İnceleme SHA-256: `0e560f735aaf5e4a8878a9cc480752a44fd04bfa2606588f91b769392b65a3fb`
- Tarih: 2026-09-06T13:37:42.878585+00:00
- Sonuç: Aynı analiz bütün çıktı yüzeylerinde aynı normalize bulguyu ve kapsamı verir.
- focused-tests: PASS; SHA-256 `9c630397496e25943cc6b9702f61ce47fbe0cd2b53c5841e3ac5971b1e2c724f`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U002/run_offline.sh /workspace/build/tests/codeskeptic_tests '--gtest_filter=JsonReporterTest.*:SarifReporterTest.*:HtmlReporterTest.*:OutputParityReporterTest.*:CapabilitiesTest.*:ConfigTest.*:ReportPathsTest.*:AnalysisResultTest.*'`
- cli-smoke: PASS; SHA-256 `fad153ac35cc4ce38023a12ac46558fc34c920376c8e4e9b1289f6a7d49c3b7f`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U002/complete_qualification.sh`
- queue-check: PASS; SHA-256 `8f031226c14f3095c98ac49f9793bbcd09c25c700c73f34d1de48a0ff4355bce`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; python3 -B scripts/check_capabilities_sync.py; git diff --check; test "$(git rev-parse HEAD)" = 184a30cdef4c33f4b70394d15fa771f823fd8c13; test -z "$(git status --porcelain)"`
- exact-version: PASS; SHA-256 `6687641b8adba6ee940dfdea66223711715e97d3781fcf57076078f0b156bb89`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U002/run_offline.sh /workspace/build/src/codeskeptic --version`

## CS3-CH03-S01-U001 — Kural ve CWE eşlemesini tek sözleşmede yayınla

- Commit: `160d8d8d5f0c1e0614c216f8a065d05c7c09cf79`
- Dal: `agent/cs3-ch03-s01-u001-rule-cwe-contract`
- Implementer: `root-cwe-ch03-s01-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch03-s01-u001-product-160d8d8-20260906`
- İnceleme SHA-256: `76e39369de3fb824bdcecdf577c63bdfddf16a810fcea5d94d32f1b5b9aeffd3`
- Tarih: 2026-09-06T12:48:33.951400+00:00
- Sonuç: Bulguların stable rule ID, doğru CWE ve açıklama bağlantısı vardır.
- focused-tests: PASS; SHA-256 `fda99d15e9b10e7b9a91f01c0b5e05c84d9be1cf29ebe76329cf75c1d14898b7`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/run_offline.sh /workspace/build/tests/codeskeptic_tests '--gtest_filter=BoundsRuleTest.*:IntOverflowRuleTest.*:SignConversionRuleTest.*:CapabilitiesTest.*:JsonReporterTest.*:SarifReporterTest.*:BaselineTest.*:MemoryLeakRuleExTest.*:PathSensitivityTest.*:AllocFunctionsTest.*:AllocatorPairTest.*:AliasLifetimeV2Test.*:ReallocLifetimeV2Test.*:SmartOwnerLifetimeV2Test.*:AbseilFpTest.*:AddrOfMemberTest.*:AliasEscapeTest.*:CallGuardTest.*:CarbonFpTest.*:CleanupAttrTest.*:DocumentedLimitTest.*:ExceptionalOwnerLifetimeV2Test.*:ExceptionalTransferBoundaryTest.*:FprimeFpTest.*:OwningPointerTest.*:ShadPS4FpTest.*:SystemdIdiomTest.*:FdResource*.*'`
- cli-smoke: PASS; SHA-256 `1488359e5f37c9b789b7af30a5972f01156d7cfb54c359f583852e853c8a3213`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/run_offline.sh python3 -B tests/CapabilitiesCliTest.py /workspace/build/src/codeskeptic`
- queue-check: PASS; SHA-256 `6fe9a27f63f5d034fe4afbe18ae33b6eb37fafbf4d02de52eb7ae341ea0e7d1b`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; python3 -B scripts/check_capabilities_sync.py; python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/check_metadata_registry_negatives.py /home/tanzer/Projects/CodeSkeptic; git diff --check`
- exact-version: PASS; SHA-256 `2f07019e1b9b71744683c3b3e22e5fb2ac701f6c4672d47dcaeeab3e393ff48a`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/run_offline.sh /workspace/build/src/codeskeptic --version`
- arithmetic-cli: PASS; SHA-256 `aeef16a1eff41b53773d10dc722330f59fd5a400e831e5458991f766f99431c8`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/run_offline.sh python3 -B /evidence/arithmetic_cli.py /workspace/build/src/codeskeptic /evidence/160d8d8d5f0c1e0614c216f8a065d05c7c09cf79/arithmetic`
- variant-metadata: PASS; SHA-256 `b0faa0a29d8cfa39f99be7a61f501b823cdae9ad4dfe8495bf5b61c36b5885d5`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/run_offline.sh python3 -B /evidence/variant_metadata_probe.py /workspace/build/src/codeskeptic /evidence/160d8d8d5f0c1e0614c216f8a065d05c7c09cf79/variants`
- lifetime-metadata-parity: PASS; SHA-256 `32eb8041bb5d5af7a23ebdf9ce838bb33b65e19b5190d8775d039bff9f8d9206`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/check_lifetime_metadata.py /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/160d8d8d5f0c1e0614c216f8a065d05c7c09cf79/lifetime/result.json /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/lifetime-red/result.json`
- leak-metadata: PASS; SHA-256 `e09178f7f46bf6c29f8da995058af724b6d50bc318878895e68b9ddb6fc65817`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/check_leak_metadata.py /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH03-S01-U001/160d8d8d5f0c1e0614c216f8a065d05c7c09cf79/leaks/result.json`

## CS3-CH02-S04-U001 — Compilation discovery için native LLVM/MSVC uyumluluğunu doğrula

- Commit: `94cb335ffc7a73509c64a98ee029f5f44c7322f0`
- Dal: `agent/cs3-ch02-s04-u001-native-compilation`
- Implementer: `primary-cwe-restart-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s04-u001-product-94cb335-20260906`
- İnceleme SHA-256: `b8dceebff92fe4db13eb60f6b2a968b00c5bbbf2af43337acf013d6ec8901dfe`
- Tarih: 2026-09-06T11:15:15.039366+00:00
- Sonuç: Mevcut Windows toolchain compilation discovery kodunu derler; komut kimliği doğrulaması ve ürün kapıları korunur.
- linux-suite: PASS; SHA-256 `4ac9049143423cb677412b0b0e365a7098ac51bd0ad760b6bd362252d2f80a35`; `bash scripts/local_test.sh full; exact-head qualification via bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S04-U001/verify_native_candidate.sh 94cb335ffc7a73509c64a98ee029f5f44c7322f0`
- compilation-database-cli: PASS; SHA-256 `275bab733506dd716c1366a2244ecf1db063bd6cd386398c125f1d455e448301`; `python3 -B tests/CompilationDatabaseCliTest.py /workspace/build/src/codeskeptic; bash scripts/local_test.sh smoke; exact-head stages of verify_native_candidate.sh 94cb335ffc7a73509c64a98ee029f5f44c7322f0`
- hosted-windows: PASS; SHA-256 `92887f0fa0ec4c427b95471e22f2b548d1f15709339a8aeed84fd0d93cb508ca`; `GitHub Actions Windows run 34028582912, windows-native job 101473882322: cmake --build build -- -k 0; ctest --test-dir build --output-on-failure; .\build\tests\codeskeptic_tests.exe; native smoke, SDK discovery, both package rehearsals and relocation smoke from exact-head .github/workflows/windows.yml. All required steps succeeded; the unchanged unreadable-directory fixture was explicitly skipped on Windows and passed on Linux.`
- hosted-windows-status: PASS; SHA-256 `76467b92c987e1128c34b9cef22b2f35fbf9aa1c2ec06422ea75462277834a9c`; `jq '{headSha,databaseId,status,conclusion,url,jobs:[.jobs[]|{name,databaseId,status,conclusion,steps}]}' windows-final.json; independently verify exact candidate and successful terminal required steps for run 34028582912`
- queue-check: PASS; SHA-256 `1b9ca795495970b7005d1700e7abf22b6800b5d68dcb6122153339f473707ea6`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; git diff --check; verify clean exact HEAD, task branch and unchanged main`
- hosted-linux: PASS; SHA-256 `e8198aadba240f68e6073988b6d40bbe8e17e97c325f757a5174a40b5b3fd1d1`; `GitHub Actions CI run 34028582902, build-and-test job 101473882108: ctest --test-dir build --output-on-failure; ./build/tests/codeskeptic_tests; native smoke; ./build/src/codeskeptic src/ --build-path build --policy no-absolute-paths --json /tmp/selfscan.json; bash scripts/run_corpus.sh ./build/src/codeskeptic /tmp/corpus; bash scripts/run_thesis.sh ./build/src/codeskeptic`
- hosted-linux-status: PASS; SHA-256 `ceb376ff2fdc2bc401e4cc84b40cc06264928837ec44ea578d28fb1ce6e44783`; `jq '{headSha,headBranch,databaseId,status,conclusion,event,url,jobs}' linux-hosted-final.json; independently verify exact candidate and successful terminal required steps for run 34028582902`
- corpus-same-input: PASS; SHA-256 `5fd326ce4a986751468a82d22e3a18113bd5e0506bdd2e264c54d76ad8b6b5cf`; `python3 -B /evidence/compare_diagnostic_corpus.py candidate-94cb335ffc7a73509c64a98ee029f5f44c7322f0 /workspace/build/src/codeskeptic; independent raw-report multiset, source-identity, summary-delta and 497 frozen-input hash inspection`
- hosted-juliet: PASS; SHA-256 `5283a2130e17b5fbcaa9947d190d2c4bb1917a6aecdab26ceaa402a5b45ddbb9`; `GitHub Actions Juliet run 34028582866: python3 scripts/juliet_eval.py --selftest; bash scripts/run_juliet.sh ./build/src/codeskeptic juliet-work 400; python3 scripts/render_quality_dashboard.py --juliet-output juliet-output.txt --baseline scripts/measurement_baseline.json --time-output juliet-time.txt --json-output juliet-dashboard.json --markdown-output juliet-dashboard.md. Push-time gates only; scheduled deep corpus was skipped and is not claimed.`

## CS3-CH02-S03-U002 — Frontend ve CFG düşmanca geçerli girdilerde sonlansın

- Commit: `5cfa9022f9aafc8d07c22a6f3f2fb06232e8c423`
- Dal: `agent/cs3-ch02-s03-u002-frontend-cfg`
- Implementer: `root-cs3-ch02-s03-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s03-u002-product-5cfa902-20260906`
- İnceleme SHA-256: `1d12e3c3ea52ba885fc29c5c7ac8c7649486a7990ff6a89ff914bd944013f8cb`
- Tarih: 2026-09-06T08:48:47.830059+00:00
- Sonuç: Template/macro/CFG köşeleri crash/hang yerine sınırları belirli sonuç verir.
- build: PASS; SHA-256 `709da6b9723d1a0fef59f7f98e930d75f34457d4af1344c0abfa2bb0da52e01c`; `bash scripts/local_test.sh build`
- linux-suite: PASS; SHA-256 `7fad23b66aa00e940fba839d5cba73dac89f72bd9350ec4109c4c22d6d904fa7`; `bash scripts/local_test.sh full`
- relevant-corpus: PASS; SHA-256 `76c8e66d1b9bb853878750c4fb8a78a9ada2db326f3388773289853509d0d601`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S03-U002/verify_frontend_candidate.sh 5cfa9022f9aafc8d07c22a6f3f2fb06232e8c423`
- queue-check: PASS; SHA-256 `19a4d39a89069f131373c867cfe37d2863a77f4a74ecabf92bbbdbe9dc22a433`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base HEAD^ && bash scripts/check_docs_sync.sh && git diff --check`

## CS3-CH02-S03-U001 — İstenen/analiz edilen/atlanan/başarısız dosyaları uzlaştır

- Commit: `36b332cf7f5fa0bcc37429fcca92278e112dcbfc`
- Dal: `agent/cs3-ch02-s03-u001-coverage-reconciliation`
- Implementer: `root-cs3-ch02-s03-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s03-u001-product-36b332c-20260906`
- İnceleme SHA-256: `7abc6a99f3717375859afbb3f3966505ba89ca5ecdcbaa7d20efa0b292bf6496`
- Tarih: 2026-09-06T08:01:47.811078+00:00
- Sonuç: Her istenen kaynak tek kimlikle sonuç sınıfına ve gerekçeye sahip olur.
- build: PASS; SHA-256 `b297497743c66c1f0cc5d737380d8c384e2a726171fc461e546e41bbc7b7df92`; `bash scripts/local_test.sh build`
- focused-tests: PASS; SHA-256 `45f94b14e8b49fb8abe0748f4cbbb1a7dbe9085b00ebe405632cda931dc13f27`; `bash scripts/local_test.sh focused 'McpServerTest.*:SourceManagerTargetTest.*:ConfigTest.*:AnalysisResultTest.*:VerdictIntegrityTest.*:ExitPolicyTest.*:JsonReporterTest.*:SarifReporterTest.*:HtmlReporterTest.*:BrokenTuTest.*:CoverageReportTest.*' && python3 -B tests/RealworldCampaignTest.py && python3 -B tests/RegressionCheckpointTest.py`
- cli-smoke: PASS; SHA-256 `006128110605867ce84654a36a08a8bb60afe9a29f68139bd019cbc8d2b967b3`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S03-U001/run_coverage_cli.sh`
- queue-check: PASS; SHA-256 `f8ceb5f685d0202d327d417cf85f5e0114ab713730ac518b366d082ace86ca6f`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base HEAD^ && bash scripts/check_docs_sync.sh && git diff --check`

## CS3-CH02-S02-U002 — MCP istek zarfını ve yaşam döngüsünü sınırla

- Commit: `e9ec726d8a4b49a4eb5f0dd9cd5a6d2d237cffea`
- Dal: `agent/cs3-ch02-s02-u002-mcp-request-envelope`
- Implementer: `root-cs3-ch02-s02-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s02-u002-product-e9ec726-20260906`
- İnceleme SHA-256: `930ca08ae9c6dd8862c12b8c497d9332cb2823df74062b9df1fbec81d29e3d51`
- Tarih: 2026-09-06T06:12:51.860327+00:00
- Sonuç: Malformed JSON-RPC istekleri ve işlem hataları sunucuyu veya sonraki isteği bozmaz.
- build: PASS; SHA-256 `63ef5ec7db5848ed5d075c3c61bdbf1a5b4cd049ea5c3d38a37350ff2fe5e31c`; `bash scripts/local_test.sh build`
- focused-tests: PASS; SHA-256 `c9fb16a5455e10374e22b84260372b8e93c50f68cfdb33e1ab821870b4f30177`; `bash scripts/local_test.sh focused 'McpServerTest.*:ConfigTest.*:SourceManagerTest.*:SourceManagerTargetTest.*:BrokenTuTest.*:VerdictIntegrityTest.*:ParamIntervalsTest.*:ImmutableFlagsTest.*:FunctionFilterTest.*:PolicyTest.*:SummaryPersistTest.*:CfgCacheTest.*:AssertRecoveryTest.*:CoverageReportTest.*'`
- cli-smoke: PASS; SHA-256 `597cd3e126a9224dc4adb037d8f179cd0be641ce0ae02c30e0d36baac962e9e8`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S02-U002/verify_mcp_candidate.sh e9ec726d8a4b49a4eb5f0dd9cd5a6d2d237cffea`
- queue-check: PASS; SHA-256 `ff57c37570555bc1914bd601a60a5a0af97e009ebe68d89f365983c1da1601f4`; `bash /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH02-S02-U002/verify_mcp_candidate.sh e9ec726d8a4b49a4eb5f0dd9cd5a6d2d237cffea`
- numeric-id-oracle: PASS; SHA-256 `71a7feaba09aac19623f413631550d6c2f962a84b8436caf9e419a591bd2f2a2`; `python3 -B /evidence/numeric_cli_matrix.py /workspace/build/src/codeskeptic`

## CS3-CH02-S02-U001 — Fonksiyon özeti/model parser sınırlarını sağlamlaştır

- Commit: `574fa3158093782407118e93b36caa252c1be09e`
- Dal: `agent/cs3-ch02-s02-u001-summary-model-parser`
- Implementer: `root-cs3-ch02-s02-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s02-u001-574fa31-20260906`
- İnceleme SHA-256: `97f30d8eca4131882b3e9fcc959536e6c4afb8af7a021ad6ba6978c4c1d90dc8`
- Tarih: 2026-09-06T05:35:27.745596+00:00
- Sonuç: Bozuk, sürümü uyumsuz veya aşırı büyük özet/model dosyası güvenli reddedilir.
- focused-tests: PASS; SHA-256 `19f1f181bf9c2053b4c01956a63ea177b53455d984a50f0826528e85171358ee`; `bash scripts/local_test.sh focused '*Summary*:*Interproc*:*CrossTU*:*Contract*:*Sidecar*:*Policy*:*ConditionedNull*'; bounded rootless offline image 25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5: /usr/bin/ctest --test-dir /workspace/build -R '^SummaryPersistTest[.]Parser' --repeat until-fail:3 --parallel 2 --output-on-failure --no-tests=error; bash scripts/local_test.sh focused 'LibraryModelFileTest.*' (all terminal zero, same clean exact head)`
- cli-smoke: PASS; SHA-256 `0a873af0a492a1516c00cf639875d453e1166beb7b9b5d39e9be141ec520e149`; `Bounded rootless offline image 25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5, 2 CPUs, 6 GiB, timeout 180s: python3 -B /evidence/parser_cli_smoke.py /workspace/build/src/codeskeptic; bash scripts/local_test.sh smoke (set -e; exact-head version, 45 JSON analyses, 2 SARIF checks and 4 same-process MCP requests)`
- queue-check: PASS; SHA-256 `53ef652b90ce8bfd4f138dbac0d5cbaf1a021075e167f04d00afe82138d5bf23`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; git diff --check; git rev-parse HEAD main; git status --short --branch; assert clean HEAD 574fa3158093782407118e93b36caa252c1be09e and unchanged main 7dfd37596414c9512316093ff4fb6b039673f55f (set -e)`

## CS3-CH02-S01-U003 — Çoklu producer kural seçimini diagnostic ID ile tutarlı uygula

- Commit: `e108ce50cb8c3e99576b82daf2dad9365e833b72`
- Dal: `agent/cs3-ch02-s01-u003-diagnostic-selection`
- Implementer: `root-cs3-ch02-s01-u003-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s01-u003-e108ce5-20260906`
- İnceleme SHA-256: `70265fd2b56cbdbce480966165e3f63bb7bdc28eae6b2ed88f58840cc74c6bff`
- Tarih: 2026-09-05T23:59:53.454408+00:00
- Sonuç: Kural kapatma işlemi yalnız sınıf adını değil yayımlanan diagnostic ID sözleşmesini bütün ilgili producer'larda uygular.
- focused-tests: PASS; SHA-256 `7872bda9c9501d17a1214f94cf6fb0f7bdbae5b56c441d0058e0405c9eecbf4c`; `bash scripts/local_test.sh focused 'ConfigTest.*:McpServerTest.*:CapabilitiesTest.*:VerdictIntegrityTest.*:AnalysisResultTest.*:FdResourceRuleTest.*:MemoryLeakRuleExTest.*:SourceManagerTargetTest.*:ReportPathsTest.*:FunctionFilterTest.*:BrokenTuTest.*'`
- cli-smoke: PASS; SHA-256 `3174c6a95817f9324e8f2882ee386559f8aa77385bb2f7e39db212e7a892adb4`; `Bounded rootless offline image 25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5 with read-only source/build and CS3-CH02-S01-U002 evidence mounted at /evidence: /workspace/build/src/codeskeptic --version; python3 -B tests/CapabilitiesCliTest.py /workspace/build/src/codeskeptic; python3 -B tests/CompilationDatabaseCliTest.py /workspace/build/src/codeskeptic; python3 -B /evidence/input_cli_smoke.py /workspace/build/src/codeskeptic (set -e, timeout 180s, 2 CPUs, 6 GiB); then bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `a6b32840649760bdff7723dbc21b0a620ab07f72db7bdd78ca4a35657ed61650`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; git diff --check; git rev-parse HEAD; git status --short --branch; git rev-parse main (set -e)`

## CS3-CH02-S01-U002 — Config ve target-scope güncellemelerini işlemsel yap

- Commit: `464546bd478245e14c80984c5011524a79025e13`
- Dal: `agent/cs3-ch02-s01-u002-transactional-config`
- Implementer: `root-cs3-ch02-s01-u002-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s01-u002-464546b-20260906`
- İnceleme SHA-256: `b266abcb3834bb82176801f0e5a7e4d41e5acf823517d0cc2421f08bb35eafe2`
- Tarih: 2026-09-05T23:18:03.129792+00:00
- Sonuç: Geçersiz config/scope girdisi önceki geçerli durumu kısmen değiştirmez.
- focused-tests: PASS; SHA-256 `96eaef52de33139d5be74e6b99f023eb4ddafc46b899b6dff2eccc9baaca0bd2`; `bash scripts/local_test.sh focused 'ConfigTest.*:SourceManagerTargetTest.*:McpServerTest.*:ReportPathsTest.*:FunctionFilterTest.*:BrokenTuTest.*:VerdictIntegrityTest.*'`
- cli-smoke: PASS; SHA-256 `1e5e98603942173179634fdf6fbda2ca606f8cf660652818372fc196996b9d81`; `Bounded rootless offline exact-head binary: codeskeptic --version; python3 -B tests/CompilationDatabaseCliTest.py <binary>; retained CS3-CH02-S01-U002/input_cli_smoke.py <binary> for 11 exact CLI/MCP error pairs and same-process valid-invalid-valid isolation; bash scripts/local_test.sh smoke.`
- queue-check: PASS; SHA-256 `f147a4a24beffe72306c51082891bef48abb8fe1bde794b28c41d69bf37f5f7f`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; git diff --check; git rev-parse HEAD; git status --short --branch`

## CS3-CH02-S01-U001 — Compilation database keşfi ve doctor komutunu yeniden uygula

- Commit: `9bb1b1983a0e1849313f3df9d443f9d7c2fe1a67`
- Dal: `agent/cs3-ch02-s01-u001-compilation-database-doctor`
- Implementer: `root-cs3-ch02-s01-u001-20260906`
- Bağımsız denetçi: `independent-cwe-ch02-s01-u001-9bb1b19-20260906`
- İnceleme SHA-256: `28e52b8283aa999e081868680a3230c17a5ef0c13456dbba830d58c84752de12`
- Tarih: 2026-09-05T22:27:14.427633+00:00
- Sonuç: Kullanıcı doğru database'i veya düzeltilebilir açık hatayı görür.
- focused-tests: PASS; SHA-256 `d8eb4867cea1b83e9ceb699b58fe280832444eaa7a9fe5ed680434c45585e8db`; `bash scripts/local_test.sh focused 'ConfigTest.*:BrokenTuTest.*:VerdictIntegrityTest.*:McpServerTest.*:SummaryPersistTest.*:LibraryModelFileTest.*:ReturnAliasSummaryTest.*:FunctionPointerSummaryTest.*:AllocatorSizeSummaryTest.*'`
- cli-smoke: PASS; SHA-256 `5388ce2ffdb35d2db5922c09ac401ff6e609f0bebe0ae432fb152d45404d1a5e`; `Bounded rootless offline container image 25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5: /workspace/build/src/codeskeptic --version && python3 -B tests/CompilationDatabaseCliTest.py /workspace/build/src/codeskeptic; then bash scripts/local_test.sh smoke.`
- queue-check: PASS; SHA-256 `f9ba089c2685f2ad687a11f61b297ca8a7f8cf794097c44571c3fa70774e59bc`; `python3 -B tests/WorkflowPolicyTest.py; /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S07-U001/971d8c8/actionlint -shellcheck= -pyflakes= .github/workflows/windows.yml; python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; bash scripts/check_docs_sync.sh; git diff --check; git rev-parse HEAD; git status --short --branch`

## CS3-CH01-S07-U003 — İlk hosted regresyon checkpoint'ini gerçek exact-head kanıtıyla kapat

- Commit: `caa389100f6bc60f1736581c571dd2e3677790ed`
- Dal: `agent/cs3-ch01-s07-u003-hosted-qualification`
- Implementer: `root-cs3-ch01-s07-u003-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s07-u003-caa3891-20260906`
- İnceleme SHA-256: `518b8d2144b84efe3af101cb897034384f77a1d4a4059e87137083281e148b91`
- Tarih: 2026-09-05T21:29:01.898058+00:00
- Sonuç: Yeni kuyruk hattının eski ürün ve gerçek dünya kontrollerindeki durumu gerçek GitHub sonuçlarıyla doğrulanır; main entegrasyonu yapılmaz.
- hosted-regressions: PASS; SHA-256 `77290be2eef9491a18461f44bf9a62d3e3a064ca610106d6be76585660aa062c`; `Independent audit of direct GitHub run/attempt job evidence: Linux 33991053139, Windows 33991053177, Juliet 33991053103, and raw-validated measurement 33991053122; attempt 1, exact caa389100f6bc60f1736581c571dd2e3677790ed; verify workflow identities and every required non-skipped step.`
- hosted-realworld-base-head: PASS; SHA-256 `abfa40567a9185f6758b6a50e7dfd7ecf9b4a8e849ee547c511a226e7fd234a3`; `python3 -B scripts/verify_regression_checkpoint.py with the retained realworld-run-33991053110-attempt-1-jedi_obk config/adjudications/context/run/jobs/catalog JSON and archives, --inputs-root /tmp/codeskeptic-checkpoint-inputs-pA9shQ/inputs; independently revalidate all 51 archive digests and all 48 raw shard reports against original base pins and exact reviewed head Counter deltas.`
- checkpoint-receipt-validation: PASS; SHA-256 `7e28479169f5c03c3f2d51fe32935c6980b3397aceef9f055de797764fa33a38`; `python3 -B scripts/verify_regression_checkpoint.py separately for measurement 33991053122/1 and realworld 33991053110/1, with exact retained --config --adjudications --context --run-json --jobs-json --catalog-json --archives and pinned --inputs-root; commands and byte-identical independently reproduced receipts are recorded in the evidence log.`
- queue-check: PASS; SHA-256 `30c553fff507b5bb253c542db4c6b1f6325df9c4e3d57ed7a9046e4ca5b2186a`; `python3 -B scripts/project_queue.py check; python3 -B scripts/project_queue.py guard --base HEAD^; git diff --check; verify clean exact HEAD caa389100f6bc60f1736581c571dd2e3677790ed.`

## CS3-CH01-S07-U002 — Exact base-head checkpoint ve kanıt doğrulayıcısını kur

- Commit: `b18ed2546f838f9d5ef6882a8fc1597420f6848d`
- Dal: `agent/cs3-ch01-s07-u002-regression-checkpoint`
- Implementer: `root-cs3-ch01-s07-u002-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s07-u002-b18ed25-20260905`
- İnceleme SHA-256: `ba5d296b8c2fb7fe8bf4280b531b0660a733390d032ab58a9f489b75ea24bf11`
- Tarih: 2026-09-05T18:41:47.077721+00:00
- Sonuç: Açıkça seçilen feature checkpoint'i sabit girdilerde kesin base/head analyzer sürümlerini karşılaştırır; eksik veya farklı kimlikte kanıt kabul edilmez.
- checkpoint-tests: PASS; SHA-256 `e557b04d0c9797188007e8e22f296b424230625c01bd6aabc347b630d21739c3`; `python3 -B tests/RegressionCheckpointTest.py && python3 -B tests/RealworldCampaignTest.py`
- workflow-validation: PASS; SHA-256 `24c465acc866198409ddb8e32b36495fcfb988a71aa35c39439e6eca45c11ac3`; `python3 -B tests/WorkflowPolicyTest.py && python3 -B tests/MeasurementWorkflowTest.py && /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S07-U001/971d8c8/actionlint -shellcheck= -pyflakes= .github/workflows/ci.yml .github/workflows/windows.yml .github/workflows/juliet.yml .github/workflows/measurement.yml .github/workflows/realworld.yml`
- linux-suite: PASS; SHA-256 `3a98b81bd0aab4b8865ad7b209098063234d7da96fd6634654a0defc32ed37ef`; `bash scripts/local_test.sh full`
- checkpoint-cli-smoke: PASS; SHA-256 `2b16f31414153cea1521f53c883fca66e2e99e9cd28a1eb0819c0d2cb62cbd43`; `timeout --signal=TERM --kill-after=10s 120s podman run --rm --pull=never --network=none --read-only --userns=keep-id --user "$(id -u):$(id -g)" --security-opt=label=disable --cap-drop=all --cpus=2 --memory=6g --pids-limit=256 --tmpfs /tmp:rw,size=1g -e PYTHONDONTWRITEBYTECODE=1 -e CODESKEPTIC_CHECKPOINT_BINARY=/workspace/build/src/codeskeptic -v /home/tanzer/Projects/CodeSkeptic:/workspace/src:ro -v /home/tanzer/Projects/CodeSkeptic/build/cwe-restart:/workspace/build:ro -w /workspace/src 25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5 python3 -B tests/RegressionCheckpointTest.py RealCliSliceTest`
- queue-check: PASS; SHA-256 `30d6475667b276337a8cc61e3ef20ab25f79eb3e52a76b95e08ffc2e37841867`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base 4a1626f4f809bb4261993b277bead6395719974b && python3 -B tests/test_project_queue.py && python3 -B tests/StatusAutomationTest.py && bash scripts/check_docs_sync.sh && git diff --check`

## CS3-CH01-S07-U001 — Mevcut CI kapılarını agent dalı push olayına bağla

- Commit: `971d8c85c7de059de35b663db467c02dbb057895`
- Dal: `agent/cs3-ch01-s07-u001-ci-push-wiring`
- Implementer: `root-cs3-ch01-s07-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s07-u001-971d8c8-20260905`
- İnceleme SHA-256: `6d77b378f978a38aac192f6659a754d0f6cc17bca1ff22241798d7fb7f79a661`
- Tarih: 2026-09-05T15:19:56.534113+00:00
- Sonuç: Yeni görev dalları mevcut Linux, Windows ve ilgili Juliet kontrollerini tetikleyebilir; FIFO yeşili ürün yeterliliğiyle karıştırılmaz.
- workflow-policy-tests: PASS; SHA-256 `92df9a24bf033ad7502589cb2289758db52027d4267c0cfcc16ceffd28923721`; `python3 -B tests/WorkflowPolicyTest.py`
- workflow-validation: PASS; SHA-256 `f6c24d79f4b9514df0b631ed0ac304a345f423a48d640c6529e7305c576aa4d6`; `/home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S07-U001/971d8c8/actionlint -shellcheck= -pyflakes= .github/workflows/ci.yml .github/workflows/windows.yml .github/workflows/juliet.yml && python3 -B tests/MeasurementWorkflowTest.py && python3 -B tests/ReleaseWorkflowTest.py && python3 -B tests/DockerWorkflowTest.py`
- queue-check: PASS; SHA-256 `ce2ca4274a15d0d68ea17a866abf3496f8ffc718f81d54a74f554a5a14b9aaa1`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base 67ae9204218176e003b56fe8f9553f9cb991d008 && python3 -B tests/test_project_queue.py && python3 -B tests/StatusAutomationTest.py && bash scripts/check_docs_sync.sh && git diff --check`

## CS3-CH01-S06-U003 — accept ailesinin wrapper sahipliğini ortak özette koru

- Commit: `aedcf460a0d81cd0b4ef9f44a728aa698c155573`
- Dal: `agent/cs3-ch01-s06-u003-accept-wrapper-summary`
- Implementer: `root-cs3-ch01-s06-u003-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s06-u003-aedcf46-20260905`
- İnceleme SHA-256: `3fbae45ffe4cef65fc69eb5db53b010b2b8ae1acbd4157ec4ff6123768f2bdb5`
- Tarih: 2026-09-05T14:09:42.710261+00:00
- Sonuç: accept/accept4 çağrısından dönen sahiplik ortak function summary üzerinden caller'a taşınır; wrapper arkasındaki sızıntı kaybolmaz.
- linux-suite: PASS; SHA-256 `6aa7887bf179da8611c263706048123751c79cfa35bb00f3a115e27eea4b4209`; `bash scripts/local_test.sh full`
- relevant-corpus: PASS; SHA-256 `f43c1f27216a10041bed5f46e8fb76d6cbb08fd826565d8b7754a6abddd7f07e`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S06-U003/corpus.py && python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S06-U003/observer.py`
- queue-check: PASS; SHA-256 `39ebbc132774353b0208758696f1d2564e99953c016e06b36891520b8df8928c`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base c61ae739`

## CS3-CH01-S06-U002 — Ortak integer literal ve guard çözümünde unsigned değeri koru

- Commit: `d1ddc8d64fb9f669af1ca82b0d76583307a097bc`
- Dal: `agent/cs3-ch01-s06-u002-unsigned-literal-guards`
- Implementer: `root-cs3-ch01-s06-u002-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s06-u002-d1ddc8d-20260905`
- İnceleme SHA-256: `7b0bbecafa8f234a93175eb76c68bbfeae5108099a25ce92598ac3aa0ed1a9f0`
- Tarih: 2026-09-05T12:36:03.928336+00:00
- Sonuç: Paylaşılan interval literal/guard çözümünde unsigned sabitin gerçek değeri korunur; sahte negatif değerle erişilebilirlik veya kapasite kanıtı üretilmez.
- linux-suite: PASS; SHA-256 `587dea6d0ca9ce7a34ae004bd5f774313b05ee457eef40d12c79f7122448377a`; `bash scripts/local_test.sh full`
- relevant-corpus: PASS; SHA-256 `91c270cc806f7f788a8e05c968d559d32b05937be326569069ebb1462d36ba63`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S06-U002/corpus.py`
- queue-check: PASS; SHA-256 `d4a384a4fad7ec40439f006b3f14651dc7c49b684cf3112721b9939ba31d41be`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base 0e27486`

## CS3-CH01-S06-U001 — uint64 out-param kaynak kökenini sayısal aralıktan ayır

- Commit: `c0b14253d08cb144f56e496f5dbd9d3fde73f450`
- Dal: `agent/cs3-ch01-s06-u001-uint64-outparam-origin`
- Implementer: `root-cs3-ch01-s06-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s06-u001-c0b1425-20260905`
- İnceleme SHA-256: `e833cb4ea6e281c2d242bb92080f10301814cbb1190aa059c0127d7dea623256`
- Tarih: 2026-09-05T10:32:09.269606+00:00
- Sonuç: Beyan edilmiş kaynağın doğrudan uint64 pointer/reference çıktısı, signed interval üst sınırı gösterilemiyor diye güvenilir kabul edilmez.
- linux-suite: PASS; SHA-256 `a172c66c1dcf609cdd839c4f9d3d3d235f8ba3a1066afca48c266dcfc0a3a62a`; `bash scripts/local_test.sh full`
- relevant-corpus: PASS; SHA-256 `aca79c3114775957b394aacb04fd6a4599207e29c16a8b2413d3db53c1b07af3`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S06-U001/corpus.py`
- queue-check: PASS; SHA-256 `48807a4102f5ee6e356a9920981a1225f14f56d954ddabbd12c90f447f88557b`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base d07f12d`
- independent-focused: PASS; SHA-256 `00af96f80c883b283d0887b823f09206fb519c0190a6b79212c5b1eb2c65578a`; `/workspace/build/tests/codeskeptic_tests --gtest_filter=AllocSizeOverflowRuleTest.*:IntOverflowRuleTest.*:SignConversionRuleTest.*:IntervalTest.*:IntervalAnalysisTest.*:UntrustedIntSourceTest.*`

## CS3-CH01-S05-U001 — Uzunluk ve index sink'lerinde kanıtlı narrowing kaybını raporla

- Commit: `8359ce4804ad04a7e13da69c84dbb2d4e2e3550f`
- Dal: `agent/cs3-ch01-s05-u001-narrowing-sinks`
- Implementer: `root-cs3-ch01-s05-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s05-u001-8359ce4-20260905`
- İnceleme SHA-256: `8932f49efcdac133fd499a13aab44486ca4554f2fab66fc85c736bf482e943d5`
- Tarih: 2026-09-05T06:37:56.883574+00:00
- Sonuç: Implicit sayısal daraltmada hedef türe sığmayan kanıtlı aralık sink'e bağlanır.
- focused-tests: PASS; SHA-256 `3fcd3aab9874425b7c5b38267650697a0f4f885b23861ffc4536198eb4092129`; `bash scripts/local_test.sh focused 'SignConversionRuleTest.*:IntOverflowRuleTest.*:IntervalTest.*:FunctionFilterTest.*:CapabilitiesTest.*'`
- cli-smoke: PASS; SHA-256 `696830334325284d642ee57ffcbbbb20ca0fdb9b1bfa60bb940223a5ef892e32`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S05-U001/cli_smoke.py`
- queue-check: PASS; SHA-256 `e4bdc57937d77036c0dc3a828c4c2dae5c023feea3d97f72289a3a8af6e096ff`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base c6832f90bf8f5b430ed99e581c302bcac7e743e1 && python3 -B scripts/check_capabilities_sync.py`
- generic-cli-smoke: PASS; SHA-256 `37d698d52c5bdd03030ed70c155b9afa3b1ad47e3d50bfcf70ed13554c90baa9`; `bash scripts/local_test.sh smoke`

## CS3-CH01-S04-U002 — pipe/pipe2 çift descriptor çıkışını modelle

- Commit: `7b94bd30c61ece2e3733351fb3898d841dbc3db1`
- Dal: `agent/cs3-ch01-s04-u002-pipe-ownership`
- Implementer: `root-cs3-ch01-s04-u002-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s04-u002-7b94bd3-20260905`
- İnceleme SHA-256: `b06baf2486a27d7aa9d349beaddf3983d9c46c8bc97fea0fe05bb0e90d005547`
- Tarih: 2026-09-05T05:45:46.291762+00:00
- Sonuç: Başarılı iki out-param descriptor bağımsız kaynak olarak izlenir.
- focused-tests: PASS; SHA-256 `321521fa73c6df4d9feb929c9b41d2d58c8d2a1438a9be11f88521e9fbaab652`; `bash scripts/local_test.sh focused 'FdResourceRuleTest.*:MemoryLeakRuleExTest.*:FunctionFilterTest.*:CapabilitiesTest.*'`
- cli-smoke: PASS; SHA-256 `ef7fbdc8f5ac358ef0a796c37a91f14ec690a5ed92640b502f9dc63bbec2a925`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S04-U002/cli_smoke.py`
- queue-check: PASS; SHA-256 `911fd457658aa0a5d7d838ef4ae62c6afa98ea390cd39b70b986d4e3e68230ea`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base 57d946b36376ba575308c1226421d937257a8d76 && python3 -B scripts/check_capabilities_sync.py`
- accept-regression: PASS; SHA-256 `b16fa89facdbb4394d41b8877f3d9c43ada86d798e515015341fdf65ee93d7d3`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S04-U001/cli_smoke.py`
- generic-cli-smoke: PASS; SHA-256 `37d698d52c5bdd03030ed70c155b9afa3b1ad47e3d50bfcf70ed13554c90baa9`; `bash scripts/local_test.sh smoke`

## CS3-CH01-S04-U001 — accept/accept4 descriptor sahipliğini modelle

- Commit: `6512d771063a830a39756efccaf6e077aca71f67`
- Dal: `agent/cs3-ch01-s04-u001-accept-ownership`
- Implementer: `root-cs3-ch01-s04-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s04-u001-6512d77-20260905`
- İnceleme SHA-256: `a6593431f3149b268daf122810af44106d13306220b9189cc983798af02771d0`
- Tarih: 2026-09-05T04:40:47.110254+00:00
- Sonuç: Başarılı accept ailesi çağrısından dönen descriptor için close/transfer/leak takibi yapılır.
- focused-tests: PASS; SHA-256 `ffd8c02a1e576992a4f319ff17f1344d972d80abfc7557205e0864a37f6d4ec6`; `bash scripts/local_test.sh focused 'FdResourceRuleTest.*:MemoryLeakRuleExTest.*:FunctionFilterTest.*:CapabilitiesTest.*'`
- cli-smoke: PASS; SHA-256 `71ce91eb0c20a771fb46b68dc676824840b0060f7ae31627c95a3eedf4d25e58`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S04-U001/cli_smoke.py`
- generic-cli-smoke: PASS; SHA-256 `37d698d52c5bdd03030ed70c155b9afa3b1ad47e3d50bfcf70ed13554c90baa9`; `bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `bc678359734e5677f7efed2bdb8c3f942b5b26b60912db46f883b62f4f85c244`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base 8ccf1d4c953da113b8a47cc270c517a2985f5a18 && python3 -B scripts/check_capabilities_sync.py`

## CS3-CH01-S03-U002 — Scalar initialization durumunu CFG birleşimlerinde koru

- Commit: `51a20952deae5ec9520d680d8312816c823a5b83`
- Dal: `agent/cs3-ch01-s03-u002-scalar-cfg-joins`
- Implementer: `root-cs3-ch01-s03-u002-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s03-u002-51a2095-20260905`
- İnceleme SHA-256: `f7e657c634b8cf8dcf9054fd7065a6c9889dc10d57a1d101d40316a8b57c76dd`
- Tarih: 2026-09-05T03:53:16.900897+00:00
- Sonuç: Branch/loop birleşimlerinde definitely-initialized ile possibly-uninitialized ayrılır.
- focused-tests: PASS; SHA-256 `48bbe8f1261b78eaba94487f3fde1fb9dedd182d2e3fb3f0109b9cac89fe5a41`; `bash scripts/local_test.sh focused 'UninitScalarRuleTest.*:UninitPointerRuleExTest.*:CapabilitiesTest.*:FunctionFilterTest.*:McpServerTest.*'`
- cli-smoke: PASS; SHA-256 `af96a43aeb3b75f8211ce3cd7dfed00cbc700e98d8ef90ae662bb386aa608d5a`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S03-U002/cli_smoke.py`
- queue-check: PASS; SHA-256 `4dc69f85bbb00e3cc72e6bbdeec3d404a10549b28f2377855bae5c340e77f3fd`; `python3 -B scripts/project_queue.py check && python3 -B scripts/project_queue.py guard --base bf03da4634a52d1e241b74c6708e1f0b1d52fb1e && python3 -B scripts/check_capabilities_sync.py`
- cli-u001-regression: PASS; SHA-256 `776622323623ba1a6ed9d346ba332bf1433ff7e7eb4729ffb56426fabf61c3a7`; `python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S03-U001/cli_smoke.py`
- generic-cli-smoke: PASS; SHA-256 `b0344728a94d7c433b70b506caa35bbfb15ff4b610968b541dbb12afbf1e20d3`; `bash scripts/local_test.sh smoke`

## CS3-CH01-S03-U001 — Yerel scalar uninitialized-read kuralını ekle

- Commit: `e637439dc55d42a4565e32afcad5023e57eb1806`
- Dal: `agent/cs3-ch01-s03-u001-uninitialized-scalars`
- Implementer: `root-cs3-ch01-s03-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s03-u001-e637439-20260905`
- İnceleme SHA-256: `dcb498109ca40aca7292b95100e3b0c874e08fa3049c9f2e933e25d6fe326600`
- Tarih: 2026-09-05T03:25:10.959412+00:00
- Sonuç: Yerel integer/bool değerinin atama öncesi gerçek okuması yeni experimental kimlikle raporlanır.
- focused-tests: PASS; SHA-256 `ef4ace77bff63f6443df9b0215166466cb2f09a31a8c589e4281a3e3dcbe42ca`; `bash scripts/local_test.sh focused 'UninitScalarRuleTest.*:UninitPointerRuleExTest.*:CapabilitiesTest.*:FunctionFilterTest.*:McpServerTest.*'`
- cli-smoke: PASS; SHA-256 `5c6bfa51e3d82ec6777a139e6e10e1914ad4420cb67825507e041f39470319cf`; `PYTHONDONTWRITEBYTECODE=1 python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S03-U001/cli_smoke.py && bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `996fbc28a011084502d8dab89b28f4c18bc135e9332fe3c3bcf9c1e8f46a00a5`; `PYTHONDONTWRITEBYTECODE=1 bash scripts/check_docs_sync.sh && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py check && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base 70710aa64f276f33d387c9dca98554506c652a08`

## CS3-CH01-S02-U002 — Sabit pointer-offset kalan kapasitesini izle

- Commit: `c32825c7873008fc1f38b4ff695590551a20fa7f`
- Dal: `agent/cs3-ch01-s02-u002-pointer-offsets`
- Implementer: `root-cs3-ch01-s02-u002-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s02-u002-c32825c-20260905`
- İnceleme SHA-256: `562591c08716a7f726cf4f22d8bb3fb5a74697d5912d876640b51e9cfc2f7d78`
- Tarih: 2026-09-05T02:36:36.742925+00:00
- Sonuç: buf+k ve &buf[k] için bilinen kalan kapasite okuma/yazma denetimine girer.
- focused-tests: PASS; SHA-256 `d6a389cb3125ad0667c9a977ee25e06187e8295ed969c48bfcf7e617af8acd4e`; `bash scripts/local_test.sh focused 'BoundsRuleTest.*:IntervalTest.*:IntervalAnalysisTest.*'`
- cli-smoke: PASS; SHA-256 `0b04ea31786085942a8758f8423f51beb5103e4d9181a6bf40c1de3a6e5cfbc4`; `PYTHONDONTWRITEBYTECODE=1 python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S02-U002/cli_smoke.py && bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `0133b1f864bcd86f617090ab62c1f296aa8d8a7c33e2460edcce450e4d4dce96`; `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py check && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base b9dd8de1c907e023f050d9c5a62fe245edbbdae1`

## CS3-CH01-S02-U001 — memcpy/memmove kaynak okuma kapasitesini denetle

- Commit: `0816619b14df12e3ee3d7398e91d7a4c2942b181`
- Dal: `agent/cs3-ch01-s02-u001-source-read-capacity`
- Implementer: `root-cs3-ch01-s02-u001-20260905`
- Bağımsız denetçi: `independent-cwe-ch01-s02-u001-0816619-20260905`
- İnceleme SHA-256: `7e95beba10776d5d00ffc94376e90a1b095f8fdbd11f480566e79bac91eb9a88`
- Tarih: 2026-09-05T01:31:38.388974+00:00
- Sonuç: Hedef yeterli olsa bile küçük kaynaktan taşan okuma CWE-125 olarak ayrılır.
- focused-tests: PASS; SHA-256 `125c5962cb20e80b51bf8c780e48cf5c5b0112ead89fc610e639bd5459a5eb9d`; `bash scripts/local_test.sh focused 'BoundsRuleTest.*:IntervalTest.*:IntervalAnalysisTest.*'`
- cli-smoke: PASS; SHA-256 `75f4711e89d8407e080777f743f2c0206edb70b54d654f8e49eafb5c47b1d578`; `PYTHONDONTWRITEBYTECODE=1 python3 -B /home/tanzer/.local/state/codeskeptic/cwe-restart-evidence/CS3-CH01-S02-U001/cli_smoke.py && bash scripts/local_test.sh smoke`
- queue-check: PASS; SHA-256 `62688908232d9bb24b9d9e5bae3e1d880b5b338c3005d8fcb3060650ac07e56a`; `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py check && PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/project_queue.py guard --base 4d0f53ac3224a78e377170c4e1a27ac1e2bcc4dc`

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
