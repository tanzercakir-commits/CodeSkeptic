# CodeSkeptic — PROGRESS

Yalnız bağımsız doğrulanmış yerel tamamlamalar; GitHub yayını veya release anlamına gelmez. Eski programın kayıtları referans arşivinde korunmuştur.

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
