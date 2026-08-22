# V7 independent determinism confirmation

This bundle retains the first accepted independent confirmation against the
kernel-bound V7 baseline for
`fedora44-i5-1235u-exclusive-pcores-0-3`. The measured source is
`88e369b21675e64e0a92842b0ce22f0c8148745e` with source-manifest SHA-256
`b8c4b7235c1c8704304dd5fe4de90728e6cd0b4ab020526b76f1e4731b3e0d9b`.

## Qualification result

- `qualification/confirmation/receipt.json` is an accepted V7 receipt with
  an empty failure list.
- Unit, real-repository, and release-candidate workloads each completed ten
  outer repetitions. The unit workload retained ten inner invocations per
  outer repetition.
- All three semantic fingerprints match the pinned baseline. The semantic and
  performance gates both pass and the regression list is empty.
- The receipt retains 631 raw artifacts. Its SHA-256 is
  `a7d8409199a22a2896d8486e2e7d95674ba254bdb9c6df84da9746f2a3c096f9`.
- The self-excluded inner manifest contains 633 entries; the qualification
  stage manifest contains 636 entries. Both verify without error.
- The measured interval lasted `2670421` ms, from
  `2026-08-22T15:11:16.647198+00:00` through
  `2026-08-22T15:55:47.065151+00:00`.

## Host envelope and immutable erratum

The headless controller completed with payload exit `0`, cleanup failure `0`,
and a valid terminal receipt. The controller log contains both run and verify
qualification success markers. The transaction journal verifies against
SHA-256 `0fbf295b58009e7166652b57363fb08ba9a46dd30904f1de2f960246e898e163`.
The coredump inventory remained
`07e99c98540c0b6c24b099f8b88d2802b8f501737194bedaed888079fa6083b5`;
no system or user unit remained failed, and graphical, multi-user, and
Plasma-login targets were active after restoration.

The Attempt23 guided result remains immutable and records payload exit `2`
despite the accepted qualification and payload-`0` terminal receipt. Its
wrapper required the DrKonqi socket `NAccepted` counter to reset to exactly
zero after restoration. The controller's stricter, already-tested contract
correctly allowed either preservation of the journal value or a zero reset;
the retained controller trace records `previous=160 current=160`. No coredump
inventory change accompanied that preserved counter.

The retained Attempt24 erratum operator changes only that outer transition:
`160 -> 160` and `160 -> 0` pass, while `160 -> 161` remains rejected. The
new behavioral regression failed against the Attempt23 rule before the patch,
then passed after it. The complete corrected operator suite passed `65/65`,
and its production-shaped root-owned staging emulation passed. Attempt24 was
not physically rerun because the measured Attempt23 receipt, its independent
verification, all raw bytes, the payload-`0` terminal receipt, and cleanup
evidence were already complete and checksummed.

The Attempt24 operator is retained byte-for-byte as an audit record. Its
launchers intentionally pin the frozen build location where the `65/65` suite
ran, so the relocated copy is not presented as a directly runnable package.

`assessment.json` records the machine-readable distinction between the
accepted qualification payload and the guided-wrapper false negative. The
top-level `SHA256SUMS` binds every retained file except itself.
