# Idiom profiles

**Idioms are configuration, not code.** Every real codebase has its own
allocation vocabulary (wrapper allocators, owning smart pointers), its
own fatal-assert handlers, its own untrusted-input sources — and the
analysis only sees the code the way the project means it once that
vocabulary is declared. These profiles are the exact configurations
used in the [real-world scans](../README.md#proven-on-real-code); each
one doubles as documentation of what the analyzer understood about
that codebase.

Use one directly:

```bash
cp profiles/libgit2.conf .codeskeptic.conf
codeskeptic src/ --build-path build
```

or read it as a worked example when writing your own project's
`.codeskeptic.conf` (key reference: [docs/usage.md](../docs/usage.md)).

Every profile is format-checked in CI (`scripts/check_profiles.sh`):
keys must be ones `Config` actually parses — a silently-ignored key in
a shipped example would be worse than none.

| Profile | Project | What it declares |
|---------|---------|------------------|
| `libgit2.conf` | libgit2 | `git__*` allocator family |
| `fprime.conf` | NASA fprime | F´'s `SwAssert` handler (10 → 0 findings) |
| `joltphysics.conf` | JoltPhysics | custom aligned allocators + `Ref` owning pointers |
| `imgui.conf` | Dear ImGui | `MemAlloc`/`MemFree` wrappers |
| `carbon.conf` | carbon-lang | `CHECK`'s non-returning fail handler |
| `redis.conf` | Redis | `zmalloc` family (idiom round 2 in progress) |
| `systemd.conf` | systemd | mostly engine-native (cleanup attributes) — see comments |
