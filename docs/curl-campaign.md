# curl Scan — status: PARKED (triage round reserved for fresh quota)

First scan: curl 8.11.0, `lib/` through its own CMake compile db
(2026-07-25, `probe-curl-expat` on the realworld-scan lane).

## The measurement (honest, distrust-verified)

```
project=curl v=8.11.0 findings=86 broken=0 processed=170 exit=1
```

`broken=0` over 170 TUs — this is REAL, complete coverage, not a
false clean (the ReactOS lesson applied: processed/broken counts
printed and checked). Idiom profile used:
`--alloc-functions Curl_cmalloc,Curl_ccalloc,Curl_crealloc,Curl_cstrdup,curl_malloc,curl_calloc`
`--free-functions Curl_cfree,curl_free`.

## The 86, categorized

- **~83 null-deref warnings**, spread across url.c, ftp.c, http.c,
  transfer.c, splay.c, hostip.c, ws.c, vtls/openssl.c, …
- **3 bounds (unbounded strcpy into a fixed buffer)** —
  `http_aws_sigv4.c:646` (65-byte), `smb.c:726` (1024-byte),
  `ws.c:728` (40-byte).

## Working hypothesis (why parked, not triaged now)

curl is one of the most audited C codebases in existence; 83
null-derefs is almost certainly an FP FAMILY, not 83 real bugs — the
libgit2 149→34 shape. Leading suspect: **`DEBUGASSERT()`**. curl
guards pointers with `DEBUGASSERT(ptr)` (a no-op in release builds,
a non-null assertion in debug); if the engine does not treat the
declared assert handler as establishing non-null, every deref after
one reads as unchecked — exactly the systemd/fprime assert family we
already close with `--fatal-asserts`. First triage step next round:
add `profiles/curl.conf` declaring curl's assert macro and re-scan;
the spread should collapse the way fprime's 10→0 did.

The 3 strcpy findings are the real-CANDIDATE signal and worth
per-site adjudication against curl source (does a `strlen` guard sit
in a dominating block the witness scan missed, or are they genuine?).
Not adjudicated here — the sandbox cannot clone curl (network is
repo-only), so this needs a round that fetches source.

## Resumption recipe

1. Fresh weekly quota + max effort (this is an FP-hunt round, not a
   quick win — budget like the libgit2 round).
2. `profiles/curl.conf`: declare the DEBUGASSERT handler via
   `--fatal-asserts`; re-scan; measure the null-deref collapse.
3. Whatever survives: adjudicate per-site against curl source, split
   real bugs from remaining FP families, each family → an engine
   feature with a pinned test (the standing discipline).
4. The 3 strcpy sites: confirm guarded-or-real; a real one is a PR
   candidate (curl's maintainers merge fixes fast — the shadPS4
   pattern).

## libexpat (same round, contrasting result — clean)

libexpat 2.6.4 full `lib/`: `findings=0 broken=0 processed=5` — the
core is genuinely ~5 .c files and all compiled. A hardened XML
parser came back clean, and the v0.4.7 untrusted-length→bounds arm
produced zero false positives on exactly the kind of length-field
code it targets. Recorded in the README trophy table as a precision
data point.
