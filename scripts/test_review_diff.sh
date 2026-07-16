#!/usr/bin/env bash
# End-to-end test for the diff-review flow (review_diff.sh +
# review_report.py). Hermetic: builds its own tiny git repo fixture in a
# temp dir (no network, pinned git identity), runs the real analyzer
# binary, and pins the delta semantics that make a review trustworthy:
#
#   1. A change that introduces a definite finding, fixes an old one and
#      weakens a contract -> exactly that verdict (FAIL, new=1 fixed=1
#      weakened=1), with the new finding marked as on a changed line.
#   2. Findings that merely SHIFT lines (code added above them) must NOT
#      resurface as "new" — the Baseline-v2 content-hash key parity.
#   3. A self-review (base == head) is clean.
#   4. A pure file RENAME introduces nothing — the old->new path map.
#
# Usage: scripts/test_review_diff.sh <zerodefect-binary>
# Wired into ctest as ReviewDiffFlow (tests/CMakeLists.txt), so the
# referee gate and CI run it with every build.
set -euo pipefail

ZD_BIN="${1:?usage: test_review_diff.sh <zerodefect-binary>}"
ZD_BIN="$(cd "$(dirname "$ZD_BIN")" && pwd)/$(basename "$ZD_BIN")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic git: no user/system config, fixed identity, no GPG.
export HOME="$TMP/home"
export GIT_CONFIG_GLOBAL="$TMP/gitconfig"
export GIT_CONFIG_SYSTEM=/dev/null
export LC_ALL=C
mkdir -p "$HOME"
git config --file "$GIT_CONFIG_GLOBAL" user.email "zd@test.invalid"
git config --file "$GIT_CONFIG_GLOBAL" user.name "zd-test"
git config --file "$GIT_CONFIG_GLOBAL" init.defaultBranch main
git config --file "$GIT_CONFIG_GLOBAL" commit.gpgsign false

REPO="$TMP/repo"
mkdir "$REPO"
cd "$REPO"
git init -q

fail() {
    echo "FAIL: $1" >&2
    echo "--- stdout ---" >&2;    cat "$TMP/stdout.txt" 2>/dev/null >&2 || true
    echo "--- review.md ---" >&2; cat review.md 2>/dev/null >&2 || true
    exit 1
}
assert_grep()     { grep -qF -- "$1" "$2" || fail "expected '$1' in $2"; }
assert_not_grep() { if grep -qF -- "$1" "$2"; then fail "unexpected '$1' in $2"; fi; }

write_db() { # regenerate the compile DB for the current source file name
    printf '[\n {"directory": "%s", "file": "%s/%s", "command": "clang -c %s/%s"}\n]\n' \
        "$REPO" "$REPO" "$1" "$REPO" "$1" > compile_commands.json
}

# --- base revision ----------------------------------------------------------
cat > lib.c <<'EOF'
#include <stdlib.h>

int* make_item(void) {
    static int slot;
    return &slot;
}

int fixed_later(void) {
    int* p = 0;
    return *p;
}

int stable_warning(void) {
    int* q = (int*)malloc(4);
    return q[0];
}
EOF
write_db lib.c
git add -A
git commit -qm base
BASE_SHA="$(git rev-parse HEAD)"

# --- head revision ----------------------------------------------------------
# * make_item gains a null return path        -> contract WEAKENED
# * fixed_later gains a guard                 -> old definite finding FIXED
# * fresh_overflow is new, definitely OOB     -> the one NEW error
# * stable_warning is byte-identical, shifted -> must NOT resurface
cat > lib.c <<'EOF'
#include <stdlib.h>

int* make_item(void) {
    static int slot;
    if (slot > 0) return 0;
    return &slot;
}

int fixed_later(void) {
    int* p = 0;
    if (!p) return -1;
    return *p;
}

int fresh_overflow(void) {
    int a[4];
    int i = 9;
    return a[i];
}

int stable_warning(void) {
    int* q = (int*)malloc(4);
    return q[0];
}
EOF
git add -A
git commit -qm head
HEAD_SHA="$(git rev-parse HEAD)"

# --- 1+2: the real delta ------------------------------------------------
code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$BASE_SHA" --out review.md \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 1 ] || fail "delta review: expected gate exit 1, got $code"

assert_grep "REVIEW_RESULT new_errors=1 new_warnings=0 fixed=1 weakened=1 gate=fail" \
    "$TMP/stdout.txt"
assert_grep "Verdict: FAIL" review.md
assert_grep "out-of-bounds" review.md            # the new bounds error...
assert_grep "fresh_overflow" review.md           # ...in the new function
assert_grep "(on changed line)" review.md        # ...marked as changed
assert_grep "WEAKENED" review.md
assert_grep "make_item" review.md                # the weakened contract
assert_not_grep "stable_warning" review.md       # shifted-only: silent

# --- 3: self-review is clean ---------------------------------------------
code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$HEAD_SHA" --out review.md \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "self review: expected exit 0, got $code"
assert_grep "REVIEW_RESULT new_errors=0 new_warnings=0 fixed=0 weakened=0 gate=pass" \
    "$TMP/stdout.txt"
assert_grep "Verdict: PASS" review.md

# --- 4: pure rename introduces nothing ------------------------------------
git mv lib.c core.c
write_db core.c
git add -A
git commit -qm rename
RENAME_SHA="$(git rev-parse HEAD)"

code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$HEAD_SHA" --out review.md \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "rename review: expected exit 0, got $code"
assert_grep "REVIEW_RESULT new_errors=0 new_warnings=0 fixed=0 weakened=0 gate=pass" \
    "$TMP/stdout.txt"

# --- 5: gate ladder — a new WARNING reports but does not gate by default
# (evidence discipline: definite = error = gate; "may" = warning = human
# judgment), gates under --strict, and --gate warn always exits 0 while
# still SAYING fail.
cat >> core.c <<'EOF'

static int* maybe_null(int f) {
    static int s;
    if (f) return 0;
    return &s;
}

int warn_only(int f) {
    int* w = maybe_null(f);
    return *w;
}
EOF
git add -A
git commit -qm warning

code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$RENAME_SHA" --out review.md \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "warning review (default): expected exit 0, got $code"
assert_grep "REVIEW_RESULT new_errors=0 new_warnings=1 fixed=0 weakened=0 gate=pass" \
    "$TMP/stdout.txt"
assert_grep "pass --strict" review.md            # the hint that warnings exist

code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$RENAME_SHA" --out review.md --strict \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 1 ] || fail "warning review (--strict): expected exit 1, got $code"
assert_grep "gate=fail" "$TMP/stdout.txt"

code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$RENAME_SHA" --out review.md \
    --strict --gate warn > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "warning review (--gate warn): expected exit 0, got $code"
assert_grep "gate=fail" "$TMP/stdout.txt"        # says fail, exits 0
WARN_SHA="$(git rev-parse HEAD)"

# --- 6: assumption delta — a new unchecked-param deref (the CWE-476
# review shape, cJSON #991) surfaces as ONE info finding, on by
# default, and does not gate.
cat >> core.c <<'EOF'

int deref_param(int* p) {
    return *p;
}
EOF
git add -A
git commit -qm assumption
ASSUME_SHA="$(git rev-parse HEAD)"

code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$WARN_SHA" --out review.md \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "assumption review: expected exit 0, got $code"
assert_grep "REVIEW_RESULT new_errors=0 new_warnings=1 fixed=0 weakened=0 gate=pass" \
    "$TMP/stdout.txt"
assert_grep "assumed non-null" review.md
assert_grep "deref_param" review.md
assert_grep "New findings (1 info)" review.md   # severity-true label
assert_not_grep "1 warning" review.md           # info is NOT mislabeled

# ...and --no-assumptions turns the delta off.
code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$WARN_SHA" --out review.md \
    --no-assumptions > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "no-assumptions review: expected exit 0, got $code"
assert_grep "REVIEW_RESULT new_errors=0 new_warnings=0 fixed=0 weakened=0 gate=pass" \
    "$TMP/stdout.txt"

# --- 7: --exclude skips matching changed files but LISTS them ----------
mkdir -p vendor
cat > vendor/extra.c <<'EOF'
int vendor_deref(int* p) {
    return *p;
}
EOF
git add -A
git commit -qm vendor

code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$ASSUME_SHA" --out review.md \
    --exclude 'vendor/*' > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "exclude review: expected exit 0, got $code"
assert_grep "REVIEW_RESULT new_errors=0 new_warnings=0 fixed=0 weakened=0 gate=pass" \
    "$TMP/stdout.txt"
assert_grep "excluded by --exclude" review.md    # skipped, but SAID
# Control: without --exclude the same change yields the vendor finding.
code=0
bash "$SCRIPT_DIR/review_diff.sh" "$ZD_BIN" "$ASSUME_SHA" --out review.md \
    > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" || code=$?
[ "$code" -eq 0 ] || fail "exclude-control review: expected exit 0, got $code"
assert_grep "vendor_deref" review.md

echo "PASS: review-diff flow (delta + shift-immunity + self + rename + gate ladder + assumption delta + exclude)"
