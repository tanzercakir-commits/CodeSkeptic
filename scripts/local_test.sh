#!/usr/bin/env bash
# Bounded reuse of an already installed rootless toolchain. Never downloads.
set -euo pipefail
repo=$(git rev-parse --show-toplevel)
cd "$repo"
image=25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5
archive=/home/tanzer/.cache/codeskeptic-offline-substrate-v1/archives/7ff5db23de232a39cbb5c9f5143c355885e30ac596161a6b9fc50c4538bfbf01.tar.gz
archive_digest=7ff5db23de232a39cbb5c9f5143c355885e30ac596161a6b9fc50c4538bfbf01
build="$repo/build/cwe-restart"
mode=${1:-preflight}
case "$mode" in preflight|build|focused|smoke|full) ;; *) echo 'unknown local test mode' >&2; exit 2;; esac
[ "$(id -u)" -ne 0 ] || { echo 'root/sudo forbidden' >&2; exit 2; }
[ ! -L "$repo/build" ] && [ ! -L "$build" ] || { echo 'symlink build root forbidden' >&2; exit 2; }
[ "$(podman image inspect "$image" --format '{{.Id}}')" = "$image" ]
[ -f "$archive" ] && [ ! -L "$archive" ]
printf '%s  %s\n' "$archive_digest" "$archive" | sha256sum --check --status
[ "$(df --output=avail -B1 "$repo" | tail -1)" -ge 34359738368 ] || { echo 'less than 32 GiB free' >&2; exit 2; }
if [ -d "$build" ]; then
    [ "$(du -sb "$build" | cut -f1)" -le 4294967296 ] || { echo 'build exceeded 4 GiB; inspect before cleanup' >&2; exit 2; }
fi
printf 'LOCAL_TOOLCHAIN_OK image=%s archive=%s\n' "$image" "$archive_digest"
[ "$mode" != preflight ] || exit 0
mkdir -p "$build"
# flock prevents two builds or a test/build race. Resource caps apply per run.
exec 9>"$build/.local-test.lock"
flock -n 9 || { echo 'another local test/build is active' >&2; exit 2; }
if [ ! -d "$build/googletest" ]; then
    task_dep_dir=$(mktemp -d "$build/gtest-XXXXXX")
    tar -xzf "$archive" --strip-components=1 -C "$task_dep_dir"
    mv "$task_dep_dir" "$build/googletest"
fi
container=(timeout --signal=TERM --kill-after=15s 900s podman run --rm --pull=never --network=none --read-only
    --userns=keep-id --security-opt=label=disable --cap-drop=all
    --cpus=2 --memory=6g --pids-limit=256 --tmpfs /tmp:rw,size=1g
    -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPYCACHEPREFIX=/dev/null/codeskeptic
    -v "$repo:/workspace/src:ro" -v "$build:/workspace/build:rw"
    -w /workspace/src "$image")
case "$mode" in
build)
    "${container[@]}" /usr/bin/cmake -S /workspace/src -B /workspace/build -G Ninja \
        -DCMAKE_C_COMPILER=/usr/bin/clang-20 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-20 \
        -DLLVM_DIR=/usr/lib/llvm-20/lib/cmake/llvm -DClang_DIR=/usr/lib/llvm-20/lib/cmake/clang \
        -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/workspace/build/googletest \
        -DFETCHCONTENT_FULLY_DISCONNECTED=ON
    "${container[@]}" /usr/bin/cmake --build /workspace/build --target codeskeptic codeskeptic_tests --parallel 2
    ;;
focused)
    [ -n "${2:-}" ] || { echo 'explicit gtest filter required' >&2; exit 2; }
    "${container[@]}" /workspace/build/tests/codeskeptic_tests "--gtest_filter=$2"
    ;;
smoke)
    # Generated disposable fixture, not repository source or completion evidence.
    task_smoke_dir=$(mktemp -d "$build/smoke-XXXXXX")
    printf 'int f(){ int* p=new int(42); delete p; return *p; }\n' > "$task_smoke_dir/input.cpp"
    task_smoke_name=${task_smoke_dir##*/}
    status=0
    "${container[@]}" /workspace/build/src/codeskeptic "/workspace/build/$task_smoke_name/input.cpp" \
        --json "/workspace/build/$task_smoke_name/result.json" || status=$?
    [ "$status" -eq 1 ] || { echo "CLI smoke expected 1, got $status" >&2; exit 2; }
    python3 -B -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["total"] > 0, d' "$task_smoke_dir/result.json"
    ;;
full)
    "${container[@]}" /usr/bin/ctest --test-dir /workspace/build --output-on-failure --no-tests=error --parallel 2
    "${container[@]}" /workspace/build/tests/codeskeptic_tests
    ;;
esac
