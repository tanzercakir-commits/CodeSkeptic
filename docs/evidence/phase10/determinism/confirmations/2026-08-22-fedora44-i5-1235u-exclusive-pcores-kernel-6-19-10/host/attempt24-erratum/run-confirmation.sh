#!/usr/bin/env bash
set -euo pipefail

readonly snapshot=/var/lib/codeskeptic-p10-07/88e369b21675e64e0a92842b0ce22f0c8148745e-confirmation-v7-24
readonly repo=$snapshot/source
readonly revision=88e369b21675e64e0a92842b0ce22f0c8148745e
readonly build_host=$snapshot/build
readonly mirror_host=$snapshot/llama-mirror.git
readonly stage_host=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-88e369b-attempt24
readonly image=localhost/codeskeptic-p10-07-evidence@sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca
readonly hardware_class=fedora44-i5-1235u-exclusive-pcores-0-3
readonly container_entry=/run/codeskeptic-p10-07/container-entry.py
readonly git_authority_entry=/run/codeskeptic-p10-07/git-authority-entry.sh
readonly controller_membership=0::/codeskeptic-p10-07-authority/controller
readonly build_mountpoint=$repo/build-p10-07-v6-release
readonly expected_os='Linux 6.19.10-300.fc44.x86_64'

if [[ $# != 1 ]]; then
  echo 'usage: run-confirmation.sh MEASUREMENT_CGROUP' >&2
  exit 2
fi
readonly measurement_cgroup=$1

finalize() {
  local status=$?
  set +e
  if [[ -d $stage_host ]]; then
    printf '%s\n' "$status" > "$stage_host/operator-exit-code.txt"
    if ! (
      cd "$stage_host" || exit 1
      find . -type f ! -name SHA256SUMS -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum > SHA256SUMS
      sha256sum -c SHA256SUMS
    ); then
      echo 'outer confirmation manifest verification failed' >&2
      status=2
    fi
  fi
  trap - EXIT
  exit "$status"
}
trap finalize EXIT

[[ $(id -un) == tanzer ]] || { echo 'confirmation must run as tanzer' >&2; exit 2; }
[[ $(/usr/bin/uname -sr) == "$expected_os" ]] || {
  echo 'host kernel differs from the frozen V7 authority' >&2
  exit 2
}
export GIT_OPTIONAL_LOCKS=0
[[ -d $measurement_cgroup ]] || { echo 'measurement cgroup is missing' >&2; exit 2; }
[[ -d $build_mountpoint && -z $(find "$build_mountpoint" -mindepth 1 -print -quit) ]] || {
  echo 'sealed build mountpoint is missing or not empty' >&2
  exit 2
}
[[ ! -e $stage_host ]] || { echo "refusing existing stage: $stage_host" >&2; exit 2; }
[[ $(git -c safe.directory="$repo" -C "$repo" rev-parse HEAD) == "$revision" ]] || {
  echo 'frozen source revision drift' >&2
  exit 2
}
[[ -z $(git -c safe.directory="$repo" -C "$repo" status --porcelain) ]] || {
  echo 'frozen source worktree is dirty' >&2
  exit 2
}
[[ $(taskset -pc $$ 2>/dev/null) == *'4-11' ]] || {
  echo 'controller process affinity is not pinned to CPUs 4-11' >&2
  exit 2
}

mkdir "$stage_host"

podman run --rm \
  --network none \
  --cgroups disabled \
  --cgroupns=host \
  --security-opt label=disable \
  --security-opt unmask=/sys/devices/system/cpu/cpu0/thermal_throttle \
  --security-opt unmask=/sys/devices/system/cpu/cpu1/thermal_throttle \
  --security-opt unmask=/sys/devices/system/cpu/cpu2/thermal_throttle \
  --security-opt unmask=/sys/devices/system/cpu/cpu3/thermal_throttle \
  -e CODESKEPTIC_EXPECTED_CONTROLLER_CGROUP="$controller_membership" \
  -e CODESKEPTIC_MEASUREMENT_CGROUP="$measurement_cgroup" \
  -e GIT_OPTIONAL_LOCKS=0 \
  -e GIT_ALLOW_PROTOCOL=file \
  -v "$repo:/work:ro" \
  -v "$build_host:/work/build-p10-07-v6-release:ro" \
  -v "$mirror_host:/mirror:ro" \
  -v "$stage_host:/evidence:rw" \
  -v "$container_entry:/container-entry.py:ro" \
  -v "$git_authority_entry:/git-authority-entry.sh:ro" \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /release-workspace:rw,size=4g,mode=0700 \
  "$image" \
  python3 /container-entry.py \
  /git-authority-entry.sh \
  python3 /work/scripts/run_determinism_qualification.py \
    --manifest /work/scripts/determinism_workloads.json \
    --baseline /work/scripts/determinism_baseline.json \
    --baseline-authority-root /work \
    --binary /work/build-p10-07-v6-release/src/codeskeptic \
    --repo-root /work \
    --build-path /work/build-p10-07-v6-release \
    --revision "$revision" \
    --output /evidence/confirmation \
    --hardware-class "$hardware_class" \
    --measurement-cgroup "$measurement_cgroup" \
    --repetitions 10 \
    --clang /usr/bin/clang-20 \
    --c-compiler /usr/bin/clang-20 \
    --cxx-compiler /usr/bin/clang++-20 \
    --cmake /usr/bin/cmake \
    --ninja /usr/bin/ninja \
    --time-binary /usr/bin/time \
    --prepare-release-candidate \
    --release-workspace /release-workspace \
    --jobs 2 \
    --performance-policy required \
  2>&1 | tee "$stage_host/operator.log"

podman run --rm \
  --network none \
  --cgroups disabled \
  --cgroupns=host \
  --security-opt label=disable \
  -e CODESKEPTIC_EXPECTED_CONTROLLER_CGROUP="$controller_membership" \
  -e CODESKEPTIC_MEASUREMENT_CGROUP="$measurement_cgroup" \
  -e GIT_OPTIONAL_LOCKS=0 \
  -e GIT_CONFIG_COUNT=1 \
  -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0=/work \
  -v "$repo:/work:ro" \
  -v "$build_host:/work/build-p10-07-v6-release:ro" \
  -v "$stage_host:/evidence:ro" \
  -v "$container_entry:/container-entry.py:ro" \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$image" \
  python3 /container-entry.py \
  python3 /work/scripts/run_determinism_qualification.py \
    --manifest /work/scripts/determinism_workloads.json \
    --baseline /work/scripts/determinism_baseline.json \
    --baseline-authority-root /work \
    --repo-root /work \
    --verify-receipt /evidence/confirmation \
  2>&1 | tee "$stage_host/confirmation-verify.log"
