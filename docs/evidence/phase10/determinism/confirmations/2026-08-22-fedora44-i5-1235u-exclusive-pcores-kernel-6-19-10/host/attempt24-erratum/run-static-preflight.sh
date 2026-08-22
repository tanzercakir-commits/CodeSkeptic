#!/usr/bin/env bash
set -euo pipefail

readonly snapshot=/var/lib/codeskeptic-p10-07/88e369b21675e64e0a92842b0ce22f0c8148745e-confirmation-v7-24
readonly repo=$snapshot/source
readonly build_host=$snapshot/build
readonly mirror_host=$snapshot/llama-mirror.git
readonly image=localhost/codeskeptic-p10-07-evidence@sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca
readonly preflight=/run/codeskeptic-p10-07/static-preflight.py
readonly container_entry=/run/codeskeptic-p10-07/container-entry.py
readonly controller_membership=0::/codeskeptic-p10-07-authority/controller
readonly measurement_cgroup=/sys/fs/cgroup/codeskeptic-p10-07-authority/measurement
readonly build_mountpoint=$repo/build-p10-07-v6-release
readonly expected_os='Linux 6.19.10-300.fc44.x86_64'

[[ $(id -un) == tanzer ]] || { echo 'preflight must run as tanzer' >&2; exit 2; }
[[ $(/usr/bin/uname -sr) == "$expected_os" ]] || {
  echo 'host kernel differs from the frozen V7 authority' >&2
  exit 2
}
[[ -r $preflight ]] || { echo 'root-owned preflight is missing' >&2; exit 2; }
[[ -r $container_entry ]] || { echo 'root-owned container entry is missing' >&2; exit 2; }
[[ -d $build_mountpoint && -z $(find "$build_mountpoint" -mindepth 1 -print -quit) ]] || {
  echo 'sealed build mountpoint is missing or not empty' >&2
  exit 2
}

podman run --rm \
  --network none \
  --cgroups disabled \
  --cgroupns=host \
  --security-opt label=disable \
  -e CODESKEPTIC_EXPECTED_CONTROLLER_CGROUP="$controller_membership" \
  -e CODESKEPTIC_MEASUREMENT_CGROUP="$measurement_cgroup" \
  -e GIT_OPTIONAL_LOCKS=0 \
  -e GIT_CONFIG_COUNT=3 \
  -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0=/work \
  -e GIT_CONFIG_KEY_1=safe.directory \
  -e GIT_CONFIG_VALUE_1=/mirror \
  -e GIT_CONFIG_KEY_2=url.file:///mirror/.insteadOf \
  -e GIT_CONFIG_VALUE_2=https://github.com/ggml-org/llama.cpp.git \
  -e GIT_ALLOW_PROTOCOL=file \
  -v "$repo:/work:ro" \
  -v "$build_host:/work/build-p10-07-v6-release:ro" \
  -v "$mirror_host:/mirror:ro" \
  -v "$preflight:/preflight.py:ro" \
  -v "$container_entry:/container-entry.py:ro" \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$image" \
  python3 /container-entry.py python3 /preflight.py
