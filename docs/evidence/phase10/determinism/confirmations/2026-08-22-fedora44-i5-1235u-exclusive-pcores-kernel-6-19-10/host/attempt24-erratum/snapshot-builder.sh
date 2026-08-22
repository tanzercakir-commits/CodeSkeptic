#!/usr/bin/env bash
set -euo pipefail
export GIT_OPTIONAL_LOCKS=0

readonly revision=88e369b21675e64e0a92842b0ce22f0c8148745e
readonly llama_revision=4dee52f82dc455a035e900fed6a40cb45cd7a454
readonly source_input=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-source-worktree
readonly build_input=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v6-release-492eca7
readonly mirror_input=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v5-evidence-clang20-026a9e6/release-calibration/llama-cpp
readonly snapshot_parent=/var/lib/codeskeptic-p10-07
readonly snapshot=$snapshot_parent/${revision}-confirmation-v7-24
readonly build_mountpoint=build-p10-07-v6-release
readonly tree_hash=/run/codeskeptic-p10-07/tree-hash.py
readonly expected_build_identity='{"entry_count": 102, "manifest_sha256": "a0bdda40f9d855cab64ad2ef02fed47e5f7e8e143a19bed3c1e6b272e28f9fd5"}'
readonly expected_identity="source_revision=$revision
build_entry_count=102
build_manifest_sha256=a0bdda40f9d855cab64ad2ef02fed47e5f7e8e143a19bed3c1e6b272e28f9fd5
llama_revision=$llama_revision
source_mountpoint=$build_mountpoint"

verify_snapshot() {
  local top_level snapshot_before snapshot_after
  [[ ! -L $snapshot && -d $snapshot && \
        $(stat -c '%U:%G:%a' "$snapshot") == root:root:555 ]] || {
    echo 'sealed snapshot root ownership or mode drift' >&2
    return 2
  }
  [[ -z $(find "$snapshot" \( ! -user root -o ! -group root \) -print -quit) ]] || {
    echo 'sealed snapshot ownership drift' >&2
    return 2
  }
  [[ -z $(find "$snapshot" -perm /222 -print -quit) ]] || {
    echo 'sealed snapshot contains writable entries' >&2
    return 2
  }
  snapshot_before=$(python3 "$tree_hash" "$snapshot") || return 2
  top_level=$(find "$snapshot" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
  [[ $top_level == $'build\nidentity.txt\nllama-mirror.git\nsource' ]] || {
    echo 'sealed snapshot top-level inventory drift' >&2
    return 2
  }
  [[ $(git -C "$snapshot/source" rev-parse HEAD) == "$revision" && \
        -z $(git -C "$snapshot/source" status --porcelain) && \
        -z $(git -C "$snapshot/source" remote) ]] || {
    echo 'sealed snapshot source identity drift' >&2
    return 2
  }
  [[ -d $snapshot/source/$build_mountpoint && \
        -z $(find "$snapshot/source/$build_mountpoint" -mindepth 1 -print -quit) ]] || {
    echo 'sealed snapshot build mountpoint drift' >&2
    return 2
  }
  [[ $(python3 "$tree_hash" "$snapshot/build") == "$expected_build_identity" ]] || {
    echo 'sealed snapshot release build identity drift' >&2
    return 2
  }
  [[ $(git -C "$snapshot/llama-mirror.git" rev-parse --is-bare-repository) == true && \
        -z $(git -C "$snapshot/llama-mirror.git" remote) && \
        ! -s $snapshot/llama-mirror.git/objects/info/alternates ]] || {
    echo 'sealed snapshot mirror shape drift' >&2
    return 2
  }
  git -C "$snapshot/llama-mirror.git" cat-file -e "$llama_revision^{commit}"
  git -C "$snapshot/llama-mirror.git" fsck --full --no-dangling
  [[ $(<"$snapshot/identity.txt") == "$expected_identity" ]] || {
    echo 'sealed snapshot identity receipt drift' >&2
    return 2
  }
  snapshot_after=$(python3 "$tree_hash" "$snapshot") || return 2
  [[ $snapshot_after == "$snapshot_before" ]] || {
    echo 'sealed snapshot changed during verification' >&2
    return 2
  }
  [[ ! -L $snapshot && -d $snapshot && \
        $(stat -c '%U:%G:%a' "$snapshot") == root:root:555 && \
        -z $(find "$snapshot" \( ! -user root -o ! -group root \) -print -quit) && \
        -z $(find "$snapshot" -perm /222 -print -quit) ]] || {
    echo 'sealed snapshot final ownership or write-protection drift' >&2
    return 2
  }
}

cleanup_failed_snapshot() {
  local status=$?
  trap - EXIT
  if [[ $status != 0 && -d $snapshot ]]; then
    mv "$snapshot" "$snapshot.failed.$$" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup_failed_snapshot EXIT

[[ $(id -u) == 0 ]] || { echo 'snapshot builder must run as root' >&2; exit 2; }
[[ $(stat -c '%U:%G:%a' "$tree_hash") == root:root:555 ]] || {
  echo 'root-owned tree hash helper permissions drift' >&2
  exit 2
}
printf '%s  %s\n' \
  b7765dcf006e346ebcca69b93a5a1686e51ec760fb06bd09e36eceaf19cb034d \
  "$tree_hash" | sha256sum -c -
[[ $(git -c safe.directory="$source_input" -C "$source_input" rev-parse HEAD) == "$revision" ]] || {
  echo 'input source revision drift' >&2
  exit 2
}
[[ -z $(git -c safe.directory="$source_input" -C "$source_input" status --porcelain) ]] || {
  echo 'input source worktree is dirty' >&2
  exit 2
}
[[ $(python3 "$tree_hash" "$build_input") == "$expected_build_identity" ]] || {
  echo 'input release build identity drift' >&2
  exit 2
}
[[ $(git -c safe.directory="$mirror_input" -C "$mirror_input" rev-parse HEAD) == "$llama_revision" ]] || {
  echo 'input llama mirror revision drift' >&2
  exit 2
}
[[ -z $(git -c safe.directory="$mirror_input" -C "$mirror_input" status --porcelain) ]] || {
  echo 'input llama mirror is dirty' >&2
  exit 2
}

if [[ -e $snapshot || -L $snapshot ]]; then
  verify_snapshot
  trap - EXIT
  echo "CODESKEPTIC_AUTHORITY_SNAPSHOT_REUSED $snapshot"
  exit 0
fi

install -d -o root -g root -m 755 "$snapshot_parent"
mkdir -m 700 "$snapshot"

git -c safe.directory="$source_input" clone --quiet --no-local --no-checkout \
  "$source_input" "$snapshot/source"
git -C "$snapshot/source" checkout --quiet --detach "$revision"
git -C "$snapshot/source" remote remove origin
[[ $(git -C "$snapshot/source" rev-parse HEAD) == "$revision" ]] || {
  echo 'snapshot source revision drift' >&2
  exit 2
}
[[ -z $(git -C "$snapshot/source" status --porcelain) ]] || {
  echo 'snapshot source worktree is dirty' >&2
  exit 2
}
mkdir "$snapshot/source/$build_mountpoint"
[[ -z $(find "$snapshot/source/$build_mountpoint" -mindepth 1 -print -quit) ]] || {
  echo 'snapshot build mountpoint is not empty' >&2
  exit 2
}

cp -a --reflink=auto "$build_input" "$snapshot/build"
[[ $(python3 "$tree_hash" "$snapshot/build") == "$expected_build_identity" ]] || {
  echo 'snapshot release build identity drift' >&2
  exit 2
}

git -c safe.directory="$mirror_input" clone --quiet --mirror --no-local \
  "$mirror_input" "$snapshot/llama-mirror.git"
git -C "$snapshot/llama-mirror.git" remote remove origin
git -C "$snapshot/llama-mirror.git" cat-file -e "$llama_revision^{commit}"
git -C "$snapshot/llama-mirror.git" fsck --full --no-dangling

printf '%s\n' "$expected_identity" > "$snapshot/identity.txt"
chown -R root:root "$snapshot"
chmod -R a-w "$snapshot"
find "$snapshot" -type d -exec chmod a+rx {} +
find "$snapshot" -type f -exec chmod a+r {} +
chmod 555 "$snapshot"

verify_snapshot
trap - EXIT
echo "CODESKEPTIC_AUTHORITY_SNAPSHOT_OK $snapshot"
