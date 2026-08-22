#!/usr/bin/env bash
set -euo pipefail

readonly config=/tmp/codeskeptic-authority.gitconfig

[[ $# -ge 1 ]] || { echo 'usage: git-authority-entry.sh COMMAND [ARG ...]' >&2; exit 2; }
[[ ! -e $config ]] || { echo 'ephemeral Git authority already exists' >&2; exit 2; }

umask 077
export GIT_CONFIG_GLOBAL=$config
/usr/bin/git config --global --add safe.directory /work
/usr/bin/git config --global --add safe.directory /mirror
/usr/bin/git config --global --add \
  url.file:///mirror/.insteadOf https://github.com/ggml-org/llama.cpp.git

[[ $(/usr/bin/stat -c '%U:%G:%a' "$config") == root:root:600 ]] || {
  echo 'ephemeral Git authority ownership or mode drift' >&2
  exit 2
}
[[ $(/usr/bin/git config --global --get-all safe.directory) == $'/work\n/mirror' ]] || {
  echo 'ephemeral Git safe-directory authority drift' >&2
  exit 2
}
[[ $(/usr/bin/git config --global --get-all \
  url.file:///mirror/.insteadOf) == https://github.com/ggml-org/llama.cpp.git ]] || {
  echo 'ephemeral Git URL authority drift' >&2
  exit 2
}

exec "$@"
