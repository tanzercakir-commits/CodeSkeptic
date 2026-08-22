#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH

readonly wrapper=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-operator-88e369b-attempt24/guided-headless-confirmation.sh
readonly wrapper_sha=5497722724fd987c04af9f6f0341a2aadda7631ed403191e7dc9d59c21b4851f
readonly helper=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-operator-88e369b-attempt24/vscode-helper-drain.py
readonly helper_sha=67ddbda20b788b0ea7af0fbcc4479221c038292e51b908914b820d984569206a

[[ -f $wrapper && ! -L $wrapper && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$wrapper") == \
        tanzer:tanzer:500:regular\ file && \
      $(/usr/bin/sha256sum "$wrapper" | /usr/bin/cut -d' ' -f1) == \
        "$wrapper_sha" ]] || {
  echo 'Attempt24 wrapper kimliği doğrulanamadı; koşu başlatılmadı.' >&2
  exit 2
}

[[ -f $helper && ! -L $helper && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$helper") == \
        tanzer:tanzer:555:regular\ file && \
      $(/usr/bin/sha256sum "$helper" | /usr/bin/cut -d' ' -f1) == \
        "$helper_sha" ]] || {
  echo 'Attempt24 VSCode yokluk denetçisi doğrulanamadı; koşu başlatılmadı.' >&2
  exit 2
}

absence_output=
for ((attempt = 1; attempt <= 60; attempt++)); do
  if absence_output=$(/usr/bin/python3 -I -B "$helper" --require-absent 2>&1); then
    printf '%s\n' "$absence_output"
    echo 'CODESKEPTIC_A24_VSCODE_ABSENCE_STABLE'
    exec "$wrapper"
  fi
  if [[ $absence_output == *'not in a physical TTY session cgroup'* ]]; then
    printf '%s\n' "$absence_output" >&2
    echo 'Attempt24 yalnız fiziksel TTY üzerinden çalıştırılabilir.' >&2
    exit 2
  fi
  if ((attempt == 1 || attempt % 5 == 0)); then
    printf 'VSCode/Codex kapanışı bekleniyor (%d/60)...\n' "$attempt"
  fi
  /usr/bin/sleep 1
done

printf '%s\n' "$absence_output" >&2
echo 'VSCode/Codex 60 saniye içinde tamamen kapanmadı; Attempt24 başlatılmadı.' >&2
exit 2
