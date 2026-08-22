#!/usr/bin/env bash
set -u -o pipefail

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH

readonly operator_root=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-operator-88e369b-attempt24
readonly authorizer=$operator_root/authorize-headless-confirmation.sh
readonly authorizer_sha=ad024f4bd1337a4a04b04a9750cdfde48447b41601f44d7d7073394cd0514ee3
readonly helper_local=$operator_root/vscode-helper-drain.py
readonly helper_sha=67ddbda20b788b0ea7af0fbcc4479221c038292e51b908914b820d984569206a
readonly authority_root=/var/lib/codeskeptic-p10-07
readonly headless_root=$authority_root/headless
readonly headless_log=$headless_root/88e369b-confirmation-v7-24.log
readonly terminal_receipt=$headless_root/88e369b-confirmation-v7-24.terminal
readonly transaction_journal=$headless_root/88e369b-confirmation-v7-24.journal
readonly transaction_journal_sha=$headless_root/88e369b-confirmation-v7-24.journal.sha256
readonly recovery_script=$headless_root/recover-88e369b-confirmation-v7-24.sh
readonly active_stage=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-88e369b-attempt24
readonly authority_cgroup=/sys/fs/cgroup/codeskeptic-p10-07-authority
readonly result_file=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-guided-confirmation-88e369b-attempt24.result
readonly precontroller_status=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-precontroller-88e369b-attempt24.status
readonly helper_log=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-vscode-helper-88e369b-attempt24.log
readonly expected_os='Linux 6.19.10-300.fc44.x86_64'
readonly expected_wireplumber_main=wireplumber-0.5.14-1.1.codeskeptic.fc44.x86_64
readonly expected_wireplumber_libs=wireplumber-libs-0.5.14-1.1.codeskeptic.fc44.x86_64
readonly expected_wireplumber_hashes='7f13a431f6f583ffed76a4e41992a5b1de034bd684010f977b638c359b27ed8f  /usr/bin/wireplumber
1ca47df2f52a238a790ad078ebad4dbb5f2d2793bb26edd2185b000decfe95eb  /usr/lib64/libwireplumber-0.5.so.0.514.0
d757620f8ee18a95f10b432136738726050f3bd9b2b7306c2e94cc89b15cf3be  /usr/lib64/wireplumber-0.5/libwireplumber-module-lua-scripting.so
f8a0f7edee013239f0dc8f03255fed973ee1d48ea2a330ba2520e9ad4de9d6f6  /usr/lib64/wireplumber-0.5/libwireplumber-module-portal-permissionstore.so'

caller_tty=
payload_rc=2
terminal_restoration_failed=
terminal_payload_exit=
terminal_journal_sha=
signal_received=
result_tmp=
coredump_before_isolate_sha=
drkonqi_accepted_before_isolate=

ring() {
  [[ -n $caller_tty && -c $caller_tty ]] || return 0
  printf '\a\a\a' > "$caller_tty" 2>/dev/null || true
}

say() {
  printf '%s\n' "$*"
}

fail() {
  say "CODESKEPTIC_GUIDED_FAIL $*" >&2
  ring
  exit 2
}

handle_signal() {
  [[ -n $signal_received ]] || signal_received=$1
}

signal_exit_code() {
  case $signal_received in
    HUP) printf '129\n' ;;
    INT) printf '130\n' ;;
    TERM) printf '143\n' ;;
    *) printf '2\n' ;;
  esac
}

cleanup_result_tmp() {
  [[ -n $result_tmp ]] || return 0
  if [[ $result_tmp == "$result_file".tmp.* && ! -L $result_tmp && \
        -f $result_tmp && $(/usr/bin/stat -c '%U:%G' "$result_tmp") == tanzer:tanzer ]]; then
    /usr/bin/rm -f -- "$result_tmp"
  fi
  result_tmp=
}

system_value() {
  /usr/bin/systemctl show "$2" -p "$1" --value
}

userctl() {
  /usr/bin/env XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    /usr/bin/systemctl --user --no-pager "$@"
}

user_value() {
  userctl show "$2" -p "$1" --value
}

require_wireplumber_candidate() {
  local main libs verification hashes
  main=$(/usr/bin/rpm -q wireplumber) || return 2
  libs=$(/usr/bin/rpm -q wireplumber-libs) || return 2
  [[ $main == "$expected_wireplumber_main" && \
        $libs == "$expected_wireplumber_libs" ]] || return 2
  verification=$(/usr/bin/rpm -V wireplumber wireplumber-libs 2>&1) || return 2
  [[ -z $verification ]] || return 2
  hashes=$(/usr/bin/sha256sum \
    /usr/bin/wireplumber \
    /usr/lib64/libwireplumber-0.5.so.0.514.0 \
    /usr/lib64/wireplumber-0.5/libwireplumber-module-lua-scripting.so \
    /usr/lib64/wireplumber-0.5/libwireplumber-module-portal-permissionstore.so) \
    || return 2
  [[ $hashes == "$expected_wireplumber_hashes" ]]
}

require_no_failed_system_units() {
  local failed
  if ! failed=$(/usr/bin/systemctl --failed --no-legend --plain); then
    fail 'başarısız sistem birimleri okunamadı'
  fi
  [[ -z $failed ]] || fail "başarısız sistem birimleri varken confirmation başlatılmayacak: $failed"
}

require_no_failed_user_units() {
  local failed
  if ! failed=$(userctl --failed --no-legend --plain); then
    fail 'başarısız kullanıcı birimleri okunamadı'
  fi
  [[ -z $failed ]] || fail "başarısız kullanıcı birimleri varken confirmation başlatılmayacak: $failed"
}

coredump_inventory_sha() {
  local inventory
  inventory=$(/usr/bin/coredumpctl --quiet --no-pager --no-legend \
    --json=short list) || return 2
  printf '%s' "$inventory" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
}

require_no_coredump_helper_instances() {
  local instances system_instances
  instances=$(userctl list-units 'drkonqi-coredump-launcher@*.service' \
    --all --no-legend --plain) || return 2
  [[ -z $instances ]] || return 2
  system_instances=$(/usr/bin/systemctl list-units \
    'systemd-coredump@*.service' 'drkonqi-coredump-processor@*.service' \
    --all --no-legend --plain) || return 2
  [[ -z $system_instances ]]
}

capture_graphical_transition_baseline() {
  coredump_before_isolate_sha=$(coredump_inventory_sha) || return 2
  [[ $coredump_before_isolate_sha =~ ^[0-9a-f]{64}$ ]] || return 2
  drkonqi_accepted_before_isolate=$(user_value NAccepted \
    drkonqi-coredump-launcher.socket) || return 2
  [[ $drkonqi_accepted_before_isolate =~ ^[0-9]+$ ]] || return 2
  require_no_coredump_helper_instances
}

require_graphical_transition_clean() {
  local latest accepted failed
  latest=$(coredump_inventory_sha) || return 2
  accepted=$(user_value NAccepted drkonqi-coredump-launcher.socket) || return 2
  [[ $latest == "$coredump_before_isolate_sha" && \
        $accepted == "$drkonqi_accepted_before_isolate" ]] || return 2
  require_no_coredump_helper_instances || return 2
  failed=$(/usr/bin/systemctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]] || return 2
  failed=$(userctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]]
}

require_graphical_transition_non_counter_clean() {
  local latest failed
  latest=$(coredump_inventory_sha) || return 2
  [[ $latest == "$coredump_before_isolate_sha" ]] || return 2
  require_no_coredump_helper_instances || return 2
  failed=$(/usr/bin/systemctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]] || return 2
  failed=$(userctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]]
}

transition_graphical_counter_after_receipt() {
  local line payload unit state unit_file extra journal_accepted=
  local accepted_count=0 unit_count=0 journal_unit_file=
  local load substate result job accepted
  [[ $terminal_journal_sha != none ]] || return 0
  while IFS= read -r line; do
    case "$line" in
      JOURNAL_DRKONQI_SOCKET_NACCEPTED=*)
        ((accepted_count += 1))
        journal_accepted=${line#*=}
        [[ $journal_accepted =~ ^[0-9]+$ ]] || return 2
        ;;
      JOURNAL_USER_UNIT=drkonqi-coredump-launcher.socket\|*)
        ((unit_count += 1))
        payload=${line#*=}
        IFS='|' read -r unit state journal_unit_file extra <<< "$payload"
        [[ -z $extra && $unit == drkonqi-coredump-launcher.socket && \
              $state == active && $journal_unit_file =~ ^[A-Za-z0-9_-]+$ && \
              $journal_unit_file != masked && \
              $journal_unit_file != masked-runtime ]] || return 2
        ;;
    esac
  done < "$transaction_journal" || return 2
  [[ $accepted_count == 1 && $unit_count == 1 && \
        $journal_accepted == "$drkonqi_accepted_before_isolate" ]] || return 2
  load=$(user_value LoadState drkonqi-coredump-launcher.socket) || return 2
  state=$(user_value ActiveState drkonqi-coredump-launcher.socket) || return 2
  substate=$(user_value SubState drkonqi-coredump-launcher.socket) || return 2
  result=$(user_value Result drkonqi-coredump-launcher.socket) || return 2
  unit_file=$(user_value UnitFileState drkonqi-coredump-launcher.socket) || return 2
  job=$(user_value Job drkonqi-coredump-launcher.socket) || return 2
  accepted=$(user_value NAccepted drkonqi-coredump-launcher.socket) || return 2
  [[ $load == loaded && $state == active && \
        ( $substate == listening || $substate == running ) && \
        $result == success && $unit_file == "$journal_unit_file" && -z $job && \
        ( $accepted == "$journal_accepted" || $accepted == 0 ) ]] || return 2
  drkonqi_accepted_before_isolate=$accepted
  say "CODESKEPTIC_GUIDED_DRKONQI_COUNTER_TRANSITION previous=$journal_accepted current=$accepted"
}

restoration_surface_clean() {
  local failed
  failed=$(/usr/bin/systemctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]] || return 2
  failed=$(userctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]] || return 2
  require_no_coredump_helper_instances
}

ensure_podman_pause() {
  local output rc pid args cgroup uid_line
  local -a pause_pids=()
  /usr/bin/podman unshare /usr/bin/true \
    || fail 'Podman pause süreci hazırlanamadı'
  if output=$(/usr/bin/pgrep -u 1000 -x catatonit); then
    [[ -n $output ]] || fail 'Podman pause süreci bulunamadı'
  else
    rc=$?
    fail "Podman pause süreci okunamadı: pgrep exit $rc"
  fi
  mapfile -t pause_pids <<< "$output"
  ((${#pause_pids[@]} == 1)) || fail 'tam olarak bir Podman pause süreci gerekli'
  pid=${pause_pids[0]}
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline && \
        -r /proc/$pid/cgroup && -r /proc/$pid/status ]] \
    || fail 'Podman pause süreç kimliği okunamıyor'
  args=$(/usr/bin/tr '\0' '\n' < "/proc/$pid/cmdline") \
    || fail 'Podman pause komut satırı okunamadı'
  cgroup=$(<"/proc/$pid/cgroup") || fail 'Podman pause cgroup bilgisi okunamadı'
  uid_line=$(/usr/bin/awk '/^Uid:/{print $2 " " $3 " " $4 " " $5}' \
    "/proc/$pid/status") || fail 'Podman pause UID bilgisi okunamadı'
  [[ $args == $'catatonit\n-P' && $uid_line == '1000 1000 1000 1000' && \
        $cgroup =~ ^0::/user\.slice/user-1000\.slice/user@1000\.service/user\.slice/podman-pause-[0-9a-f]+\.scope$ ]] \
    || fail 'Podman pause süreç kimliği beklenen sözleşmeyle eşleşmiyor'
}

wait_for_headless() {
  local deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    [[ -z $signal_received ]] || return 130
    if [[ $(system_value ActiveState graphical.target) == inactive && \
          $(system_value ActiveState multi-user.target) == active && \
          $(system_value ActiveState plasmalogin.service) == inactive ]]; then
      return 0
    fi
    /usr/bin/sleep 1
  done
  return 2
}

wait_for_graphical() {
  local deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    if [[ $(system_value ActiveState graphical.target) == active && \
          $(system_value ActiveState multi-user.target) == active && \
          $(system_value ActiveState plasmalogin.service) == active ]]; then
      return 0
    fi
    /usr/bin/sleep 1
  done
  return 2
}

await_graphical_restore_authorization() {
  local acknowledgement rc
  say 'CODESKEPTIC_GUIDED_GRAPHICAL_AUTHORIZATION_REQUIRED'
  say 'Confirmation tamamlandı. Grafik ekranını açmak için bu TTY üzerinde yalnız Enter tuşuna basın.'
  say 'Siz dönene kadar her 15 saniyede bir alarm çalacak; açık bir sudo parola istemi bırakılmayacak.'
  while [[ -z $signal_received ]]; do
    ring
    if IFS= read -r -t 15 acknowledgement; then
      if [[ -z $acknowledgement ]]; then
        say 'CODESKEPTIC_GUIDED_GRAPHICAL_AUTHORIZATION_ACKNOWLEDGED'
        return 0
      fi
      say 'Yalnız Enter tuşuna basın; başka metin girmeyin.' >&2
    else
      rc=$?
      ((rc > 128)) || return 2
    fi
  done
  return "$(signal_exit_code)"
}

restore_graphical_noninteractive() {
  /usr/bin/sudo -n /usr/bin/systemctl isolate graphical.target || return 2
  wait_for_graphical
}

restore_after_precontroller_failure() {
  local reason=$1 rc=${2:-2}
  say "$reason"
  say 'Grafik masaüstü geri açılıyor.'
  if restore_graphical_noninteractive; then
    say 'CODESKEPTIC_GUIDED_GRAPHICAL_RESTORED'
    ring
    exit "$rc"
  fi
  say 'Grafik masaüstünün geri açıldığı doğrulanamadı.' >&2
  say 'Bu TTY üzerinde yalnız şu komutu çalıştırın: sudo systemctl isolate graphical.target' >&2
  ring
  exit 4
}

validate_terminal_receipt() {
  local -a lines=()
  [[ ! -L $terminal_receipt && \
        $(/usr/bin/stat -c '%U:%G:%a:%F' "$terminal_receipt") == \
          root:root:444:regular\ file ]] || return 2
  mapfile -t lines < "$terminal_receipt" || return 2
  ((${#lines[@]} == 5)) || return 2
  [[ ${lines[0]} == CODESKEPTIC_HEADLESS_TERMINAL_VERSION=1 ]] || return 2
  [[ ${lines[1]} =~ ^CODESKEPTIC_HEADLESS_RESTORATION_FAILED=([01])$ ]] || return 2
  terminal_restoration_failed=${BASH_REMATCH[1]}
  [[ ${lines[2]} =~ ^CODESKEPTIC_HEADLESS_PAYLOAD_EXIT=([0-9]{1,3})$ ]] || return 2
  terminal_payload_exit=${BASH_REMATCH[1]}
  ((terminal_payload_exit <= 255)) || return 2
  [[ ${lines[3]} =~ ^CODESKEPTIC_HEADLESS_JOURNAL_SHA256=(none|[0-9a-f]{64})$ ]] || return 2
  terminal_journal_sha=${BASH_REMATCH[1]}
  [[ ${lines[4]} =~ ^CODESKEPTIC_HEADLESS_FINISH=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z)$ ]] || return 2
  [[ $terminal_payload_exit == "$payload_rc" ]] || return 2
  if [[ $terminal_journal_sha == none ]]; then
    [[ ! -e $transaction_journal && ! -L $transaction_journal && \
          ! -e $transaction_journal_sha && ! -L $transaction_journal_sha ]] || return 2
  else
    [[ ! -L $transaction_journal && ! -L $transaction_journal_sha && \
          $(/usr/bin/sha256sum "$transaction_journal" | /usr/bin/cut -d' ' -f1) == \
            "$terminal_journal_sha" ]] || return 2
    /usr/bin/sha256sum --status -c "$transaction_journal_sha" || return 2
  fi
}

publish_result() {
  local safe=$1 graphical_rc=$2 finish expected actual
  [[ ! -e $result_file && ! -L $result_file ]] || return 2
  finish=$(/usr/bin/date --utc --iso-8601=seconds) || return 2
  [[ $finish =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00$ ]] \
    || return 2
  expected="CODESKEPTIC_GUIDED_RESULT_VERSION=1
CODESKEPTIC_GUIDED_PAYLOAD_EXIT=$payload_rc
CODESKEPTIC_GUIDED_TRANSACTION_SAFE=$safe
CODESKEPTIC_GUIDED_GRAPHICAL_RESTORE_EXIT=$graphical_rc
CODESKEPTIC_GUIDED_FINISH=$finish"
  result_tmp=$(/usr/bin/mktemp "$result_file.tmp.XXXXXX") || return 2
  [[ $result_tmp == "$result_file".tmp.* && ! -L $result_tmp && \
        $(/usr/bin/stat -c '%U:%G:%a:%F' "$result_tmp") == \
          tanzer:tanzer:600:regular\ empty\ file ]] || return 2
  printf '%s\n' "$expected" > "$result_tmp" || return 2
  /usr/bin/chmod 0400 "$result_tmp" || return 2
  /usr/bin/sync -f "$result_tmp" || return 2
  [[ ! -L $result_tmp && \
        $(/usr/bin/stat -c '%U:%G:%a:%F' "$result_tmp") == \
          tanzer:tanzer:400:regular\ file ]] || return 2
  actual=$(<"$result_tmp") || return 2
  [[ $actual == "$expected" ]] || return 2
  /usr/bin/mv -T -- "$result_tmp" "$result_file" || return 2
  result_tmp=
  /usr/bin/sync -f "${result_file%/*}" || return 2
  [[ ! -L $result_file && \
        $(/usr/bin/stat -c '%U:%G:%a:%F' "$result_file") == \
          tanzer:tanzer:400:regular\ file ]] || return 2
  actual=$(<"$result_file") || return 2
  [[ $actual == "$expected" ]]
}

trap 'handle_signal HUP' HUP
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap cleanup_result_tmp EXIT

[[ $(/usr/bin/id -un) == tanzer ]] || fail 'bu rehber tanzer kullanıcısıyla çalıştırılmalı'
[[ -t 0 && -t 1 ]] || fail 'fiziksel TTY gerekli'
caller_tty=$(/usr/bin/tty) || fail 'TTY yolu okunamadı'
[[ $caller_tty =~ ^/dev/tty[1-9][0-9]*$ ]] || fail "yerel sanal konsol gerekli: $caller_tty"
[[ $(/usr/bin/uname -sr) == "$expected_os" ]] || \
  fail "yanlış çekirdek: önce Fedora 6.19.10-300.fc44.x86_64 ile açın"
[[ ! -L $authorizer && $(/usr/bin/stat -c '%U:%G:%a' "$authorizer") == tanzer:tanzer:500 ]] \
  || fail 'authorizer sahiplik veya modu değişmiş'
[[ $(/usr/bin/sha256sum "$authorizer" | /usr/bin/cut -d' ' -f1) == "$authorizer_sha" ]] \
  || fail 'authorizer SHA256 değişmiş'
[[ ! -L $helper_local && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$helper_local") == \
        tanzer:tanzer:555:regular\ file && \
      $(/usr/bin/sha256sum "$helper_local" | /usr/bin/cut -d' ' -f1) == \
        "$helper_sha" ]] || fail 'VS Code yokluk denetleyicisi değişmiş'
for path in "$headless_log" "$terminal_receipt" "$transaction_journal" "$transaction_journal_sha" \
  "$recovery_script" "$active_stage" "$authority_cgroup" "$result_file" \
  "$precontroller_status" "$helper_log"; do
  [[ ! -e $path && ! -L $path ]] || fail "88e369b-confirmation-v7-24 yolu zaten mevcut: $path"
done
[[ $(system_value ActiveState graphical.target) == active && \
      $(system_value ActiveState multi-user.target) == active && \
      $(system_value ActiveState plasmalogin.service) == active ]] \
  || fail 'başlangıç grafik durumu beklenen durumda değil'
require_no_failed_system_units
require_no_failed_user_units
require_wireplumber_candidate \
  || fail 'doğrulanmış WirePlumber shutdown adayı kurulu değil; confirmation başlatılmadı'
say 'CODESKEPTIC_WIREPLUMBER_CANDIDATE_VERIFIED'
capture_graphical_transition_baseline || fail 'coredump geçiş tabanı alınamadı'
ensure_podman_pause
/usr/bin/python3 -I -B "$helper_local" --require-absent || \
  fail 'VS Code/Codex tamamen kapanmadı; grafik kapatılmadan güvenli biçimde duruldu'

say 'CodeSkeptic rehberli deneme hazır.'
say 'Şimdi sudo parolanızı bir kez girin.'
/usr/bin/sudo -v
sudo_rc=$?
if [[ -n $signal_received ]]; then
  ring
  exit "$(signal_exit_code)"
fi
[[ $sudo_rc == 0 ]] || fail 'sudo doğrulaması başarısız'
say 'Grafik masaüstü kapatılıyor. Betik dönene kadar Ctrl+Alt+Delete, reboot veya güç düğmesi kullanmayın.'
if ! /usr/bin/sudo -n /usr/bin/systemctl isolate multi-user.target; then
  restore_after_precontroller_failure 'Multi-user geçişi tamamlanamadı.' 2
fi
if [[ -n $signal_received ]]; then
  restore_after_precontroller_failure 'Geçiş sırasında kesinti sinyali alındı.' "$(signal_exit_code)"
fi
if ! wait_for_headless; then
  if [[ -n $signal_received ]]; then
    restore_after_precontroller_failure 'Headless doğrulama sırasında kesinti sinyali alındı.' \
      "$(signal_exit_code)"
  fi
  restore_after_precontroller_failure 'Headless geçiş doğrulanamadı.' 2
fi
if ! require_graphical_transition_clean; then
  restore_after_precontroller_failure \
    'Grafik kapanışı sırasında yeni coredump, DrKonqi etkinliği veya failed unit oluştu.' 2
fi

say 'Headless durum doğrulandı. Bağımsız confirmation hazırlanıyor; uzun süre sessiz kalması normaldir.'
say 'Bitince üç kez sesli uyarı verilecek. Bu arada hiçbir komut girmeyin.'
if [[ -n $signal_received ]]; then
  restore_after_precontroller_failure 'Confirmation başlamadan önce kesinti sinyali alındı.' \
    "$(signal_exit_code)"
fi
"$authorizer" "$coredump_before_isolate_sha" \
  "$drkonqi_accepted_before_isolate"
payload_rc=$?

qualification_contaminated=0
if ! require_graphical_transition_non_counter_clean; then
  qualification_contaminated=1
  say 'CODESKEPTIC_GUIDED_QUALIFICATION_CONTAMINATED coredump_or_helper_delta=1' >&2
fi

transaction_safe=0
if [[ -e $terminal_receipt || -L $terminal_receipt ]]; then
  if validate_terminal_receipt && [[ $terminal_restoration_failed == 0 ]]; then
    transaction_safe=1
  fi
elif [[ ! -e $transaction_journal && ! -L $transaction_journal && \
        ! -e $transaction_journal_sha && ! -L $transaction_journal_sha && \
        $payload_rc != 0 ]]; then
  transaction_safe=1
fi
if [[ $transaction_safe == 1 && $qualification_contaminated == 0 ]]; then
  if ! transition_graphical_counter_after_receipt || \
      ! require_graphical_transition_clean; then
    qualification_contaminated=1
    say 'CODESKEPTIC_GUIDED_QUALIFICATION_CONTAMINATED coredump_or_helper_delta=1' >&2
  fi
fi
if ! restoration_surface_clean; then
  transaction_safe=0
fi

if [[ $transaction_safe == 1 && $qualification_contaminated == 0 ]]; then
  if ! require_graphical_transition_clean; then
    qualification_contaminated=1
    say 'CODESKEPTIC_GUIDED_QUALIFICATION_CONTAMINATED coredump_or_helper_delta=1' >&2
  fi
fi
if [[ $transaction_safe == 1 && $qualification_contaminated == 1 ]]; then
  if ! capture_graphical_transition_baseline || ! restoration_surface_clean; then
    transaction_safe=0
  fi
fi
if [[ $qualification_contaminated == 1 && $payload_rc == 0 ]]; then
  payload_rc=2
fi
say "CODESKEPTIC_GUIDED_PAYLOAD_EXIT=$payload_rc"

if [[ $transaction_safe != 1 || $(/usr/bin/nmcli networking) != enabled || \
      -e $authority_cgroup || -L $authority_cgroup ]]; then
  if ! publish_result 0 not-attempted; then
    say 'CODESKEPTIC_GUIDED_RESULT_PUBLICATION_FAILED' >&2
  fi
  say 'Güvenli restorasyon kanıtlanamadı; grafik hedef otomatik başlatılmadı.' >&2
  say "Kurtarma dosyası: $recovery_script" >&2
  ring
  exit 4
fi

ring
say 'Confirmation işlemi döndü ve sistem restorasyonu doğrulandı.'
await_graphical_restore_authorization
authorization_rc=$?
if [[ $authorization_rc != 0 ]]; then
  deferred_safe=1
  if ! require_graphical_transition_clean || ! restoration_surface_clean; then
    deferred_safe=0
    [[ $payload_rc != 0 ]] || payload_rc=2
  fi
  if ! publish_result "$deferred_safe" not-attempted; then
    say 'CODESKEPTIC_GUIDED_RESULT_PUBLICATION_FAILED' >&2
  fi
  if [[ $deferred_safe == 1 ]]; then
    say 'Grafik ekranı açma yetkisi alınmadı.' >&2
  else
    say 'Bekleme sırasında yeni coredump, helper etkinliği veya failed unit oluştu.' >&2
  fi
  say 'Hazır olduğunuzda bu TTY üzerinde yalnız şu komutu çalıştırın: sudo systemctl isolate graphical.target' >&2
  ring
  if [[ -n $signal_received ]]; then
    exit "$(signal_exit_code)"
  fi
  exit "$authorization_rc"
fi
say 'Şimdi sudo parolanızı girip Enter tuşuna basın.'
/usr/bin/sudo -v
sudo_rc=$?
if [[ $sudo_rc == 0 ]] && restore_graphical_noninteractive; then
  if require_graphical_transition_clean; then
    graphical_rc=0
  else
    graphical_rc=2
    say 'Grafik geçişi yeni coredump, DrKonqi etkinliği veya failed unit üretti.' >&2
  fi
else
  graphical_rc=2
fi
if ! publish_result 1 "$graphical_rc"; then
  say 'CODESKEPTIC_GUIDED_RESULT_PUBLICATION_FAILED' >&2
  ring
  exit 4
fi
ring
if [[ $graphical_rc == 0 ]]; then
  say "CODESKEPTIC_GUIDED_SYSTEM_RESTORED payload_exit=$payload_rc result=$result_file"
else
  say "CODESKEPTIC_GUIDED_GRAPHICAL_RESTORE_FAILED result=$result_file" >&2
  exit 4
fi
if [[ -n $signal_received ]]; then
  exit "$(signal_exit_code)"
fi
if [[ $payload_rc == 0 ]]; then
  say 'CODESKEPTIC_GUIDED_CONFIRMATION_SUCCESS payload_exit=0'
else
  say "CODESKEPTIC_GUIDED_CONFIRMATION_FAILED payload_exit=$payload_rc" >&2
fi
say "CODESKEPTIC_GUIDED_FINAL_EXIT=$payload_rc"
exit "$payload_rc"
