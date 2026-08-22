#!/usr/bin/env bash
set -euo pipefail

readonly operator_root=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-operator-88e369b-attempt24
readonly run_root=/run/codeskeptic-p10-07
readonly controller_local=$operator_root/headless-controller-root.sh
readonly controller_sha=37fc9bd118cbb1a969f13593fee65105657bb57e68993567496f4cfac6645250
readonly controller_staged=$run_root/headless-controller-root-$controller_sha.sh
readonly launcher_local=$operator_root/cgroup-launcher.sh
readonly launcher_sha=49948c981ab933baf32b7a619fe965e821e1b539b0dcd4a0df388afe260dcade
readonly helper_local=$operator_root/vscode-helper-drain.py
readonly helper_sha=67ddbda20b788b0ea7af0fbcc4479221c038292e51b908914b820d984569206a
readonly helper_staged=$run_root/vscode-helper-drain-$helper_sha.py
readonly operator_manifest_sha=2bedaa7df684c04190ed6cc098469cb7f649c0e8268a9d95fd7c6e8081cac25f
readonly rejection_root=/var/lib/codeskeptic-p10-07/rejections
readonly rejection_bundle=$rejection_root/20260817T150314Z-idle-preflight-68f2993
readonly rejection_ledger=$rejection_root/LEDGER-20260817T150314Z-idle-preflight-68f2993.sha256
readonly lock=/run/codeskeptic-p10-07-headless.lock
readonly precontroller_status=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-precontroller-88e369b-attempt24.status
readonly helper_log=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-vscode-helper-88e369b-attempt24.log
readonly -a user_graphical_targets=(
  plasma-workspace-wayland.target
  plasma-workspace.target
  plasma-core.target
  xdg-desktop-autostart.target
  graphical-session.target
  graphical-session-pre.target
)

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH

precontroller_fd_open=0
precontroller_step=not-started
coredump_handoff_sha=
drkonqi_handoff_accepted=

finish_precontroller_failure() {
  local rc=$?
  trap - EXIT
  ((rc != 0)) || rc=2
  seal_helper_log || rc=2
  if ((precontroller_fd_open == 1)); then
    printf 'CODESKEPTIC_PRECONTROLLER_EXIT=%d\n' "$rc" >&3 || rc=2
    printf 'CODESKEPTIC_PRECONTROLLER_LAST_STEP=%s\n' "$precontroller_step" >&3 || rc=2
    /usr/bin/sync -f "$precontroller_status" || rc=2
    /usr/bin/chmod 0400 "$precontroller_status" || rc=2
    exec 3>&-
    precontroller_fd_open=0
    /usr/bin/sync -f "${precontroller_status%/*}" || rc=2
  fi
  exit "$rc"
}

seal_helper_log() {
  local metadata
  [[ -e $helper_log || -L $helper_log ]] || return 0
  [[ ! -L $helper_log && -f $helper_log ]] || return 2
  metadata=$(/usr/bin/stat -c '%U:%G:%a:%F' "$helper_log") || return 2
  [[ $metadata == tanzer:tanzer:600:regular\ file || \
        $metadata == tanzer:tanzer:400:regular\ file ]] || return 2
  /usr/bin/chmod 0400 "$helper_log" || return 2
  /usr/bin/sync -f "$helper_log" || return 2
  /usr/bin/sync -f "${helper_log%/*}" || return 2
}

record_precontroller_step() {
  [[ $1 =~ ^[a-z][a-z0-9-]*$ ]] || return 2
  precontroller_step=$1
  printf 'CODESKEPTIC_PRECONTROLLER_STEP=%s\n' "$precontroller_step" >&3
  /usr/bin/sync -f "$precontroller_status"
}

seal_precontroller_status() {
  record_precontroller_step controller-handoff
  /usr/bin/chmod 0400 "$precontroller_status"
  /usr/bin/sync -f "$precontroller_status"
  exec 3>&-
  precontroller_fd_open=0
  /usr/bin/sync -f "${precontroller_status%/*}"
  trap - EXIT
}

userctl() {
  /usr/bin/env \
    XDG_RUNTIME_DIR=/run/user/1000 \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    /usr/bin/systemctl --user --no-pager "$@"
}

coredump_inventory_sha() {
  local inventory
  inventory=$(/usr/bin/coredumpctl --quiet --no-pager --no-legend \
    --json=short list) || return 2
  printf '%s' "$inventory" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
}

require_no_failed_units() {
  local failed
  failed=$(/usr/bin/systemctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]] || return 2
  failed=$(userctl --failed --no-legend --plain) || return 2
  [[ -z $failed ]]
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

require_handoff_unchanged() {
  local latest accepted
  latest=$(coredump_inventory_sha) || return 2
  accepted=$(userctl show drkonqi-coredump-launcher.socket \
    -p NAccepted --value) || return 2
  [[ $latest == "$coredump_handoff_sha" && \
        $accepted == "$drkonqi_handoff_accepted" ]] || return 2
  require_no_coredump_helper_instances || return 2
  require_no_failed_units
}

keyboxd_pids=()
observed_keyboxd_starttime=
observed_keyboxd_cmdline=
observed_keyboxd_cgroup=

collect_keyboxd_pids() {
  local output rc pid
  local -A seen=()
  keyboxd_pids=()
  if output=$(/usr/bin/pgrep -u 1000 -x keyboxd); then
    [[ -n $output ]] || return 2
  else
    rc=$?
    [[ $rc == 1 ]] && return 0
    echo 'cannot enumerate keyboxd processes' >&2
    return 2
  fi
  while IFS= read -r pid; do
    [[ $pid =~ ^[1-9][0-9]*$ && -z ${seen[$pid]+x} ]] || return 2
    seen[$pid]=1
    keyboxd_pids+=("$pid")
  done <<< "$output"
}

read_keyboxd_identity() {
  local pid=$1 stat_line rest uid_line exe cmdline cgroup
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat && \
        -r /proc/$pid/status && -r /proc/$pid/cmdline && \
        -r /proc/$pid/cgroup ]] || return 1
  stat_line=$(<"/proc/$pid/stat") || return 1
  rest=${stat_line##*) }
  set -- $rest
  (($# >= 20)) || return 1
  observed_keyboxd_starttime=${20}
  uid_line=$(/usr/bin/awk '/^Uid:/{print $2 " " $3 " " $4 " " $5}' "/proc/$pid/status") \
    || return 1
  [[ $uid_line == '1000 1000 1000 1000' ]] || return 2
  exe=$(/usr/bin/readlink -e "/proc/$pid/exe") || return 1
  cmdline=$(/usr/bin/tr '\0' '\n' < "/proc/$pid/cmdline") || return 1
  cgroup=$(<"/proc/$pid/cgroup") || return 1
  [[ $exe == /usr/libexec/keyboxd && \
        $cmdline == $'keyboxd\n--homedir\n/home/tanzer/.gnupg\n--daemon' ]] || return 2
  observed_keyboxd_cmdline=$cmdline
  observed_keyboxd_cgroup=$cgroup
}

validate_keyboxd_portal_unit() {
  local unit=$1 output line key value
  local -A props=()
  [[ $unit =~ ^dbus-:[0-9]+\.[0-9]+-org\.freedesktop\.impl\.portal\.desktop\.kwallet@[0-9]+\.service$ ]] \
    || return 2
  output=$(userctl show "$unit" \
    -p Id -p Description -p LoadState -p ActiveState -p SubState \
    -p UnitFileState -p Transient -p Type -p KillMode -p SendSIGKILL \
    -p MainPID -p ControlPID -p FragmentPath -p SourcePath -p ExecStart -p Result) \
    || return 2
  while IFS= read -r line; do
    [[ $line == *=* ]] || return 2
    key=${line%%=*}; value=${line#*=}
    [[ -z ${props[$key]+x} ]] || return 2
    props[$key]=$value
  done <<< "$output"
  for key in Id Description LoadState ActiveState SubState UnitFileState \
    Transient Type KillMode SendSIGKILL MainPID ControlPID FragmentPath \
    SourcePath ExecStart Result; do
    [[ -n ${props[$key]+x} ]] || return 2
  done
  [[ ${props[Id]} == "$unit" && ${props[Description]} == "$unit" && \
        ${props[LoadState]} == loaded && ${props[UnitFileState]} == transient && \
        ${props[Transient]} == yes && ${props[Type]} == simple && \
        ${props[KillMode]} == process && ${props[SendSIGKILL]} == yes && \
        ${props[MainPID]} =~ ^[0-9]+$ && ${props[ControlPID]} == 0 && \
        ${props[FragmentPath]} == "/run/user/1000/systemd/transient/$unit" && \
        -z ${props[SourcePath]} && \
        ${props[ExecStart]} =~ ^\{\ path=/usr/bin/ksecretd\ \;\ argv\[\]=/usr/bin/ksecretd\ \;\ ignore_errors=no\ \; ]] \
    || return 2
  case "${props[ActiveState]}/${props[SubState]}/${props[Result]}/${props[MainPID]}" in
    inactive/dead/success/0|failed/failed/exit-code/0) ;;
    active/running/success/[1-9]*|deactivating/stop-*/success/[0-9]*) return 3 ;;
    *) return 2 ;;
  esac
}

validate_keyboxd_portal_process() {
  local pid=$1 unit initial_start initial_cmdline initial_cgroup
  read_keyboxd_identity "$pid" || return $?
  initial_start=$observed_keyboxd_starttime
  initial_cmdline=$observed_keyboxd_cmdline
  initial_cgroup=$observed_keyboxd_cgroup
  [[ $initial_cgroup =~ ^0::/user\.slice/user-1000\.slice/user@1000\.service/app\.slice/(dbus-:[0-9]+\.[0-9]+-org\.freedesktop\.impl\.portal\.desktop\.kwallet@[0-9]+\.service)$ ]] \
    || return 2
  unit=${BASH_REMATCH[1]}
  validate_keyboxd_portal_unit "$unit" || return $?
  read_keyboxd_identity "$pid" || return $?
  [[ $observed_keyboxd_starttime == "$initial_start" && \
        $observed_keyboxd_cmdline == "$initial_cmdline" && \
        $observed_keyboxd_cgroup == "$initial_cgroup" ]] || return 2
}

drain_keyboxd_portal_helpers() {
  local pid rc stable=0 deadline
  deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    collect_keyboxd_pids || return 2
    if ((${#keyboxd_pids[@]} == 0)); then
      echo CODESKEPTIC_HEADLESS_KEYBOXD_PORTAL_HELPERS_ABSENT
      return 0
    fi
    stable=1
    for pid in "${keyboxd_pids[@]}"; do
      if validate_keyboxd_portal_process "$pid"; then
        :
      else
        rc=$?
        if [[ $rc == 3 || ( $rc == 1 && ! -d /proc/$pid ) ]]; then
          stable=0
          break
        fi
        echo "keyboxd process is not an exact stopped KWallet portal helper: $pid" >&2
        return 2
      fi
    done
    ((stable == 1)) && break
    /usr/bin/sleep 0.10
  done
  ((stable == 1)) || {
    echo 'keyboxd process inventory changed repeatedly' >&2
    return 2
  }
  if /usr/bin/pgrep -u 1000 -x 'gpg|gpg2|gpgsm' >/dev/null 2>&1; then
    echo 'an interactive GnuPG process is active; refusing keyboxd shutdown' >&2
    return 2
  else
    rc=$?
    [[ $rc == 1 ]] || return 2
  fi
  printf 'CODESKEPTIC_HEADLESS_KEYBOXD_PORTAL_HELPERS_VALIDATED=%d\n' \
    "${#keyboxd_pids[@]}"
  /usr/bin/env -i HOME=/home/tanzer USER=tanzer LOGNAME=tanzer \
    PATH=/usr/sbin:/usr/bin LC_ALL=C LANG=C \
    /usr/bin/gpgconf --kill keyboxd
  deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    collect_keyboxd_pids || return 2
    if ((${#keyboxd_pids[@]} == 0)); then
      echo CODESKEPTIC_HEADLESS_KEYBOXD_PORTAL_HELPERS_DRAINED
      return 0
    fi
    for pid in "${keyboxd_pids[@]}"; do
      validate_keyboxd_portal_process "$pid" || return 2
    done
    /usr/bin/sleep 0.25
  done
  printf 'keyboxd portal helpers did not drain: %s\n' "${keyboxd_pids[*]}" >&2
  return 2
}

[[ $(/usr/bin/id -un) == tanzer ]] || { echo 'run this authorizer as tanzer' >&2; exit 2; }
[[ $# == 2 && $1 =~ ^[0-9a-f]{64}$ && $2 =~ ^[0-9]+$ ]] || {
  echo 'authorizer requires inherited coredump SHA and DrKonqi NAccepted' >&2
  exit 2
}
coredump_handoff_sha=$1
drkonqi_handoff_accepted=$2
[[ -t 0 && -t 1 ]] || { echo 'headless authorizer requires an interactive TTY' >&2; exit 2; }
caller_tty=$(/usr/bin/tty)
[[ $caller_tty =~ ^/dev/tty[1-9][0-9]*$ ]] || {
  echo "headless authorizer requires a local virtual console, observed: $caller_tty" >&2
  exit 2
}
[[ ! -e $precontroller_status && ! -L $precontroller_status && \
      ! -e $helper_log && ! -L $helper_log ]] || {
  echo 'V7 confirmation Attempt-24 pre-controller evidence already exists' >&2
  exit 2
}
exec 3> "$precontroller_status"
precontroller_fd_open=1
trap finish_precontroller_failure EXIT
[[ ! -L $precontroller_status && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$precontroller_status") == \
        tanzer:tanzer:600:regular\ empty\ file ]] || exit 2
record_precontroller_step started
[[ $(/usr/bin/sha256sum "$controller_local" | /usr/bin/cut -d' ' -f1) == "$controller_sha" ]] || {
  echo 'local headless controller SHA256 drift' >&2
  exit 2
}
[[ ! -L $launcher_local && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$launcher_local") == \
        tanzer:tanzer:500:regular\ file && \
      $(/usr/bin/sha256sum "$launcher_local" | /usr/bin/cut -d' ' -f1) == "$launcher_sha" ]] || {
  echo 'local V7 Attempt-24 cgroup launcher identity drift' >&2
  exit 2
}
[[ ! -L $helper_local && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$helper_local") == \
        tanzer:tanzer:555:regular\ file && \
      $(/usr/bin/sha256sum "$helper_local" | /usr/bin/cut -d' ' -f1) == "$helper_sha" ]] || {
  echo 'local VS Code absence checker identity drift' >&2
  exit 2
}
[[ $(/usr/bin/sha256sum "$operator_root/SHA256SUMS" | /usr/bin/cut -d' ' -f1) == "$operator_manifest_sha" ]] || {
  echo 'operator manifest SHA256 drift' >&2
  exit 2
}
(
  cd "$operator_root"
  /usr/bin/sha256sum -c SHA256SUMS
)
(
  cd "$rejection_root"
  /usr/bin/sha256sum -c "$rejection_ledger"
)
(
  cd "$rejection_bundle"
  /usr/bin/sha256sum -c FORENSIC_SHA256SUMS
)
record_precontroller_step local-authority-verified

[[ $(/usr/bin/systemctl show graphical.target -p ActiveState --value) == inactive && \
      $(/usr/bin/systemctl show multi-user.target -p ActiveState --value) == active && \
      $(/usr/bin/systemctl show plasmalogin.service -p ActiveState --value) == inactive ]] || {
  echo 'system must already be isolated to multi-user.target' >&2
  exit 2
}
require_handoff_unchanged || {
  echo 'inherited coredump handoff baseline changed before authorization' >&2
  exit 2
}
/usr/bin/sudo -n -v
/usr/bin/sudo -n /usr/bin/install -d -o root -g root -m 0755 "$run_root"
/usr/bin/sudo -n /usr/bin/install -o root -g root -m 0555 \
  "$helper_local" "$helper_staged"
[[ ! -L $helper_staged && \
      $(/usr/bin/sudo -n /usr/bin/stat -c '%U:%G:%a:%F' "$helper_staged") == \
        root:root:555:regular\ file && \
      $(/usr/bin/sudo -n /usr/bin/sha256sum "$helper_staged" | /usr/bin/cut -d' ' -f1) == \
        "$helper_sha" ]] || {
  echo 'root-owned VS Code absence checker staging drift' >&2
  exit 2
}
record_precontroller_step vscode-helper-staged
record_precontroller_step vscode-absence-check-started
/usr/bin/env -i HOME=/home/tanzer USER=tanzer LOGNAME=tanzer \
  PATH=/usr/sbin:/usr/bin LC_ALL=C LANG=C \
  /usr/bin/python3 -I -B "$helper_staged" --require-absent 2>&1 | \
  /usr/bin/tee "$helper_log"
seal_helper_log
record_precontroller_step vscode-absence-check-passed

userctl stop -- "${user_graphical_targets[@]}"
for target in "${user_graphical_targets[@]}"; do
  [[ $(userctl show "$target" -p ActiveState --value) == inactive ]] || {
    echo "user graphical target did not stop: $target" >&2
    exit 2
  }
done
echo CODESKEPTIC_HEADLESS_USER_GRAPHICAL_TARGETS_STOPPED
record_precontroller_step user-graphical-targets-stopped
drain_keyboxd_portal_helpers
record_precontroller_step keyboxd-helpers-drained
require_handoff_unchanged || {
  echo 'new coredump, DrKonqi activity, or failed unit before controller handoff' >&2
  exit 2
}
record_precontroller_step coredump-handoff-verified

/usr/bin/sudo -n /usr/bin/install -o root -g root -m 0500 \
  "$operator_root/snapshot-builder.sh" "$run_root/snapshot-builder.sh"
/usr/bin/sudo -n /usr/bin/install -o root -g root -m 0500 \
  "$launcher_local" "$run_root/cgroup-launcher.sh"
for helper in tree-hash.py run-static-preflight.sh container-entry.py \
  cgroup-smoke.py static-preflight.py git-authority-entry.sh \
  run-confirmation.sh; do
  /usr/bin/sudo -n /usr/bin/install -o root -g root -m 0555 \
    "$operator_root/$helper" "$run_root/$helper"
done
/usr/bin/sudo -n /usr/bin/install -o root -g root -m 0500 \
  "$controller_local" "$controller_staged"

readonly expected_modes="root:root:755 $run_root
root:root:500 $run_root/snapshot-builder.sh
root:root:555 $run_root/tree-hash.py
root:root:500 $run_root/cgroup-launcher.sh
root:root:555 $run_root/run-static-preflight.sh
root:root:555 $run_root/container-entry.py
root:root:555 $run_root/cgroup-smoke.py
root:root:555 $run_root/static-preflight.py
root:root:555 $run_root/git-authority-entry.sh
root:root:555 $run_root/run-confirmation.sh
root:root:555 $helper_staged
root:root:500 $controller_staged"
actual_modes=$(/usr/bin/sudo -n /usr/bin/stat -c '%U:%G:%a %n' \
  "$run_root" \
  "$run_root/snapshot-builder.sh" \
  "$run_root/tree-hash.py" \
  "$run_root/cgroup-launcher.sh" \
  "$run_root/run-static-preflight.sh" \
  "$run_root/container-entry.py" \
  "$run_root/cgroup-smoke.py" \
  "$run_root/static-preflight.py" \
  "$run_root/git-authority-entry.sh" \
  "$run_root/run-confirmation.sh" \
  "$helper_staged" \
  "$controller_staged")
[[ $actual_modes == "$expected_modes" ]] || {
  echo 'root-owned headless staging ownership or mode mismatch' >&2
  exit 2
}

readonly expected_hashes="b7f048fb4a5f07443510b4de495b0728c895da65496eb5be34b28d7ab64dc84a  $run_root/snapshot-builder.sh
b7765dcf006e346ebcca69b93a5a1686e51ec760fb06bd09e36eceaf19cb034d  $run_root/tree-hash.py
$launcher_sha  $run_root/cgroup-launcher.sh
05b3f1425cefcb36f6313da54762e1c9860a9cdb9f5d4f9fa1a06d027e516e32  $run_root/run-static-preflight.sh
4554daf69ee902d746b9089dd4ad18ceee512d92b8e3c2ebb0fc7912fdb5c729  $run_root/container-entry.py
d4b2b906b833d74a1a0a21981d8715664ea7e2eb109f16a79ceaacbe5e43b985  $run_root/cgroup-smoke.py
8ecfa3aace9d61428de137f188eda3dd776d0421b9165836a44f3c8911d13492  $run_root/static-preflight.py
fbd2ff8e9db7cd71bed7c4863ce7604fad336372e662181db30a1e4726cb2d0a  $run_root/git-authority-entry.sh
1618ba5ac9d394b0ea03456d9615325624694a4a4a15009dfa1ea30a0a26696e  $run_root/run-confirmation.sh
$helper_sha  $helper_staged
$controller_sha  $controller_staged"
actual_hashes=$(/usr/bin/sudo -n /usr/bin/sha256sum \
  "$run_root/snapshot-builder.sh" \
  "$run_root/tree-hash.py" \
  "$run_root/cgroup-launcher.sh" \
  "$run_root/run-static-preflight.sh" \
  "$run_root/container-entry.py" \
  "$run_root/cgroup-smoke.py" \
  "$run_root/static-preflight.py" \
  "$run_root/git-authority-entry.sh" \
  "$run_root/run-confirmation.sh" \
  "$helper_staged" \
  "$controller_staged")
[[ $actual_hashes == "$expected_hashes" ]] || {
  echo 'root-owned headless staging SHA256 mismatch' >&2
  exit 2
}
echo CODESKEPTIC_HEADLESS_ROOT_STAGING_VERIFIED
record_precontroller_step root-staging-verified
/usr/bin/sudo -n "$run_root/snapshot-builder.sh"
record_precontroller_step snapshot-ready
require_handoff_unchanged || {
  echo 'new coredump, helper activity, or failed unit during controller staging' >&2
  exit 2
}
record_precontroller_step final-coredump-handoff-verified
seal_precontroller_status
exec /usr/bin/sudo -n /usr/bin/flock --exclusive "$lock" "$controller_staged" \
  "$coredump_handoff_sha" "$drkonqi_handoff_accepted"
