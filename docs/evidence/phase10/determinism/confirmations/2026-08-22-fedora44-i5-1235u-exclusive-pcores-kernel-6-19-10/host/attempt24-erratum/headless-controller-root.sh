#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE \
  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_CONFIG_SYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT \
  SYSTEMD_PAGER SYSTEMD_EDITOR SYSTEMD_LOG_TARGET SYSTEMD_LOG_LEVEL

readonly target_user=tanzer
readonly target_uid=1000
readonly user_runtime=/run/user/1000
readonly run_root=/run/codeskeptic-p10-07
readonly authority_root=/var/lib/codeskeptic-p10-07
readonly headless_root=$authority_root/headless
readonly headless_log=$headless_root/88e369b-confirmation-v7-24.log
readonly transaction_journal=$headless_root/88e369b-confirmation-v7-24.journal
readonly transaction_journal_tmp=$headless_root/.88e369b-confirmation-v7-24.journal.tmp
readonly transaction_journal_sha=$headless_root/88e369b-confirmation-v7-24.journal.sha256
readonly transaction_journal_sha_tmp=$headless_root/.88e369b-confirmation-v7-24.journal.sha256.tmp
readonly terminal_receipt=$headless_root/88e369b-confirmation-v7-24.terminal
readonly terminal_receipt_tmp=$headless_root/.88e369b-confirmation-v7-24.terminal.tmp
readonly recovery_script=$headless_root/recover-88e369b-confirmation-v7-24.sh
readonly recovery_lock=/run/codeskeptic-p10-07-headless.lock
readonly active_stage=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-88e369b-attempt24
readonly feature_repo=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-source-worktree
readonly primary_repo=/home/tanzer/Projects/CodeSkeptic
readonly feature_head=88e369b21675e64e0a92842b0ce22f0c8148745e
readonly main_head=7dfd37596414c9512316093ff4fb6b039673f55f
readonly rejection_root=$authority_root/rejections
readonly rejection_bundle=$rejection_root/20260817T150314Z-idle-preflight-68f2993
readonly rejection_ledger=$rejection_root/LEDGER-20260817T150314Z-idle-preflight-68f2993.sha256
readonly cooldown_seconds=180
readonly transient_drain_timeout_seconds=240
readonly transient_drain_progress_seconds=15
readonly measurement_cpus=0-3
readonly controller_cpus=4-11
readonly expected_os='Linux 6.19.10-300.fc44.x86_64'
readonly expected_wireplumber_main=wireplumber-0.5.14-1.1.codeskeptic.fc44.x86_64
readonly expected_wireplumber_libs=wireplumber-libs-0.5.14-1.1.codeskeptic.fc44.x86_64
readonly expected_wireplumber_hashes='7f13a431f6f583ffed76a4e41992a5b1de034bd684010f977b638c359b27ed8f  /usr/bin/wireplumber
1ca47df2f52a238a790ad078ebad4dbb5f2d2793bb26edd2185b000decfe95eb  /usr/lib64/libwireplumber-0.5.so.0.514.0
d757620f8ee18a95f10b432136738726050f3bd9b2b7306c2e94cc89b15cf3be  /usr/lib64/wireplumber-0.5/libwireplumber-module-lua-scripting.so
f8a0f7edee013239f0dc8f03255fed973ee1d48ea2a330ba2520e9ad4de9d6f6  /usr/lib64/wireplumber-0.5/libwireplumber-module-portal-permissionstore.so'
readonly systemd_unit_starting_message_id=7d4958e842da4a758f6c1cdc7b36dcc5
readonly systemd_unit_started_message_id=39f53479d3a045ac8e11786248231fbf
readonly systemd_unit_failed_message_id=be02cf6855d2428ba40df7e9d022f03d
readonly -a required_inactive_system_units=(
  graphical.target
  plasmalogin.service
)
readonly -a user_graphical_targets=(
  plasma-workspace-wayland.target
  plasma-workspace.target
  plasma-core.target
  xdg-desktop-autostart.target
  graphical-session.target
  graphical-session-pre.target
)

mode=run
caller_tty=
log_created=0
restoration_armed=0
quiet_gate_passed=0
network_restore_needed=0
system_quiesce_started=0
user_quiesce_started=0
pause_restore_needed=0
pause_pid=
pause_starttime=
pause_uid=
pause_cmdline_sha=
pause_cgroup_sha=
pause_original_affinity=
observed_uid=
observed_starttime=
observed_cmdline_sha=
observed_cgroup_sha=
terminal_restoration_failed=
terminal_payload_exit=
terminal_finish=
terminal_journal_sha=
coredump_baseline_sha=
drkonqi_socket_accepted_baseline=
drkonqi_socket_accepted_journal_baseline=
recovery_coredump_baseline_sha=
recovery_drkonqi_socket_accepted_baseline=
system_activation_cursor=
user_activation_cursor=
declare -a system_planned_units=()
declare -a system_mask_attempted_units=()
declare -a system_masked_units=()
declare -a system_restore_units=()
declare -a user_planned_units=()
declare -a user_mask_attempted_units=()
declare -a user_masked_units=()
declare -a user_restore_units=()
declare -a authority_bash_pids=()
declare -a active_user_transients=()
declare -A system_original_unit_files=()
declare -A user_original_unit_files=()
declare -A system_active_enter_epoch=()
declare -A system_inactive_exit_epoch=()
declare -A user_active_enter_epoch=()
declare -A user_inactive_exit_epoch=()
declare -A system_masked_epoch_mode=()
declare -A system_masked_load_state=()
declare -A user_masked_epoch_mode=()
declare -A user_masked_load_state=()

quiescent_load=
quiescent_state=
quiescent_substate=
quiescent_result=
quiescent_unit_file=
quiescent_job=
quiescent_active_enter=
quiescent_inactive_exit=
quiescent_epoch_mode=

emit_tty() {
  [[ -n $caller_tty && -c $caller_tty ]] || return 0
  printf '%s\n' "$*" > "$caller_tty" || true
}

array_contains() {
  local needle=$1 item
  shift
  for item in "$@"; do
    [[ $item == "$needle" ]] && return 0
  done
  return 1
}

remove_recoverable_atomic_tmp() {
  local path=$1 metadata
  if [[ ! -e $path && ! -L $path ]]; then
    return 0
  fi
  [[ ! -L $path ]] || return 2
  metadata=$(/usr/bin/stat -c '%U:%G:%a:%F' "$path") || return 2
  [[ $metadata == root:root:600:regular\ file || \
        $metadata == root:root:444:regular\ file ]] || return 2
  /usr/bin/rm -f -- "$path"
}

userctl() {
  /usr/bin/runuser -u "$target_user" -- \
    /usr/bin/env -i \
      HOME=/home/tanzer USER="$target_user" LOGNAME="$target_user" \
      PATH=/usr/sbin:/usr/bin LC_ALL=C LANG=C \
      XDG_RUNTIME_DIR="$user_runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
      /usr/bin/systemctl --user --no-pager "$@"
}

userjournal() {
  /usr/bin/runuser -u "$target_user" -- \
    /usr/bin/env -i \
      HOME=/home/tanzer USER="$target_user" LOGNAME="$target_user" \
      PATH=/usr/sbin:/usr/bin LC_ALL=C LANG=C \
      XDG_RUNTIME_DIR="$user_runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
      /usr/bin/journalctl --user --quiet --no-pager "$@"
}

usergit() {
  local repo=$1
  shift
  /usr/bin/runuser -u "$target_user" -- \
    /usr/bin/env -i \
      HOME=/home/tanzer USER="$target_user" LOGNAME="$target_user" \
      PATH=/usr/sbin:/usr/bin LC_ALL=C LANG=C \
      GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      /usr/bin/git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
        -c core.untrackedCache=false -c submodule.recurse=false \
        -C "$repo" "$@"
}

system_value() {
  /usr/bin/systemctl show "$2" -p "$1" --value
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

verify_initial_unit_state() {
  local scope=$1 unit=$2 expected_state=$3 substate result job main_pid
  if [[ $scope == system ]]; then
    substate=$(system_value SubState "$unit") || return 2
    result=$(system_value Result "$unit") || return 2
    job=$(system_value Job "$unit") || return 2
    main_pid=$(system_value MainPID "$unit") || return 2
  elif [[ $scope == user ]]; then
    substate=$(user_value SubState "$unit") || return 2
    result=$(user_value Result "$unit") || return 2
    job=$(user_value Job "$unit") || return 2
    main_pid=$(user_value MainPID "$unit") || return 2
  else
    return 2
  fi
  [[ -z $job ]] || return 2
  if [[ $expected_state == inactive ]]; then
    [[ $substate == dead ]] || return 2
    case "$unit" in
      *.target) [[ -z $result ]] ;;
      *.service|*.timer|*.socket|*.path) [[ $result == success ]] ;;
      *) return 2 ;;
    esac
    return
  fi
  [[ $expected_state == active ]] || return 2
  case "$unit" in
    *.service) [[ $result == success && $substate == running && \
                    $main_pid =~ ^[1-9][0-9]*$ ]] ;;
    *.timer) [[ $result == success && \
                  ( $substate == waiting || $substate == elapsed ) ]] ;;
    *.socket) [[ $result == success && \
                   ( $substate == listening || $substate == running ) ]] ;;
    *.path) [[ $result == success && \
                 ( $substate == waiting || $substate == running ) ]] ;;
    *.target) [[ -z $result && $substate == active ]] ;;
    *) return 2 ;;
  esac
}

socket_endpoint_listen_count() {
  local endpoint=$1 number ref protocol flags type state inode path extra count=0
  [[ -r /proc/net/unix ]] || return 2
  while read -r number ref protocol flags type state inode path extra; do
    [[ -z ${extra:-} ]] || return 2
    [[ ${path:-} == "$endpoint" && $flags == 00010000 && $state == 01 ]] || continue
    ((count += 1))
  done < /proc/net/unix
  printf '%s\n' "$count"
}

verify_frozen_user_socket_endpoints() {
  local unit=$1 phase=$2 observed_load=${3:-loaded}
  local expected_listen expected_accept listen accept remove
  local endpoint metadata count
  local -a endpoints=()
  case "$unit" in
    drkonqi-coredump-launcher.socket)
      expected_listen='/run/user/1000/drkonqi-coredump-launcher (SequentialPacket)'
      expected_accept=yes
      endpoints=(/run/user/1000/drkonqi-coredump-launcher) ;;
    pipewire-pulse.socket)
      expected_listen='/run/user/1000/pulse/native (Stream)'
      expected_accept=no
      endpoints=(/run/user/1000/pulse/native) ;;
    pipewire.socket)
      expected_listen=$'/run/user/1000/pipewire-0 (Stream)\n/run/user/1000/pipewire-0-manager (Stream)'
      expected_accept=no
      endpoints=(/run/user/1000/pipewire-0 /run/user/1000/pipewire-0-manager) ;;
    ssh-agent.socket)
      expected_listen='/run/user/1000/ssh-agent.socket (Stream)'
      expected_accept=no
      endpoints=(/run/user/1000/ssh-agent.socket) ;;
    systemd-ask-password.socket)
      expected_listen='/run/user/1000/systemd/io.systemd.AskPassword (Stream)'
      expected_accept=yes
      endpoints=(/run/user/1000/systemd/io.systemd.AskPassword) ;;
    *) return 2 ;;
  esac
  if [[ $observed_load == loaded ]]; then
    listen=$(user_value Listen "$unit") || return 2
    accept=$(user_value Accept "$unit") || return 2
    remove=$(user_value RemoveOnStop "$unit") || return 2
    [[ $listen == "$expected_listen" && $accept == "$expected_accept" && \
          $remove == no ]] || {
      echo "user socket property contract drift: unit=$unit phase=$phase" >&2
      return 2
    }
  elif [[ $observed_load == masked && $phase == stopped ]]; then
    : # The active contract was frozen before mutation; GC removes live properties.
  else
    echo "user socket load contract drift: unit=$unit phase=$phase load=$observed_load" >&2
    return 2
  fi
  for endpoint in "${endpoints[@]}"; do
    count=$(socket_endpoint_listen_count "$endpoint") || return 2
    if [[ $phase == active ]]; then
      [[ $count == 1 && ! -L $endpoint && -S $endpoint ]] || return 2
      metadata=$(/usr/bin/stat -c '%U:%G:%a:%F' "$endpoint") || return 2
      case "$unit" in
        pipewire-pulse.socket|pipewire.socket)
          [[ $metadata == tanzer:tanzer:666:socket ]] || return 2 ;;
        *) [[ $metadata == tanzer:tanzer:600:socket ]] || return 2 ;;
      esac
    elif [[ $phase == stopped ]]; then
      [[ $count == 0 ]] || return 2
    else
      return 2
    fi
  done
}

validate_inert_user_service() {
  local unit=$1 expected_path=$2 expected_unit_file=$3 expected_refuse_stop=$4
  [[ $(user_value LoadState "$unit") == loaded && \
        $(user_value ActiveState "$unit") == active && \
        $(user_value SubState "$unit") == exited && \
        $(user_value UnitFileState "$unit") == "$expected_unit_file" && \
        $(user_value Type "$unit") == oneshot && \
        $(user_value RemainAfterExit "$unit") == yes && \
        $(user_value RefuseManualStart "$unit") == no && \
        $(user_value RefuseManualStop "$unit") == "$expected_refuse_stop" && \
        $(user_value Transient "$unit") == no && \
        $(user_value MainPID "$unit") == 0 && \
        $(user_value ControlPID "$unit") == 0 && \
        $(user_value Result "$unit") == success && \
        $(user_value ExecMainCode "$unit") == 1 && \
        $(user_value ExecMainStatus "$unit") == 0 && \
        $(user_value FragmentPath "$unit") == "$expected_path" ]]
}

validate_graphical_transient_unit() {
  local unit=$1 expected_description= expected_args= pid args cgroup source_path
  local initial_uid initial_start initial_cmd initial_cgroup
  case "$unit" in
    dbus-:[0-9]*.[0-9]*-org.a11y.atspi.Registry@[0-9]*.service)
      [[ $unit =~ ^dbus-:[0-9]+\.[0-9]+-org\.a11y\.atspi\.Registry@[0-9]+\.service$ ]] \
        || return 2
      expected_description=$unit
      expected_args=$'/usr/libexec/at-spi2-registryd\n--use-gnome-session'
      ;;
    run-p[0-9]*-i[0-9]*.service)
      [[ $unit =~ ^run-p[0-9]+-i[0-9]+\.service$ ]] || return 2
      expected_description='[systemd-run] /usr/libexec/imsettings-daemon --replace'
      expected_args=$'/usr/libexec/imsettings-daemon\n--replace'
      ;;
    *) return 3 ;;
  esac
  source_path=$(user_value SourcePath "$unit") || return 2
  [[ $(user_value Id "$unit") == "$unit" && \
        $(user_value Description "$unit") == "$expected_description" && \
        $(user_value LoadState "$unit") == loaded && \
        $(user_value ActiveState "$unit") == active && \
        $(user_value SubState "$unit") == running && \
        $(user_value UnitFileState "$unit") == transient && \
        $(user_value Transient "$unit") == yes && \
        $(user_value RefuseManualStart "$unit") == no && \
        $(user_value RefuseManualStop "$unit") == no && \
        $(user_value ControlPID "$unit") == 0 && \
        $(user_value FragmentPath "$unit") == "$user_runtime/systemd/transient/$unit" && \
        -z $source_path ]] || return 2
  pid=$(user_value MainPID "$unit") || return 2
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 2
  read_process_identity "$pid" || return 2
  initial_uid=$observed_uid; initial_start=$observed_starttime
  initial_cmd=$observed_cmdline_sha; initial_cgroup=$observed_cgroup_sha
  args=$(/usr/bin/tr '\0' '\n' < "/proc/$pid/cmdline") || return 2
  cgroup=$(<"/proc/$pid/cgroup") || return 2
  [[ $initial_uid == "$target_uid" && $args == "$expected_args" && \
        $cgroup == "0::/user.slice/user-1000.slice/user@1000.service/app.slice/$unit" ]] \
    || return 2
  read_process_identity "$pid" || return 2
  [[ $observed_uid == "$initial_uid" && $observed_starttime == "$initial_start" && \
        $observed_cmdline_sha == "$initial_cmd" && \
        $observed_cgroup_sha == "$initial_cgroup" && \
        $(user_value MainPID "$unit") == "$pid" ]] || return 2
}

capture_user_unit_snapshot() {
  local unit=$1 output line key value
  local seen_id=0 seen_load=0 seen_active=0 seen_sub=0
  local seen_unit_file=0 seen_transient=0 seen_main=0 seen_control=0 seen_group=0
  snapshot_id=; snapshot_load=; snapshot_active=; snapshot_sub=
  snapshot_unit_file=; snapshot_transient=; snapshot_main_pid=
  snapshot_control_pid=; snapshot_control_group=
  if ! output=$(userctl show "$unit" -p Id -p LoadState -p ActiveState -p SubState \
      -p UnitFileState -p Transient -p MainPID -p ControlPID -p ControlGroup); then
    return 2
  fi
  while IFS= read -r line; do
    [[ $line == *=* ]] || return 2
    key=${line%%=*}; value=${line#*=}
    case "$key" in
      Id)
        ((seen_id == 0)) || return 2
        seen_id=1; snapshot_id=$value
        ;;
      LoadState)
        ((seen_load == 0)) || return 2
        seen_load=1; snapshot_load=$value
        ;;
      ActiveState)
        ((seen_active == 0)) || return 2
        seen_active=1; snapshot_active=$value
        ;;
      SubState)
        ((seen_sub == 0)) || return 2
        seen_sub=1; snapshot_sub=$value
        ;;
      UnitFileState)
        ((seen_unit_file == 0)) || return 2
        seen_unit_file=1; snapshot_unit_file=$value
        ;;
      Transient)
        ((seen_transient == 0)) || return 2
        seen_transient=1; snapshot_transient=$value
        ;;
      MainPID)
        ((seen_main == 0)) || return 2
        seen_main=1; snapshot_main_pid=$value
        ;;
      ControlPID)
        ((seen_control == 0)) || return 2
        seen_control=1; snapshot_control_pid=$value
        ;;
      ControlGroup)
        ((seen_group == 0)) || return 2
        seen_group=1; snapshot_control_group=$value
        ;;
      *) return 2 ;;
    esac
  done <<< "$output"
  ((seen_id == 1 && seen_load == 1 && seen_active == 1 && seen_sub == 1 && \
      seen_unit_file == 1 && seen_transient == 1 && seen_main == 1 && \
      seen_control == 1 && seen_group == 1)) \
    || return 2
  [[ $snapshot_id == "$unit" && $snapshot_transient =~ ^(yes|no)$ && \
        $snapshot_main_pid =~ ^[0-9]+$ && $snapshot_control_pid =~ ^[0-9]+$ ]]
}

parsed_cgroup_populated=
parsed_cgroup_frozen=

parse_cgroup_events() {
  local data=$1 line key value extra
  local seen_populated=0 seen_frozen=0
  parsed_cgroup_populated=; parsed_cgroup_frozen=
  while IFS= read -r line; do
    read -r key value extra <<< "$line"
    [[ -n $key && -n $value && -z $extra && $key =~ ^[a-z_]+$ && \
          $value =~ ^[0-9]+$ ]] || return 2
    case "$key" in
      populated)
        ((seen_populated == 0)) || return 2
        seen_populated=1; parsed_cgroup_populated=$value
        ;;
      frozen)
        ((seen_frozen == 0)) || return 2
        seen_frozen=1; parsed_cgroup_frozen=$value
        ;;
    esac
  done <<< "$data"
  ((seen_populated == 1 && seen_frozen == 1)) || return 2
  [[ $parsed_cgroup_populated =~ ^[01]$ && $parsed_cgroup_frozen =~ ^[01]$ ]]
}

transient_snapshot_is_inert() {
  local cgroup_path canonical_path events_before events_after procs
  local cgroup_prefix=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/
  case "$snapshot_active/$snapshot_sub" in
    inactive/dead|failed/failed) ;;
    *) return 1 ;;
  esac
  [[ $snapshot_main_pid == 0 && $snapshot_control_pid == 0 ]] || return 1
  [[ -n $snapshot_control_group ]] || return 0
  [[ $snapshot_control_group =~ ^/user\.slice/user-1000\.slice/user@1000\.service/[-A-Za-z0-9_.:@/\\]+$ ]] \
    || return 2
  cgroup_path=/sys/fs/cgroup$snapshot_control_group
  canonical_path=$(/usr/bin/realpath -m -- "$cgroup_path") || return 2
  [[ $canonical_path == "$cgroup_path" && $canonical_path == "$cgroup_prefix"* ]] \
    || return 2
  if [[ ! -e $cgroup_path && ! -L $cgroup_path ]]; then
    return 0
  fi
  [[ -d $cgroup_path && ! -L $cgroup_path && \
        -r $cgroup_path/cgroup.events && -r $cgroup_path/cgroup.procs ]] || return 2
  events_before=$(<"$cgroup_path/cgroup.events") || return 3
  parse_cgroup_events "$events_before" || return 2
  [[ $parsed_cgroup_populated == 0 && $parsed_cgroup_frozen == 0 ]] || return 1
  procs=$(<"$cgroup_path/cgroup.procs") || return 3
  [[ -z $procs ]] || return 1
  events_after=$(<"$cgroup_path/cgroup.events") || return 3
  [[ $events_after == "$events_before" ]] || return 3
  parse_cgroup_events "$events_after" || return 2
  [[ $parsed_cgroup_populated == 0 && $parsed_cgroup_frozen == 0 ]]
}

validate_planned_masked_user_service_snapshot() {
  local unit=$1
  array_contains "$unit" "${user_masked_units[@]}" || {
    echo "unexpected masked user service outside transaction plan: $unit" >&2
    return 2
  }
  [[ $snapshot_id == "$unit" && $snapshot_load == masked && \
        $snapshot_active == inactive && $snapshot_sub == dead && \
        $snapshot_unit_file == masked-runtime && $snapshot_transient == no && \
        $snapshot_main_pid == 0 && $snapshot_control_pid == 0 ]] || {
    echo "planned masked user service lifecycle drift: $unit" >&2
    return 2
  }
  transient_snapshot_is_inert || {
    echo "planned masked user service cgroup is not inert: $unit" >&2
    return 2
  }
}

collect_active_user_transients() {
  local inventory inventory_after unit listed_load listed_active listed_sub ignored
  local unit_file transient attempt unstable rc
  local initial_id initial_load initial_active initial_sub initial_unit_file
  local initial_transient initial_main initial_control initial_group
  for attempt in 1 2 3 4 5; do
    active_user_transients=()
    unstable=0
    if ! inventory=$(userctl list-units --type=service --all --no-legend --plain); then
      echo 'cannot enumerate loaded user services for transient gate' >&2
      return 2
    fi
    while read -r unit listed_load listed_active listed_sub ignored; do
      [[ -n $unit ]] || continue
      case "$listed_load" in
        not-found) continue ;;
        loaded) ;;
        masked)
          if ! capture_user_unit_snapshot "$unit" 2>/dev/null || \
              [[ $snapshot_load != "$listed_load" || \
                 $snapshot_active != "$listed_active" || \
                 $snapshot_sub != "$listed_sub" ]]; then
            unstable=1
            break
          fi
          validate_planned_masked_user_service_snapshot "$unit" || return 2
          initial_id=$snapshot_id; initial_load=$snapshot_load
          initial_active=$snapshot_active; initial_sub=$snapshot_sub
          initial_unit_file=$snapshot_unit_file; initial_transient=$snapshot_transient
          initial_main=$snapshot_main_pid; initial_control=$snapshot_control_pid
          initial_group=$snapshot_control_group
          if ! capture_user_unit_snapshot "$unit" 2>/dev/null || \
              [[ $snapshot_id != "$initial_id" || \
                 $snapshot_load != "$initial_load" || \
                 $snapshot_active != "$initial_active" || \
                 $snapshot_sub != "$initial_sub" || \
                 $snapshot_unit_file != "$initial_unit_file" || \
                 $snapshot_transient != "$initial_transient" || \
                 $snapshot_main_pid != "$initial_main" || \
                 $snapshot_control_pid != "$initial_control" || \
                 $snapshot_control_group != "$initial_group" ]]; then
            unstable=1
            break
          fi
          validate_planned_masked_user_service_snapshot "$unit" || return 2
          echo "CODESKEPTIC_HEADLESS_PLANNED_MASKED_SERVICE_INERT=$unit"
          continue
          ;;
        *)
          echo "unsupported user service load state during transient gate: unit=$unit load=$listed_load" >&2
          return 2 ;;
      esac
      if ! capture_user_unit_snapshot "$unit" 2>/dev/null || \
          [[ $snapshot_load != "$listed_load" || \
             $snapshot_active != "$listed_active" || $snapshot_sub != "$listed_sub" ]]; then
        unstable=1
        break
      fi
      unit_file=$snapshot_unit_file
      transient=$snapshot_transient
      if [[ $unit_file == transient || $transient == yes ]]; then
        [[ $unit_file == transient && $transient == yes ]] || return 2
        if transient_snapshot_is_inert; then
          initial_id=$snapshot_id; initial_load=$snapshot_load
          initial_active=$snapshot_active; initial_sub=$snapshot_sub
          initial_unit_file=$snapshot_unit_file; initial_transient=$snapshot_transient
          initial_main=$snapshot_main_pid; initial_control=$snapshot_control_pid
          initial_group=$snapshot_control_group
          if ! capture_user_unit_snapshot "$unit" 2>/dev/null || \
              [[ $snapshot_id != "$initial_id" || $snapshot_load != "$initial_load" || \
                 $snapshot_active != "$initial_active" || $snapshot_sub != "$initial_sub" || \
                 $snapshot_unit_file != "$initial_unit_file" || \
                 $snapshot_transient != "$initial_transient" || \
                 $snapshot_main_pid != "$initial_main" || \
                 $snapshot_control_pid != "$initial_control" || \
                 $snapshot_control_group != "$initial_group" ]]; then
            unstable=1
            break
          fi
          if transient_snapshot_is_inert; then
            :
          else
            rc=$?
            [[ $rc == 3 || $rc == 1 ]] || return 2
            unstable=1
            break
          fi
        else
          rc=$?
          case "$rc" in
            1) active_user_transients+=("$unit") ;;
            3) unstable=1; break ;;
            *) return 2 ;;
          esac
        fi
      fi
    done <<< "$inventory"
    if ((unstable == 0)); then
      if ! inventory_after=$(userctl list-units --type=service --all --no-legend --plain); then
        return 2
      fi
      [[ $inventory_after == "$inventory" ]] || unstable=1
    fi
    if ((unstable == 0)); then
      return 0
    fi
    /usr/bin/sleep 0.05
  done
  echo 'loaded user service inventory changed repeatedly during transient gate' >&2
  active_user_transients=()
  return 2
}

require_no_active_user_transients() {
  collect_active_user_transients || return 2
  ((${#active_user_transients[@]} == 0)) || {
    printf 'active transient user service remains: %s\n' "${active_user_transients[*]}" >&2
    return 2
  }
}

drain_graphical_transients() {
  local started=$SECONDS
  local deadline=$((started + transient_drain_timeout_seconds))
  local next_progress=$((started + transient_drain_progress_seconds))
  local stable_empty=0 unit rc state substate elapsed remaining
  local -a stoppable=()
  while ((SECONDS < deadline)); do
    collect_active_user_transients || return 2
    if ((SECONDS >= next_progress)); then
      elapsed=$((SECONDS - started))
      remaining=$((deadline - SECONDS))
      printf 'CODESKEPTIC_HEADLESS_WAIT_GRAPHICAL_TRANSIENTS elapsed=%d remaining=%d count=%d\n' \
        "$elapsed" "$remaining" "${#active_user_transients[@]}"
      next_progress=$((SECONDS + transient_drain_progress_seconds))
    fi
    if ((${#active_user_transients[@]} == 0)); then
      ((stable_empty += 1))
      if ((stable_empty == 2)); then
        echo CODESKEPTIC_HEADLESS_GRAPHICAL_TRANSIENTS_DRAINED
        return 0
      fi
      /usr/bin/sleep 1
      continue
    fi
    stable_empty=0; stoppable=()
    for unit in "${active_user_transients[@]}"; do
      state=$(user_value ActiveState "$unit") || return 2
      substate=$(user_value SubState "$unit") || return 2
      if [[ $state == active && $substate == running ]]; then
        if validate_graphical_transient_unit "$unit"; then
          stoppable+=("$unit")
        else
          rc=$?
          [[ $rc == 3 ]] || {
            echo "graphical transient identity mismatch: $unit" >&2
            return 2
          }
        fi
      elif [[ $state == activating || $state == deactivating || \
              $state == inactive || $state == failed ]]; then
        :
      else
        echo "unexpected transient user service state: $unit=$state/$substate" >&2
        return 2
      fi
    done
    for unit in "${stoppable[@]}"; do
      validate_graphical_transient_unit "$unit" || {
        echo "graphical transient identity changed before stop: $unit" >&2
        return 2
      }
      echo "CODESKEPTIC_HEADLESS_STOP_GRAPHICAL_TRANSIENT=$unit"
      if ! userctl stop -- "$unit"; then
        state=$(user_value ActiveState "$unit") || return 2
        [[ $state == inactive ]] || return 2
      fi
    done
    /usr/bin/sleep 1
  done
  collect_active_user_transients || return 2
  printf 'active transient user services did not drain: %s\n' \
    "${active_user_transients[*]:-none}" >&2
  return 2
}

session_value() {
  /usr/bin/loginctl show-session "$2" -p "$1" --value
}

read_process_identity() {
  local pid=$1 stat_line rest
  [[ $pid =~ ^[1-9][0-9]*$ && -d /proc/$pid ]] || return 1
  observed_uid=$(/usr/bin/stat -c '%u' "/proc/$pid") || return 1
  observed_cmdline_sha=$(/usr/bin/sha256sum "/proc/$pid/cmdline") || return 1
  observed_cmdline_sha=${observed_cmdline_sha%% *}
  observed_cgroup_sha=$(/usr/bin/sha256sum "/proc/$pid/cgroup") || return 1
  observed_cgroup_sha=${observed_cgroup_sha%% *}
  IFS= read -r stat_line < "/proc/$pid/stat" || return 1
  rest=${stat_line##*) }
  set -- $rest
  (($# >= 20)) || return 1
  observed_starttime=${20}
  [[ $observed_uid =~ ^[0-9]+$ && $observed_starttime =~ ^[0-9]+$ && \
        $observed_cmdline_sha =~ ^[0-9a-f]{64}$ && \
        $observed_cgroup_sha =~ ^[0-9a-f]{64}$ ]] || return 1
}

pause_identity_matches() {
  [[ -n $pause_pid ]] || return 1
  read_process_identity "$pause_pid" || return 1
  [[ $observed_uid == "$pause_uid" && \
        $observed_starttime == "$pause_starttime" && \
        $observed_cmdline_sha == "$pause_cmdline_sha" && \
        $observed_cgroup_sha == "$pause_cgroup_sha" ]]
}

capture_pause_identity() {
  local inventory pid comm args cgroup affinity count=0
  local initial_uid initial_start initial_cmd initial_cgroup
  if ! inventory=$(/usr/bin/ps -u "$target_uid" -o pid=,comm=); then
    echo 'cannot enumerate tanzer processes for Podman pause identity' >&2
    return 2
  fi
  while read -r pid comm; do
    [[ -n $pid && -n $comm ]] || continue
    [[ $comm == catatonit ]] || continue
    ((count += 1))
    ((count == 1)) || {
      echo 'multiple Podman pause processes remain' >&2
      return 2
    }
    pause_pid=$pid
    read_process_identity "$pid" || {
      echo 'cannot bind initial Podman pause process identity' >&2
      return 2
    }
    initial_uid=$observed_uid
    initial_start=$observed_starttime
    initial_cmd=$observed_cmdline_sha
    initial_cgroup=$observed_cgroup_sha
    if ! args=$(/usr/bin/tr '\0' '\n' < "/proc/$pid/cmdline"); then
      echo 'cannot read Podman pause command line' >&2
      return 2
    fi
    [[ $args == $'catatonit\n-P' ]] || {
      echo "unexpected tanzer catatonit command: $pid" >&2
      return 2
    }
    if ! cgroup=$(<"/proc/$pid/cgroup"); then
      echo 'cannot read Podman pause cgroup' >&2
      return 2
    fi
    [[ $cgroup == 0::/user.slice/user-1000.slice/user@1000.service/user.slice/podman-pause-*.scope ]] || {
      echo "unexpected tanzer catatonit cgroup: $pid" >&2
      return 2
    }
    read_process_identity "$pid" || {
      echo 'cannot re-bind Podman pause process identity' >&2
      return 2
    }
    [[ $observed_uid == "$initial_uid" && \
          $observed_starttime == "$initial_start" && \
          $observed_cmdline_sha == "$initial_cmd" && \
          $observed_cgroup_sha == "$initial_cgroup" ]] || {
      echo 'Podman pause identity changed during raw validation' >&2
      return 2
    }
    pause_uid=$initial_uid
    pause_starttime=$initial_start
    pause_cmdline_sha=$initial_cmd
    pause_cgroup_sha=$initial_cgroup
    [[ $pause_uid == "$target_uid" ]] || {
      echo 'Podman pause UID drift' >&2
      return 2
    }
    if ! affinity=$(/usr/bin/taskset -pc "$pid"); then
      echo 'cannot read Podman pause affinity' >&2
      return 2
    fi
    pause_original_affinity=${affinity##*: }
    [[ $pause_original_affinity =~ ^[0-9,-]+$ ]] || {
      echo 'Podman pause original affinity is malformed' >&2
      return 2
    }
  done <<< "$inventory"
  ((count == 1)) || {
    echo 'exactly one pre-existing Podman pause process is required before authority mutation' >&2
    return 2
  }
}

pin_pause_identity() {
  [[ -n $pause_pid ]] || return 0
  pause_identity_matches || {
    echo 'Podman pause identity changed before affinity pin' >&2
    return 2
  }
  pause_restore_needed=1
  /usr/bin/taskset -pc "$controller_cpus" "$pause_pid" >/dev/null
  pause_identity_matches || {
    echo 'Podman pause identity changed during affinity pin' >&2
    return 2
  }
  local affinity
  affinity=$(/usr/bin/taskset -pc "$pause_pid") || return 2
  [[ ${affinity##*: } == "$controller_cpus" ]] || {
    echo 'Podman pause process affinity could not be pinned' >&2
    return 2
  }
}

collect_authority_bash_ancestors() {
  authority_bash_pids=()
  local pid=$$ uid comm stat_line rest ppid
  while [[ $pid =~ ^[1-9][0-9]*$ && $pid != 1 ]]; do
    uid=$(/usr/bin/stat -c '%u' "/proc/$pid") || return 2
    IFS= read -r comm < "/proc/$pid/comm" || return 2
    IFS= read -r stat_line < "/proc/$pid/stat" || return 2
    rest=${stat_line##*) }
    set -- $rest
    (($# >= 2)) || return 2
    ppid=$2
    if [[ $uid == "$target_uid" && $comm == bash ]]; then
      authority_bash_pids+=("$pid")
    fi
    pid=$ppid
  done
  ((${#authority_bash_pids[@]} == 2)) || {
    echo "authority ancestry must contain exactly two tanzer bash processes: ${authority_bash_pids[*]}" >&2
    return 2
  }
}

require_minimal_user_processes() {
  collect_authority_bash_ancestors
  local inventory pid comm cgroup affinity stat_line rest ticks
  local systemd_count=0 pam_count=0 broker_launcher_count=0 broker_count=0
  local bash_count=0 pause_count=0
  if ! inventory=$(/usr/bin/ps -u "$target_uid" -o pid=,comm=); then
    echo 'cannot enumerate tanzer processes' >&2
    return 2
  fi
  printf 'tanzer_process_inventory_begin\n%s\ntanzer_process_inventory_end\n' "$inventory"
  while read -r pid comm; do
    [[ -n $pid && -n $comm ]] || continue
    case "$comm" in
      systemd) ((systemd_count += 1)) ;;
      '(sd-pam)') ((pam_count += 1)) ;;
      dbus-broker-lau) ((broker_launcher_count += 1)) ;;
      dbus-broker) ((broker_count += 1)) ;;
      bash)
        ((bash_count += 1))
        array_contains "$pid" "${authority_bash_pids[@]}" || {
          echo "unrelated tanzer bash process remains: $pid" >&2
          return 2
        }
        ;;
      catatonit)
        ((pause_count += 1))
        [[ -n $pause_pid && $pid == "$pause_pid" ]] || {
          echo "unexpected Podman pause process remains: $pid" >&2
          return 2
        }
        pause_identity_matches || {
          echo 'Podman pause identity drifted during authority run' >&2
          return 2
        }
        affinity=$(/usr/bin/taskset -pc "$pid") || return 2
        [[ ${affinity##*: } == "$controller_cpus" ]] || {
          echo 'Podman pause affinity drifted during authority run' >&2
          return 2
        }
        IFS= read -r stat_line < "/proc/$pid/stat" || return 2
        rest=${stat_line##*) }
        set -- $rest
        (($# >= 13)) || return 2
        ticks=$(( ${12} + ${13} ))
        cgroup=$(<"/proc/$pid/cgroup") || return 2
        printf 'podman_pause_pid=%s original_affinity=%s ticks=%s cgroup=%s\n' \
          "$pid" "$pause_original_affinity" "$ticks" "$cgroup"
        ;;
      *)
        echo "unexpected tanzer process remains in headless authority: $pid/$comm" >&2
        return 2
        ;;
    esac
  done <<< "$inventory"
  [[ $systemd_count == 1 && $pam_count == 1 && \
        $broker_launcher_count == 1 && $broker_count == 1 && \
        $bash_count == 2 ]] || {
    echo "minimal tanzer process cardinality mismatch: systemd=$systemd_count pam=$pam_count broker_launcher=$broker_launcher_count broker=$broker_count bash=$bash_count" >&2
    return 2
  }
  if [[ -n $pause_pid ]]; then
    [[ $pause_count == 1 ]] || {
      echo 'bound Podman pause process disappeared' >&2
      return 2
    }
  else
    [[ $pause_count == 0 ]] || {
      echo 'new Podman pause process appeared' >&2
      return 2
    }
  fi
}

require_local_tty_path() {
  [[ $caller_tty =~ ^/dev/tty[1-9][0-9]*$ && -c $caller_tty ]] || {
    echo "local virtual console required, observed: $caller_tty" >&2
    return 2
  }
}

require_local_tty_session() {
  require_local_tty_path
  local expected_tty=${caller_tty#/dev/}
  local inventory session ignored name type class state remote service tty
  local total=0 tty_count=0 manager_count=0
  if ! inventory=$(/usr/bin/loginctl list-sessions --no-legend); then
    echo 'cannot enumerate login sessions' >&2
    return 2
  fi
  while read -r session ignored; do
    [[ -n $session ]] || continue
    ((total += 1))
    name=$(session_value Name "$session") || return 2
    type=$(session_value Type "$session") || return 2
    class=$(session_value Class "$session") || return 2
    state=$(session_value State "$session") || return 2
    remote=$(session_value Remote "$session") || return 2
    service=$(session_value Service "$session") || return 2
    tty=$(session_value TTY "$session") || return 2
    printf 'session=%s name=%s type=%s class=%s state=%s remote=%s service=%s tty=%s\n' \
      "$session" "$name" "$type" "$class" "$state" "$remote" "$service" "$tty"
    if [[ $name == "$target_user" && $type == tty && $class == user && \
          $state == active && $remote == no && $service == login && \
          $tty == "$expected_tty" ]]; then
      ((tty_count += 1))
    elif [[ $name == "$target_user" && $type == unspecified && \
            $class == manager && $state == active && $remote == no && \
            $service == systemd-user && -z $tty ]]; then
      ((manager_count += 1))
    else
      echo "unexpected login session remains: $session" >&2
      return 2
    fi
  done <<< "$inventory"
  [[ $total == 2 && $tty_count == 1 && $manager_count == 1 ]] || {
    echo "exact local-session inventory mismatch: total=$total tty=$tty_count manager=$manager_count" >&2
    return 2
  }
}

require_system_headless() {
  local state target
  state=$(system_value ActiveState graphical.target) || return 2
  [[ $state == inactive ]] || { echo "graphical.target must be inactive: $state" >&2; return 2; }
  state=$(system_value ActiveState multi-user.target) || return 2
  [[ $state == active ]] || { echo "multi-user.target must be active: $state" >&2; return 2; }
  state=$(system_value ActiveState plasmalogin.service) || return 2
  [[ $state == inactive ]] || { echo "plasmalogin.service must be inactive: $state" >&2; return 2; }
  for target in graphical-session.target graphical-session-pre.target \
    plasma-core.target plasma-workspace.target plasma-workspace-wayland.target \
    xdg-desktop-autostart.target; do
    state=$(user_value ActiveState "$target") || return 2
    [[ $state == inactive ]] || { echo "user graphical target active: $target=$state" >&2; return 2; }
  done
}

require_no_failed_system_units() {
  local failed
  if ! failed=$(/usr/bin/systemctl --failed --no-legend --plain); then
    echo 'cannot enumerate failed system units' >&2
    return 2
  fi
  [[ -z $failed ]] || {
    printf 'failed system units block confirmation:\n%s\n' "$failed" >&2
    return 2
  }
}

require_no_failed_user_units() {
  local failed
  if ! failed=$(userctl --failed --no-legend --plain); then
    echo 'cannot enumerate failed user units' >&2
    return 2
  fi
  [[ -z $failed ]] || {
    printf 'failed user units block confirmation:\n%s\n' "$failed" >&2
    return 2
  }
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
  [[ -z $instances ]] || {
    printf 'unexpected DrKonqi coredump launcher instances:\n%s\n' "$instances" >&2
    return 2
  }
  system_instances=$(/usr/bin/systemctl list-units \
    'systemd-coredump@*.service' 'drkonqi-coredump-processor@*.service' \
    --all --no-legend --plain) || return 2
  [[ -z $system_instances ]] || {
    printf 'unexpected system coredump helper instances:\n%s\n' \
      "$system_instances" >&2
    return 2
  }
}

capture_coredump_baseline() {
  coredump_baseline_sha=$(coredump_inventory_sha) || return 2
  [[ $coredump_baseline_sha =~ ^[0-9a-f]{64}$ ]] || return 2
  drkonqi_socket_accepted_baseline=$(user_value NAccepted \
    drkonqi-coredump-launcher.socket) || return 2
  [[ $drkonqi_socket_accepted_baseline =~ ^[0-9]+$ ]] || return 2
  require_no_coredump_helper_instances
}

establish_inherited_coredump_baseline() {
  [[ $coredump_baseline_sha =~ ^[0-9a-f]{64}$ && \
        $drkonqi_socket_accepted_baseline =~ ^[0-9]+$ ]] || return 2
  require_coredump_unchanged
}

require_coredump_unchanged() {
  local latest accepted
  latest=$(coredump_inventory_sha) || return 2
  accepted=$(user_value NAccepted drkonqi-coredump-launcher.socket) || return 2
  [[ $latest == "$coredump_baseline_sha" && \
        $accepted == "$drkonqi_socket_accepted_baseline" ]] || {
    echo 'new coredump or DrKonqi socket activation detected' >&2
    return 2
  }
  require_no_coredump_helper_instances || return 2
  require_no_failed_user_units
}

transition_drkonqi_counter_after_quiesce() {
  local accepted state substate result job previous
  array_contains drkonqi-coredump-launcher.socket "${user_planned_units[@]}" \
    || return 2
  array_contains drkonqi-coredump-launcher.socket "${user_restore_units[@]}" \
    || return 2
  previous=$drkonqi_socket_accepted_baseline
  [[ $previous =~ ^[0-9]+$ ]] || return 2
  state=$(user_value ActiveState drkonqi-coredump-launcher.socket) || return 2
  substate=$(user_value SubState drkonqi-coredump-launcher.socket) || return 2
  result=$(user_value Result drkonqi-coredump-launcher.socket) || return 2
  job=$(user_value Job drkonqi-coredump-launcher.socket) || return 2
  accepted=$(user_value NAccepted drkonqi-coredump-launcher.socket) || return 2
  [[ $state == inactive && $substate == dead && $result == success && \
        -z $job && $accepted =~ ^[0-9]+$ ]] || {
    echo "DrKonqi socket is not quiescent during counter transition: state=$state substate=$substate result=$result job=${job:-<empty>} accepted=$accepted" >&2
    return 2
  }
  [[ $accepted == "$previous" || $accepted == 0 ]] || {
    echo "DrKonqi socket counter changed unexpectedly during quiescence: previous=$previous current=$accepted" >&2
    return 2
  }
  drkonqi_socket_accepted_baseline=$accepted
  echo "CODESKEPTIC_HEADLESS_DRKONQI_COUNTER_TRANSITION previous=$previous current=$accepted"
}

require_recovery_coredump_unchanged() {
  local latest accepted
  [[ $recovery_coredump_baseline_sha =~ ^[0-9a-f]{64}$ && \
        $recovery_drkonqi_socket_accepted_baseline =~ ^[0-9]+$ ]] || return 2
  latest=$(coredump_inventory_sha) || return 2
  accepted=$(user_value NAccepted drkonqi-coredump-launcher.socket) || return 2
  [[ $latest == "$recovery_coredump_baseline_sha" && \
        $accepted == "$recovery_drkonqi_socket_accepted_baseline" ]] || return 2
  require_no_coredump_helper_instances || return 2
  require_no_failed_user_units
}

verify_root_staging() {
  [[ ! -L $run_root && $(/usr/bin/stat -c '%U:%G:%a' "$run_root") == root:root:755 ]] || return 2
  local executable helper
  for executable in snapshot-builder.sh cgroup-launcher.sh; do
    [[ ! -L $run_root/$executable && $(/usr/bin/stat -c '%U:%G:%a' "$run_root/$executable") == root:root:500 ]] || return 2
  done
  for helper in tree-hash.py run-static-preflight.sh container-entry.py cgroup-smoke.py \
    static-preflight.py git-authority-entry.sh run-confirmation.sh; do
    [[ ! -L $run_root/$helper && $(/usr/bin/stat -c '%U:%G:%a' "$run_root/$helper") == root:root:555 ]] || return 2
  done
  printf '%s  %s\n' \
    b7f048fb4a5f07443510b4de495b0728c895da65496eb5be34b28d7ab64dc84a "$run_root/snapshot-builder.sh" \
    b7765dcf006e346ebcca69b93a5a1686e51ec760fb06bd09e36eceaf19cb034d "$run_root/tree-hash.py" \
    49948c981ab933baf32b7a619fe965e821e1b539b0dcd4a0df388afe260dcade "$run_root/cgroup-launcher.sh" \
    05b3f1425cefcb36f6313da54762e1c9860a9cdb9f5d4f9fa1a06d027e516e32 "$run_root/run-static-preflight.sh" \
    4554daf69ee902d746b9089dd4ad18ceee512d92b8e3c2ebb0fc7912fdb5c729 "$run_root/container-entry.py" \
    d4b2b906b833d74a1a0a21981d8715664ea7e2eb109f16a79ceaacbe5e43b985 "$run_root/cgroup-smoke.py" \
    8ecfa3aace9d61428de137f188eda3dd776d0421b9165836a44f3c8911d13492 "$run_root/static-preflight.py" \
    fbd2ff8e9db7cd71bed7c4863ce7604fad336372e662181db30a1e4726cb2d0a "$run_root/git-authority-entry.sh" \
    1618ba5ac9d394b0ea03456d9615325624694a4a4a15009dfa1ea30a0a26696e "$run_root/run-confirmation.sh" \
    | /usr/bin/sha256sum -c -
}

require_minimal_user_units() {
  local actual type
  if ! actual=$(userctl list-units --type=service --state=running --no-legend --plain \
      | /usr/bin/awk '{print $1}' | LC_ALL=C /usr/bin/sort); then return 2; fi
  [[ $actual == dbus-broker.service ]] || return 2
  if ! actual=$(userctl list-units --type=socket --state=active --no-legend --plain \
      | /usr/bin/awk '{print $1}' | LC_ALL=C /usr/bin/sort); then return 2; fi
  [[ $actual == dbus.socket ]] || return 2
  for type in timer path; do
    if ! actual=$(userctl list-units --type="$type" --state=active --no-legend --plain \
        | /usr/bin/awk '{print $1}' | LC_ALL=C /usr/bin/sort); then return 2; fi
    [[ -z $actual ]] || return 2
  done
}

require_network_disabled() {
  local state
  state=$(/usr/bin/nmcli networking) || return 2
  [[ $state == disabled ]] || return 2
}

require_quiet_authority() {
  require_local_tty_session
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=local_tty_session
  require_system_headless
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=system_headless
  require_no_failed_system_units
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=no_failed_system_units
  require_no_failed_user_units
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=no_failed_user_units
  require_coredump_unchanged
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=coredump_unchanged
  require_no_active_user_transients
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=no_active_user_transients
  require_minimal_user_units
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=minimal_user_units
  require_minimal_user_processes
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=minimal_user_processes
  require_network_disabled
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=network_disabled
  local timers service state unit_file power_entries feature_actual feature_status primary_actual primary_status
  if ! timers=$(/usr/bin/systemctl list-units --type=timer --state=active --no-legend --plain); then return 2; fi
  [[ -z $timers ]] || return 2
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=system_timers_empty
  for service in crond.service atd.service packagekit.service packagekit-offline-update.service; do
    state=$(system_value ActiveState "$service") || return 2
    [[ $state == inactive ]] || return 2
  done
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=system_services_inactive
  for service in "${system_planned_units[@]}"; do
    state=$(system_value ActiveState "$service") || return 2
    unit_file=$(system_value UnitFileState "$service") || return 2
    [[ $state == inactive && $unit_file == masked-runtime ]] || {
      echo "system plan unit is not quiescent: $service state=$state unit_file=$unit_file" >&2
      return 2
    }
  done
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=system_plan_quiescent
  if ! power_entries=$(/usr/bin/find /sys/class/power_supply -mindepth 1 -print -quit); then return 2; fi
  [[ $(< /sys/class/dmi/id/product_name) == 'HP All-in-One Desktop 24-cb1xxx' && \
        $(< /sys/class/dmi/id/chassis_type) == 13 && -z $power_entries ]] || return 2
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=hardware_identity
  [[ ! -e /sys/fs/cgroup/codeskeptic-p10-07-authority && ! -e $active_stage ]] || return 2
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=authority_paths_clear
  if ! feature_actual=$(usergit "$feature_repo" rev-parse HEAD) || \
      ! feature_status=$(usergit "$feature_repo" status --porcelain --untracked-files=normal); then return 2; fi
  [[ $feature_actual == "$feature_head" && -z $feature_status ]] || return 2
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=feature_repo_clean
  if ! primary_actual=$(usergit "$primary_repo" rev-parse HEAD) || \
      ! primary_status=$(usergit "$primary_repo" status --porcelain --untracked-files=normal); then return 2; fi
  [[ $primary_actual == "$main_head" && -z $primary_status ]] || return 2
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=primary_repo_clean
  (cd "$rejection_root" && /usr/bin/sha256sum -c "$rejection_ledger")
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=rejection_ledger
  (cd "$rejection_bundle" && /usr/bin/sha256sum -c FORENSIC_SHA256SUMS)
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=rejection_bundle
  verify_root_staging
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=root_staging
  verify_system_quiescent_units masked stable
  require_no_planned_activation_after_cursor system
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=system_quiescence_recheck
  verify_user_quiescent_units masked stable
  require_no_planned_activation_after_cursor user
  echo CODESKEPTIC_HEADLESS_QUIET_SUBGATE_PASS=user_quiescence_recheck
}

prepare_system_units() {
  local timers timers_after triggers trigger combined sorted unit load unit_file state
  local transient refuse_start refuse_stop
  system_planned_units=(); system_restore_units=()
  if ! timers=$(/usr/bin/systemctl list-units --type=timer --state=active --no-legend --plain \
      | /usr/bin/awk '{print $1}'); then return 2; fi
  triggers=
  while IFS= read -r unit; do
    [[ -n $unit ]] || continue
    [[ $unit =~ ^[A-Za-z0-9_.@:-]+\.timer$ ]] || {
      echo "active timer name is malformed: $unit" >&2
      return 2
    }
    trigger=$(system_value Unit "$unit") || return 2
    [[ $trigger =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] || {
      echo "active timer trigger is not an exact service: $unit trigger=$trigger" >&2
      return 2
    }
    triggers+=$'\n'"$trigger"
  done <<< "$timers"
  combined="$timers"$'\n'"$triggers"$'\n'crond.service$'\n'atd.service$'\n'packagekit.service$'\n'packagekit-offline-update.service$'\n'plasmalogin.service$'\n'graphical.target
  if ! sorted=$(printf '%s\n' "$combined" | /usr/bin/sed '/^$/d' | LC_ALL=C /usr/bin/sort -u); then return 2; fi
  [[ -z $sorted ]] || mapfile -t system_planned_units <<< "$sorted"
  for unit in "${system_planned_units[@]}"; do
    [[ $unit =~ ^[A-Za-z0-9_.@:-]+$ ]] || {
      echo "system plan unit name is malformed: $unit" >&2
      return 2
    }
    load=$(system_value LoadState "$unit") || {
      echo "cannot read system plan LoadState: $unit" >&2
      return 2
    }
    unit_file=$(system_value UnitFileState "$unit") || {
      echo "cannot read system plan UnitFileState: $unit" >&2
      return 2
    }
    transient=$(system_value Transient "$unit") || {
      echo "cannot read system plan Transient: $unit" >&2
      return 2
    }
    refuse_start=$(system_value RefuseManualStart "$unit") || {
      echo "cannot read system plan RefuseManualStart: $unit" >&2
      return 2
    }
    refuse_stop=$(system_value RefuseManualStop "$unit") || {
      echo "cannot read system plan RefuseManualStop: $unit" >&2
      return 2
    }
    state=$(system_value ActiveState "$unit") || {
      echo "cannot read system plan ActiveState: $unit" >&2
      return 2
    }
    verify_initial_unit_state system "$unit" "$state" || {
      echo "system plan unit has invalid initial lifecycle: $unit state=$state" >&2
      return 2
    }
    printf 'CODESKEPTIC_HEADLESS_SYSTEM_PLAN_UNIT=%s load=%s unit_file=%s state=%s transient=%s refuse_start=%s refuse_stop=%s\n' \
      "$unit" "$load" "$unit_file" "$state" "$transient" "$refuse_start" "$refuse_stop"
    [[ $load == loaded ]] || {
      echo "system plan unit is not loaded: $unit load=$load" >&2
      return 2
    }
    [[ $unit_file != masked && $unit_file != masked-runtime && \
          $unit_file =~ ^[A-Za-z0-9_-]+$ ]] || {
      echo "system plan unit-file state is invalid: $unit unit_file=$unit_file" >&2
      return 2
    }
    [[ $unit_file != transient && $transient == no && \
          $refuse_start == no && $refuse_stop == no ]] || {
      echo "system unit cannot enter restorable plan: $unit transient=$transient refuse_start=$refuse_start refuse_stop=$refuse_stop" >&2
      return 2
    }
    system_original_unit_files["$unit"]=$unit_file
    if array_contains "$unit" "${required_inactive_system_units[@]}"; then
      [[ $state == inactive ]] || {
        echo "required inactive system unit drifted: $unit state=$state" >&2
        return 2
      }
    else
      case "$state" in
        active) system_restore_units+=("$unit") ;;
        inactive) ;;
        *) echo "system plan unit has unsupported state: $unit state=$state" >&2; return 2 ;;
      esac
    fi
  done
  if ! timers_after=$(/usr/bin/systemctl list-units --type=timer --state=active --no-legend --plain \
      | /usr/bin/awk '{print $1}'); then return 2; fi
  [[ $timers_after == "$timers" ]] || {
    echo 'active system timer inventory changed during planning' >&2
    return 2
  }
}

prepare_user_units() {
  local timer_files service_inventory durable_services active_units graphical_targets
  local trigger_sources trigger_units triggers trigger
  local combined sorted unit ignored load unit_file state type output substate transient
  local refuse_start refuse_stop fragment main_pid control_pid
  local expected_refuse_start expected_fragment
  user_planned_units=(); user_restore_units=()
  require_no_active_user_transients || return 2
  if ! timer_files=$(userctl list-unit-files --type=timer --no-legend --plain | /usr/bin/awk '{print $1}'); then return 2; fi
  if ! service_inventory=$(userctl list-units --type=service --state=active --no-legend --plain); then return 2; fi
  durable_services=
  while read -r unit ignored; do
    [[ -n $unit ]] || continue
    substate=$(user_value SubState "$unit") || return 2
    unit_file=$(user_value UnitFileState "$unit") || return 2
    transient=$(user_value Transient "$unit") || return 2
    refuse_start=$(user_value RefuseManualStart "$unit") || return 2
    refuse_stop=$(user_value RefuseManualStop "$unit") || return 2
    if [[ $unit == dbus-broker.service ]]; then
      fragment=$(user_value FragmentPath "$unit") || return 2
      main_pid=$(user_value MainPID "$unit") || return 2
      control_pid=$(user_value ControlPID "$unit") || return 2
      [[ $substate == running && $unit_file == enabled && $transient == no && \
            $refuse_start == no && $refuse_stop == no && \
            $fragment == /usr/lib/systemd/user/dbus-broker.service && \
            $main_pid =~ ^[1-9][0-9]*$ && $control_pid == 0 ]] || return 2
      continue
    fi
    if [[ $unit == systemd-tmpfiles-setup.service ]]; then
      validate_inert_user_service "$unit" \
        /usr/lib/systemd/user/systemd-tmpfiles-setup.service enabled yes || return 2
      continue
    fi
    if [[ $unit == unity-gtk-module.service ]]; then
      validate_inert_user_service "$unit" \
        /usr/lib/systemd/user/unity-gtk-module.service disabled no || return 2
      continue
    fi
    [[ $substate == running && $unit_file != transient && $transient == no && \
          $refuse_start == no && $refuse_stop == no ]] || {
      echo "unexpected active user service cannot enter durable plan: $unit" >&2
      return 2
    }
    durable_services+=$'\n'"$unit"
  done <<< "$service_inventory"
  active_units=
  for type in socket path; do
    if ! output=$(userctl list-units --type="$type" --state=active --no-legend --plain \
        | /usr/bin/awk '{print $1}'); then return 2; fi
    active_units+=$'\n'"$output"
  done
  trigger_sources="$timer_files"$'\n'"$active_units"
  trigger_units=
  while IFS= read -r unit; do
    [[ -n $unit ]] || continue
    [[ $unit != dbus.socket ]] || continue
    triggers=$(user_value Triggers "$unit") || return 2
    for trigger in $triggers; do
      [[ $trigger =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] || {
        echo "user activation trigger is not an exact service: $unit trigger=$trigger" >&2
        return 2
      }
      trigger_units+=$'\n'"$trigger"
    done
  done <<< "$trigger_sources"
  printf -v graphical_targets '%s\n' "${user_graphical_targets[@]}"
  combined="$timer_files"$'\n'"$durable_services"$'\n'"$active_units"$'\n'"$trigger_units"$'\n'"$graphical_targets"
  if ! sorted=$(printf '%s\n' "$combined" | /usr/bin/awk \
      'NF && $0 != "dbus-broker.service" && $0 != "dbus.socket" { print }' \
      | LC_ALL=C /usr/bin/sort -u); then return 2; fi
  [[ -z $sorted ]] || mapfile -t user_planned_units <<< "$sorted"
  for unit in "${user_planned_units[@]}"; do
    [[ $unit =~ ^[A-Za-z0-9_.@:-]+$ ]] || return 2
    load=$(user_value LoadState "$unit") || return 2
    [[ $load == loaded ]] || return 2
    unit_file=$(user_value UnitFileState "$unit") || return 2
    [[ $unit_file != masked && $unit_file != masked-runtime ]] || return 2
    [[ $unit_file =~ ^[A-Za-z0-9_-]+$ ]] || return 2
    transient=$(user_value Transient "$unit") || return 2
    refuse_start=$(user_value RefuseManualStart "$unit") || return 2
    refuse_stop=$(user_value RefuseManualStop "$unit") || return 2
    state=$(user_value ActiveState "$unit") || return 2
    verify_initial_unit_state user "$unit" "$state" || {
      echo "user plan unit has invalid initial lifecycle: $unit state=$state" >&2
      return 2
    }
    if [[ $unit == *.socket && $unit != dbus.socket ]]; then
      [[ $state == active ]] || return 2
      verify_frozen_user_socket_endpoints "$unit" active || return 2
    fi
    if array_contains "$unit" "${user_graphical_targets[@]}"; then
      case "$unit" in
        plasma-workspace-wayland.target)
          expected_refuse_start=no
          expected_fragment=/usr/lib/systemd/user/plasma-workspace-wayland.target
          ;;
        plasma-workspace.target|plasma-core.target|xdg-desktop-autostart.target|\
          graphical-session.target|graphical-session-pre.target)
          expected_refuse_start=yes
          expected_fragment=/usr/lib/systemd/user/$unit
          ;;
        *) return 2 ;;
      esac
      fragment=$(user_value FragmentPath "$unit") || return 2
      [[ $unit_file == static && $transient == no && \
            $refuse_start == "$expected_refuse_start" && $refuse_stop == no && \
            $fragment == "$expected_fragment" && $state == inactive ]] || return 2
    else
      [[ $unit_file != transient && $transient == no && \
            $refuse_start == no && $refuse_stop == no ]] || return 2
      case "$state" in active) user_restore_units+=("$unit");; inactive) ;; *) return 2;; esac
    fi
    user_original_unit_files["$unit"]=$unit_file
  done
  require_no_active_user_transients
}

write_transaction_journal() {
  local unit state network
  network=$(/usr/bin/nmcli networking) || return 2
  [[ $network == enabled ]] || return 2
  [[ ! -e $transaction_journal && ! -L $transaction_journal && \
        ! -e $transaction_journal_sha && ! -L $transaction_journal_sha ]] || return 2
  remove_recoverable_atomic_tmp "$transaction_journal_tmp" || return 2
  /usr/bin/install -o root -g root -m 0600 /dev/null "$transaction_journal_tmp"
  {
    printf 'JOURNAL_VERSION=3\nJOURNAL_NETWORK_ORIGINAL=enabled\n'
    printf 'JOURNAL_COREDUMP_INVENTORY_SHA256=%s\n' "$coredump_baseline_sha"
    printf 'JOURNAL_DRKONQI_SOCKET_NACCEPTED=%s\n' \
      "$drkonqi_socket_accepted_journal_baseline"
    printf 'JOURNAL_SYSTEM_COUNT=%s\n' "${#system_planned_units[@]}"
    for unit in "${system_planned_units[@]}"; do
      state=inactive; array_contains "$unit" "${system_restore_units[@]}" && state=active
      printf 'JOURNAL_SYSTEM_UNIT=%s|%s|%s\n' \
        "$unit" "$state" "${system_original_unit_files[$unit]}"
    done
    printf 'JOURNAL_USER_COUNT=%s\n' "${#user_planned_units[@]}"
    for unit in "${user_planned_units[@]}"; do
      state=inactive; array_contains "$unit" "${user_restore_units[@]}" && state=active
      printf 'JOURNAL_USER_UNIT=%s|%s|%s\n' \
        "$unit" "$state" "${user_original_unit_files[$unit]}"
    done
    if [[ -n $pause_pid ]]; then
      printf 'JOURNAL_PAUSE=%s|%s|%s|%s|%s|%s\n' "$pause_pid" "$pause_starttime" \
        "$pause_uid" "$pause_cmdline_sha" "$pause_cgroup_sha" "$pause_original_affinity"
    else
      printf 'JOURNAL_PAUSE=none\n'
    fi
    printf 'JOURNAL_READY=1\n'
  } > "$transaction_journal_tmp"
  /usr/bin/chmod 0444 "$transaction_journal_tmp"
  [[ ! -L $transaction_journal_tmp && \
        $(/usr/bin/stat -c '%U:%G:%a' "$transaction_journal_tmp") == root:root:444 ]] \
    || return 2
  /usr/bin/sync -f "$transaction_journal_tmp"
  /usr/bin/mv -T -- "$transaction_journal_tmp" "$transaction_journal"
  /usr/bin/sync -f "$headless_root"
  remove_recoverable_atomic_tmp "$transaction_journal_sha_tmp" || return 2
  local journal_hash
  journal_hash=$(/usr/bin/sha256sum "$transaction_journal") || return 2
  journal_hash=${journal_hash%% *}
  [[ $journal_hash =~ ^[0-9a-f]{64}$ ]] || return 2
  /usr/bin/install -o root -g root -m 0600 /dev/null "$transaction_journal_sha_tmp"
  printf '%s  %s\n' "$journal_hash" "$transaction_journal" \
    > "$transaction_journal_sha_tmp"
  /usr/bin/chmod 0444 "$transaction_journal_sha_tmp"
  /usr/bin/sync -f "$transaction_journal_sha_tmp"
  /usr/bin/mv -T -- "$transaction_journal_sha_tmp" "$transaction_journal_sha"
  /usr/bin/sync -f "$headless_root"
  load_transaction_journal
  printf 'CODESKEPTIC_HEADLESS_TRANSACTION_JOURNAL=%s\n' "$transaction_journal"
}

load_transaction_journal() {
  local line payload unit state unit_file extra expected_system= expected_user=
  local actual_journal_hash actual_sidecar expected_sidecar
  local version_count=0 network_count=0 coredump_count=0 drkonqi_count=0
  local system_count_count=0 user_count_count=0 pause_count=0 ready_count=0
  local loaded_coredump_sha= loaded_drkonqi_accepted=
  local loaded_pause_pid= loaded_pause_start= loaded_pause_uid= loaded_pause_cmd= loaded_pause_cgroup= loaded_pause_affinity=
  local -a loaded_system=() loaded_system_active=() loaded_user=() loaded_user_active=()
  local -A loaded_system_unit_files=() loaded_user_unit_files=()
  [[ ! -L $transaction_journal && \
        $(/usr/bin/stat -c '%U:%G:%a' "$transaction_journal") == root:root:444 && \
        ! -L $transaction_journal_sha && \
        $(/usr/bin/stat -c '%U:%G:%a' "$transaction_journal_sha") == root:root:444 ]] \
    || return 2
  actual_journal_hash=$(/usr/bin/sha256sum "$transaction_journal") || return 2
  actual_journal_hash=${actual_journal_hash%% *}
  [[ $actual_journal_hash =~ ^[0-9a-f]{64}$ ]] || return 2
  actual_sidecar=$(<"$transaction_journal_sha") || return 2
  expected_sidecar="$actual_journal_hash  $transaction_journal"
  [[ $actual_sidecar == "$expected_sidecar" ]] || return 2
  /usr/bin/sha256sum --status -c "$transaction_journal_sha" || return 2
  while IFS= read -r line; do
    case "$line" in
      JOURNAL_VERSION=*) ((version_count += 1)); [[ $line == JOURNAL_VERSION=3 ]] || return 2 ;;
      JOURNAL_NETWORK_ORIGINAL=*) ((network_count += 1)); [[ $line == JOURNAL_NETWORK_ORIGINAL=enabled ]] || return 2 ;;
      JOURNAL_COREDUMP_INVENTORY_SHA256=*)
        ((coredump_count += 1)); loaded_coredump_sha=${line#*=}
        [[ $loaded_coredump_sha =~ ^[0-9a-f]{64}$ ]] || return 2 ;;
      JOURNAL_DRKONQI_SOCKET_NACCEPTED=*)
        ((drkonqi_count += 1)); loaded_drkonqi_accepted=${line#*=}
        [[ $loaded_drkonqi_accepted =~ ^[0-9]+$ ]] || return 2 ;;
      JOURNAL_SYSTEM_COUNT=*) ((system_count_count += 1)); expected_system=${line#*=}; [[ $expected_system =~ ^[0-9]+$ ]] || return 2 ;;
      JOURNAL_USER_COUNT=*) ((user_count_count += 1)); expected_user=${line#*=}; [[ $expected_user =~ ^[0-9]+$ ]] || return 2 ;;
      JOURNAL_SYSTEM_UNIT=*)
        payload=${line#*=}; IFS='|' read -r unit state unit_file extra <<< "$payload"
        [[ -z $extra && $unit =~ ^[A-Za-z0-9_.@:-]+$ && \
              ( $state == active || $state == inactive ) && \
              $unit_file =~ ^[A-Za-z0-9_-]+$ && \
              $unit_file != masked && $unit_file != masked-runtime ]] || return 2
        array_contains "$unit" "${loaded_system[@]}" && return 2
        loaded_system+=("$unit"); [[ $state == inactive ]] || loaded_system_active+=("$unit")
        loaded_system_unit_files["$unit"]=$unit_file ;;
      JOURNAL_USER_UNIT=*)
        payload=${line#*=}; IFS='|' read -r unit state unit_file extra <<< "$payload"
        [[ -z $extra && $unit =~ ^[A-Za-z0-9_.@:-]+$ && \
              ( $state == active || $state == inactive ) && \
              $unit_file =~ ^[A-Za-z0-9_-]+$ && \
              $unit_file != masked && $unit_file != masked-runtime ]] || return 2
        array_contains "$unit" "${loaded_user[@]}" && return 2
        loaded_user+=("$unit"); [[ $state == inactive ]] || loaded_user_active+=("$unit")
        loaded_user_unit_files["$unit"]=$unit_file ;;
      JOURNAL_PAUSE=*)
        ((pause_count += 1)); payload=${line#*=}
        if [[ $payload != none ]]; then
          IFS='|' read -r loaded_pause_pid loaded_pause_start loaded_pause_uid loaded_pause_cmd \
            loaded_pause_cgroup loaded_pause_affinity extra <<< "$payload"
          [[ -z $extra && $loaded_pause_pid =~ ^[1-9][0-9]*$ && $loaded_pause_start =~ ^[0-9]+$ && \
                $loaded_pause_uid == "$target_uid" && $loaded_pause_cmd =~ ^[0-9a-f]{64}$ && \
                $loaded_pause_cgroup =~ ^[0-9a-f]{64}$ && $loaded_pause_affinity =~ ^[0-9,-]+$ ]] || return 2
        fi ;;
      JOURNAL_READY=*) ((ready_count += 1)); [[ $line == JOURNAL_READY=1 ]] || return 2 ;;
      *) return 2 ;;
    esac
  done < "$transaction_journal"
  [[ $version_count == 1 && $network_count == 1 && $coredump_count == 1 && \
        $drkonqi_count == 1 && $system_count_count == 1 && \
        $user_count_count == 1 && $pause_count == 1 && $ready_count == 1 && \
        $expected_system == "${#loaded_system[@]}" && $expected_user == "${#loaded_user[@]}" ]] || return 2
  system_planned_units=("${loaded_system[@]}"); system_restore_units=("${loaded_system_active[@]}")
  user_planned_units=("${loaded_user[@]}"); user_restore_units=("${loaded_user_active[@]}")
  for unit in "${loaded_system[@]}"; do
    system_original_unit_files["$unit"]=${loaded_system_unit_files[$unit]}
  done
  for unit in "${loaded_user[@]}"; do
    user_original_unit_files["$unit"]=${loaded_user_unit_files[$unit]}
  done
  pause_pid=$loaded_pause_pid; pause_starttime=$loaded_pause_start; pause_uid=$loaded_pause_uid
  pause_cmdline_sha=$loaded_pause_cmd; pause_cgroup_sha=$loaded_pause_cgroup
  pause_original_affinity=$loaded_pause_affinity
  coredump_baseline_sha=$loaded_coredump_sha
  drkonqi_socket_accepted_journal_baseline=$loaded_drkonqi_accepted
}

capture_system_activation_guard() {
  local unit state expected unit_file job cursor_line
  cursor_line=$(/usr/bin/journalctl --system --quiet --no-pager \
    --show-cursor -n 0) || return 2
  system_activation_cursor=${cursor_line#-- cursor: }
  [[ $system_activation_cursor != "$cursor_line" && \
        $system_activation_cursor =~ ^s=[0-9a-f]+\;i=[0-9a-f]+\;b=[0-9a-f]+\;m=[0-9a-f]+\;t=[0-9a-f]+\;x=[0-9a-f]+$ ]] || return 2
  for unit in "${system_planned_units[@]}"; do
    state=$(system_value ActiveState "$unit") || return 2
    expected=inactive
    array_contains "$unit" "${system_restore_units[@]}" && expected=active
    unit_file=$(system_value UnitFileState "$unit") || return 2
    job=$(system_value Job "$unit") || return 2
    [[ $state == "$expected" && \
          $unit_file == "${system_original_unit_files[$unit]}" && -z $job ]] || {
      echo "system unit drifted before stop: $unit" >&2
      return 2
    }
  done
}

capture_user_activation_guard() {
  local unit state expected unit_file job cursor_line
  cursor_line=$(userjournal --show-cursor -n 0) || return 2
  user_activation_cursor=${cursor_line#-- cursor: }
  [[ $user_activation_cursor != "$cursor_line" && \
        $user_activation_cursor =~ ^s=[0-9a-f]+\;i=[0-9a-f]+\;b=[0-9a-f]+\;m=[0-9a-f]+\;t=[0-9a-f]+\;x=[0-9a-f]+$ ]] || return 2
  for unit in "${user_planned_units[@]}"; do
    state=$(user_value ActiveState "$unit") || return 2
    expected=inactive
    array_contains "$unit" "${user_restore_units[@]}" && expected=active
    unit_file=$(user_value UnitFileState "$unit") || return 2
    job=$(user_value Job "$unit") || return 2
    [[ $state == "$expected" && \
          $unit_file == "${user_original_unit_files[$unit]}" && -z $job ]] || {
      echo "user unit drifted before stop: $unit" >&2
      return 2
    }
  done
}

require_no_planned_activation_after_cursor() {
  local scope=$1 cursor inventory message_id unit
  local -a planned=()
  if [[ $scope == system ]]; then
    cursor=$system_activation_cursor
    planned=("${system_planned_units[@]}")
    /usr/bin/journalctl --sync || return 2
    inventory=$(/usr/bin/journalctl --system --quiet --no-pager \
      --after-cursor="$cursor" -o json \
      MESSAGE_ID="$systemd_unit_starting_message_id" \
      MESSAGE_ID="$systemd_unit_started_message_id" \
      MESSAGE_ID="$systemd_unit_failed_message_id" \
      | /usr/bin/jq -r '[.MESSAGE_ID, (.UNIT // .USER_UNIT // empty)] | @tsv') || return 2
  elif [[ $scope == user ]]; then
    cursor=$user_activation_cursor
    planned=("${user_planned_units[@]}")
    userjournal --sync || return 2
    inventory=$(userjournal --after-cursor="$cursor" -o json \
      MESSAGE_ID="$systemd_unit_starting_message_id" \
      MESSAGE_ID="$systemd_unit_started_message_id" \
      MESSAGE_ID="$systemd_unit_failed_message_id" \
      | /usr/bin/jq -r '[.MESSAGE_ID, (.USER_UNIT // .UNIT // empty)] | @tsv') || return 2
  else
    return 2
  fi
  while IFS=$'\t' read -r message_id unit; do
    [[ -n $unit ]] || continue
    if array_contains "$unit" "${planned[@]}" || \
        [[ $scope == user && $unit =~ ^drkonqi-coredump-launcher@[A-Za-z0-9_.@:-]+\.service$ ]] || \
        [[ $scope == system && $unit =~ ^(systemd-coredump|drkonqi-coredump-processor)@[A-Za-z0-9_.@:-]+\.service$ ]]; then
      echo "planned $scope unit activation event after stop guard: unit=$unit message_id=$message_id cursor=$cursor" >&2
      return 2
    fi
  done <<< "$inventory"
}

system_quiescent_show() {
  /usr/bin/systemctl show "$1" \
    -p LoadState -p ActiveState -p SubState -p Result -p UnitFileState -p Job \
    -p ActiveEnterTimestampMonotonic -p InactiveExitTimestampMonotonic
}

user_quiescent_show() {
  userctl show "$1" \
    -p LoadState -p ActiveState -p SubState -p Result -p UnitFileState -p Job \
    -p ActiveEnterTimestampMonotonic -p InactiveExitTimestampMonotonic
}

read_quiescent_snapshot() {
  local scope=$1 unit=$2 output line key value required
  local -A seen=() snapshot=()
  if [[ $scope == system ]]; then
    output=$(system_quiescent_show "$unit") || {
      echo "system unit snapshot failed: unit=$unit" >&2
      return 2
    }
  elif [[ $scope == user ]]; then
    output=$(user_quiescent_show "$unit") || {
      echo "user unit snapshot failed: unit=$unit" >&2
      return 2
    }
  else
    return 2
  fi
  while IFS= read -r line; do
    [[ $line == *=* ]] || {
      echo "$scope unit snapshot has malformed line: unit=$unit" >&2
      return 2
    }
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      LoadState|ActiveState|SubState|Result|UnitFileState|Job|\
      ActiveEnterTimestampMonotonic|InactiveExitTimestampMonotonic) ;;
      *)
        echo "$scope unit snapshot has unexpected property: unit=$unit property=$key" >&2
        return 2 ;;
    esac
    [[ -z ${seen[$key]+x} ]] || {
      echo "$scope unit snapshot repeats property: unit=$unit property=$key" >&2
      return 2
    }
    seen["$key"]=1
    snapshot["$key"]=$value
  done <<< "$output"
  for required in LoadState ActiveState SubState UnitFileState Job \
      ActiveEnterTimestampMonotonic InactiveExitTimestampMonotonic; do
    [[ -n ${seen[$required]+x} ]] || {
      echo "$scope unit snapshot omits property: unit=$unit property=$required" >&2
      return 2
    }
  done
  case "$unit" in
    *.target)
      [[ -n ${seen[Result]+x} ]] || snapshot[Result]= ;;
    *.service|*.timer|*.socket|*.path)
      if [[ -z ${seen[Result]+x} ]]; then
        echo "$scope unit snapshot omits property: unit=$unit property=Result" >&2
        return 2
      fi ;;
    *)
      echo "$scope unit snapshot has unsupported unit type: unit=$unit" >&2
      return 2 ;;
  esac
  quiescent_load=${snapshot[LoadState]}
  quiescent_state=${snapshot[ActiveState]}
  quiescent_substate=${snapshot[SubState]}
  quiescent_result=${snapshot[Result]}
  quiescent_unit_file=${snapshot[UnitFileState]}
  quiescent_job=${snapshot[Job]}
  quiescent_active_enter=${snapshot[ActiveEnterTimestampMonotonic]}
  quiescent_inactive_exit=${snapshot[InactiveExitTimestampMonotonic]}
}

reject_quiescent_snapshot() {
  local scope=$1 unit=$2 phase=$3 sample=$4 reason=$5 baseline_active=$6 baseline_inactive=$7 cursor=$8
  local result_display=$quiescent_result job_display=$quiescent_job
  [[ -n $result_display ]] || result_display='<empty>'
  [[ -n $job_display ]] || job_display='<empty>'
  echo "$scope unit quiescence rejected: unit=$unit phase=$phase sample=$sample reason=$reason tuple=$quiescent_load/$quiescent_state/$quiescent_substate/$result_display/$quiescent_unit_file job=$job_display epochs=$quiescent_active_enter/$quiescent_inactive_exit baseline=$baseline_active/$baseline_inactive cursor=$cursor" >&2
  return 2
}

classify_masked_epoch() {
  local load=$1 active_enter=$2 inactive_exit=$3 baseline_active=$4 baseline_inactive=$5
  quiescent_epoch_mode=
  [[ $active_enter =~ ^[0-9]+$ && $inactive_exit =~ ^[0-9]+$ && \
        $baseline_active =~ ^[0-9]+$ && $baseline_inactive =~ ^[0-9]+$ ]] || return 2
  if [[ $active_enter == "$baseline_active" && $inactive_exit == "$baseline_inactive" ]]; then
    quiescent_epoch_mode=preserved
  elif [[ $load == masked && $active_enter == 0 && $inactive_exit == 0 ]]; then
    quiescent_epoch_mode=gc-reset
  else
    return 2
  fi
  [[ $load != loaded || $quiescent_epoch_mode == preserved ]]
}

verify_runtime_mask_link() {
  local scope=$1 unit=$2 path target
  if [[ $scope == system ]]; then
    path=/run/systemd/system/$unit
  elif [[ $scope == user ]]; then
    path=$user_runtime/systemd/user/$unit
  else
    return 2
  fi
  [[ -L $path ]] || {
    echo "$scope runtime mask link missing: unit=$unit path=$path" >&2
    return 2
  }
  target=$(/usr/bin/readlink -- "$path") || return 2
  [[ $target == /dev/null ]] || {
    echo "$scope runtime mask link has wrong target: unit=$unit path=$path target=$target" >&2
    return 2
  }
}

verify_quiescent_units() {
  local scope=$1 phase=$2 sample=${3:-single} unit expected_file baseline_active baseline_inactive
  local cursor previous_mode previous_load
  case "$scope" in
    system)
      local -n planned_units=system_planned_units
      local -n original_unit_files=system_original_unit_files
      local -n active_enter_epochs=system_active_enter_epoch
      local -n inactive_exit_epochs=system_inactive_exit_epoch
      local -n masked_epoch_modes=system_masked_epoch_mode
      local -n masked_load_states=system_masked_load_state
      cursor=$system_activation_cursor ;;
    user)
      local -n planned_units=user_planned_units
      local -n original_unit_files=user_original_unit_files
      local -n active_enter_epochs=user_active_enter_epoch
      local -n inactive_exit_epochs=user_inactive_exit_epoch
      local -n masked_epoch_modes=user_masked_epoch_mode
      local -n masked_load_states=user_masked_load_state
      cursor=$user_activation_cursor ;;
    *) return 2 ;;
  esac
  [[ $phase == stopped || $phase == masked ]] || return 2
  [[ $phase != masked || $sample == initial || $sample == stable ]] || return 2
  for unit in "${planned_units[@]}"; do
    read_quiescent_snapshot "$scope" "$unit" || return 2
    baseline_active=${active_enter_epochs[$unit]:-'<unset>'}
    baseline_inactive=${inactive_exit_epochs[$unit]:-'<unset>'}
    [[ $quiescent_active_enter =~ ^[0-9]+$ && $quiescent_inactive_exit =~ ^[0-9]+$ ]] || \
      reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" nonnumeric-epoch \
        "$baseline_active" "$baseline_inactive" "$cursor" || return 2
    if [[ $phase == stopped ]]; then
      expected_file=${original_unit_files[$unit]}
      [[ $quiescent_load == loaded ]] || \
        reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" unexpected-load \
          "$baseline_active" "$baseline_inactive" "$cursor" || return 2
    else
      expected_file=masked-runtime
      [[ $quiescent_load == loaded || $quiescent_load == masked ]] || \
        reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" unexpected-load \
          "$baseline_active" "$baseline_inactive" "$cursor" || return 2
      verify_runtime_mask_link "$scope" "$unit" || return 2
    fi
    [[ -z $quiescent_job && $quiescent_state == inactive && \
          $quiescent_substate == dead && $quiescent_unit_file == "$expected_file" ]] || \
      reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" lifecycle-tuple \
        "$baseline_active" "$baseline_inactive" "$cursor" || return 2
    case "$unit" in
      *.target)
        [[ -z $quiescent_result ]] || \
          reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" target-result \
            "$baseline_active" "$baseline_inactive" "$cursor" || return 2 ;;
      *.service|*.timer|*.socket|*.path)
        [[ $quiescent_result == success ]] || \
          reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" typed-result \
            "$baseline_active" "$baseline_inactive" "$cursor" || return 2 ;;
      *)
        reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" unsupported-unit-type \
          "$baseline_active" "$baseline_inactive" "$cursor" || return 2 ;;
    esac
    if [[ $phase == stopped ]]; then
      active_enter_epochs["$unit"]=$quiescent_active_enter
      inactive_exit_epochs["$unit"]=$quiescent_inactive_exit
    else
      baseline_active=${active_enter_epochs[$unit]}
      baseline_inactive=${inactive_exit_epochs[$unit]}
      classify_masked_epoch "$quiescent_load" "$quiescent_active_enter" \
        "$quiescent_inactive_exit" "$baseline_active" "$baseline_inactive" || \
        reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" invalid-epoch-normalization \
          "$baseline_active" "$baseline_inactive" "$cursor" || return 2
      if [[ $sample != initial ]]; then
        previous_mode=${masked_epoch_modes[$unit]:-}
        previous_load=${masked_load_states[$unit]:-}
        [[ $previous_mode == preserved || $previous_mode == gc-reset ]] || \
          reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" missing-initial-sample \
            "$baseline_active" "$baseline_inactive" "$cursor" || return 2
        [[ $previous_load != masked || $quiescent_load == masked ]] || \
          reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" masked-load-rehydrated \
            "$baseline_active" "$baseline_inactive" "$cursor" || return 2
        [[ $previous_mode != gc-reset || $quiescent_epoch_mode == gc-reset ]] || \
          reject_quiescent_snapshot "$scope" "$unit" "$phase" "$sample" gc-epoch-rehydrated \
            "$baseline_active" "$baseline_inactive" "$cursor" || return 2
      fi
      masked_epoch_modes["$unit"]=$quiescent_epoch_mode
      masked_load_states["$unit"]=$quiescent_load
      echo "CODESKEPTIC_HEADLESS_UNIT_QUIESCENT scope=$scope phase=$phase sample=$sample unit=$unit load=$quiescent_load epoch_mode=$quiescent_epoch_mode epochs=$quiescent_active_enter/$quiescent_inactive_exit"
    fi
    [[ $scope != user || $unit != *.socket ]] || \
      verify_frozen_user_socket_endpoints \
        "$unit" stopped "$quiescent_load" || return 2
  done
}

verify_system_quiescent_units() {
  verify_quiescent_units system "$@"
}

verify_user_quiescent_units() {
  verify_quiescent_units user "$@"
}

quiesce_system_units() {
  system_quiesce_started=1
  capture_system_activation_guard
  if ((${#system_planned_units[@]})); then
    /usr/bin/systemctl stop -- "${system_planned_units[@]}" || return 2
  fi
  verify_system_quiescent_units stopped
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_system_units:stopped-snapshot
  require_no_planned_activation_after_cursor system
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_system_units:stopped-journal
  system_mask_attempted_units=("${system_planned_units[@]}")
  if ((${#system_mask_attempted_units[@]})); then
    /usr/bin/systemctl mask --runtime -- "${system_mask_attempted_units[@]}" || return 2
  fi
  system_masked_units=("${system_mask_attempted_units[@]}")
  verify_system_quiescent_units masked initial
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_system_units:masked-initial
  require_no_planned_activation_after_cursor system
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_system_units:masked-initial-journal
  /usr/bin/sleep 0.05
  verify_system_quiescent_units masked stable
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_system_units:masked-stable
  require_no_planned_activation_after_cursor system
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_system_units:masked-stable-journal
}

quiesce_user_units() {
  user_quiesce_started=1
  capture_user_activation_guard
  require_coredump_unchanged
  if ((${#user_planned_units[@]})); then
    userctl stop -- "${user_planned_units[@]}" || return 2
  fi
  verify_user_quiescent_units stopped
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_user_units:stopped-snapshot
  require_no_planned_activation_after_cursor user
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_user_units:stopped-journal
  user_mask_attempted_units=("${user_planned_units[@]}")
  if ((${#user_mask_attempted_units[@]})); then
    userctl mask --runtime -- "${user_mask_attempted_units[@]}" || return 2
  fi
  user_masked_units=("${user_mask_attempted_units[@]}")
  verify_user_quiescent_units masked initial
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_user_units:masked-initial
  require_no_planned_activation_after_cursor user
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_user_units:masked-initial-journal
  transition_drkonqi_counter_after_quiesce
  /usr/bin/sleep 0.05
  verify_user_quiescent_units masked stable
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_user_units:masked-stable
  require_no_planned_activation_after_cursor user
  echo CODESKEPTIC_HEADLESS_SUBGATE_PASS=quiesce_user_units:masked-stable-journal
  require_coredump_unchanged
}

verify_unit_restoration() {
  local scope=$1 unit state substate result unit_file expected job main_pid
  shift
  local -a planned=("$@")
  for unit in "${planned[@]}"; do
    if [[ $scope == system ]]; then
      state=$(system_value ActiveState "$unit") || return 2
      substate=$(system_value SubState "$unit") || return 2
      result=$(system_value Result "$unit") || return 2
      unit_file=$(system_value UnitFileState "$unit") || return 2
      job=$(system_value Job "$unit") || return 2
      main_pid=$(system_value MainPID "$unit") || return 2
      expected=inactive; array_contains "$unit" "${system_restore_units[@]}" && expected=active
    else
      state=$(user_value ActiveState "$unit") || return 2
      substate=$(user_value SubState "$unit") || return 2
      result=$(user_value Result "$unit") || return 2
      unit_file=$(user_value UnitFileState "$unit") || return 2
      job=$(user_value Job "$unit") || return 2
      main_pid=$(user_value MainPID "$unit") || return 2
      expected=inactive; array_contains "$unit" "${user_restore_units[@]}" && expected=active
    fi
    if [[ $scope == system ]]; then
      [[ $unit_file == "${system_original_unit_files[$unit]}" && $state == "$expected" ]] || return 2
    else
      [[ $unit_file == "${user_original_unit_files[$unit]}" && $state == "$expected" ]] || return 2
    fi
    [[ -z $job ]] || return 2
    if [[ $expected == inactive ]]; then
      [[ $substate == dead ]] || return 2
      case "$unit" in
        *.target) [[ -z $result ]] || return 2 ;;
        *.service|*.timer|*.socket|*.path) [[ $result == success ]] || return 2 ;;
        *) return 2 ;;
      esac
      if [[ $scope == user && $unit == *.socket ]]; then
        verify_frozen_user_socket_endpoints "$unit" stopped || return 2
      fi
      continue
    fi
    case "$unit" in
      *.service) [[ $result == success && $substate == running && \
                      $main_pid =~ ^[1-9][0-9]*$ ]] || return 2 ;;
      *.timer) [[ $result == success && \
                    ( $substate == waiting || $substate == elapsed ) ]] || return 2 ;;
      *.socket) [[ $result == success && \
                     ( $substate == listening || $substate == running ) ]] || return 2 ;;
      *.path) [[ $result == success && \
                   ( $substate == waiting || $substate == running ) ]] || return 2 ;;
      *.target) [[ -z $result && $substate == active ]] || return 2 ;;
      *) return 2 ;;
    esac
    if [[ $scope == user && $unit == *.socket ]]; then
      verify_frozen_user_socket_endpoints "$unit" active || return 2
    fi
  done
}

verify_pause_restoration() {
  local inventory pid comm count=0 affinity
  inventory=$(/usr/bin/ps -u "$target_uid" -o pid=,comm=) || return 2
  while read -r pid comm; do
    [[ $comm == catatonit ]] || continue
    ((count += 1))
    [[ -n $pause_pid && $pid == "$pause_pid" ]] || return 2
  done <<< "$inventory"
  if [[ -z $pause_pid ]]; then [[ $count == 0 ]]; return; fi
  [[ $count == 1 ]] || return 2
  pause_identity_matches || return 2
  affinity=$(/usr/bin/taskset -pc "$pause_pid") || return 2
  [[ ${affinity##*: } == "$pause_original_affinity" ]]
}

verify_original_unit_files() {
  local scope=$1 unit unit_file
  shift
  local -a planned=("$@")
  for unit in "${planned[@]}"; do
    if [[ $scope == system ]]; then
      unit_file=$(system_value UnitFileState "$unit") || return 2
      [[ $unit_file == "${system_original_unit_files[$unit]}" ]] || return 2
    elif [[ $scope == user ]]; then
      unit_file=$(user_value UnitFileState "$unit") || return 2
      [[ $unit_file == "${user_original_unit_files[$unit]}" ]] || return 2
    else
      return 2
    fi
  done
}

stop_unexpected_transaction_activations() {
  local scope=$1 unit state
  shift
  local -a planned=("$@") unexpected=()
  for unit in "${planned[@]}"; do
    if [[ $scope == system ]]; then
      array_contains "$unit" "${system_restore_units[@]}" && continue
      state=$(system_value ActiveState "$unit") || return 2
    else
      array_contains "$unit" "${user_restore_units[@]}" && continue
      state=$(user_value ActiveState "$unit") || return 2
    fi
    case "$state" in
      inactive|failed) ;;
      active|activating|deactivating|reloading) unexpected+=("$unit") ;;
      *) return 2 ;;
    esac
  done
  ((${#unexpected[@]} == 0)) && return 0
  printf 'CODESKEPTIC_HEADLESS_STOP_UNEXPECTED_ACTIVATION=%s:%s\n' \
    "$scope" "${unexpected[*]}"
  if [[ $scope == system ]]; then
    /usr/bin/systemctl stop -- "${unexpected[@]}"
  else
    userctl stop -- "${unexpected[@]}"
  fi
}

restore_transaction() {
  local failed=0 graph_ready=1 state
  if ((${#system_mask_attempted_units[@]})); then
    /usr/bin/systemctl unmask --runtime -- "${system_mask_attempted_units[@]}" || graph_ready=0
  fi
  if ((${#user_mask_attempted_units[@]})); then
    userctl unmask --runtime -- "${user_mask_attempted_units[@]}" || graph_ready=0
  fi
  if [[ $system_quiesce_started == 1 ]]; then
    verify_original_unit_files system "${system_planned_units[@]}" || graph_ready=0
  fi
  if [[ $user_quiesce_started == 1 ]]; then
    verify_original_unit_files user "${user_planned_units[@]}" || graph_ready=0
  fi
  if [[ $graph_ready != 1 ]]; then
    echo 'unit graph restoration failed; refusing corrective stop/start on a masked graph' >&2
    failed=1
  elif [[ $system_quiesce_started == 1 ]]; then
    stop_unexpected_transaction_activations system "${system_planned_units[@]}" || failed=1
  fi
  if [[ $graph_ready == 1 && $user_quiesce_started == 1 ]]; then
    stop_unexpected_transaction_activations user "${user_planned_units[@]}" || failed=1
  fi
  if [[ $graph_ready == 1 && $system_quiesce_started == 1 && ${#system_restore_units[@]} -gt 0 ]]; then /usr/bin/systemctl start -- "${system_restore_units[@]}" || failed=1; fi
  if [[ $graph_ready == 1 && $user_quiesce_started == 1 && ${#user_restore_units[@]} -gt 0 ]]; then userctl start -- "${user_restore_units[@]}" || failed=1; fi
  if [[ $pause_restore_needed == 1 ]]; then
    if pause_identity_matches; then
      /usr/bin/taskset -pc "$pause_original_affinity" "$pause_pid" >/dev/null || failed=1
      pause_identity_matches || failed=1
    else echo 'Podman pause identity changed; refusing affinity restore to reused PID' >&2; failed=1; fi
  fi
  if [[ $network_restore_needed == 1 ]]; then /usr/bin/nmcli networking on || failed=1; fi
  if [[ $graph_ready == 1 && $system_quiesce_started == 1 ]]; then verify_unit_restoration system "${system_planned_units[@]}" || failed=1; fi
  if [[ $graph_ready == 1 && $user_quiesce_started == 1 ]]; then verify_unit_restoration user "${user_planned_units[@]}" || failed=1; fi
  if [[ $network_restore_needed == 1 ]]; then
    if ! state=$(/usr/bin/nmcli networking); then failed=1
    elif [[ $state != enabled ]]; then failed=1; fi
  fi
  verify_pause_restoration || failed=1
  [[ ! -e /sys/fs/cgroup/codeskeptic-p10-07-authority ]] || failed=1
  require_no_failed_system_units || failed=1
  require_no_failed_user_units || failed=1
  return "$failed"
}

require_final_restoration_surface() {
  local network
  network=$(/usr/bin/nmcli networking) || return 2
  [[ $network == enabled && \
        ! -e /sys/fs/cgroup/codeskeptic-p10-07-authority ]] || return 2
  require_no_failed_system_units || return 2
  require_no_failed_user_units || return 2
  require_no_coredump_helper_instances || return 2
  verify_pause_restoration || return 2
  if [[ $system_quiesce_started == 1 ]]; then
    verify_original_unit_files system "${system_planned_units[@]}" || return 2
    verify_unit_restoration system "${system_planned_units[@]}" || return 2
  fi
  if [[ $user_quiesce_started == 1 ]]; then
    verify_original_unit_files user "${user_planned_units[@]}" || return 2
    verify_unit_restoration user "${user_planned_units[@]}" || return 2
  fi
}

validate_terminal_receipt() {
  local -a lines=()
  [[ ! -L $terminal_receipt && \
        $(/usr/bin/stat -c '%U:%G:%a' "$terminal_receipt") == root:root:444 ]] \
    || return 2
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
  [[ ${lines[4]} =~ ^CODESKEPTIC_HEADLESS_FINISH=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z))$ ]] || return 2
  terminal_finish=${BASH_REMATCH[1]}
  local actual_journal_sha=none
  if [[ -e $transaction_journal || -L $transaction_journal || \
        -e $transaction_journal_sha || -L $transaction_journal_sha ]]; then
    load_transaction_journal || return 2
    actual_journal_sha=$(/usr/bin/sha256sum "$transaction_journal") || return 2
    actual_journal_sha=${actual_journal_sha%% *}
  fi
  [[ $terminal_journal_sha == "$actual_journal_sha" ]] || return 2
}

recovery_is_permitted() {
  if [[ ! -e $terminal_receipt && ! -L $terminal_receipt ]]; then
    return 0
  fi
  validate_terminal_receipt || {
    echo 'terminal restoration receipt is malformed' >&2
    return 2
  }
  if [[ $terminal_restoration_failed == 0 ]]; then
    echo 'transaction already has a durable successful restoration receipt' >&2
    return 3
  fi
}

publish_terminal_receipt() {
  local restoration_failed=$1 payload_exit=$2 finish=$3 expected actual journal_hash=none
  [[ $restoration_failed == 0 || $restoration_failed == 1 ]] || return 2
  [[ $payload_exit =~ ^[0-9]+$ ]] || return 2
  ((payload_exit <= 255)) || return 2
  [[ $finish =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z)$ ]] || return 2
  if [[ -e $transaction_journal || -L $transaction_journal || \
        -e $transaction_journal_sha || -L $transaction_journal_sha ]]; then
    load_transaction_journal || return 2
    journal_hash=$(/usr/bin/sha256sum "$transaction_journal") || return 2
    journal_hash=${journal_hash%% *}
  fi
  if [[ -e $terminal_receipt || -L $terminal_receipt ]]; then
    validate_terminal_receipt || return 2
    [[ $terminal_restoration_failed == 1 ]] || return 2
  fi
  remove_recoverable_atomic_tmp "$terminal_receipt_tmp" || return 2
  /usr/bin/install -o root -g root -m 0600 /dev/null "$terminal_receipt_tmp"
  expected="CODESKEPTIC_HEADLESS_TERMINAL_VERSION=1
CODESKEPTIC_HEADLESS_RESTORATION_FAILED=$restoration_failed
CODESKEPTIC_HEADLESS_PAYLOAD_EXIT=$payload_exit
CODESKEPTIC_HEADLESS_JOURNAL_SHA256=$journal_hash
CODESKEPTIC_HEADLESS_FINISH=$finish"
  printf '%s\n' "$expected" > "$terminal_receipt_tmp"
  /usr/bin/chmod 0444 "$terminal_receipt_tmp"
  [[ ! -L $terminal_receipt_tmp && \
        $(/usr/bin/stat -c '%U:%G:%a' "$terminal_receipt_tmp") == root:root:444 ]] \
    || return 2
  actual=$(<"$terminal_receipt_tmp") || return 2
  [[ $actual == "$expected" ]] || return 2
  if [[ $restoration_failed == 0 ]]; then
    require_final_restoration_surface || return 2
    if [[ $mode == recover ]]; then
      require_recovery_coredump_unchanged || return 2
    else
      require_coredump_unchanged || return 2
    fi
  fi
  /usr/bin/sync -f "$terminal_receipt_tmp"
  /usr/bin/mv -T -- "$terminal_receipt_tmp" "$terminal_receipt"
  /usr/bin/sync -f "$headless_root"
  validate_terminal_receipt || return 2
  [[ $terminal_restoration_failed == "$restoration_failed" && \
        $terminal_payload_exit == "$payload_exit" && \
        $terminal_journal_sha == "$journal_hash" && \
        $terminal_finish == "$finish" ]]
}

cleanup() {
  local status=$? cleanup_failed=0 finish=
  trap - EXIT INT TERM HUP
  set +e
  if [[ $quiet_gate_passed == 1 ]]; then
    require_minimal_user_processes || cleanup_failed=1
    [[ ! -e /sys/fs/cgroup/codeskeptic-p10-07-authority ]] || cleanup_failed=1
  fi
  if [[ $restoration_armed == 1 ]]; then
    restore_transaction || cleanup_failed=1
    if [[ $mode == recover ]]; then
      require_recovery_coredump_unchanged || [[ $status != 0 ]] || status=2
    elif ! require_coredump_unchanged; then
      [[ $status != 0 ]] || status=2
    fi
  fi
  if [[ $log_created == 1 ]]; then
    /usr/bin/sync -f "$headless_log" || cleanup_failed=1
    finish=$(/usr/bin/date --utc --iso-8601=seconds) || cleanup_failed=1
  fi
  if [[ $cleanup_failed == 1 && $status == 0 ]]; then status=2; fi
  if ! publish_terminal_receipt "$cleanup_failed" "$status" "$finish"; then
    cleanup_failed=1
    [[ $status != 0 ]] || status=2
  fi
  if [[ $log_created == 1 ]]; then
    printf 'CODESKEPTIC_HEADLESS_TERMINAL_RECEIPT=%s\n' "$terminal_receipt"
    printf 'CODESKEPTIC_HEADLESS_CONTROLLER_CLEANUP_FAILED=%s\n' "$cleanup_failed"
    printf 'CODESKEPTIC_HEADLESS_CONTROLLER_EXIT=%s\n' "$status"
    printf 'CODESKEPTIC_HEADLESS_CONTROLLER_FINISH=%s\n' "$finish"
    /usr/bin/sync -f "$headless_log" || \
      emit_tty 'CodeSkeptic headless log durability check failed; restoration receipt remains authoritative.'
  fi
  if [[ $cleanup_failed == 1 ]]; then emit_tty 'CodeSkeptic headless cleanup FAILED; run the logged recovery command.'
  else emit_tty "CodeSkeptic headless run finished with exit $status."; fi
  [[ -z $caller_tty ]] || printf '\a\a\a' > "$caller_tty" 2>/dev/null || true
  exit "$status"
}

install_recovery_copy() {
  if [[ -e $recovery_script ]]; then
    [[ ! -L $recovery_script && \
          $(/usr/bin/stat -c '%U:%G:%a' "$recovery_script") == root:root:500 ]] \
      || return 2
    /usr/bin/cmp -s "$0" "$recovery_script" || return 2
  else
    /usr/bin/install -o root -g root -m 0500 "$0" "$recovery_script"
  fi
  /usr/bin/sync -f "$recovery_script"
  /usr/bin/sync -f "$headless_root"
  printf 'CODESKEPTIC_HEADLESS_RECOVERY_COMMAND=sudo /usr/bin/flock --exclusive %s %s recover\n' "$recovery_lock" "$recovery_script"
  emit_tty "Recovery if interrupted: sudo /usr/bin/flock --exclusive $recovery_lock $recovery_script recover"
}

run_recovery_mode() {
  local recovery_rc
  require_local_tty_path
  [[ ! -L $headless_log && $(/usr/bin/stat -c '%U:%G:%a' "$headless_log") == root:root:444 ]] || exit 2
  set +e
  recovery_is_permitted
  recovery_rc=$?
  set -e
  case "$recovery_rc" in
    0) ;;
    3) echo 'recovery replay refused after successful restoration' >&2; exit 2 ;;
    *) echo 'recovery refused because terminal state is not trustworthy' >&2; exit 2 ;;
  esac
  exec >>"$headless_log" 2>&1
  log_created=1
  echo "CODESKEPTIC_HEADLESS_RECOVERY_BEGIN=$(/usr/bin/date --utc --iso-8601=seconds)"
  if ! load_transaction_journal; then echo 'durable transaction journal is incomplete; no automated recovery attempted' >&2; exit 2; fi
  if ! capture_coredump_baseline; then
    echo 'cannot establish a clean recovery coredump baseline' >&2
    exit 2
  fi
  recovery_coredump_baseline_sha=$coredump_baseline_sha
  recovery_drkonqi_socket_accepted_baseline=$drkonqi_socket_accepted_baseline
  system_mask_attempted_units=("${system_planned_units[@]}")
  user_mask_attempted_units=("${user_planned_units[@]}")
  system_quiesce_started=1; user_quiesce_started=1; network_restore_needed=1
  [[ -z $pause_pid ]] || pause_restore_needed=1
  restoration_armed=1
  trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
  exit 0
}

[[ $(/usr/bin/id -u) == 0 ]] || { echo 'headless controller must run as root' >&2; exit 2; }
[[ ${SUDO_USER:-} == "$target_user" && ${SUDO_UID:-} == "$target_uid" ]] || { echo 'headless controller requires direct sudo from tanzer' >&2; exit 2; }
if [[ $# == 1 && $1 == recover ]]; then
  mode=recover
elif [[ $# == 2 && $1 =~ ^[0-9a-f]{64}$ && $2 =~ ^[0-9]+$ ]]; then
  coredump_baseline_sha=$1
  drkonqi_socket_accepted_baseline=$2
  drkonqi_socket_accepted_journal_baseline=$2
else
  echo 'headless controller requires inherited coredump SHA and DrKonqi NAccepted, or recover' >&2
  exit 2
fi
caller_tty=${SUDO_TTY:-}
require_local_tty_path
if [[ $mode == recover ]]; then run_recovery_mode; fi

[[ ! -e $headless_log && ! -L $headless_log && \
      ! -e $transaction_journal && ! -L $transaction_journal && \
      ! -e $transaction_journal_sha && ! -L $transaction_journal_sha && \
      ! -e $terminal_receipt && ! -L $terminal_receipt ]] || {
  echo 'headless authority log, journal, or terminal receipt already exists' >&2
  exit 2
}
/usr/bin/install -d -o root -g root -m 0755 "$headless_root"
/usr/bin/install -o root -g root -m 0444 /dev/null "$headless_log"
[[ ! -L $headless_root && $(/usr/bin/stat -c '%U:%G:%a' "$headless_root") == root:root:755 ]] || exit 2
[[ ! -L $headless_log && $(/usr/bin/stat -c '%U:%G:%a' "$headless_log") == root:root:444 ]] || exit 2
exec >>"$headless_log" 2>&1
log_created=1
trap cleanup EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
emit_tty 'CodeSkeptic headless authority preparation started.'
echo "CODESKEPTIC_HEADLESS_CONTROLLER_BEGIN=$(/usr/bin/date --utc --iso-8601=seconds)"
echo "caller_tty=$caller_tty"
echo "feature_head=$feature_head"
echo "main_head=$main_head"
echo "cooldown_seconds=$cooldown_seconds"
echo "kernel=$(/usr/bin/uname -srmo)"
[[ $(/usr/bin/uname -sr) == "$expected_os" ]] || {
  echo 'host kernel differs from the frozen V7 authority' >&2
  exit 2
}
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_wireplumber_candidate
require_wireplumber_candidate
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_wireplumber_candidate
echo "cmdline=$(< /proc/cmdline)"
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_local_tty_session
require_local_tty_session
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_local_tty_session
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_system_headless
require_system_headless
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_system_headless
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_no_failed_system_units
require_no_failed_system_units
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_no_failed_system_units
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_no_failed_user_units
require_no_failed_user_units
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_no_failed_user_units
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=establish_inherited_coredump_baseline
establish_inherited_coredump_baseline
echo CODESKEPTIC_HEADLESS_GATE_PASS=establish_inherited_coredump_baseline
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=drain_graphical_transients
drain_graphical_transients
echo CODESKEPTIC_HEADLESS_GATE_PASS=drain_graphical_transients
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_no_active_user_transients
require_no_active_user_transients
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_no_active_user_transients
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_coredump_unchanged_preplan
require_coredump_unchanged
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_coredump_unchanged_preplan
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=install_recovery_copy
install_recovery_copy
echo CODESKEPTIC_HEADLESS_GATE_PASS=install_recovery_copy

echo CODESKEPTIC_HEADLESS_GATE_BEGIN=prepare_system_units
prepare_system_units
echo CODESKEPTIC_HEADLESS_GATE_PASS=prepare_system_units
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=prepare_user_units
prepare_user_units
echo CODESKEPTIC_HEADLESS_GATE_PASS=prepare_user_units
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=capture_pause_identity
capture_pause_identity
echo CODESKEPTIC_HEADLESS_GATE_PASS=capture_pause_identity
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=collect_authority_bash_ancestors
collect_authority_bash_ancestors
echo CODESKEPTIC_HEADLESS_GATE_PASS=collect_authority_bash_ancestors
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=write_transaction_journal
write_transaction_journal
echo CODESKEPTIC_HEADLESS_GATE_PASS=write_transaction_journal
restoration_armed=1
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=quiesce_system_units
quiesce_system_units
echo CODESKEPTIC_HEADLESS_GATE_PASS=quiesce_system_units
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=quiesce_user_units
quiesce_user_units
echo CODESKEPTIC_HEADLESS_GATE_PASS=quiesce_user_units
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=pin_pause_identity
pin_pause_identity
echo CODESKEPTIC_HEADLESS_GATE_PASS=pin_pause_identity
network_restore_needed=1
/usr/bin/nmcli networking off
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_quiet_authority_initial
require_quiet_authority
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_quiet_authority_initial
quiet_gate_passed=1
echo "CODESKEPTIC_HEADLESS_COOLDOWN_BEGIN=$(/usr/bin/date --utc --iso-8601=seconds)"
/usr/bin/sleep "$cooldown_seconds"
echo CODESKEPTIC_HEADLESS_GATE_BEGIN=require_quiet_authority_post_cooldown
require_quiet_authority
echo CODESKEPTIC_HEADLESS_GATE_PASS=require_quiet_authority_post_cooldown
echo "CODESKEPTIC_HEADLESS_CONFIRMATION_BEGIN=$(/usr/bin/date --utc --iso-8601=seconds)"
set +e
"$run_root/cgroup-launcher.sh" confirmation
status=$?
set -e
exit "$status"
