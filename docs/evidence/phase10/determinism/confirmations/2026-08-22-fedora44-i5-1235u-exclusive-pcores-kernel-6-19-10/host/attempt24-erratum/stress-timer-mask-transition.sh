#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH

readonly operator_root=/home/tanzer/Projects/CodeSkeptic/build/p10-07-v7-confirmation-operator-88e369b-attempt24
readonly user_unit_root=/home/tanzer/.local/share/systemd/user
readonly runtime_unit_root=/run/user/1000/systemd/user
readonly runtime_root=/run/user/1000
readonly backend_name=codeskeptic-attempt24-mask-stress.service
readonly manager_name=codeskeptic-attempt24-mask-stress-manager.service
readonly consumer_name=codeskeptic-attempt24-mask-stress-consumer.service
readonly timer_name=codeskeptic-attempt24-mask-stress.timer
readonly socket_name=codeskeptic-attempt24-mask-stress.socket
readonly path_name=codeskeptic-attempt24-mask-stress.path
readonly target_name=codeskeptic-attempt24-mask-stress.target
readonly socket_template_name=codeskeptic-attempt24-mask-stress@.service
readonly helper=$operator_root/stress-dependency-service.sh
readonly socket_endpoint=$runtime_root/codeskeptic-attempt24-mask-stress.sock
readonly path_trigger=$runtime_root/codeskeptic-attempt24-mask-stress.trigger
readonly manager_marker=$runtime_root/codeskeptic-attempt24-manager-live
readonly stop_order=$runtime_root/codeskeptic-attempt24-stop-order
readonly helper_sha=86e13bc93014381b3e812b98e22704204d5d09513534cc3114cfac982b902356
readonly backend_sha=3d294bba2af934d26c8db7121b9c8138e62938f38d1dbc895865d43f770db0de
readonly manager_sha=a2b0a03451d5f78e909aa95a8901febd4ba74b988b792b6054798d74cd9371fb
readonly consumer_sha=6866340410043b6ae7eb6167e5ff931a9638e8538d802dff53af426158e45bec
readonly timer_sha=3882c4be0050e020f1e6a83c67f651f277606ecc351d7262ff76bd5acbe97be5
readonly socket_sha=9d03c730d9876951117f41b94dbbe2d9280bbab4f379bcbc64cb4d478913c70a
readonly path_sha=b2c2d1963bd89176c402e3247e0cfaaaca2f2f2edad6a5f7c9867528a9b659c4
readonly target_sha=f8019156a30544543748860586ae221ccac3c1902fd368f9ac411b261280aac8
readonly socket_template_sha=3a2947dc7bf0279f2f915025d11c89c114131d29411e98fb4e4a527f64227dcd
readonly -a all_units=(
  "$timer_name" "$socket_name" "$path_name" "$consumer_name"
  "$manager_name" "$backend_name" "$target_name"
)
readonly -a active_units=(
  "$timer_name" "$socket_name" "$path_name"
  "$backend_name" "$manager_name" "$consumer_name"
)
readonly -a installed_names=(
  "${all_units[@]}" "$socket_template_name"
)
readonly -a sources=(
  "$operator_root/$timer_name"
  "$operator_root/$socket_name"
  "$operator_root/$path_name"
  "$operator_root/$consumer_name"
  "$operator_root/$manager_name"
  "$operator_root/$backend_name"
  "$operator_root/$target_name"
  "$operator_root/$socket_template_name"
)
readonly -a destinations=(
  "$user_unit_root/$timer_name"
  "$user_unit_root/$socket_name"
  "$user_unit_root/$path_name"
  "$user_unit_root/$consumer_name"
  "$user_unit_root/$manager_name"
  "$user_unit_root/$backend_name"
  "$user_unit_root/$target_name"
  "$user_unit_root/$socket_template_name"
)
readonly -a expected_shas=(
  "$timer_sha" "$socket_sha" "$path_sha" "$consumer_sha"
  "$manager_sha" "$backend_sha" "$target_sha"
  "$socket_template_sha"
)

installed=0
cycles_passed=0
activation_guard_rejected=0
accept_gap_guard_rejected=0
coredump_baseline_sha=
drkonqi_accepted_baseline=
stress_socket_accepted_baseline=
stress_socket_accepted_pre_stop=
activation_cursor=
declare -A active_enter_epoch=()
declare -A inactive_exit_epoch=()

userctl() {
  /usr/bin/systemctl --user --no-pager "$@"
}

unit_value() {
  userctl show "$2" -p "$1" --value
}

coredump_inventory_sha() {
  local inventory
  inventory=$(/usr/bin/coredumpctl --quiet --no-pager --no-legend \
    --json=short list)
  printf '%s' "$inventory" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
}

require_clean_host_delta() {
  local latest accepted failed instances
  latest=$(coredump_inventory_sha)
  accepted=$(unit_value NAccepted drkonqi-coredump-launcher.socket)
  failed=$(userctl --failed --no-legend --plain)
  instances=$(userctl list-units 'drkonqi-coredump-launcher@*.service' \
    --all --no-legend --plain)
  [[ $latest == "$coredump_baseline_sha" && \
        $accepted == "$drkonqi_accepted_baseline" && \
        -z $failed && -z $instances ]]
}

require_stress_socket_clean() {
  local accepted instances
  accepted=$(unit_value NAccepted "$socket_name")
  instances=$(userctl list-units 'codeskeptic-attempt24-mask-stress@*.service' \
    --all --no-legend --plain)
  [[ $accepted == "$stress_socket_accepted_baseline" && -z $instances ]]
}

wait_for_stress_socket_accept() {
  local expected=$1 accepted attempt instances
  [[ $expected =~ ^[1-9][0-9]*$ ]] || return 2
  for ((attempt = 0; attempt < 100; attempt++)); do
    accepted=$(unit_value NAccepted "$socket_name") || return 2
    instances=$(userctl list-units 'codeskeptic-attempt24-mask-stress@*.service' \
      --all --no-legend --plain) || return 2
    [[ $accepted == "$expected" && -z $instances ]] && return 0
    /usr/bin/sleep 0.05
  done
  return 2
}

connect_stress_socket() {
  /usr/bin/python3 -I -B - "$socket_endpoint" <<'PY'
import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect(sys.argv[1])
PY
}

remove_exact_template_copy() {
  local destination=$1 source=$2 expected_sha=$3 metadata actual
  [[ -f $destination && ! -L $destination ]] || return 2
  metadata=$(/usr/bin/stat -c '%U:%G:%a:%F' "$destination")
  [[ $metadata == tanzer:tanzer:644:regular\ file ]] || return 2
  actual=$(/usr/bin/sha256sum "$destination" | /usr/bin/cut -d' ' -f1)
  [[ $actual == "$expected_sha" ]] || return 2
  /usr/bin/cmp -s "$destination" "$source"
  /usr/bin/rm -- "$destination"
}

cleanup() {
  local original_rc=$? cleanup_failed=0 index
  trap - EXIT HUP INT TERM
  userctl unmask --runtime -- "${all_units[@]}" >/dev/null 2>&1 || cleanup_failed=1
  userctl stop -- "${all_units[@]}" >/dev/null 2>&1 || cleanup_failed=1
  userctl reset-failed -- "${all_units[@]}" >/dev/null 2>&1 || true
  /usr/bin/rm -f -- "$socket_endpoint" "$path_trigger" "$manager_marker" "$stop_order"
  if ((installed == 1)); then
    for ((index = 0; index < ${#destinations[@]}; index++)); do
      remove_exact_template_copy \
        "${destinations[index]}" "${sources[index]}" "${expected_shas[index]}" \
        || cleanup_failed=1
    done
  fi
  userctl daemon-reload >/dev/null 2>&1 || cleanup_failed=1
  for index in "${!destinations[@]}"; do
    [[ ! -e ${destinations[index]} && ! -L ${destinations[index]} && \
          ! -e $runtime_unit_root/${installed_names[index]} && \
          ! -L $runtime_unit_root/${installed_names[index]} ]] || cleanup_failed=1
  done
  [[ ! -e $socket_endpoint && ! -L $socket_endpoint && \
        ! -e $path_trigger && ! -L $path_trigger && \
        ! -e $manager_marker && ! -L $manager_marker && \
        ! -e $stop_order && ! -L $stop_order ]] || cleanup_failed=1
  ((cleanup_failed == 0)) || exit 2
  exit "$original_rc"
}

capture_epochs() {
  local unit active_enter inactive_exit job
  for unit in "${all_units[@]}"; do
    active_enter=$(unit_value ActiveEnterTimestampMonotonic "$unit")
    inactive_exit=$(unit_value InactiveExitTimestampMonotonic "$unit")
    job=$(unit_value Job "$unit")
    [[ $active_enter =~ ^[0-9]+$ && $inactive_exit =~ ^[0-9]+$ && -z $job ]]
    active_enter_epoch["$unit"]=$active_enter
    inactive_exit_epoch["$unit"]=$inactive_exit
  done
}

capture_activation_cursor() {
  local cursor_line
  cursor_line=$(/usr/bin/journalctl --user --quiet --no-pager \
    --show-cursor -n 0)
  activation_cursor=${cursor_line#-- cursor: }
  [[ $activation_cursor != "$cursor_line" && \
        $activation_cursor =~ ^s=[0-9a-f]+\;i=[0-9a-f]+\;b=[0-9a-f]+\;m=[0-9a-f]+\;t=[0-9a-f]+\;x=[0-9a-f]+$ ]]
}

activation_inventory() {
  /usr/bin/journalctl --user --quiet --no-pager \
    --after-cursor="$activation_cursor" -o json \
    MESSAGE_ID=39f53479d3a045ac8e11786248231fbf \
    | /usr/bin/jq -r '.USER_UNIT // .UNIT // empty'
}

require_no_stress_activation() {
  local inventory unit
  inventory=$(activation_inventory)
  while IFS= read -r unit; do
    [[ -n $unit ]] || continue
    for planned in "${all_units[@]}"; do
      [[ $unit != "$planned" ]] || return 2
    done
    [[ ! $unit =~ ^codeskeptic-attempt24-mask-stress@[A-Za-z0-9_.@:-]+\.service$ ]] \
      || return 2
  done <<< "$inventory"
}

verify_stopped() {
  local unit load state substate result unit_file job active_enter inactive_exit
  for unit in "${all_units[@]}"; do
    load=$(unit_value LoadState "$unit")
    state=$(unit_value ActiveState "$unit")
    substate=$(unit_value SubState "$unit")
    result=$(unit_value Result "$unit")
    unit_file=$(unit_value UnitFileState "$unit")
    job=$(unit_value Job "$unit")
    active_enter=$(unit_value ActiveEnterTimestampMonotonic "$unit")
    inactive_exit=$(unit_value InactiveExitTimestampMonotonic "$unit")
    [[ $load == loaded && $state == inactive && $substate == dead && \
          $unit_file == static && -z $job && \
          $active_enter =~ ^[0-9]+$ && $inactive_exit =~ ^[0-9]+$ ]]
    if [[ $unit == "$target_name" ]]; then
      [[ -z $result ]]
    else
      [[ $result == success ]]
    fi
  done
}

verify_masked() {
  local unit load state substate result unit_file job active_enter inactive_exit
  for unit in "${all_units[@]}"; do
    load=$(unit_value LoadState "$unit")
    state=$(unit_value ActiveState "$unit")
    substate=$(unit_value SubState "$unit")
    result=$(unit_value Result "$unit")
    unit_file=$(unit_value UnitFileState "$unit")
    job=$(unit_value Job "$unit")
    active_enter=$(unit_value ActiveEnterTimestampMonotonic "$unit")
    inactive_exit=$(unit_value InactiveExitTimestampMonotonic "$unit")
    [[ ( $load == loaded || $load == masked ) && \
          $state == inactive && $substate == dead && \
          $unit_file == masked-runtime && -z $job && \
          $active_enter == "${active_enter_epoch[$unit]}" && \
          $inactive_exit == "${inactive_exit_epoch[$unit]}" ]]
    if [[ $unit == "$target_name" ]]; then
      [[ -z $result ]]
    else
      [[ $result == success ]]
    fi
  done
}

report_error() {
  local rc=$?
  printf 'CODESKEPTIC_ATTEMPT24_STRESS_FAIL line=%s rc=%s command=%s\n' \
    "$1" "$rc" "$2" >&2
  return "$rc"
}

trap cleanup EXIT
trap 'report_error "$LINENO" "$BASH_COMMAND"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[[ $(/usr/bin/id -un) == tanzer && $(/usr/bin/id -u) == 1000 ]] || exit 2
[[ -d $user_unit_root && ! -L $user_unit_root && \
      -d $runtime_unit_root && ! -L $runtime_unit_root ]] || exit 2
[[ ! -L $helper && -f $helper && \
      $(/usr/bin/stat -c '%U:%G:%a:%F' "$helper") == tanzer:tanzer:500:regular\ file && \
      $(/usr/bin/sha256sum "$helper" | /usr/bin/cut -d' ' -f1) == "$helper_sha" ]] || exit 2
for index in "${!destinations[@]}"; do
  [[ ! -e ${destinations[index]} && ! -L ${destinations[index]} && \
        ! -e $runtime_unit_root/${installed_names[index]} && \
        ! -L $runtime_unit_root/${installed_names[index]} ]] || exit 2
  [[ $(/usr/bin/sha256sum "${sources[index]}" | /usr/bin/cut -d' ' -f1) == \
        "${expected_shas[index]}" ]] || exit 2
done
[[ ! -e $socket_endpoint && ! -L $socket_endpoint && \
      ! -e $path_trigger && ! -L $path_trigger && \
      ! -e $manager_marker && ! -L $manager_marker && \
      ! -e $stop_order && ! -L $stop_order ]] || exit 2

coredump_baseline_sha=$(coredump_inventory_sha)
drkonqi_accepted_baseline=$(unit_value NAccepted drkonqi-coredump-launcher.socket)
[[ $coredump_baseline_sha =~ ^[0-9a-f]{64}$ && \
      $drkonqi_accepted_baseline =~ ^[0-9]+$ ]]
require_clean_host_delta

for index in "${!destinations[@]}"; do
  /usr/bin/install -m 0644 "${sources[index]}" "${destinations[index]}"
done
installed=1
userctl daemon-reload

userctl start -- "$socket_name"
[[ $(unit_value ActiveState "$socket_name") == active && \
      ( $(unit_value SubState "$socket_name") == listening || \
        $(unit_value SubState "$socket_name") == running ) && \
      -S $socket_endpoint ]]
connect_stress_socket
wait_for_stress_socket_accept 1
capture_activation_cursor
connect_stress_socket
wait_for_stress_socket_accept 2
[[ $(unit_value NAccepted "$socket_name") == 2 ]]
userctl stop -- "$socket_name"
[[ $(unit_value NAccepted "$socket_name") == 0 && \
      ! -e $socket_endpoint && ! -L $socket_endpoint ]]
if require_no_stress_activation; then
  accept_gap_guard_rc=0
else
  accept_gap_guard_rc=$?
fi
[[ $accept_gap_guard_rc == 2 ]]
accept_gap_guard_rejected=1
require_clean_host_delta

userctl start -- "$socket_name"
[[ $(unit_value ActiveState "$socket_name") == active && \
      ( $(unit_value SubState "$socket_name") == listening || \
        $(unit_value SubState "$socket_name") == running ) && \
      -S $socket_endpoint ]]
connect_stress_socket
wait_for_stress_socket_accept 1
stress_socket_accepted_pre_stop=$(unit_value NAccepted "$socket_name")
[[ $stress_socket_accepted_pre_stop == 1 ]]
userctl stop -- "$socket_name"
[[ $(unit_value ActiveState "$socket_name") == inactive && \
      $(unit_value SubState "$socket_name") == dead && \
      $(unit_value Result "$socket_name") == success && \
      -z $(unit_value Job "$socket_name") && \
      ! -e $socket_endpoint && ! -L $socket_endpoint ]]
stress_socket_accepted_baseline=$(unit_value NAccepted "$socket_name")
[[ $stress_socket_accepted_baseline == 0 ]]
require_clean_host_delta
require_stress_socket_clean

for ((cycle = 1; cycle <= 100; cycle++)); do
  /usr/bin/rm -f -- "$stop_order"
  userctl start -- "${active_units[@]}"
  for service in "$backend_name" "$manager_name" "$consumer_name"; do
    [[ $(unit_value ActiveState "$service") == active && \
          $(unit_value SubState "$service") == running && \
          $(unit_value Result "$service") == success ]]
  done
  [[ $(unit_value SubState "$timer_name") == waiting && \
        ( $(unit_value SubState "$socket_name") == listening || \
          $(unit_value SubState "$socket_name") == running ) && \
        ( $(unit_value SubState "$path_name") == waiting || \
          $(unit_value SubState "$path_name") == running ) && \
        $(unit_value ActiveState "$target_name") == inactive && \
        -S $socket_endpoint && -f $manager_marker ]]
  require_stress_socket_clean
  capture_activation_cursor

  userctl stop -- "${all_units[@]}"
  [[ $(<"$stop_order") == $'consumer\nmanager\nbackend' ]]
  [[ ! -e $manager_marker && ! -L $manager_marker && \
        ! -e $socket_endpoint && ! -L $socket_endpoint ]]
  verify_stopped
  capture_epochs

  userctl mask --runtime -- "${all_units[@]}" >/dev/null 2>&1
  verify_masked
  /usr/bin/sleep 0.05
  verify_masked
  require_no_stress_activation
  require_clean_host_delta
  require_stress_socket_clean

  userctl unmask --runtime -- "${all_units[@]}" >/dev/null 2>&1
  verify_stopped
  require_clean_host_delta
  require_stress_socket_clean
  ((cycles_passed += 1))
done

/usr/bin/rm -f -- "$stop_order"
capture_activation_cursor
userctl start -- "$backend_name"
userctl stop -- "$backend_name"
gap_inventory=$(activation_inventory)
[[ $gap_inventory == "$backend_name" ]]
if require_no_stress_activation; then
  gap_guard_rc=0
else
  gap_guard_rc=$?
fi
[[ $gap_guard_rc == 2 ]]
activation_guard_rejected=1
require_clean_host_delta
require_stress_socket_clean

printf '%s\n' \
  "CODESKEPTIC_ATTEMPT24_STOP_BEFORE_MASK_STRESS_PASS cycles=$cycles_passed dependency_order=consumer-manager-backend activation_guard_rejected=$activation_guard_rejected accept_gap_guard_rejected=$accept_gap_guard_rejected accept_socket_pre_stop=$stress_socket_accepted_pre_stop accept_socket_post_stop=$stress_socket_accepted_baseline accept_socket_delta=0 coredump_inventory_delta=0 drkonqi_accept_delta=0"
