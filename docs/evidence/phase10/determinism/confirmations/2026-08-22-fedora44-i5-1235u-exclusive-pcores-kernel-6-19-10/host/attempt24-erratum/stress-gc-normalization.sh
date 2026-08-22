#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH

readonly unit=codeskeptic-attempt24-gc-normalization.service
readonly unit_file=/home/tanzer/.local/share/systemd/user/$unit
readonly enable_link=/home/tanzer/.config/systemd/user/default.target.wants/$unit
readonly mask_link=/run/user/1000/systemd/user/$unit

baseline_active=
baseline_inactive=
coredump_before=
drkonqi_before=
unit_file_sha=
unit_file_installed=0
unit_enabled=0
mask_created=0

userctl() {
  /usr/bin/systemctl --user --no-pager "$@"
}

coredump_inventory_sha() {
  local inventory
  inventory=$(/usr/bin/coredumpctl --quiet --no-pager --no-legend --json=short list)
  printf '%s' "$inventory" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
}

cleanup() {
  local status=$? cleanup_failed=0 actual_sha target
  trap - EXIT INT TERM HUP
  set +e
  if ((unit_file_installed == 1)); then
    userctl stop "$unit" >/dev/null 2>&1 || cleanup_failed=1
  fi
  if ((mask_created == 1)); then
    if [[ -L $mask_link ]] && target=$(/usr/bin/readlink -- "$mask_link") && \
        [[ $target == /dev/null ]]; then
      userctl unmask --runtime "$unit" >/dev/null 2>&1 || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  if ((unit_enabled == 1)); then
    if [[ -L $enable_link ]] && target=$(/usr/bin/readlink -- "$enable_link") && \
        [[ $target == "$unit_file" ]]; then
      userctl disable "$unit" >/dev/null 2>&1 || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  if ((unit_file_installed == 1)); then
    if [[ -f $unit_file && ! -L $unit_file && \
          $(/usr/bin/stat -c '%U:%G:%a:%F' "$unit_file") == tanzer:tanzer:600:regular\ file ]]; then
      actual_sha=$(/usr/bin/sha256sum "$unit_file" | /usr/bin/cut -d' ' -f1)
      if [[ $actual_sha == "$unit_file_sha" ]]; then
        /usr/bin/rm -f -- "$unit_file" || cleanup_failed=1
      else
        cleanup_failed=1
      fi
    else
      cleanup_failed=1
    fi
  fi
  if ((unit_file_installed == 1 || unit_enabled == 1 || mask_created == 1)); then
    userctl daemon-reload >/dev/null 2>&1 || cleanup_failed=1
  fi
  if ((unit_file_installed == 1)); then
    [[ ! -e $unit_file && ! -L $unit_file ]] || cleanup_failed=1
  fi
  if ((unit_enabled == 1)); then
    [[ ! -e $enable_link && ! -L $enable_link ]] || cleanup_failed=1
  fi
  if ((mask_created == 1)); then
    [[ ! -e $mask_link && ! -L $mask_link ]] || cleanup_failed=1
  fi
  set -e
  ((cleanup_failed == 0)) || exit 2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[[ $(/usr/bin/id -u) == 1000 ]]
[[ ! -e $unit_file && ! -L $unit_file && \
      ! -e $enable_link && ! -L $enable_link && \
      ! -e $mask_link && ! -L $mask_link ]]
/usr/bin/install -d -m 0700 /home/tanzer/.local/share/systemd/user
printf '%s\n' \
  '[Unit]' \
  'Description=CodeSkeptic Attempt24 GC normalization probe' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/bin/true' \
  'RemainAfterExit=yes' \
  '[Install]' \
  'WantedBy=default.target' \
  | /usr/bin/install -m 0600 /dev/stdin "$unit_file"
unit_file_installed=1
unit_file_sha=$(/usr/bin/sha256sum "$unit_file" | /usr/bin/cut -d' ' -f1)
[[ $unit_file_sha =~ ^[0-9a-f]{64}$ ]]

coredump_before=$(coredump_inventory_sha)
drkonqi_before=$(userctl show drkonqi-coredump-launcher.socket -p NAccepted --value)
[[ $drkonqi_before =~ ^[0-9]+$ ]]
[[ -z $(userctl --failed --no-legend --plain) ]]

userctl daemon-reload
userctl enable "$unit"
[[ -L $enable_link && $(/usr/bin/readlink -- "$enable_link") == "$unit_file" ]]
unit_enabled=1
userctl start "$unit"
[[ $(userctl show "$unit" -p ActiveState --value) == active ]]
userctl stop "$unit"
baseline_active=$(userctl show "$unit" -p ActiveEnterTimestampMonotonic --value)
baseline_inactive=$(userctl show "$unit" -p InactiveExitTimestampMonotonic --value)
[[ $baseline_active =~ ^[1-9][0-9]*$ && $baseline_inactive =~ ^[1-9][0-9]*$ ]]
[[ $(userctl show "$unit" -p ActiveState --value) == inactive ]]
[[ $(userctl show "$unit" -p SubState --value) == dead ]]
[[ $(userctl show "$unit" -p Result --value) == success ]]

userctl disable "$unit"
unit_enabled=0
[[ ! -e $enable_link && ! -L $enable_link ]]
userctl mask --runtime "$unit"
[[ -L $mask_link && $(/usr/bin/readlink -- "$mask_link") == /dev/null ]]
mask_created=1
userctl daemon-reload
snapshot=$(userctl show "$unit" \
  -p LoadState -p ActiveState -p SubState -p Result -p UnitFileState -p Job \
  -p ActiveEnterTimestampMonotonic -p InactiveExitTimestampMonotonic)
expected='LoadState=masked
ActiveState=inactive
SubState=dead
UnitFileState=masked-runtime
InactiveExitTimestampMonotonic=0
ActiveEnterTimestampMonotonic=0
Job=
Result=success'
[[ $snapshot == "$expected" ]]
[[ $(userctl show "$unit" -p Id --value) == "$unit" ]]
[[ $(userctl show "$unit" -p Transient --value) == no ]]
[[ $(userctl show "$unit" -p MainPID --value) == 0 ]]
[[ $(userctl show "$unit" -p ControlPID --value) == 0 ]]
control_group=$(userctl show "$unit" -p ControlGroup --value)
if [[ -n $control_group ]]; then
  [[ $control_group =~ ^/user\.slice/user-1000\.slice/user@1000\.service/[-A-Za-z0-9_.:@/\\]+$ ]]
  cgroup_path=/sys/fs/cgroup$control_group
  if [[ -e $cgroup_path || -L $cgroup_path ]]; then
    [[ -d $cgroup_path && ! -L $cgroup_path ]]
    [[ -z $(<"$cgroup_path/cgroup.procs") ]]
  fi
fi
echo CODESKEPTIC_ATTEMPT24_MASKED_SERVICE_TRANSIENT_GATE_SHAPE_PASS

[[ $(coredump_inventory_sha) == "$coredump_before" ]]
[[ $(userctl show drkonqi-coredump-launcher.socket -p NAccepted --value) == "$drkonqi_before" ]]
[[ -z $(userctl --failed --no-legend --plain) ]]
printf 'CODESKEPTIC_ATTEMPT24_GC_NORMALIZATION_PASS baseline=%s/%s masked=0/0\n' \
  "$baseline_active" "$baseline_inactive"
