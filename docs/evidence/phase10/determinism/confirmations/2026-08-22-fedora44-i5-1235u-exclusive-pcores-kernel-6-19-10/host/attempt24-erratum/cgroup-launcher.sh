#!/usr/bin/env bash
set -euo pipefail

readonly cgroup_root=/sys/fs/cgroup
readonly authority=$cgroup_root/codeskeptic-p10-07-authority
readonly controller=$authority/controller
readonly measurement=$authority/measurement
readonly run_root=/run/codeskeptic-p10-07
readonly repo=/var/lib/codeskeptic-p10-07/88e369b21675e64e0a92842b0ce22f0c8148745e-confirmation-v7-24/source
readonly snapshot=${repo%/source}
readonly target_user=tanzer
readonly measurement_cpus=0-3
readonly controller_cpus=4-11
readonly all_cpus=0-11
readonly expected_os='Linux 6.19.10-300.fc44.x86_64'

controller_pid=
original_cgroup=
moved_launcher=0
created_authority=0

group_is_gone() {
  local pgid=$1
  ! kill -0 -- "-$pgid" 2>/dev/null
}

reap_zombie_controller() {
  local pid=$1
  local state
  state=$(/usr/bin/ps -o stat= -p "$pid" 2>/dev/null) || return 0
  if [[ $state == Z* ]]; then
    wait "$pid" 2>/dev/null || true
  fi
}

stop_controller_group() {
  local pgid=$1
  local failed=0
  kill -TERM -- "-$pgid" 2>/dev/null || true
  for _ in {1..100}; do
    reap_zombie_controller "$pgid"
    group_is_gone "$pgid" && break
    sleep 0.01
  done
  if ! group_is_gone "$pgid"; then
    kill -KILL -- "-$pgid" 2>/dev/null || true
    for _ in {1..100}; do
      reap_zombie_controller "$pgid"
      group_is_gone "$pgid" && break
      sleep 0.01
    done
  fi
  if ! group_is_gone "$pgid"; then
    echo "controller process group survived SIGKILL: $pgid" >&2
    failed=1
  fi
  wait "$pgid" 2>/dev/null || true
  return "$failed"
}

cgroup_is_empty() {
  local path=$1
  [[ -f $path/cgroup.events ]] && grep -qx 'populated 0' <(
    grep '^populated ' "$path/cgroup.events"
  )
}

kill_and_wait_cgroup() {
  local path=$1
  [[ -d $path ]] || return 0
  if [[ ! -w $path/cgroup.kill ]]; then
    echo "cgroup.kill is unavailable: $path" >&2
    return 1
  fi
  printf '%s\n' 1 > "$path/cgroup.kill" || return 1
  for _ in {1..200}; do
    cgroup_is_empty "$path" && return 0
    sleep 0.01
  done
  echo "cgroup remained populated: $path" >&2
  return 1
}

cleanup() {
  local status=$?
  local cleanup_failed=0
  local original_target
  trap - EXIT INT TERM HUP
  set +e

  if [[ -n $controller_pid ]]; then
    stop_controller_group "$controller_pid" || cleanup_failed=1
    controller_pid=
  fi

  if [[ $moved_launcher == 1 ]]; then
    original_target=$cgroup_root$original_cgroup
    if ! printf '%s\n' $$ > "$original_target/cgroup.procs"; then
      echo "cannot restore launcher to original cgroup: $original_cgroup" >&2
      cleanup_failed=1
    elif [[ $(< /proc/self/cgroup) != "0::$original_cgroup" ]]; then
      echo 'launcher cgroup restoration did not take effect' >&2
      cleanup_failed=1
    else
      moved_launcher=0
    fi
  fi

  if [[ $moved_launcher == 0 && $created_authority == 1 ]]; then
    kill_and_wait_cgroup "$measurement" || cleanup_failed=1
    kill_and_wait_cgroup "$controller" || cleanup_failed=1
    if [[ -d $measurement ]]; then
      printf '%s\n' member > "$measurement/cpuset.cpus.partition" || cleanup_failed=1
      rmdir "$measurement" || cleanup_failed=1
    fi
    [[ ! -d $controller ]] || rmdir "$controller" || cleanup_failed=1
    if [[ -d $authority ]]; then
      printf '%s\n' '-cpuset -cpu -memory' > "$authority/cgroup.subtree_control" \
        || cleanup_failed=1
      rmdir "$authority" || cleanup_failed=1
    fi
  elif [[ $created_authority == 1 ]]; then
    echo "authority retained for manual recovery: $authority" >&2
    cleanup_failed=1
  fi

  if [[ $cleanup_failed == 1 ]]; then
    echo 'cgroup cleanup or rollback failed; manual recovery is required' >&2
    [[ $status != 0 ]] || status=2
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run_as_controller() {
  /usr/bin/setsid --wait \
    /usr/bin/runuser -u "$target_user" -- \
    /usr/bin/env -i \
      HOME="$(getent passwd "$target_user" | cut -d: -f6)" \
      USER="$target_user" \
      LOGNAME="$target_user" \
      PATH=/usr/local/bin:/usr/bin:/bin \
      XDG_RUNTIME_DIR="/run/user/$(id -u "$target_user")" \
      /usr/bin/taskset -c "$controller_cpus" "$@" &
  controller_pid=$!
  local status=0
  wait "$controller_pid" || status=$?
  controller_pid=
  return "$status"
}

[[ $(id -u) == 0 ]] || { echo 'launcher must run as root' >&2; exit 2; }
[[ $# == 1 && $1 =~ ^(smoke|confirmation)$ ]] || {
  echo 'usage: launcher smoke|confirmation' >&2
  exit 2
}
readonly mode=$1

[[ $(/usr/bin/uname -sr) == "$expected_os" ]] || {
  echo 'host kernel differs from the frozen V7 authority' >&2
  exit 2
}

exec 9>/run/lock/codeskeptic-p10-07-cgroup.lock
/usr/bin/flock -n 9 || { echo 'another CodeSkeptic cgroup operation is active' >&2; exit 2; }

[[ -d $run_root ]] || { echo 'root-owned run directory is missing' >&2; exit 2; }
[[ $(stat -c '%U:%G:%a' "$run_root") == root:root:755 ]] || {
  echo 'root-owned run directory permissions drift' >&2
  exit 2
}
for required in \
  static-preflight.py run-static-preflight.sh container-entry.py \
  cgroup-smoke.py git-authority-entry.sh run-confirmation.sh; do
  [[ $(stat -c '%U:%G:%a' "$run_root/$required") == root:root:555 ]] || {
    echo "root-owned operator file permissions drift: $required" >&2
    exit 2
  }
done
printf '%s  %s\n' \
  8ecfa3aace9d61428de137f188eda3dd776d0421b9165836a44f3c8911d13492 \
  "$run_root/static-preflight.py" \
  05b3f1425cefcb36f6313da54762e1c9860a9cdb9f5d4f9fa1a06d027e516e32 \
  "$run_root/run-static-preflight.sh" \
  4554daf69ee902d746b9089dd4ad18ceee512d92b8e3c2ebb0fc7912fdb5c729 \
  "$run_root/container-entry.py" \
  d4b2b906b833d74a1a0a21981d8715664ea7e2eb109f16a79ceaacbe5e43b985 \
  "$run_root/cgroup-smoke.py" \
  fbd2ff8e9db7cd71bed7c4863ce7604fad336372e662181db30a1e4726cb2d0a \
  "$run_root/git-authority-entry.sh" \
  1618ba5ac9d394b0ea03456d9615325624694a4a4a15009dfa1ea30a0a26696e \
  "$run_root/run-confirmation.sh" \
  | /usr/bin/sha256sum -c -
[[ $(stat -c '%U:%G:%a' "$snapshot") == root:root:555 ]] || {
  echo 'authority snapshot ownership or mode drift' >&2
  exit 2
}
[[ -z $(find "$snapshot" \( ! -user root -o ! -group root \) -print -quit) ]] || {
  echo 'authority snapshot ownership drift' >&2
  exit 2
}
[[ -z $(find "$snapshot" -perm /222 -print -quit) ]] || {
  echo 'authority snapshot contains writable entries' >&2
  exit 2
}

[[ ! -e $authority ]] || { echo "refusing existing authority: $authority" >&2; exit 2; }
[[ $(<"$cgroup_root/cpuset.cpus.effective") == "$all_cpus" ]] || {
  echo 'host effective CPU topology differs from the frozen contract' >&2
  exit 2
}
[[ -z $(<"$cgroup_root/cpuset.cpus.isolated") ]] || {
  echo 'host already contains isolated cpuset partitions' >&2
  exit 2
}
[[ $(< /proc/sys/kernel/sched_util_clamp_min) == 1024 ]] || {
  echo 'system uclamp minimum is not pinned' >&2
  exit 2
}
[[ $(< /proc/sys/kernel/sched_util_clamp_max) == 1024 ]] || {
  echo 'system uclamp maximum is not pinned' >&2
  exit 2
}
original_cgroup=$(awk -F: '$1 == "0" && $2 == "" { print $3 }' /proc/self/cgroup)
[[ $original_cgroup == /* && $(grep -c '^0::' /proc/self/cgroup) == 1 ]] || {
  echo 'cannot establish original unified cgroup identity' >&2
  exit 2
}

if ! grep -qw cpuset "$cgroup_root/cgroup.subtree_control"; then
  printf '%s\n' +cpuset > "$cgroup_root/cgroup.subtree_control"
  echo 'NOTICE: root cpuset controller was enabled and is retained for Phase 10 evidence runs' >&2
fi
grep -qw cpuset "$cgroup_root/cgroup.subtree_control" || {
  echo 'root cpuset controller is not enabled' >&2
  exit 2
}
grep -qw cpu "$cgroup_root/cgroup.subtree_control" || {
  echo 'root CPU controller is not enabled' >&2
  exit 2
}
grep -qw memory "$cgroup_root/cgroup.subtree_control" || {
  echo 'root memory controller is not enabled' >&2
  exit 2
}

mkdir -m 0755 "$authority"
created_authority=1
[[ $(stat -c '%U:%G:%a' "$authority") == root:root:755 ]] || {
  echo 'authority cgroup traversal mode differs from the frozen contract' >&2
  exit 2
}
cat "$cgroup_root/cpuset.mems.effective" > "$authority/cpuset.mems"
printf '%s\n' "$all_cpus" > "$authority/cpuset.cpus"
printf '%s\n' "$measurement_cpus" > "$authority/cpuset.cpus.exclusive"
printf '%s\n' 100.00 > "$authority/cpu.uclamp.max"
printf '%s\n' '+cpuset +cpu +memory' > "$authority/cgroup.subtree_control"
for required_controller in cpuset cpu memory; do
  grep -qw "$required_controller" "$authority/cgroup.subtree_control" || {
    echo "authority controller was not enabled: $required_controller" >&2
    exit 2
  }
done
[[ $(wc -w < "$authority/cgroup.subtree_control") == 3 ]] || {
  echo 'authority subtree-control set differs from the frozen contract' >&2
  exit 2
}

mkdir -m 0755 "$controller" "$measurement"
for delegated_directory in "$controller" "$measurement"; do
  [[ $(stat -c '%U:%G:%a' "$delegated_directory") == root:root:755 ]] || {
    echo "delegated cgroup traversal mode differs from the frozen contract: $delegated_directory" >&2
    exit 2
  }
done
cat "$authority/cpuset.mems.effective" > "$controller/cpuset.mems"
cat "$authority/cpuset.mems.effective" > "$measurement/cpuset.mems"
printf '%s\n' "$controller_cpus" > "$controller/cpuset.cpus"
printf '%s\n' "$measurement_cpus" > "$measurement/cpuset.cpus"
printf '%s\n' "$measurement_cpus" > "$measurement/cpuset.cpus.exclusive"
printf '%s\n' 100.00 > "$measurement/cpu.uclamp.min"
printf '%s\n' 100.00 > "$measurement/cpu.uclamp.max"
printf '%s\n' isolated > "$measurement/cpuset.cpus.partition"

[[ $(<"$measurement/cpuset.cpus.partition") == isolated ]] || {
  echo 'kernel did not establish an isolated partition' >&2
  exit 2
}
[[ $(<"$measurement/cpuset.cpus.effective") == "$measurement_cpus" ]] || {
  echo 'effective measurement CPU set differs from requested set' >&2
  exit 2
}
[[ $(<"$measurement/cpuset.cpus.exclusive.effective") == "$measurement_cpus" ]] || {
  echo 'effective exclusive CPU set differs from requested set' >&2
  exit 2
}
[[ $(<"$controller/cpuset.cpus.effective") == "$controller_cpus" ]] || {
  echo 'effective controller CPU set differs from requested set' >&2
  exit 2
}

chown "$(id -u "$target_user"):$(id -g "$target_user")" \
  "$authority/cgroup.procs" "$measurement/cgroup.procs"
printf '%s\n' $$ > "$controller/cgroup.procs"
moved_launcher=1
/usr/bin/taskset -pc "$controller_cpus" $$ >/dev/null
[[ $(< /proc/self/cgroup) == "0::/${controller#"$cgroup_root/"}" ]] || {
  echo 'launcher did not enter the controller cgroup' >&2
  exit 2
}

run_as_controller "$run_root/run-static-preflight.sh"
if [[ $mode == smoke ]]; then
  run_as_controller \
    python3 "$run_root/cgroup-smoke.py" "$repo" "$measurement"
  run_as_controller "$run_root/run-static-preflight.sh"
  echo 'CODESKEPTIC_CGROUP_SMOKE_OK'
else
  run_as_controller "$run_root/run-confirmation.sh" "$measurement"
  run_as_controller "$run_root/run-static-preflight.sh"
  echo 'CODESKEPTIC_CONFIRMATION_RUN_OK'
fi
