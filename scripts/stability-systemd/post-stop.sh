#!/usr/bin/env bash
# Fail-closed host recovery and durable GUI restoration for P10-09.
set -u
umask 077

readonly PYTHON="/usr/bin/python3"
readonly SYSTEMCTL="/usr/bin/systemctl"
readonly HOST_RECOVERY="/opt/codeskeptic-p10-09/operator/host-recovery.py"
readonly RUNTIME_ROOT="/run/codeskeptic-p10-09"
readonly SESSION_PATH="/run/codeskeptic-p10-09/session-name"
readonly RESTORE_GRAPHICAL_PATH="/var/lib/codeskeptic-p10-09/graphical-restoration-state.json"
readonly RESTORE_GRAPHICAL_SCHEMA="codeskeptic-graphical-restoration-v1"
readonly STATUS_ROOT="/var/lib/codeskeptic-p10-09/status"
readonly STATUS_PATH="/var/lib/codeskeptic-p10-09/status/post-stop-status.txt"
readonly STATUS_SCHEMA="codeskeptic-post-stop-v3"
readonly RESTORE_WAIT_ATTEMPTS=600
readonly RESTORE_WAIT_INTERVAL=0.1
readonly -a TRANSITION_TARGETS=(
    shutdown.target
    rescue.target
    emergency.target
)

read_bound_session() {
    "$PYTHON" -B - "$SESSION_PATH" <<'PY'
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
try:
    metadata = path.lstat()
except OSError as error:
    raise SystemExit(f"cgroup recovery session is unavailable: {error}")
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o400
    or metadata.st_nlink != 1
    or metadata.st_size > 256
):
    raise SystemExit("cgroup recovery session metadata is invalid")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    data = os.read(descriptor, 257)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (
    opened.st_dev != metadata.st_dev
    or opened.st_ino != metadata.st_ino
    or opened.st_size != metadata.st_size
    or after.st_size != metadata.st_size
    or len(data) != metadata.st_size
    or len(data) > 256
):
    raise SystemExit("cgroup recovery session changed while reading")
try:
    value = data.decode("ascii", errors="strict")
except UnicodeDecodeError as error:
    raise SystemExit(f"cgroup recovery session is not ASCII: {error}")
uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
session = value.removesuffix("\n")
if value != session + "\n" or re.fullmatch(
    rf"(?:[0-9]{{8}}T[0-9]{{6}}Z-{uuid}-{uuid}|probe-{uuid})", session
) is None:
    raise SystemExit("cgroup recovery session is malformed")
print(session)
PY
}

read_bound_restoration_intent() {
    local expected_session="${1:-}"
    "$PYTHON" -B - "$RESTORE_GRAPHICAL_PATH" \
        "$RESTORE_GRAPHICAL_SCHEMA" "$expected_session" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
expected_session = sys.argv[3]
try:
    metadata = path.lstat()
except OSError as error:
    raise SystemExit(f"graphical restoration state is unavailable: {error}")
if (
    not stat.S_ISREG(metadata.st_mode)
    or path.is_symlink()
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o400
    or metadata.st_nlink != 1
    or metadata.st_size > 512
):
    raise SystemExit("graphical restoration intent metadata is invalid")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    data = os.read(descriptor, 513)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (
    opened.st_dev != metadata.st_dev
    or opened.st_ino != metadata.st_ino
    or opened.st_size != metadata.st_size
    or after.st_size != metadata.st_size
    or len(data) != metadata.st_size
    or len(data) > 512
):
    raise SystemExit("graphical restoration intent is not exactly bound")
try:
    value = json.loads(data.decode("ascii", errors="strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"graphical restoration intent is malformed: {error}")
if not isinstance(value, dict) or set(value) != {
    "nonce", "phase", "schema", "session",
}:
    raise SystemExit("graphical restoration intent fields are invalid")
nonce = value["nonce"]
session = value["session"]
uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
if (
    value["schema"] != schema
    or value["phase"] != "restore-required"
    or not isinstance(nonce, str)
    or re.fullmatch(uuid, nonce) is None
    or not isinstance(session, str)
    or re.fullmatch(
        rf"[0-9]{{8}}T[0-9]{{6}}Z-{uuid}-{re.escape(nonce)}", session
    ) is None
    or (expected_session and session != expected_session)
):
    raise SystemExit("graphical restoration intent is not exactly bound")
canonical = (
    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
).encode("ascii")
if data != canonical:
    raise SystemExit("graphical restoration intent is not canonical")
print(session)
print(nonce)
PY
}

clear_graphical_restoration_state() {
    local expected_session="$1"
    local expected_nonce="$2"
    "$PYTHON" -B - "$RESTORE_GRAPHICAL_PATH" \
        "$RESTORE_GRAPHICAL_SCHEMA" "$expected_session" \
        "$expected_nonce" <<'PY'
import json
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
schema, session, nonce = sys.argv[2:]
expected = (json.dumps(
    {
        "nonce": nonce,
        "phase": "restore-required",
        "schema": schema,
        "session": session,
    },
    sort_keys=True,
    separators=(",", ":"),
) + "\n").encode("ascii")
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or path.is_symlink()
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o400
    or metadata.st_nlink != 1
    or metadata.st_size != len(expected)
):
    raise SystemExit("graphical restoration state changed before clearing")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    data = os.read(descriptor, len(expected) + 1)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (
    opened.st_dev != metadata.st_dev
    or opened.st_ino != metadata.st_ino
    or after.st_size != metadata.st_size
    or data != expected
):
    raise SystemExit("graphical restoration state changed before clearing")
path.unlink()
directory = os.open(
    path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

system_transition_clear() {
    local identity target
    for target in "${TRANSITION_TARGETS[@]}"; do
        identity="$(
            "$SYSTEMCTL" show --no-pager \
                --property=ActiveState --property=Job "$target"
        )" || return 2
        [[ "$identity" == $'ActiveState=inactive\nJob=' ]] || return 1
    done
}

read_graphical_identity() {
    "$SYSTEMCTL" show --no-pager --property=LoadState \
        --property=ActiveState --property=SubState --property=Job \
        graphical.target
}

read_display_manager_identity() {
    "$SYSTEMCTL" show --no-pager --property=LoadState \
        --property=ActiveState --property=SubState --property=Job \
        display-manager.service
}

restore_graphical_state() {
    local expected_session="${1:-}"
    local -a restoration_fields=()
    local restoration_session=""
    local restoration_nonce=""
    local graphical_identity=""
    local display_identity=""
    local attempt
    local transition_state=0

    if [[ ! -e "$RESTORE_GRAPHICAL_PATH" \
        && ! -L "$RESTORE_GRAPHICAL_PATH" ]]; then
        graphical_outcome="not-requested"
        return 0
    fi
    mapfile -t restoration_fields < <(
        read_bound_restoration_intent "$expected_session"
    ) || {
        graphical_outcome="skipped-invalid-restoration-intent"
        return 1
    }
    (( ${#restoration_fields[@]} == 2 )) || {
        graphical_outcome="skipped-invalid-restoration-intent"
        return 1
    }
    restoration_session="${restoration_fields[0]}"
    restoration_nonce="${restoration_fields[1]}"
    [[ -n "$restoration_session" && -n "$restoration_nonce" ]] || {
        graphical_outcome="skipped-invalid-restoration-intent"
        return 1
    }
    session_name="$restoration_session"

    if system_transition_clear; then
        transition_state=0
    else
        transition_state=$?
    fi
    if (( transition_state == 1 )); then
        graphical_outcome="skipped-system-transition"
        return 0
    elif (( transition_state != 0 )); then
        graphical_outcome="skipped-unverified-transition"
        return 1
    fi

    graphical_identity="$(read_graphical_identity)" || {
        graphical_outcome="restore-state-unavailable"
        return 1
    }
    display_identity="$(read_display_manager_identity)" || {
        graphical_outcome="restore-state-unavailable"
        return 1
    }
    if [[ "$graphical_identity" != $'LoadState=loaded\nActiveState=active\nSubState=active\nJob=' \
        || "$display_identity" != $'LoadState=loaded\nActiveState=active\nSubState=running\nJob=' ]]; then
        [[ "$graphical_identity" == LoadState=loaded$'\n'* \
            && "$display_identity" == LoadState=loaded$'\n'* ]] || {
            graphical_outcome="restore-unloaded"
            return 1
        }
        "$SYSTEMCTL" start --no-block graphical.target display-manager.service || {
            graphical_outcome="restore-start-failed"
            return 1
        }
    fi

    for (( attempt = 0; attempt < RESTORE_WAIT_ATTEMPTS; attempt++ )); do
        if system_transition_clear; then
            transition_state=0
        else
            transition_state=$?
            if (( transition_state == 1 )); then
                graphical_outcome="skipped-system-transition"
                return 0
            fi
            graphical_outcome="skipped-unverified-transition"
            return 1
        fi
        graphical_identity="$(read_graphical_identity)" || {
            graphical_outcome="restore-state-unavailable"
            return 1
        }
        display_identity="$(read_display_manager_identity)" || {
            graphical_outcome="restore-state-unavailable"
            return 1
        }
        if [[ "$graphical_identity" == $'LoadState=loaded\nActiveState=active\nSubState=active\nJob=' \
            && "$display_identity" == $'LoadState=loaded\nActiveState=active\nSubState=running\nJob=' ]]; then
            clear_graphical_restoration_state \
                "$restoration_session" "$restoration_nonce" || {
                graphical_outcome="restore-confirmed-marker-retained"
                return 1
            }
            graphical_outcome="restored-and-confirmed"
            return 0
        fi
        /usr/bin/sleep "$RESTORE_WAIT_INTERVAL"
    done
    graphical_outcome="restore-timeout"
    return 1
}

write_status() {
    local session="$1"
    local cleanup="$2"
    local graphical="$3"
    local service_result="$4"
    local temporary=""
    if [[ ! -e "$STATUS_ROOT" && ! -L "$STATUS_ROOT" ]]; then
        /usr/bin/install -d -o root -g root -m 0700 -- "$STATUS_ROOT" ||
            return 1
    fi
    [[ ! -L "$STATUS_ROOT" && -d "$STATUS_ROOT" ]] || return 1
    [[ "$(/usr/bin/stat --format='%u:%g:%a' -- "$STATUS_ROOT")" == \
        "0:0:700" ]] || return 1
    temporary="$(/usr/bin/mktemp "${STATUS_ROOT}/.post-stop-status.XXXXXX")" ||
        return 1
    if ! /usr/bin/printf \
        'schema=%s\nsession=%s\nhost_cleanup=%s\ngraphical=%s\nservice_result=%s\n' \
        "$STATUS_SCHEMA" "$session" "$cleanup" "$graphical" \
        "$service_result" >"$temporary"; then
        /usr/bin/rm -- "$temporary" || true
        return 1
    fi
    if ! /usr/bin/chown root:root -- "$temporary" \
        || ! /usr/bin/chmod 0400 -- "$temporary" \
        || ! /usr/bin/sync --file-system "$temporary" \
        || ! /usr/bin/mv --no-target-directory -- "$temporary" "$STATUS_PATH" \
        || ! /usr/bin/sync --file-system "$STATUS_ROOT"; then
        [[ ! -e "$temporary" && ! -L "$temporary" ]] ||
            /usr/bin/rm -- "$temporary" || true
        return 1
    fi
}

if (( $# == 1 )) && [[ "$1" == "--startup-recovery" ]]; then
    session_name="unverified"
    graphical_outcome="not-attempted"
    cleanup_outcome="failure"
    startup_status=0
    if "$HOST_RECOVERY" recover; then
        cleanup_outcome="startup-recovered"
    else
        startup_status=1
    fi
    restore_graphical_state "" || startup_status=1
    write_status "$session_name" "$cleanup_outcome" \
        "$graphical_outcome" "startup-recovery" || startup_status=1
    exit "$startup_status"
elif (( $# != 0 )); then
    /usr/bin/printf 'CODESKEPTIC_POST_STOP_FAIL unsupported invocation\n' >&2
    exit 2
fi

status=0
session_name="unverified"
runtime_session=""
cleanup_outcome="unverified"
graphical_outcome="not-attempted"
service_result="${SERVICE_RESULT:-unknown}"
case "$service_result" in
    success|resources|timeout|exit-code|signal|core-dump|watchdog|start-limit-hit|oom-kill)
        ;;
    *)
        service_result="unknown"
        status=1
        ;;
esac

if [[ -e "$SESSION_PATH" || -L "$SESSION_PATH" ]]; then
    if runtime_session="$(read_bound_session)"; then
        session_name="$runtime_session"
    else
        status=1
    fi
fi
if "$HOST_RECOVERY" recover; then
    if [[ -n "$runtime_session" ]]; then
        cleanup_outcome="recovered-bound-session"
    else
        cleanup_outcome="recovered-without-runtime-session"
    fi
else
    cleanup_outcome="failure"
    status=1
fi

# Whole-host recovery (including cgroups) is always attempted before GUI recovery.
restore_graphical_state "$runtime_session" || status=1
write_status "$session_name" "$cleanup_outcome" "$graphical_outcome" \
    "$service_result" || status=1
/usr/bin/printf '\a\a\a' >/dev/console 2>/dev/null || true
exit "$status"
