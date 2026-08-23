#!/usr/bin/env bash
# One-command, fail-closed front end for the already-staged P10-09 service.
set -Eeuo pipefail
umask 077

readonly GUIDED_PATH="/opt/codeskeptic-p10-09/operator/guided-stability.sh"
readonly OPERATOR_ROOT="/opt/codeskeptic-p10-09/operator"
readonly STAGING_TOOL_PATH="${OPERATOR_ROOT}/stage_stability_campaign.py"
readonly AUTHORITY_ROOT="/opt/codeskeptic-p10-09/authority"
readonly RUNNER_PATH="${AUTHORITY_ROOT}/source/scripts/run_stability_campaign.py"
readonly OPERATOR_PATH="${OPERATOR_ROOT}/run-authoritative-stability.sh"
readonly README_PATH="${OPERATOR_ROOT}/README.md"
readonly UNIT_BUNDLE_PATH="${OPERATOR_ROOT}/codeskeptic-stability.service"
readonly UNIT_PATH="/etc/systemd/system/codeskeptic-stability.service"
readonly CONFIG_ROOT="/etc/codeskeptic-p10-09"
readonly CONFIG_PATH="${CONFIG_ROOT}/runtime.json"
readonly CONFIG_SHA_PATH="${CONFIG_PATH}.sha256"
readonly RUNTIME_ROOT="/run/codeskeptic-p10-09"
readonly PROBE_REQUEST_PATH="/run/codeskeptic-p10-09/probe-only.request"
readonly PROBE_REQUEST_SCHEMA="codeskeptic-probe-only-v1"
readonly CAMPAIGN_REQUEST_PATH="/run/codeskeptic-p10-09/campaign.request"
readonly CAMPAIGN_REQUEST_SCHEMA="codeskeptic-campaign-request-v1"
readonly STATUS_PATH="/var/lib/codeskeptic-p10-09/status/terminal-status"
readonly INSTALLATION_RECEIPT_PATH="/opt/codeskeptic-p10-09/installation/receipt.json"
readonly SERVICE_UNIT="codeskeptic-stability.service"
readonly SYSTEMCTL="/usr/bin/systemctl"
readonly LOGINCTL="/usr/bin/loginctl"
readonly PYTHON="/usr/bin/python3"
readonly MAX_STATUS_BYTES=1024
readonly MAX_CONFIG_BYTES=1048576

guided_mode="campaign"
owned_probe_nonce=""
owned_campaign_nonce=""
campaign_target_user=""
campaign_target_uid=""

terminal_bell() {
    /usr/bin/printf '\a\a\a' >/dev/tty 2>/dev/null ||
        /usr/bin/printf '\a\a\a' >/dev/console 2>/dev/null || true
}

if (( EUID != 0 )); then
    if (( $# == 1 )) && [[ "$1" == "--probe-only" ]]; then
        guided_mode="probe-only"
    elif (( $# != 0 )); then
        /usr/bin/printf 'CODESKEPTIC_GUIDED_STAGING_UNAVAILABLE run exactly %s [--probe-only]\n' \
            "$GUIDED_PATH" >&2
        terminal_bell
        exit 2
    fi
    /usr/bin/printf \
        'CODESKEPTIC_GUIDED_INPUT_REQUIRED sudo password may be required\n' >&2
    terminal_bell
    if [[ "$guided_mode" == "probe-only" ]]; then
        exec /usr/bin/sudo -- "$GUIDED_PATH" --root --probe-only
    fi
    exec /usr/bin/sudo -- "$GUIDED_PATH" --root
fi

staging_unavailable() {
    /usr/bin/printf \
        'CODESKEPTIC_GUIDED_STAGING_UNAVAILABLE %s\n' "$*" >&2
    exit 2
}

cleanup_owned_probe_request() {
    [[ -n "$owned_probe_nonce" ]] || return 0
    if [[ ! -e "$PROBE_REQUEST_PATH" && ! -L "$PROBE_REQUEST_PATH" ]]; then
        return 0
    fi
    "$PYTHON" -B - "$PROBE_REQUEST_PATH" "$PROBE_REQUEST_SCHEMA" \
        "$owned_probe_nonce" <<'PY' || return 1
import json
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
nonce = sys.argv[3]
metadata = path.lstat()
expected = (
    json.dumps(
        {"mode": "probe-only", "nonce": nonce, "schema": schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size != len(expected)
    or path.read_bytes() != expected
):
    raise SystemExit("probe request is not owned by this invocation")
PY
    /usr/bin/rm -- "$PROBE_REQUEST_PATH"
}

cleanup_owned_campaign_request() {
    [[ -n "$owned_campaign_nonce" ]] || return 0
    if [[ ! -e "$CAMPAIGN_REQUEST_PATH" && ! -L "$CAMPAIGN_REQUEST_PATH" ]]; then
        return 0
    fi
    "$PYTHON" -B - "$CAMPAIGN_REQUEST_PATH" "$CAMPAIGN_REQUEST_SCHEMA" \
        "$owned_campaign_nonce" "$campaign_target_user" \
        "$campaign_target_uid" <<'PY' || return 1
import json
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
expected = {
    "mode": "campaign",
    "nonce": sys.argv[3],
    "schema": sys.argv[2],
    "target_uid": int(sys.argv[5]),
    "target_user": sys.argv[4],
}
data = (json.dumps(
    expected, sort_keys=True, separators=(",", ":")
) + "\n").encode("ascii")
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size != len(data)
    or path.read_bytes() != data
):
    raise SystemExit("campaign request is not owned by this invocation")
PY
    /usr/bin/rm -- "$CAMPAIGN_REQUEST_PATH"
}

guided_exit() {
    local exit_code=$?
    trap - EXIT
    if ! cleanup_owned_probe_request; then
        /usr/bin/printf \
            'CODESKEPTIC_GUIDED_FAILURE refused to remove an unbound probe request\n' >&2
        exit_code=1
    fi
    if ! cleanup_owned_campaign_request; then
        /usr/bin/printf \
            'CODESKEPTIC_GUIDED_FAILURE refused to remove an unbound campaign request\n' >&2
        exit_code=1
    fi
    terminal_bell
    exit "$exit_code"
}

trap guided_exit EXIT

require_root_immutable_directory() {
    local mode
    local path="$1"
    [[ ! -L "$path" && -d "$path" ]] ||
        staging_unavailable "install the checksummed exact-head staging bundle: missing ${path}"
    [[ "$(/usr/bin/stat --format='%u' -- "$path")" == "0" ]] ||
        staging_unavailable "reinstall the staging bundle: ${path} is not root-owned"
    mode="$(/usr/bin/stat --format='%a' -- "$path")"
    (( (8#${mode} & 8#022) == 0 )) ||
        staging_unavailable "reinstall the staging bundle: ${path} is writable"
}

require_root_immutable_file() {
    local mode
    local path="$1"
    [[ ! -L "$path" && -f "$path" ]] ||
        staging_unavailable "install the checksummed exact-head staging bundle: missing ${path}"
    [[ "$(/usr/bin/stat --format='%u' -- "$path")" == "0" ]] ||
        staging_unavailable "reinstall the staging bundle: ${path} is not root-owned"
    mode="$(/usr/bin/stat --format='%a' -- "$path")"
    (( (8#${mode} & 8#022) == 0 )) ||
        staging_unavailable "reinstall the staging bundle: ${path} is writable"
}

require_root_immutable_executable() {
    local path="$1"
    local resolved
    [[ -x "$path" && ! -d "$path" ]] ||
        staging_unavailable "required executable is unavailable: ${path}"
    resolved="$(/usr/bin/readlink --canonicalize-existing -- "$path")" ||
        staging_unavailable "cannot resolve required executable: ${path}"
    [[ "$resolved" == /* ]] ||
        staging_unavailable "required executable did not resolve absolutely: ${path}"
    require_root_immutable_file "$resolved"
}

ensure_root_private_directory() {
    local path="$1"
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        /usr/bin/mkdir --mode=0700 -- "$path"
    fi
    [[ ! -L "$path" && -d "$path" ]] ||
        staging_unavailable "runtime directory is unavailable: ${path}"
    [[ "$(/usr/bin/stat --format='%u:%g:%a' -- "$path")" == "0:0:700" ]] ||
        staging_unavailable "runtime directory ownership or mode drift: ${path}"
}

create_probe_request() {
    "$PYTHON" -B - "$PROBE_REQUEST_PATH" "$PROBE_REQUEST_SCHEMA" \
        "$owned_probe_nonce" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
nonce = sys.argv[3]
payload = (
    json.dumps(
        {"mode": "probe-only", "nonce": nonce, "schema": schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    written = 0
    while written < len(payload):
        count = os.write(descriptor, payload[written:])
        if count <= 0:
            raise OSError("probe request write was incomplete")
        written += count
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

create_campaign_request() {
    "$PYTHON" -B - "$CAMPAIGN_REQUEST_PATH" "$CAMPAIGN_REQUEST_SCHEMA" \
        "$owned_campaign_nonce" "$campaign_target_user" \
        "$campaign_target_uid" <<'PY'
import json
import os
import pathlib
import pwd
import re
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
nonce = sys.argv[3]
user = sys.argv[4]
try:
    uid = int(sys.argv[5])
except ValueError as error:
    raise SystemExit("campaign target UID is malformed") from error
if (
    re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) is None
    or uid < 1
    or pwd.getpwnam(user).pw_uid != uid
    or pwd.getpwuid(uid).pw_name != user
):
    raise SystemExit("campaign target user identity is invalid")
payload = (json.dumps(
    {
        "mode": "campaign",
        "nonce": nonce,
        "schema": schema,
        "target_uid": uid,
        "target_user": user,
    },
    sort_keys=True,
    separators=(",", ":"),
) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("campaign request write was incomplete")
        offset += written
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

status_fingerprint() {
    local size
    if [[ ! -L "$STATUS_PATH" && -f "$STATUS_PATH" ]]; then
        size="$(/usr/bin/stat --format='%s' -- "$STATUS_PATH")" || {
            /usr/bin/printf 'invalid\n'
            return
        }
        if (( size > MAX_STATUS_BYTES )); then
            /usr/bin/printf 'invalid\n'
            return
        fi
        /usr/bin/sha256sum --binary -- "$STATUS_PATH"
    else
        /usr/bin/printf 'absent\n'
    fi
}

read_bounded_terminal_status() {
    local expected_mode="$1"
    local expected_probe_request="$2"
    local expected_campaign_request="$3"
    "$PYTHON" -B - "$STATUS_PATH" "$MAX_STATUS_BYTES" "$expected_mode" \
        "$expected_probe_request" "$expected_campaign_request" <<'PY'
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
maximum = int(sys.argv[2])
expected_mode = sys.argv[3]
expected_probe_request = sys.argv[4] or "none"
expected_campaign_request = sys.argv[5] or "none"
try:
    metadata = path.lstat()
except OSError as error:
    raise SystemExit(f"terminal status is unavailable: {error}")
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size > maximum
):
    raise SystemExit("terminal status ownership, mode, type, or size is invalid")
flags = os.O_RDONLY
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    if (
        opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
        or opened.st_size != metadata.st_size
    ):
        raise SystemExit("terminal status changed while opening")
    data = os.read(descriptor, maximum + 1)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if len(data) > maximum or after.st_size != metadata.st_size:
    raise SystemExit("terminal status changed while reading")
try:
    text = data.decode("ascii", errors="strict")
except UnicodeDecodeError as error:
    raise SystemExit(f"terminal status is not ASCII: {error}")
lines = text.splitlines(keepends=True)
if len(lines) != 6 or any(not line.endswith("\n") for line in lines):
    raise SystemExit("terminal status line inventory is invalid")
values = {}
for line in lines:
    key, separator, value = line[:-1].partition("=")
    if separator != "=" or key in values:
        raise SystemExit("terminal status fields are invalid")
    values[key] = value
if set(values) != {
    "mode", "probe_request", "result", "exit_code", "session", "completed_utc",
}:
    raise SystemExit("terminal status fields are incomplete")
if values["mode"] != expected_mode or expected_mode not in {"campaign", "probe-only"}:
    raise SystemExit("terminal status mode differs from this invocation")
if values["probe_request"] != expected_probe_request:
    raise SystemExit("terminal status probe request differs from this invocation")
if expected_mode == "campaign" and values["probe_request"] != "none":
    raise SystemExit("campaign status claimed a probe request")
uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
if expected_mode == "campaign" and re.fullmatch(uuid, expected_campaign_request) is None:
    raise SystemExit("campaign request identity is malformed")
if values["result"] not in {"success", "failure"}:
    raise SystemExit("terminal status result is invalid")
if (
    re.fullmatch(r"0|[1-9][0-9]{0,2}", values["exit_code"]) is None
    or int(values["exit_code"]) > 255
    or (values["result"] == "success") != (values["exit_code"] == "0")
):
    raise SystemExit("terminal status exit code is invalid")
if values["session"] != "none" and re.fullmatch(
    r"/var/lib/codeskeptic-p10-09/sessions/"
    rf"[0-9]{{8}}T[0-9]{{6}}Z-{uuid}-{uuid}",
    values["session"],
) is None:
    raise SystemExit("terminal status session is invalid")
if (
    expected_mode == "campaign"
    and values["session"] != "none"
    and not values["session"].endswith("-" + expected_campaign_request)
):
    raise SystemExit("terminal status session differs from this campaign request")
if expected_mode == "probe-only" and values["session"] != "none":
    raise SystemExit("probe-only status claimed campaign evidence")
if (
    expected_mode == "campaign"
    and values["result"] == "success"
    and values["session"] == "none"
):
    raise SystemExit("successful campaign status omitted its evidence session")
if re.fullmatch(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    values["completed_utc"],
) is None:
    raise SystemExit("terminal status completion time is invalid")
sys.stdout.write(text)
PY
}

if (( $# == 0 )); then
    guided_mode="campaign"
elif (( $# == 1 )) && [[ "$1" == "--root" ]]; then
    guided_mode="campaign"
elif (( $# == 1 )) && [[ "$1" == "--probe-only" ]]; then
    guided_mode="probe-only"
elif (( $# == 2 )) && [[ "$1" == "--root" && "$2" == "--probe-only" ]]; then
    guided_mode="probe-only"
else
    staging_unavailable "run exactly ${GUIDED_PATH} [--probe-only]"
fi
[[ "$0" == "$GUIDED_PATH" ]] ||
    staging_unavailable "run the installed entrypoint ${GUIDED_PATH}"
if [[ "$guided_mode" == "campaign" ]]; then
    campaign_target_user="${SUDO_USER:-}"
    campaign_target_uid="${SUDO_UID:-}"
    [[ "$campaign_target_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ \
        && "$campaign_target_uid" =~ ^[1-9][0-9]*$ ]] ||
        staging_unavailable \
            "campaign must be launched by the installed non-root guided command"
fi

for directory in "$OPERATOR_ROOT" "$AUTHORITY_ROOT" "${AUTHORITY_ROOT}/source" \
    "$CONFIG_ROOT"; do
    require_root_immutable_directory "$directory"
done
for file in "$GUIDED_PATH" "$OPERATOR_PATH" "$README_PATH" \
    "$STAGING_TOOL_PATH" "$INSTALLATION_RECEIPT_PATH" \
    "$UNIT_BUNDLE_PATH" "$UNIT_PATH" "$RUNNER_PATH" "$CONFIG_PATH" \
    "$CONFIG_SHA_PATH"; do
    require_root_immutable_file "$file"
done
require_root_immutable_executable "$SYSTEMCTL"
require_root_immutable_executable "$LOGINCTL"
require_root_immutable_executable "$PYTHON"
installation_authority="$({
    "$PYTHON" -B - "$INSTALLATION_RECEIPT_PATH" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 1024 * 1024:
    raise SystemExit("installation receipt is oversized")
data = path.read_bytes()
value = json.loads(data.decode("utf-8", errors="strict"))
canonical = (
    json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False
    )
    + "\n"
).encode("utf-8")
revision = value.get("bundle_revision")
receipt_sha = value.get("bundle_receipt_sha256")
if (
    data != canonical
    or not isinstance(revision, str)
    or re.fullmatch(r"[0-9a-f]{40}", revision) is None
    or not isinstance(receipt_sha, str)
    or re.fullmatch(r"[0-9a-f]{64}", receipt_sha) is None
):
    raise SystemExit("installation authority is malformed")
print(revision, receipt_sha)
PY
} 2>/dev/null)" ||
    staging_unavailable "cannot read installed out-of-band bundle authority"
IFS=' ' read -r expected_revision expected_bundle_receipt_sha extra \
    <<<"$installation_authority"
[[ -z "${extra:-}" && "$expected_revision" =~ ^[0-9a-f]{40}$ \
    && "$expected_bundle_receipt_sha" =~ ^[0-9a-f]{64}$ ]] ||
    staging_unavailable "installed out-of-band bundle authority is malformed"
"$PYTHON" -B "$STAGING_TOOL_PATH" verify-install \
    --receipt "$INSTALLATION_RECEIPT_PATH" \
    --expected-revision "$expected_revision" \
    --expected-bundle-receipt-sha256 "$expected_bundle_receipt_sha" ||
    staging_unavailable "installed staging receipt verification failed"
ensure_root_private_directory "$RUNTIME_ROOT"
/usr/bin/cmp --silent -- "$UNIT_BUNDLE_PATH" "$UNIT_PATH" ||
    staging_unavailable "reinstall ${UNIT_PATH} from the staged operator bundle"

"$PYTHON" -B - "$CONFIG_PATH" "$CONFIG_SHA_PATH" "$MAX_CONFIG_BYTES" <<'PY' ||
import hashlib
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
sidecar_path = pathlib.Path(sys.argv[2])
maximum = int(sys.argv[3])
if config_path.stat().st_size > maximum or sidecar_path.stat().st_size > 1024:
    raise SystemExit("runtime config pair exceeds its size limit")
data = config_path.read_bytes()
json.loads(data.decode("utf-8", errors="strict"))
expected = f"{hashlib.sha256(data).hexdigest()}  runtime.json\n".encode("ascii")
if sidecar_path.read_bytes() != expected:
    raise SystemExit("runtime config checksum sidecar mismatch")
PY
    staging_unavailable "reinstall the canonical runtime config pair"

kernel_arguments=()
IFS=' ' read -r -a kernel_arguments </proc/cmdline
kernel_target_found=0
for kernel_argument in "${kernel_arguments[@]}"; do
    if [[ "$kernel_argument" == "systemd.unit=multi-user.target" ]]; then
        kernel_target_found=1
        break
    fi
done
(( kernel_target_found == 1 )) || staging_unavailable \
    "boot with systemd.unit=multi-user.target; this command never reboots or isolates"

"$SYSTEMCTL" daemon-reload ||
    staging_unavailable "systemd daemon-reload failed"
fragment_path="$(
    "$SYSTEMCTL" show --property=FragmentPath --value "$SERVICE_UNIT"
)"
[[ "$fragment_path" == "$UNIT_PATH" ]] ||
    staging_unavailable "systemd did not load the exact staged unit ${UNIT_PATH}"
drop_in_paths="$(
    "$SYSTEMCTL" show --property=DropInPaths --value "$SERVICE_UNIT"
)" || staging_unavailable "cannot inspect ${SERVICE_UNIT} drop-in authority"
[[ -z "$drop_in_paths" ]] ||
    staging_unavailable \
        "${SERVICE_UNIT} must not have systemd drop-ins: ${drop_in_paths}"
[[ "$("$SYSTEMCTL" show --property=LoadState --value "$SERVICE_UNIT")" == "loaded" ]] ||
    staging_unavailable "systemd could not load ${SERVICE_UNIT}"
[[ "$("$SYSTEMCTL" show --property=UnitFileState --value "$SERVICE_UNIT")" == "static" ]] ||
    staging_unavailable \
        "${SERVICE_UNIT} must remain static and must never be enabled at boot"

graphical_state="$(
    "$SYSTEMCTL" show --property=ActiveState --value graphical.target
)" || staging_unavailable "cannot inspect graphical.target"
[[ "$graphical_state" == "inactive" ]] ||
    staging_unavailable \
        "graphical.target must already be inactive; this command will not stop it"
display_manager_load="$(
    "$SYSTEMCTL" show --property=LoadState --value display-manager.service
)" || staging_unavailable "cannot inspect display-manager.service"
if [[ "$display_manager_load" != "not-found" ]]; then
    [[ "$display_manager_load" == "loaded" ]] ||
        staging_unavailable \
            "display-manager.service has unexpected load state ${display_manager_load}"
    display_manager_state="$(
        "$SYSTEMCTL" show --property=ActiveState --value display-manager.service
    )"
    display_manager_substate="$(
        "$SYSTEMCTL" show --property=SubState --value display-manager.service
    )"
    [[ "$display_manager_state" == "inactive" \
        && "$display_manager_substate" == "dead" ]] ||
        staging_unavailable \
            "display-manager.service must already be inactive/dead"
fi
session_inventory="$($LOGINCTL list-sessions --no-legend --no-pager)" ||
    staging_unavailable "cannot inspect login sessions"
while IFS=' ' read -r session_id _; do
    [[ -n "$session_id" ]] || continue
    [[ "$session_id" =~ ^[A-Za-z0-9_.:-]+$ ]] ||
        staging_unavailable "login session identity is malformed"
    session_type="$($LOGINCTL show-session --property=Type --value "$session_id")" ||
        staging_unavailable "cannot inspect login session ${session_id}"
    case "$session_type" in
        x11|wayland|mir)
            staging_unavailable \
                "graphical login session ${session_id} must be closed before this command"
            ;;
    esac
done <<<"$session_inventory"

active_state="$(
    "$SYSTEMCTL" show --property=ActiveState --value "$SERVICE_UNIT"
)"
if [[ "$active_state" == "failed" ]]; then
    "$SYSTEMCTL" reset-failed "$SERVICE_UNIT" ||
        staging_unavailable "systemd could not reset the previous failed state"
    active_state="$(
        "$SYSTEMCTL" show --property=ActiveState --value "$SERVICE_UNIT"
    )"
elif [[ "$active_state" != "inactive" && "$active_state" != "active" \
    && "$active_state" != "activating" && "$active_state" != "deactivating" ]]; then
    staging_unavailable "unexpected service state ${active_state}"
fi
[[ "$active_state" == "inactive" ]] ||
    staging_unavailable \
        "${SERVICE_UNIT} must be inactive before a new guided invocation"

[[ ! -e "$PROBE_REQUEST_PATH" && ! -L "$PROBE_REQUEST_PATH" ]] ||
    staging_unavailable \
        "stale probe request exists; inspect ${PROBE_REQUEST_PATH} as root"
[[ ! -e "$CAMPAIGN_REQUEST_PATH" && ! -L "$CAMPAIGN_REQUEST_PATH" ]] ||
    staging_unavailable \
        "stale campaign request exists; inspect ${CAMPAIGN_REQUEST_PATH} as root"
stale_consumed_request="$(
    /usr/bin/find "$RUNTIME_ROOT" -mindepth 1 -maxdepth 1 \
        \( -name '.probe-only.consumed.*' \
        -o -name '.campaign.consumed.*' \) -print -quit
)"
[[ -z "$stale_consumed_request" ]] ||
    staging_unavailable \
        "stale consumed probe request exists; inspect ${stale_consumed_request} as root"

before_status="$(status_fingerprint)"
if [[ "$guided_mode" == "probe-only" ]]; then
    owned_probe_nonce="$(/usr/bin/tr --delete '\n' </proc/sys/kernel/random/uuid)"
    [[ "$owned_probe_nonce" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
        staging_unavailable "kernel probe-request nonce is malformed"
    create_probe_request ||
        staging_unavailable "cannot create the exclusive root-owned probe request"
else
    owned_campaign_nonce="$(/usr/bin/tr --delete '\n' </proc/sys/kernel/random/uuid)"
    [[ "$owned_campaign_nonce" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
        staging_unavailable "kernel campaign-request nonce is malformed"
    create_campaign_request ||
        staging_unavailable "cannot create the exclusive root-owned campaign request"
fi
service_exit=0
"$SYSTEMCTL" start --wait "$SERVICE_UNIT" || service_exit=$?

after_status=""
for _ in {1..50}; do
    after_status="$(status_fingerprint)"
    [[ "$after_status" != "$before_status" && "$after_status" != "absent" ]] && break
    /usr/bin/sleep 0.1
done
[[ "$after_status" != "$before_status" && "$after_status" != "absent" ]] ||
    staging_unavailable \
        "no fresh terminal status; inspect journalctl -u ${SERVICE_UNIT} -b"

terminal_status="$(
    read_bounded_terminal_status "$guided_mode" "$owned_probe_nonce" \
        "$owned_campaign_nonce"
)" ||
    staging_unavailable \
        "terminal status is invalid; inspect journalctl -u ${SERVICE_UNIT} -b"
/usr/bin/printf 'CODESKEPTIC_GUIDED_TERMINAL_STATUS\n%s\n' "$terminal_status"

terminal_result="$(
    /usr/bin/printf '%s\n' "$terminal_status" |
        /usr/bin/awk -F= '$1 == "result" { print $2 }'
)"
terminal_exit="$(
    /usr/bin/printf '%s\n' "$terminal_status" |
        /usr/bin/awk -F= '$1 == "exit_code" { print $2 }'
)"
if (( service_exit != 0 )) || [[ "$terminal_result" != "success" ]] ||
    (( terminal_exit != 0 )); then
    /usr/bin/printf \
        'CODESKEPTIC_GUIDED_FAILURE inspect journalctl -u %s -b\n' \
        "$SERVICE_UNIT" >&2
    exit 1
fi
/usr/bin/printf 'CODESKEPTIC_GUIDED_SUCCESS\n'
