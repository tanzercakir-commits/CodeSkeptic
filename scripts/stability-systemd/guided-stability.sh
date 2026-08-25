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
readonly CGROUP_AUTHORITY_PATH="${OPERATOR_ROOT}/cgroup-authority.py"
readonly HOST_RECOVERY_PATH="${OPERATOR_ROOT}/host-recovery.py"
readonly POST_STOP_PATH="${OPERATOR_ROOT}/post-stop.sh"
readonly README_PATH="${OPERATOR_ROOT}/README.md"
readonly UNIT_BUNDLE_PATH="${OPERATOR_ROOT}/codeskeptic-stability.service"
readonly UNIT_PATH="/etc/systemd/system/codeskeptic-stability.service"
readonly CONFIG_ROOT="/etc/codeskeptic-p10-09"
readonly CONFIG_PATH="${CONFIG_ROOT}/runtime.json"
readonly CONFIG_SHA_PATH="${CONFIG_PATH}.sha256"
readonly RUNTIME_ROOT="/run/codeskeptic-p10-09"
readonly PROBE_REQUEST_PATH="/run/codeskeptic-p10-09/probe-only.request"
readonly PROBE_REQUEST_TEMP="/run/codeskeptic-p10-09/.probe-only.request.tmp"
readonly PROBE_REQUEST_SCHEMA="codeskeptic-probe-only-v1"
readonly CAMPAIGN_REQUEST_PATH="/run/codeskeptic-p10-09/campaign.request"
readonly CAMPAIGN_REQUEST_TEMP="/run/codeskeptic-p10-09/.campaign.request.tmp"
readonly CAMPAIGN_REQUEST_SCHEMA="codeskeptic-campaign-request-v1"
readonly HANDOFF_PATH="/run/codeskeptic-p10-09/guided-handoff.json"
readonly HANDOFF_SCHEMA="codeskeptic-guided-handoff-v1"
readonly GUIDED_DECISION_PATH="/run/codeskeptic-p10-09/guided-decision.json"
readonly GUIDED_DECISION_TEMP="/run/codeskeptic-p10-09/.guided-decision.json.tmp"
readonly GUIDED_DECISION_SCHEMA="codeskeptic-guided-decision-v1"
readonly SESSION_PATH="/run/codeskeptic-p10-09/session-name"
readonly RESTORE_GRAPHICAL_PATH="/var/lib/codeskeptic-p10-09/graphical-restoration-state.json"
readonly INSTALLATION_RECEIPT_PATH="/opt/codeskeptic-p10-09/installation/receipt.json"
readonly INSTALLATION_AUTHORITY_PATH="/var/lib/codeskeptic-p10-09/installation-authority.json"
readonly SERVICE_UNIT="codeskeptic-stability.service"
readonly SYSTEMCTL="/usr/bin/systemctl"
readonly PRLIMIT="/usr/bin/prlimit"
readonly PYTHON="/usr/bin/python3"
readonly MAX_HANDOFF_BYTES=512
readonly HANDOFF_WAIT_ATTEMPTS=600
readonly HANDOFF_WAIT_INTERVAL=0.1
readonly MAX_CONFIG_BYTES=1048576

guided_mode="campaign"
owned_probe_nonce=""
owned_campaign_nonce=""
campaign_target_user=""
campaign_target_uid=""
expected_nonce=""
handoff_session=""
guided_decision_published=0
guided_lock_inherited=0
guided_lock_fd=""

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
    if (( exit_code != 0 && guided_decision_published == 0 )) \
        && [[ -n "$handoff_session" && -n "$expected_nonce" ]] \
        && [[ ! -e "$GUIDED_DECISION_PATH" \
            && ! -L "$GUIDED_DECISION_PATH" ]]; then
        if ! publish_guided_decision "cancel" "$guided_mode" \
            "$expected_nonce" "$handoff_session"; then
            /usr/bin/printf \
                'CODESKEPTIC_GUIDED_FAILURE could not publish the bound cancellation\n' >&2
            exit_code=1
        fi
    fi
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
    "$PYTHON" -B - "$PROBE_REQUEST_PATH" "$PROBE_REQUEST_TEMP" \
        "$PROBE_REQUEST_SCHEMA" \
        "$owned_probe_nonce" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
temporary = pathlib.Path(sys.argv[2])
schema = sys.argv[3]
nonce = sys.argv[4]
if temporary.parent != path.parent or temporary.name != ".probe-only.request.tmp":
    raise SystemExit("probe request temporary path drift")
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
descriptor = os.open(temporary, flags, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    written = 0
    while written < len(payload):
        count = os.write(descriptor, payload[written:])
        if count <= 0:
            raise OSError("probe request write was incomplete")
        written += count
    os.fsync(descriptor)
except BaseException:
    os.close(descriptor)
    try:
        temporary.unlink()
    except OSError:
        pass
    raise
else:
    os.close(descriptor)
os.link(temporary, path, follow_symlinks=False)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
temporary.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

create_campaign_request() {
    "$PYTHON" -B - "$CAMPAIGN_REQUEST_PATH" "$CAMPAIGN_REQUEST_TEMP" \
        "$CAMPAIGN_REQUEST_SCHEMA" \
        "$owned_campaign_nonce" "$campaign_target_user" \
        "$campaign_target_uid" <<'PY'
import json
import os
import pathlib
import pwd
import re
import sys

path = pathlib.Path(sys.argv[1])
temporary = pathlib.Path(sys.argv[2])
schema = sys.argv[3]
nonce = sys.argv[4]
user = sys.argv[5]
try:
    uid = int(sys.argv[6])
except ValueError as error:
    raise SystemExit("campaign target UID is malformed") from error
if temporary.parent != path.parent or temporary.name != ".campaign.request.tmp":
    raise SystemExit("campaign request temporary path drift")
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
descriptor = os.open(temporary, flags, 0o600)
try:
    os.fchmod(descriptor, 0o600)
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("campaign request write was incomplete")
        offset += written
    os.fsync(descriptor)
except BaseException:
    os.close(descriptor)
    try:
        temporary.unlink()
    except OSError:
        pass
    raise
else:
    os.close(descriptor)
os.link(temporary, path, follow_symlinks=False)
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
temporary.unlink()
directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

read_bound_handoff() {
    local expected_mode="$1"
    local expected_nonce="$2"
    "$PYTHON" -B - "$HANDOFF_PATH" "$HANDOFF_SCHEMA" "$expected_mode" "$expected_nonce" "$MAX_HANDOFF_BYTES" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
expected_mode = sys.argv[3]
expected_nonce = sys.argv[4]
maximum = int(sys.argv[5])
try:
    metadata = path.lstat()
except OSError as error:
    raise SystemExit(f"guided handoff is unavailable: {error}")
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o400
    or metadata.st_nlink != 1
    or metadata.st_size > maximum
):
    raise SystemExit("guided handoff ownership, mode, type, or size is invalid")
flags = os.O_RDONLY
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
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
        raise SystemExit("guided handoff changed while opening")
    data = os.read(descriptor, maximum + 1)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if (
    len(data) > maximum
    or len(data) != metadata.st_size
    or after.st_size != metadata.st_size
):
    raise SystemExit("guided handoff changed while reading")
try:
    value = json.loads(data.decode("ascii", errors="strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"guided handoff is malformed: {error}")
if not isinstance(value, dict) or set(value) != {"mode", "nonce", "schema", "session"}:
    raise SystemExit("guided handoff fields are invalid")
uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
if expected_mode == "campaign":
    session_pattern = rf"[0-9]{{8}}T[0-9]{{6}}Z-{uuid}-{re.escape(expected_nonce)}"
elif expected_mode == "probe-only":
    session_pattern = rf"probe-{re.escape(expected_nonce)}"
else:
    raise SystemExit("guided handoff mode is invalid")
if (
    value["schema"] != schema
    or value["mode"] != expected_mode
    or value["nonce"] != expected_nonce
    or re.fullmatch(uuid, expected_nonce) is None
    or not isinstance(value["session"], str)
    or re.fullmatch(session_pattern, value["session"]) is None
):
    raise SystemExit("guided handoff differs from this invocation")
canonical = (
    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
).encode("ascii")
if data != canonical:
    raise SystemExit("guided handoff is not canonical")
print(value["session"])
PY
}

wait_for_bound_handoff() {
    local expected_mode="$1"
    local expected_nonce="$2"
    local handoff_session=""
    local attempt
    for (( attempt = 0; attempt < HANDOFF_WAIT_ATTEMPTS; attempt++ )); do
        if [[ -e "$HANDOFF_PATH" || -L "$HANDOFF_PATH" ]]; then
            handoff_session="$(read_bound_handoff "$expected_mode" "$expected_nonce")" ||
                return 1
            /usr/bin/printf '%s\n' "$handoff_session"
            return 0
        fi
        /usr/bin/sleep "$HANDOFF_WAIT_INTERVAL"
    done
    return 1
}

publish_guided_decision() {
    local action="$1"
    local mode="$2"
    local nonce="$3"
    local session="$4"
    "$PYTHON" -B - "$GUIDED_DECISION_PATH" "$GUIDED_DECISION_TEMP" \
        "$GUIDED_DECISION_SCHEMA" \
        "$action" "$mode" "$nonce" "$session" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
temporary = pathlib.Path(sys.argv[2])
schema, action, mode, nonce, session = sys.argv[3:]
uuid = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
if action not in {"accept", "cancel"} or re.fullmatch(uuid, nonce) is None:
    raise SystemExit("guided decision action or nonce is malformed")
if mode == "campaign":
    session_pattern = rf"[0-9]{{8}}T[0-9]{{6}}Z-{uuid}-{re.escape(nonce)}"
elif mode == "probe-only":
    session_pattern = rf"probe-{re.escape(nonce)}"
else:
    raise SystemExit("guided decision mode is malformed")
if re.fullmatch(session_pattern, session) is None:
    raise SystemExit("guided decision session is malformed")
parent = path.parent
if temporary.parent != parent or temporary.name != ".guided-decision.json.tmp":
    raise SystemExit("guided decision temporary path drift")
metadata = parent.lstat()
if (
    not stat.S_ISDIR(metadata.st_mode)
    or parent.is_symlink()
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o700
):
    raise SystemExit("guided decision runtime authority drift")
payload = (json.dumps(
    {
        "action": action,
        "mode": mode,
        "nonce": nonce,
        "schema": schema,
        "session": session,
    },
    sort_keys=True,
    separators=(",", ":"),
) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
flags |= getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(temporary, flags, 0o400)
try:
    os.fchown(descriptor, 0, 0)
    os.fchmod(descriptor, 0o400)
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("guided decision write was incomplete")
        offset += written
    os.fsync(descriptor)
except BaseException:
    os.close(descriptor)
    try:
        temporary.unlink()
    except OSError:
        pass
    raise
else:
    os.close(descriptor)
os.link(temporary, path, follow_symlinks=False)
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
temporary.unlink()
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
    guided_decision_published=1
}

if (( $# == 0 )); then
    guided_mode="campaign"
elif (( $# == 1 )) && [[ "$1" == "--root" ]]; then
    guided_mode="campaign"
elif (( $# == 1 )) && [[ "$1" == "--probe-only" ]]; then
    guided_mode="probe-only"
elif (( $# == 2 )) && [[ "$1" == "--root" && "$2" == "--probe-only" ]]; then
    guided_mode="probe-only"
elif (( $# == 3 )) && [[ "$1" == "--root-locked" \
    && ( "$2" == "campaign" || "$2" == "probe-only" ) \
    && "$3" =~ ^[1-9][0-9]*$ ]]; then
    guided_mode="$2"
    guided_lock_fd="$3"
    guided_lock_inherited=1
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
for file in "$GUIDED_PATH" "$OPERATOR_PATH" "$CGROUP_AUTHORITY_PATH" \
    "$HOST_RECOVERY_PATH" \
    "$POST_STOP_PATH" "$README_PATH" \
    "$STAGING_TOOL_PATH" "$INSTALLATION_RECEIPT_PATH" \
    "$INSTALLATION_AUTHORITY_PATH" \
    "$UNIT_BUNDLE_PATH" "$UNIT_PATH" "$RUNNER_PATH" "$CONFIG_PATH" \
    "$CONFIG_SHA_PATH"; do
    require_root_immutable_file "$file"
done
require_root_immutable_executable "$SYSTEMCTL"
require_root_immutable_executable "$PRLIMIT"
require_root_immutable_executable "$PYTHON"
require_root_immutable_executable "$CGROUP_AUTHORITY_PATH"
require_root_immutable_executable "$HOST_RECOVERY_PATH"
installation_authority="$({
    "$PYTHON" -B - "$INSTALLATION_AUTHORITY_PATH" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 4096:
    raise SystemExit("installation authority is oversized")
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
    or set(value) != {"bundle_receipt_sha256", "bundle_revision", "schema"}
    or value.get("schema") != "codeskeptic-stability-installation-authority-v1"
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
"$PYTHON" -B "$STAGING_TOOL_PATH" verify-install-filesystem \
    --receipt "$INSTALLATION_RECEIPT_PATH" \
    --expected-revision "$expected_revision" \
    --expected-bundle-receipt-sha256 "$expected_bundle_receipt_sha" ||
    staging_unavailable "installed filesystem authority verification failed"
ensure_root_private_directory "$RUNTIME_ROOT"
# A second root guided process must never publish or clean a request while
# this invocation is between validation, publication, service consumption,
# and EXIT cleanup. host-recovery opens the fixed inode with O_NOFOLLOW and
# O_CLOEXEC, validates it before use, locks it, then execs this script with an
# explicitly inherited descriptor.
if (( guided_lock_inherited == 0 )); then
    "$HOST_RECOVERY_PATH" lock-guided --mode "$guided_mode"
    exit $?
fi
"$HOST_RECOVERY_PATH" validate-guided-lock --fd "$guided_lock_fd" ||
    staging_unavailable "guided invocation lock is not exactly inherited"
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

# A durable restoration record can survive a killed service or reboot. Retry
# it before requiring the normal graphical authorization boundary.
"$POST_STOP_PATH" --startup-recovery ||
    staging_unavailable \
        "pending graphical restoration could not be exactly confirmed"
"$HOST_RECOVERY_PATH" discard-unbound-launch-requests ||
    staging_unavailable "stale unpublished launch authority could not be discarded"
# Dynamic image, empty-store, and in-image static-authority probes run only
# after the service has published its durable host marker. The guided process
# stays mutation-free with respect to Podman, so SIGKILL cannot create an
# anonymous container outside the recovery envelope.

graphical_identity="$(
    "$SYSTEMCTL" show --no-pager --property=LoadState \
        --property=ActiveState --property=SubState --property=Job \
        graphical.target
)" || staging_unavailable "cannot inspect graphical.target"
[[ "$graphical_identity" == \
    $'LoadState=loaded\nActiveState=active\nSubState=active\nJob=' ]] ||
    staging_unavailable \
        "graphical.target must be active with no queued job at authorization"
display_manager_identity="$(
    "$SYSTEMCTL" show --no-pager --property=LoadState --property=ActiveState \
        --property=SubState --property=Job display-manager.service
)" || staging_unavailable "cannot inspect display-manager.service"
[[ "$display_manager_identity" == \
    $'LoadState=loaded\nActiveState=active\nSubState=running\nJob=' ]] ||
    staging_unavailable \
        "display-manager.service must be active/running with no queued job at authorization"

[[ ! -e "$PROBE_REQUEST_PATH" && ! -L "$PROBE_REQUEST_PATH" ]] ||
    staging_unavailable \
        "stale probe request exists; inspect ${PROBE_REQUEST_PATH} as root"
[[ ! -e "$CAMPAIGN_REQUEST_PATH" && ! -L "$CAMPAIGN_REQUEST_PATH" ]] ||
    staging_unavailable \
        "stale campaign request exists; inspect ${CAMPAIGN_REQUEST_PATH} as root"
[[ ! -e "$HANDOFF_PATH" && ! -L "$HANDOFF_PATH" ]] ||
    staging_unavailable \
        "stale guided handoff exists; inspect ${HANDOFF_PATH} as root"
[[ ! -e "$GUIDED_DECISION_PATH" && ! -L "$GUIDED_DECISION_PATH" ]] ||
    staging_unavailable \
        "stale guided decision exists; inspect ${GUIDED_DECISION_PATH} as root"
[[ ! -e "$SESSION_PATH" && ! -L "$SESSION_PATH" ]] ||
    staging_unavailable \
        "stale cgroup session marker exists; inspect ${SESSION_PATH} as root"
[[ ! -e "$RESTORE_GRAPHICAL_PATH" && ! -L "$RESTORE_GRAPHICAL_PATH" ]] ||
    staging_unavailable \
        "unconfirmed graphical restoration state exists after startup recovery"
stale_consumed_request="$(
    /usr/bin/find "$RUNTIME_ROOT" -mindepth 1 -maxdepth 1 \
        \( -name '.probe-only.consumed.*' \
        -o -name '.campaign.consumed.*' \) -print -quit
)"
[[ -z "$stale_consumed_request" ]] ||
    staging_unavailable \
        "stale consumed probe request exists; inspect ${stale_consumed_request} as root"

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
"$SYSTEMCTL" start --no-block "$SERVICE_UNIT" ||
    staging_unavailable "systemd refused the nonblocking service start"
if [[ "$guided_mode" == "probe-only" ]]; then
    expected_nonce="$owned_probe_nonce"
else
    expected_nonce="$owned_campaign_nonce"
fi
handoff_session="$(wait_for_bound_handoff "$guided_mode" "$expected_nonce")" ||
    staging_unavailable \
        "no exact request-consumed handoff; inspect journalctl -u ${SERVICE_UNIT} -b"
publish_guided_decision "accept" "$guided_mode" "$expected_nonce" \
    "$handoff_session" ||
    staging_unavailable "cannot publish the exact session-bound guided ACK"

# The service owns the consumed request and the durable ACK. Clearing these
# fields prevents this invocation's EXIT trap from racing either authority.
owned_probe_nonce=""
owned_campaign_nonce=""
/usr/bin/printf 'CODESKEPTIC_P10_09_HANDOFF_ACCEPTED %s\n' "$handoff_session"
/usr/bin/printf \
    'CODESKEPTIC_P10_09_STARTED no exit-code capture is required; wait for graphical recovery\n'
