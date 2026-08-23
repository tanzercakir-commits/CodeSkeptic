#!/usr/bin/env bash
# Root transport for one new, scope-bound P10-09 evidence session.
# Only the sealed campaign receipt and its independent verifier decide acceptance.
set -Eeuo pipefail
umask 077

readonly AUTHORITY_ROOT="/opt/codeskeptic-p10-09/authority"
readonly OPERATOR_ROOT="/opt/codeskeptic-p10-09/operator"
readonly RUNNER_PATH="${AUTHORITY_ROOT}/source/scripts/run_stability_campaign.py"
readonly CONFIG_PATH="/etc/codeskeptic-p10-09/runtime.json"
readonly CONFIG_SHA_PATH="${CONFIG_PATH}.sha256"
readonly STATE_ROOT="/var/lib/codeskeptic-p10-09"
readonly SESSION_ROOT="${STATE_ROOT}/sessions"
readonly LAUNCH_ROOTS="${STATE_ROOT}/launches"
readonly STATUS_ROOT="${STATE_ROOT}/status"
readonly PODMAN_ROOT="${STATE_ROOT}/podman-root"
readonly PODMAN_ENVIRONMENT_ROOT="${STATE_ROOT}/podman-environment"
readonly RUNTIME_ROOT="/run/codeskeptic-p10-09"
readonly CONTAINER_RUNTIME_ROOT="${STATE_ROOT}/runtime"
readonly RUNTIME_IDENTITY_ROOT="${STATE_ROOT}/runtime-identities"
readonly PODMAN_RUNROOT="${RUNTIME_ROOT}/podman-runroot"
readonly LOCK_PATH="${RUNTIME_ROOT}/stability.lock"
readonly PROBE_REQUEST_PATH="/run/codeskeptic-p10-09/probe-only.request"
readonly PROBE_REQUEST_SCHEMA="codeskeptic-probe-only-v1"
readonly CAMPAIGN_REQUEST_PATH="/run/codeskeptic-p10-09/campaign.request"
readonly CAMPAIGN_REQUEST_SCHEMA="codeskeptic-campaign-request-v1"
readonly CGROUP_ROOT="/sys/fs/cgroup"
readonly SERVICE_CGROUP_RELATIVE="/system.slice/codeskeptic-stability.service"
readonly CONTROLLER_CGROUP_RELATIVE="${SERVICE_CGROUP_RELATIVE}/controller"
readonly PAYLOAD_CGROUP_RELATIVE="${SERVICE_CGROUP_RELATIVE}/codeskeptic-p10-09"
readonly SERVICE_CGROUP="${CGROUP_ROOT}${SERVICE_CGROUP_RELATIVE}"
readonly PAYLOAD_CGROUP="${CGROUP_ROOT}${PAYLOAD_CGROUP_RELATIVE}"
readonly MEASUREMENT_CGROUP="${CGROUP_ROOT}${PAYLOAD_CGROUP_RELATIVE}/measurement"
readonly CONTROLLER_CPUS="4-11"
readonly CONTROLLER_CPU_LIST="4,5,6,7,8,9,10,11"
readonly CAMPAIGN_CPUS="0-11"
readonly MEASUREMENT_CPUS="0-3"
readonly MEASUREMENT_CPU_LIST="0,1,2,3"
readonly PODMAN="/usr/bin/podman"
readonly ENV="/usr/bin/env"
readonly PYTHON="/usr/bin/python3"
readonly MAX_CONFIG_BYTES=1048576
readonly PINNED_EVIDENCE_IMAGE="localhost/codeskeptic-p10-07-evidence@sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
readonly PINNED_EVIDENCE_IMAGE_DIGEST="sha256:3408b08a92f59d67f5c46347baca76bdb1aafeca34601fae82d6ebd9d8d837ca"
readonly PINNED_EVIDENCE_IMAGE_ID="sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5"

readonly PREFLIGHT_PYTHON='
import os
import pathlib
import re
import resource
import subprocess
import sys
import yaml

def fail(message):
    print(f"CODESKEPTIC_ROOTFUL_PREFLIGHT_FAIL {message}", file=sys.stderr)
    raise SystemExit(125)

expected_parent = pathlib.PurePosixPath(sys.argv[1])
measurement_path = pathlib.Path(sys.argv[2])
measurement_relative = sys.argv[3]
measurement_cpu_list = sys.argv[4]
if os.getpid() != 1:
    fail("private PID namespace is unavailable")
record = pathlib.Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
if not record.startswith("0::"):
    fail("container cgroup record is malformed")
current = pathlib.PurePosixPath(record[3:])
try:
    suffix = current.relative_to(expected_parent)
except ValueError:
    fail("container escaped the delegated service payload subtree")
if len(suffix.parts) != 1 or re.fullmatch(
    r"libpod-[0-9a-f]{64}(?:[.]scope)?", suffix.name
) is None:
    fail("container cgroup identity is malformed")
if sorted(os.sched_getaffinity(0)) != list(range(4, 12)):
    fail("controller affinity is not exact CPUs 4-11")
if resource.getrlimit(resource.RLIMIT_NOFILE) != (4096, 4096):
    fail("container open-file limit is not exact")
if yaml.safe_load("probe: true") != {"probe": True}:
    fail("PyYAML runtime dependency is unusable")
child_code = """
import os
import pathlib
import sys

expected = sys.argv[1]
record = pathlib.Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
if record != f"0::{expected}":
    print("CODESKEPTIC_MEASUREMENT_PREFLIGHT_FAIL cgroup", file=sys.stderr)
    raise SystemExit(125)
if sorted(os.sched_getaffinity(0)) != list(range(0, 4)):
    print("CODESKEPTIC_MEASUREMENT_PREFLIGHT_FAIL affinity", file=sys.stderr)
    raise SystemExit(125)
print("CODESKEPTIC_MEASUREMENT_PREFLIGHT_OK")
"""
completed = subprocess.run(
    [
        "/usr/bin/python3",
        "-B",
        "/authority/source/scripts/run_in_measurement_cgroup.py",
        "--cgroup",
        os.fspath(measurement_path),
        "--cpus",
        measurement_cpu_list,
        "--",
        "/usr/bin/python3",
        "-B",
        "-c",
        child_code,
        measurement_relative,
    ],
    check=False,
)
if completed.returncode != 0:
    fail("measurement child probe failed")
if (measurement_path / "cgroup.procs").read_text(encoding="ascii").strip():
    fail("measurement cgroup retained a process")
events = dict(
    line.split() for line in
    (measurement_path / "cgroup.events").read_text(encoding="ascii").splitlines()
)
if events.get("populated") != "0" or events.get("frozen") != "0":
    fail("measurement cgroup did not return to idle")
print(f"CODESKEPTIC_ROOTFUL_PREFLIGHT_OK yaml={yaml.__version__}")
'

readonly -a RUNTIME_CONTROLLER_COMMAND=(
    "/usr/bin/python3"
    "-B"
    "/authority/source/scripts/run_stability_campaign.py"
    "run"
    "--config"
    "/config/runtime.json"
    "--output"
    "/evidence"
)

readonly -a RUNTIME_VERIFIER_COMMAND=(
    "/usr/bin/python3"
    "-B"
    "/authority/source/scripts/run_stability_campaign.py"
    "verify"
    "--config"
    "/config/runtime.json"
    "--evidence"
    "/evidence"
)

# Dedicated root/runroot paths prevent ambient rootful Podman state from
# selecting another image or retaining a container outside this cleanup scope.
readonly -a PODMAN_GLOBAL_OPTIONS=(
    --root "$PODMAN_ROOT"
    --runroot "$PODMAN_RUNROOT"
    --storage-driver=overlay
    --cgroup-manager=cgroupfs
    --conmon=/usr/bin/conmon
    --events-backend=none
    --hooks-dir="$OPERATOR_ROOT"
    --runtime=/usr/bin/crun
)

readonly -a PODMAN_HOST_ENVIRONMENT=(
    "HOME=${PODMAN_ENVIRONMENT_ROOT}/home"
    "XDG_DATA_HOME=${PODMAN_ENVIRONMENT_ROOT}/data"
    "XDG_CACHE_HOME=${PODMAN_ENVIRONMENT_ROOT}/cache"
    "XDG_CONFIG_HOME=${PODMAN_ENVIRONMENT_ROOT}/config"
    "XDG_RUNTIME_DIR=${PODMAN_ENVIRONMENT_ROOT}/runtime"
    "TMPDIR=${PODMAN_ENVIRONMENT_ROOT}/tmp"
)

run_podman() {
    "$ENV" -- "${PODMAN_HOST_ENVIRONMENT[@]}" \
        "$PODMAN" "${PODMAN_GLOBAL_OPTIONS[@]}" "$@"
}

readonly -a PODMAN_CONTAINER_OPTIONS=(
    run
    --pull=never
    --network=none
    --cgroups=no-conmon
    --cgroupns=host
    --cgroup-parent "$PAYLOAD_CGROUP_RELATIVE"
    --pid=private
    --ulimit nofile=4096:4096
    --read-only
    --read-only-tmpfs=false
    --user=0:0
    --http-proxy=false
    --env-host=false
    --image-volume=ignore
    --security-opt=label=disable
    --security-opt=no-new-privileges
    --workdir=/authority/source
    --env=HOME=/runtime/home
    --env=TMPDIR=/runtime/tmp
    --env=XDG_CACHE_HOME=/runtime/xdg-cache
    --env=LANG=C
    --env=LC_ALL=C
    --env=TZ=UTC
)

session_output=""
evidence_output=""
host_output=""
launch_root=""
launch_receipt=""
launch_receipt_sha=""
container_runtime=""
container_runtime_identity=""
probe_root=""
container_name=""
cidfile=""
main_container_name=""
main_cidfile=""
main_container_id=""
verifier_container_id=""
inner_verifier_log=""
campaign_acceptance_complete=0
cgroup_prepared=0
operator_mode="campaign"
probe_request_nonce=""
consumed_probe_request=""
campaign_request_nonce=""
campaign_target_user=""
campaign_target_uid=""
consumed_campaign_request=""
session_name=""

fail() {
    /usr/bin/printf 'CODESKEPTIC_STABILITY_OPERATOR_FAIL %s\n' "$*" >&2
    return 1
}

require_root_immutable_directory() {
    local path="$1"
    local mode
    [[ ! -L "$path" && -d "$path" ]] || fail "not a real directory: ${path}"
    [[ "$(/usr/bin/stat --format='%u' -- "$path")" == "0" ]] ||
        fail "directory is not root-owned: ${path}"
    mode="$(/usr/bin/stat --format='%a' -- "$path")"
    (( (8#${mode} & 8#022) == 0 )) ||
        fail "directory is group/other writable: ${path}"
}

require_root_immutable_file() {
    local path="$1"
    local mode
    [[ ! -L "$path" && -f "$path" ]] || fail "not a regular file: ${path}"
    [[ "$(/usr/bin/stat --format='%u' -- "$path")" == "0" ]] ||
        fail "file is not root-owned: ${path}"
    mode="$(/usr/bin/stat --format='%a' -- "$path")"
    (( (8#${mode} & 8#022) == 0 )) ||
        fail "file is group/other writable: ${path}"
}

require_root_private_directory() {
    local path="$1"
    [[ ! -L "$path" && -d "$path" ]] || fail "not a private directory: ${path}"
    [[ "$(/usr/bin/stat --format='%u:%g:%a' -- "$path")" == "0:0:700" ]] ||
        fail "private directory ownership or mode drift: ${path}"
}

ensure_root_private_directory() {
    local path="$1"
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        /usr/bin/mkdir --mode=0700 -- "$path"
    fi
    require_root_private_directory "$path"
}

read_probe_request_nonce() {
    local path="$1"
    "$PYTHON" -B - "$path" "$PROBE_REQUEST_SCHEMA" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size > 256
):
    raise SystemExit("probe request metadata is invalid")
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
        raise SystemExit("probe request changed while opening")
    data = os.read(descriptor, 257)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if len(data) > 256 or len(data) != metadata.st_size or after.st_size != metadata.st_size:
    raise SystemExit("probe request changed while reading")
try:
    value = json.loads(data.decode("ascii", errors="strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"probe request is malformed: {error}")
if not isinstance(value, dict) or set(value) != {"mode", "nonce", "schema"}:
    raise SystemExit("probe request fields are invalid")
nonce = value["nonce"]
if (
    value["mode"] != "probe-only"
    or value["schema"] != schema
    or not isinstance(nonce, str)
    or re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        nonce,
    ) is None
):
    raise SystemExit("probe request claim is invalid")
expected = (
    json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
).encode("ascii")
if data != expected:
    raise SystemExit("probe request is not canonical")
print(nonce)
PY
}

consume_probe_request() {
    local stale_consumed
    stale_consumed="$(
        /usr/bin/find "$RUNTIME_ROOT" -mindepth 1 -maxdepth 1 \
            -name '.probe-only.consumed.*' -print -quit
    )"
    [[ -z "$stale_consumed" ]] ||
        fail "stale consumed probe request exists: ${stale_consumed}"
    if [[ ! -e "$PROBE_REQUEST_PATH" && ! -L "$PROBE_REQUEST_PATH" ]]; then
        return 0
    fi
    [[ ! -L "$PROBE_REQUEST_PATH" && -f "$PROBE_REQUEST_PATH" ]] ||
        fail "probe request is not a regular file"
    consumed_probe_request="${RUNTIME_ROOT}/.probe-only.consumed.${BASHPID}"
    [[ ! -e "$consumed_probe_request" && ! -L "$consumed_probe_request" ]] ||
        fail "probe request consumption path already exists"
    /usr/bin/mv --no-target-directory -- \
        "$PROBE_REQUEST_PATH" "$consumed_probe_request"
    probe_request_nonce="$(read_probe_request_nonce "$consumed_probe_request")" ||
        fail "probe request validation failed"
    operator_mode="probe-only"
}

cleanup_consumed_probe_request() {
    local current_nonce
    [[ -n "$consumed_probe_request" ]] || return 0
    if [[ ! -e "$consumed_probe_request" && ! -L "$consumed_probe_request" ]]; then
        return 0
    fi
    current_nonce="$(read_probe_request_nonce "$consumed_probe_request")" ||
        return 1
    [[ -n "$probe_request_nonce" && "$current_nonce" == "$probe_request_nonce" ]] ||
        return 1
    /usr/bin/rm -- "$consumed_probe_request" || return 1
    consumed_probe_request=""
}

read_campaign_request() {
    local path="$1"
    "$PYTHON" -B - "$path" "$CAMPAIGN_REQUEST_SCHEMA" <<'PY'
import json
import os
import pathlib
import pwd
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
schema = sys.argv[2]
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size > 512
):
    raise SystemExit("campaign request metadata is invalid")
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
        raise SystemExit("campaign request changed while opening")
    data = os.read(descriptor, 513)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
if len(data) > 512 or len(data) != metadata.st_size or after.st_size != metadata.st_size:
    raise SystemExit("campaign request changed while reading")
try:
    value = json.loads(data.decode("ascii", errors="strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"campaign request is malformed: {error}")
if not isinstance(value, dict) or set(value) != {
    "mode", "nonce", "schema", "target_uid", "target_user",
}:
    raise SystemExit("campaign request fields are invalid")
nonce = value["nonce"]
user = value["target_user"]
uid = value["target_uid"]
if (
    value["mode"] != "campaign"
    or value["schema"] != schema
    or not isinstance(nonce, str)
    or re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        nonce,
    ) is None
    or not isinstance(user, str)
    or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) is None
    or isinstance(uid, bool)
    or not isinstance(uid, int)
    or uid < 1
    or pwd.getpwnam(user).pw_uid != uid
    or pwd.getpwuid(uid).pw_name != user
):
    raise SystemExit("campaign request claim is invalid")
expected = (json.dumps(
    value, sort_keys=True, separators=(",", ":")
) + "\n").encode("ascii")
if data != expected:
    raise SystemExit("campaign request is not canonical")
print(nonce)
print(user)
print(uid)
PY
}

consume_campaign_request() {
    local -a request_fields=()
    local stale_consumed
    stale_consumed="$(
        /usr/bin/find "$RUNTIME_ROOT" -mindepth 1 -maxdepth 1 \
            -name '.campaign.consumed.*' -print -quit
    )"
    [[ -z "$stale_consumed" ]] ||
        fail "stale consumed campaign request exists: ${stale_consumed}"
    [[ ! -L "$CAMPAIGN_REQUEST_PATH" && -f "$CAMPAIGN_REQUEST_PATH" ]] ||
        fail "an exclusive guided campaign request is required"
    consumed_campaign_request="${RUNTIME_ROOT}/.campaign.consumed.${BASHPID}"
    [[ ! -e "$consumed_campaign_request" && ! -L "$consumed_campaign_request" ]] ||
        fail "campaign request consumption path already exists"
    /usr/bin/mv --no-target-directory -- \
        "$CAMPAIGN_REQUEST_PATH" "$consumed_campaign_request"
    mapfile -t request_fields < <(read_campaign_request "$consumed_campaign_request")
    (( ${#request_fields[@]} == 3 )) || fail "campaign request validation failed"
    campaign_request_nonce="${request_fields[0]}"
    campaign_target_user="${request_fields[1]}"
    campaign_target_uid="${request_fields[2]}"
}

cleanup_consumed_campaign_request() {
    local -a request_fields=()
    [[ -n "$consumed_campaign_request" ]] || return 0
    if [[ ! -e "$consumed_campaign_request" && ! -L "$consumed_campaign_request" ]]; then
        return 0
    fi
    mapfile -t request_fields < <(read_campaign_request "$consumed_campaign_request")
    (( ${#request_fields[@]} == 3 )) || return 1
    [[ "${request_fields[0]}" == "$campaign_request_nonce" \
        && "${request_fields[1]}" == "$campaign_target_user" \
        && "${request_fields[2]}" == "$campaign_target_uid" ]] || return 1
    /usr/bin/rm -- "$consumed_campaign_request" || return 1
    consumed_campaign_request=""
}

consume_launch_request() {
    if [[ -e "$PROBE_REQUEST_PATH" || -L "$PROBE_REQUEST_PATH" ]]; then
        [[ ! -e "$CAMPAIGN_REQUEST_PATH" && ! -L "$CAMPAIGN_REQUEST_PATH" ]] ||
            fail "probe and campaign requests cannot coexist"
        consume_probe_request
        return
    fi
    consume_campaign_request
}

require_empty_private_directory() {
    local path="$1"
    require_root_private_directory "$path" || return 1
    [[ -z "$(/usr/bin/find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
        fail "private directory retained unexpected content: ${path}"
}

create_campaign_runtime_identity() {
    container_runtime_identity="${RUNTIME_IDENTITY_ROOT}/${session_name}.json"
    [[ ! -e "$container_runtime_identity" && ! -L "$container_runtime_identity" ]] ||
        fail "campaign runtime identity already exists"
    "$PYTHON" -B - "$container_runtime_identity" "$session_name" \
        "$boot_id" "$session_nonce" "$container_runtime" <<'PY'
import json
import os
import sys

path, session, boot_id, nonce, runtime = sys.argv[1:]
data = (json.dumps(
    {
        "boot_id": boot_id,
        "runtime": runtime,
        "session": session,
        "session_nonce": nonce,
    },
    sort_keys=True,
    separators=(",", ":"),
) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o400)
try:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short campaign runtime identity write")
        offset += written
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    require_root_immutable_file "$container_runtime_identity"
    /usr/bin/sync --file-system "$RUNTIME_IDENTITY_ROOT"
}

verify_campaign_runtime_identity() {
    [[ -n "$container_runtime_identity" ]] || return 1
    require_root_immutable_file "$container_runtime_identity" || return 1
    "$PYTHON" -B - "$container_runtime_identity" "$session_name" \
        "$boot_id" "$session_nonce" "$container_runtime" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = {
    "boot_id": sys.argv[3],
    "runtime": sys.argv[5],
    "session": sys.argv[2],
    "session_nonce": sys.argv[4],
}
data = path.read_bytes()
if len(data) > 4096:
    raise SystemExit("campaign runtime identity is oversized")
try:
    value = json.loads(data.decode("ascii", errors="strict"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"campaign runtime identity is malformed: {error}")
canonical = (json.dumps(
    value, sort_keys=True, separators=(",", ":")
) + "\n").encode("ascii")
if value != expected or data != canonical:
    raise SystemExit("campaign runtime identity differs from this session")
PY
}

cleanup_probe_runtime() {
    local path
    [[ -n "$probe_root" ]] || return 0
    for path in \
        "${container_runtime}/home" \
        "${container_runtime}/tmp" \
        "${container_runtime}/xdg-cache" \
        "$launch_root" \
        "$evidence_output"; do
        require_empty_private_directory "$path" || return 1
        /usr/bin/rmdir -- "$path" || return 1
    done
    require_empty_private_directory "$container_runtime" || return 1
    /usr/bin/rmdir -- "$container_runtime" || return 1
    require_empty_private_directory "$probe_root" || return 1
    /usr/bin/rmdir -- "$probe_root" || return 1
    probe_root=""
}

cleanup_campaign_runtime() {
    local parent_device
    local runtime_device
    [[ "$operator_mode" == "campaign" && -n "$container_runtime" ]] || return 0
    [[ -n "$session_name" \
        && "$container_runtime" == "${CONTAINER_RUNTIME_ROOT}/${session_name}" ]] || {
        fail "campaign runtime cleanup identity is malformed"
        return 1
    }
    require_root_private_directory "$CONTAINER_RUNTIME_ROOT" || return 1
    require_root_private_directory "$container_runtime" || return 1
    verify_campaign_runtime_identity || {
        fail "campaign runtime cleanup marker is invalid"
        return 1
    }
    parent_device="$(/usr/bin/stat --format='%d' -- "$CONTAINER_RUNTIME_ROOT")" ||
        return 1
    runtime_device="$(/usr/bin/stat --format='%d' -- "$container_runtime")" ||
        return 1
    [[ "$runtime_device" == "$parent_device" ]] || {
        fail "campaign runtime is a separate filesystem"
        return 1
    }
    "$PYTHON" -B - "$container_runtime" <<'PY' || {
import pathlib
import sys

runtime = pathlib.Path(sys.argv[1])

def unescape(value):
    for escaped, raw in (
        ("\\040", " "), ("\\011", "\t"),
        ("\\012", "\n"), ("\\134", "\\"),
    ):
        value = value.replace(escaped, raw)
    return value

for line in pathlib.Path("/proc/self/mountinfo").read_text(
    encoding="utf-8", errors="strict"
).splitlines():
    fields = line.split()
    if len(fields) < 6:
        raise SystemExit("mountinfo record is malformed")
    target = pathlib.Path(unescape(fields[4]))
    if target == runtime or runtime in target.parents:
        raise SystemExit(f"campaign runtime contains mountpoint {target}")
PY
        fail "campaign runtime mount topology is unsafe"
        return 1
    }
    /usr/bin/rm --recursive --one-file-system --preserve-root=all -- \
        "$container_runtime" || {
        fail "cannot remove the exact campaign runtime tree"
        return 1
    }
    [[ ! -e "$container_runtime" && ! -L "$container_runtime" ]] || {
        fail "campaign runtime tree survived cleanup"
        return 1
    }
    /usr/bin/rm -- "$container_runtime_identity" || {
        fail "cannot remove the consumed campaign runtime identity"
        return 1
    }
    container_runtime=""
    container_runtime_identity=""
}

require_closed_hooks_directory() {
    local hook_file
    require_root_immutable_directory "$OPERATOR_ROOT"
    hook_file="$(
        /usr/bin/find "$OPERATOR_ROOT" -mindepth 1 -maxdepth 1 \
            -name '*.json' -print -quit
    )"
    [[ -z "$hook_file" ]] || fail "closed OCI hooks directory contains JSON"
}

verify_dedicated_container_inventory_empty() {
    local inventory
    inventory="$(
        run_podman container list \
            --all --no-trunc --format '{{.ID}}|{{.Names}}'
    )" || {
        fail "cannot inspect the dedicated Podman container inventory"
        return 1
    }
    [[ -z "$inventory" ]] || {
        fail "dedicated Podman store contains stale container state"
        return 1
    }
}

verify_pinned_image_and_empty_container_store() {
    local image_digest
    local image_id
    local image_identity
    image_identity="$(
        run_podman image inspect \
            --format '{{.Id}}|{{.Digest}}' "$PINNED_EVIDENCE_IMAGE"
    )" || {
        fail "cannot inspect the pinned evidence image in the dedicated store"
        return 1
    }
    [[ "$image_identity" != *$'\n'* && "$image_identity" == *"|"* ]] || {
        fail "pinned image inspection is malformed"
        return 1
    }
    image_id="${image_identity%%|*}"
    image_digest="${image_identity#*|}"
    if [[ "$image_id" != sha256:* ]]; then
        image_id="sha256:${image_id}"
    fi
    [[ "$image_id" == "$PINNED_EVIDENCE_IMAGE_ID" ]] ||
        fail "pinned image ID drift"
    [[ "$image_digest" == "$PINNED_EVIDENCE_IMAGE_DIGEST" ]] ||
        fail "pinned image digest drift"
    verify_dedicated_container_inventory_empty
}

cgroup_value() {
    local path="$1"
    [[ ! -L "$path" && -f "$path" ]] || fail "cgroup file is unavailable: ${path}"
    /usr/bin/tr --delete '\n' <"$path"
}

cgroup_has_word() {
    local path="$1"
    local required="$2"
    local word
    for word in $(cgroup_value "$path"); do
        [[ "$word" == "$required" ]] && return 0
    done
    return 1
}

require_empty_cgroup() {
    local path="$1"
    local events
    [[ -z "$(cgroup_value "${path}/cgroup.procs")" ]] ||
        fail "cgroup is not empty: ${path}"
    events="$(cgroup_value "${path}/cgroup.events")"
    [[ "$events" == *"populated 0"* && "$events" == *"frozen 0"* ]] ||
        fail "cgroup is populated or frozen: ${path}"
}

require_absent_or_empty_cgroup() {
    local path="$1"
    if [[ ! -e "$path" && ! -L "$path" ]]; then
        return 0
    fi
    [[ ! -L "$path" && -d "$path" ]] || {
        fail "cleanup cgroup path is not a real directory: ${path}"
        return 1
    }
    require_empty_cgroup "$path"
}

require_controller_context() {
    local affinity
    local current_cgroup
    local filesystem_type
    local hard_limit
    local soft_limit

    filesystem_type="$(/usr/bin/stat --file-system --format='%T' -- "$CGROUP_ROOT")"
    [[ "$filesystem_type" == "cgroup2fs" ]] || fail "unified cgroup v2 is required"
    current_cgroup="$(
        /usr/bin/awk -F: '$1 == "0" && $2 == "" { print $3 }' /proc/self/cgroup
    )"
    [[ "$(/usr/bin/grep --count '^0::' /proc/self/cgroup)" == "1" ]] ||
        fail "controller cgroup authority is ambiguous"
    [[ "$current_cgroup" == "$CONTROLLER_CGROUP_RELATIVE" ]] ||
        fail "controller is outside its exact delegated systemd subgroup"
    affinity="$(
        "$PYTHON" -B -c \
            'import os; print(",".join(str(cpu) for cpu in sorted(os.sched_getaffinity(0))))'
    )"
    [[ "$affinity" == "$CONTROLLER_CPU_LIST" ]] ||
        fail "controller affinity is not exact CPUs ${CONTROLLER_CPUS}"
    soft_limit="$(ulimit -Sn)"
    hard_limit="$(ulimit -Hn)"
    [[ "$soft_limit" == "4096" && "$hard_limit" == "4096" ]] ||
        fail "operator open-file limit is not exact"
    [[ "$(cgroup_value "${SERVICE_CGROUP}/cpuset.cpus.effective")" == "$CAMPAIGN_CPUS" ]] ||
        fail "service AllowedCPUs differs from the fixed campaign topology"
}

prepare_measurement_cgroup() {
    local child
    local memory_nodes

    require_controller_context
    for controller in cpuset cpu memory pids; do
        cgroup_has_word "${SERVICE_CGROUP}/cgroup.controllers" "$controller" ||
            fail "service did not delegate required controller: ${controller}"
    done
    /usr/bin/printf '%s\n' '+cpuset +cpu +memory +pids' \
        >"${SERVICE_CGROUP}/cgroup.subtree_control"
    for controller in cpuset cpu memory pids; do
        cgroup_has_word "${SERVICE_CGROUP}/cgroup.subtree_control" "$controller" ||
            fail "service controller was not enabled: ${controller}"
    done

    if [[ ! -e "$PAYLOAD_CGROUP" && ! -L "$PAYLOAD_CGROUP" ]]; then
        /usr/bin/mkdir --mode=0755 -- "$PAYLOAD_CGROUP"
    fi
    [[ ! -L "$PAYLOAD_CGROUP" && -d "$PAYLOAD_CGROUP" ]] ||
        fail "payload cgroup is not a real directory"
    cgroup_prepared=1
    for child in $(
        /usr/bin/find "$PAYLOAD_CGROUP" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'
    ); do
        [[ "$child" == "measurement" ]] ||
            fail "unexpected stale payload cgroup: ${child}"
    done
    require_empty_cgroup "$PAYLOAD_CGROUP"
    memory_nodes="$(cgroup_value "${SERVICE_CGROUP}/cpuset.mems.effective")"
    [[ -n "$memory_nodes" ]] || fail "service effective memory nodes are empty"
    /usr/bin/printf '%s\n' "$memory_nodes" >"${PAYLOAD_CGROUP}/cpuset.mems"
    /usr/bin/printf '%s\n' "$CAMPAIGN_CPUS" >"${PAYLOAD_CGROUP}/cpuset.cpus"
    /usr/bin/printf '%s\n' "$MEASUREMENT_CPUS" \
        >"${PAYLOAD_CGROUP}/cpuset.cpus.exclusive"
    /usr/bin/printf '%s\n' '+cpuset +cpu +memory +pids' \
        >"${PAYLOAD_CGROUP}/cgroup.subtree_control"
    for controller in cpuset cpu memory pids; do
        cgroup_has_word "${PAYLOAD_CGROUP}/cgroup.subtree_control" "$controller" ||
            fail "payload controller was not enabled: ${controller}"
    done

    if [[ ! -e "$MEASUREMENT_CGROUP" && ! -L "$MEASUREMENT_CGROUP" ]]; then
        /usr/bin/mkdir --mode=0755 -- "$MEASUREMENT_CGROUP"
    fi
    [[ ! -L "$MEASUREMENT_CGROUP" && -d "$MEASUREMENT_CGROUP" ]] ||
        fail "measurement cgroup is not a real directory"
    require_empty_cgroup "$MEASUREMENT_CGROUP"
    /usr/bin/printf '%s\n' "$memory_nodes" >"${MEASUREMENT_CGROUP}/cpuset.mems"
    /usr/bin/printf '%s\n' "$MEASUREMENT_CPUS" >"${MEASUREMENT_CGROUP}/cpuset.cpus"
    /usr/bin/printf '%s\n' "$MEASUREMENT_CPUS" \
        >"${MEASUREMENT_CGROUP}/cpuset.cpus.exclusive"
    /usr/bin/printf '%s\n' 100.00 >"${MEASUREMENT_CGROUP}/cpu.uclamp.min"
    /usr/bin/printf '%s\n' 100.00 >"${MEASUREMENT_CGROUP}/cpu.uclamp.max"
    /usr/bin/printf '%s\n' isolated >"${MEASUREMENT_CGROUP}/cpuset.cpus.partition"
    [[ "$(cgroup_value "${MEASUREMENT_CGROUP}/cpuset.cpus.effective")" == "$MEASUREMENT_CPUS" ]] ||
        fail "measurement effective CPU set drift"
    [[ "$(cgroup_value "${MEASUREMENT_CGROUP}/cpuset.cpus.exclusive.effective")" == "$MEASUREMENT_CPUS" ]] ||
        fail "measurement exclusive CPU set drift"
    [[ "$(cgroup_value "${MEASUREMENT_CGROUP}/cpuset.cpus.partition")" == "isolated" ]] ||
        fail "measurement cgroup is not an isolated partition"
    [[ "$(cgroup_value "${PAYLOAD_CGROUP}/cpuset.cpus.effective")" == "$CONTROLLER_CPUS" ]] ||
        fail "payload controller CPU set drift"
    require_empty_cgroup "$MEASUREMENT_CGROUP"
}

cleanup_measurement_cgroup() {
    local populated=""
    local waited
    (( cgroup_prepared == 1 )) || return 0
    if [[ -d "$MEASUREMENT_CGROUP" && ! -L "$MEASUREMENT_CGROUP" ]]; then
        populated="$(cgroup_value "${MEASUREMENT_CGROUP}/cgroup.procs")" || return 1
        if [[ -n "$populated" ]]; then
            /usr/bin/printf '%s\n' 1 >"${MEASUREMENT_CGROUP}/cgroup.kill" || return 1
            for waited in {1..200}; do
                [[ -z "$(cgroup_value "${MEASUREMENT_CGROUP}/cgroup.procs")" ]] && break
                /usr/bin/sleep 0.01
            done
        fi
        require_empty_cgroup "$MEASUREMENT_CGROUP" || return 1
        /usr/bin/printf '%s\n' member \
            >"${MEASUREMENT_CGROUP}/cpuset.cpus.partition" || return 1
        /usr/bin/rmdir -- "$MEASUREMENT_CGROUP" || return 1
    fi
    if [[ -d "$PAYLOAD_CGROUP" && ! -L "$PAYLOAD_CGROUP" ]]; then
        require_empty_cgroup "$PAYLOAD_CGROUP" || return 1
        /usr/bin/printf '%s\n' '-cpuset -cpu -memory -pids' \
            >"${PAYLOAD_CGROUP}/cgroup.subtree_control" || return 1
        /usr/bin/rmdir -- "$PAYLOAD_CGROUP" || return 1
    fi
    cgroup_prepared=0
}

cleanup_container_by_name() {
    [[ -n "$container_name" ]] || return 0
    if ! run_podman rm --force --ignore -- "$container_name"; then
        fail "cannot remove a possible campaign container by its unique name"
        return 1
    fi
}

read_bound_container_id() {
    local bound_container_name
    local container_id

    [[ -n "$container_name" && -n "$cidfile" ]] || {
        fail "container cleanup identity is incomplete"
        return 1
    }
    [[ ! -L "$cidfile" && -f "$cidfile" ]] || {
        fail "container ID file is unavailable"
        return 1
    }
    require_root_immutable_file "$cidfile" || return 1
    container_id="$(/usr/bin/tr --delete '\n' <"$cidfile")" || return 1
    [[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || {
        fail "container ID file is malformed"
        return 1
    }
    bound_container_name="$(
        run_podman container inspect \
            --format '{{.Name}}' "$container_id"
    )" || {
        fail "cannot bind the container ID to its unique campaign name"
        return 1
    }
    [[ "$bound_container_name" == "$container_name" ]] || {
        fail "container ID does not name this campaign container"
        return 1
    }
    /usr/bin/printf '%s\n' "$container_id"
}

verify_bound_container_execution() {
    local command_json
    local container_id="$1"
    local expected_command_json
    local image_id
    local kind="$2"
    local -a expected_command=()

    case "$kind" in
        campaign) expected_command=("${RUNTIME_CONTROLLER_COMMAND[@]}") ;;
        verifier) expected_command=("${RUNTIME_VERIFIER_COMMAND[@]}") ;;
        *)
            fail "container execution kind is invalid"
            return 1
            ;;
    esac
    image_id="$(
        run_podman container inspect \
            --format '{{.Image}}' "$container_id"
    )" || {
        fail "cannot inspect the bound container image"
        return 1
    }
    if [[ "$image_id" != sha256:* ]]; then
        image_id="sha256:${image_id}"
    fi
    [[ "$image_id" == "$PINNED_EVIDENCE_IMAGE_ID" ]] || {
        fail "bound container image identity drift"
        return 1
    }
    command_json="$(
        run_podman container inspect \
            --format '{{json .Config.Cmd}}' "$container_id"
    )" || {
        fail "cannot inspect the bound container command"
        return 1
    }
    expected_command_json="$(
        "$PYTHON" -B - "${expected_command[@]}" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1:], separators=(",", ":")))
PY
    )" || return 1
    [[ "$command_json" == "$expected_command_json" ]] || {
        fail "bound container command identity drift"
        return 1
    }
}

cleanup_container() {
    local container_id

    [[ -n "$cidfile" ]] || return 0
    if [[ ! -e "$cidfile" && ! -L "$cidfile" ]]; then
        cleanup_container_by_name
        return $?
    fi
    container_id="$(read_bound_container_id)" || {
        cleanup_container_by_name || true
        return 1
    }
    if ! run_podman rm --force --ignore -- "$container_id"; then
        fail "cannot remove the campaign container by its sealed ID"
        return 1
    fi
    /usr/bin/rm -- "$cidfile" || {
        fail "cannot remove the consumed container ID file"
        return 1
    }
}

run_rootful_preflight_probe() {
    local bind_mount
    local probe_exit=0
    local -a probe_args=("${PODMAN_CONTAINER_OPTIONS[@]}")

    container_name="codeskeptic-p10-09-preflight-${session_nonce}"
    cidfile="${RUNTIME_ROOT}/${session_name}.preflight.cid"
    [[ ! -e "$cidfile" && ! -L "$cidfile" ]] ||
        fail "preflight container ID path already exists"
    probe_args+=(--name "$container_name")
    probe_args+=(--cidfile "$cidfile")
    for bind_mount in "${CONTAINER_BIND_MOUNTS[@]}"; do
        probe_args+=(--volume "$bind_mount")
    done
    probe_args+=(
        "$PINNED_EVIDENCE_IMAGE"
        "/usr/bin/python3"
        "-B"
        "-c"
        "$PREFLIGHT_PYTHON"
        "$PAYLOAD_CGROUP_RELATIVE"
        "$MEASUREMENT_CGROUP"
        "${PAYLOAD_CGROUP_RELATIVE}/measurement"
        "$MEASUREMENT_CPU_LIST"
    )
    run_podman "${probe_args[@]}" ||
        probe_exit=$?
    if (( probe_exit == 0 )) && [[ ! -f "$cidfile" || -L "$cidfile" ]]; then
        fail "successful preflight did not retain its cleanup identity"
        probe_exit=1
    fi
    if ! cleanup_container; then
        probe_exit=1
    fi
    container_name=""
    cidfile=""
    require_empty_cgroup "$MEASUREMENT_CGROUP" || probe_exit=1
    (( probe_exit == 0 )) || fail "rootful Podman preflight probe failed"
}

capture_host_snapshot() {
    local phase="$1"
    [[ "$operator_mode" == "campaign" && "$phase" =~ ^(pre|post)$ ]] || {
        fail "host snapshot phase is invalid"
        return 1
    }
    [[ ! -e "${host_output}/${phase}" && ! -L "${host_output}/${phase}" ]] || {
        fail "host snapshot path already exists: ${host_output}/${phase}"
        return 1
    }
    "$PYTHON" -B "$RUNNER_PATH" capture-host \
        --output "${host_output}/${phase}" \
        --boot-id "$boot_id" \
        --target-user "$campaign_target_user" \
        --target-uid "$campaign_target_uid"
    require_root_private_directory "${host_output}/${phase}"
    /usr/bin/sync --file-system "${host_output}/${phase}"
}

run_inner_verifier() {
    local bind_mount
    local new_file
    local stderr_path="${RUNTIME_ROOT}/${session_name}.verifier.stderr"
    local verifier_exit=0
    local -a verifier_args=("${PODMAN_CONTAINER_OPTIONS[@]}")
    local -a verifier_bind_mounts=(
        "${AUTHORITY_ROOT}:/authority:ro"
        "${CONFIG_PATH}:/config/runtime.json:ro"
        "${CONFIG_SHA_PATH}:/config/runtime.json.sha256:ro"
        "${launch_root}:/launch:ro"
        "${evidence_output}:/evidence:ro"
        "${container_runtime}:/runtime:ro"
        "/sys/fs/cgroup:/sys/fs/cgroup:ro"
    )

    container_name="codeskeptic-p10-09-verifier-${session_nonce}"
    cidfile="${RUNTIME_ROOT}/${session_name}.verifier.cid"
    inner_verifier_log="${host_output}/inner-verification.log"
    for new_file in "$cidfile" "$stderr_path" "$inner_verifier_log"; do
        [[ ! -e "$new_file" && ! -L "$new_file" ]] || {
            fail "verifier output path already exists: ${new_file}"
            return 1
        }
    done
    verifier_args+=(--name "$container_name")
    verifier_args+=(--cidfile "$cidfile")
    for bind_mount in "${verifier_bind_mounts[@]}"; do
        verifier_args+=(--volume "$bind_mount")
    done
    verifier_args+=("$PINNED_EVIDENCE_IMAGE" "${RUNTIME_VERIFIER_COMMAND[@]}")

    run_podman "${verifier_args[@]}" \
        >"$inner_verifier_log" 2>"$stderr_path" || verifier_exit=$?
    if (( verifier_exit == 0 )) && [[ ! -f "$cidfile" || -L "$cidfile" ]]; then
        fail "successful verifier did not retain its cleanup identity"
        verifier_exit=1
    fi
    if [[ -f "$cidfile" && ! -L "$cidfile" ]]; then
        verifier_container_id="$(read_bound_container_id)" || verifier_exit=1
        if [[ "$verifier_container_id" =~ ^[0-9a-f]{64}$ ]]; then
            verify_bound_container_execution \
                "$verifier_container_id" verifier || verifier_exit=1
        fi
    fi
    if ! cleanup_container; then
        verifier_exit=1
    fi
    container_name=""
    cidfile=""
    if [[ ! -f "$stderr_path" || -L "$stderr_path" ]]; then
        fail "verifier stderr path is unavailable"
        verifier_exit=1
    elif [[ -s "$stderr_path" ]]; then
        fail "strict inner verifier wrote stderr"
        verifier_exit=1
    fi
    /usr/bin/rm -- "$stderr_path" || verifier_exit=1
    if [[ ! -f "$inner_verifier_log" || -L "$inner_verifier_log" ]]; then
        fail "strict inner verifier log is unavailable"
        verifier_exit=1
    elif (( $(/usr/bin/stat --format='%s' -- "$inner_verifier_log") > 4096 )); then
        fail "strict inner verifier log exceeds its fixed size limit"
        verifier_exit=1
    fi
    require_empty_cgroup "$MEASUREMENT_CGROUP" || verifier_exit=1
    (( verifier_exit == 0 )) || {
        fail "strict inner verifier container failed"
        return 1
    }
    [[ "$verifier_container_id" =~ ^[0-9a-f]{64}$ ]] ||
        fail "verifier container identity is malformed"
    /usr/bin/sync --file-system "$inner_verifier_log"
}

write_cleanup_record() {
    local cleanup_path="${host_output}/cleanup.json"
    local expected_runtime="${CONTAINER_RUNTIME_ROOT}/${session_name}"
    local expected_marker="${RUNTIME_IDENTITY_ROOT}/${session_name}.json"

    [[ "$main_container_id" =~ ^[0-9a-f]{64}$ \
        && "$verifier_container_id" =~ ^[0-9a-f]{64}$ ]] || {
        fail "cleanup container identities are malformed"
        return 1
    }
    [[ "$main_container_id" != "$verifier_container_id" ]] || {
        fail "campaign and verifier container identities are not distinct"
        return 1
    }
    [[ ! -e "$main_cidfile" && ! -L "$main_cidfile" ]] ||
        fail "campaign container ID file survived cleanup"
    [[ ! -e "${RUNTIME_ROOT}/${session_name}.verifier.cid" \
        && ! -L "${RUNTIME_ROOT}/${session_name}.verifier.cid" ]] ||
        fail "verifier container ID file survived cleanup"
    [[ ! -e "$expected_runtime" && ! -L "$expected_runtime" ]] ||
        fail "campaign runtime survived cleanup"
    [[ ! -e "$expected_marker" && ! -L "$expected_marker" ]] ||
        fail "campaign runtime identity survived cleanup"
    require_absent_or_empty_cgroup "$MEASUREMENT_CGROUP"
    require_absent_or_empty_cgroup "$PAYLOAD_CGROUP"
    verify_dedicated_container_inventory_empty
    [[ ! -e "$cleanup_path" && ! -L "$cleanup_path" ]] ||
        fail "host cleanup record already exists"

    "$PYTHON" -B - "$cleanup_path" "$boot_id" "$session_name" \
        "$session_nonce" "$campaign_target_user" "$campaign_target_uid" \
        "$main_container_id" "$main_container_name" "$main_cidfile" \
        "$verifier_container_id" \
        "codeskeptic-p10-09-verifier-${session_nonce}" \
        "${RUNTIME_ROOT}/${session_name}.verifier.cid" \
        "$MEASUREMENT_CGROUP" "$PAYLOAD_CGROUP" \
        "$expected_runtime" "$expected_marker" "$OPERATOR_ROOT" <<'PY'
import json
import os
import sys

(
    path, boot_id, session, nonce, target_user, target_uid,
    campaign_id, campaign_name, campaign_cidfile,
    verifier_id, verifier_name, verifier_cidfile,
    measurement_cgroup, payload_cgroup, runtime_tree,
    identity_marker, hooks_dir,
) = sys.argv[1:]
value = {
    "schema": "codeskeptic-stability-host-cleanup-v2",
    "boot_id": boot_id,
    "session": session,
    "session_nonce": nonce,
    "target_user": target_user,
    "target_uid": int(target_uid),
    "podman": {
        "executable": "/usr/bin/podman",
        "root": "/var/lib/codeskeptic-p10-09/podman-root",
        "runroot": "/run/codeskeptic-p10-09/podman-runroot",
        "storage_driver": "overlay",
        "cgroup_manager": "cgroupfs",
        "events_backend": "none",
        "hooks_dir": hooks_dir,
        "runtime": "/usr/bin/crun",
        "conmon": "/usr/bin/conmon",
    },
    "container": {
        "id": campaign_id,
        "name": campaign_name,
        "cidfile": campaign_cidfile,
        "image_id": "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5",
        "command": [
            "/usr/bin/python3", "-B",
            "/authority/source/scripts/run_stability_campaign.py", "run",
            "--config", "/config/runtime.json", "--output", "/evidence",
        ],
    },
    "verifier_container": {
        "id": verifier_id,
        "name": verifier_name,
        "cidfile": verifier_cidfile,
        "image_id": "sha256:25640c190484acc04e0dab2c64f8683668ad33930a3670900ff407023efc7fc5",
        "command": [
            "/usr/bin/python3", "-B",
            "/authority/source/scripts/run_stability_campaign.py", "verify",
            "--config", "/config/runtime.json", "--evidence", "/evidence",
        ],
    },
    "cgroups": {
        "measurement": measurement_cgroup,
        "payload": payload_cgroup,
    },
    "runtime": {
        "identity_marker": identity_marker,
        "tree": runtime_tree,
    },
    "gates": {
        "campaign_cidfile_absent": "pass",
        "campaign_container_identity_absent": "pass",
        "container_inventory_empty": "pass",
        "measurement_cgroup_empty": "pass",
        "payload_cgroup_empty": "pass",
        "runtime_absent": "pass",
        "runtime_identity_absent": "pass",
        "verifier_cidfile_absent": "pass",
        "verifier_container_identity_absent": "pass",
    },
}
data = (json.dumps(
    value, sort_keys=True, separators=(",", ":")
) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
try:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short host cleanup record write")
        offset += written
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
    require_root_immutable_file "$cleanup_path"
    /usr/bin/sync --file-system "$cleanup_path"
}

seal_operator_evidence() {
    local sealed_file
    [[ "$inner_verifier_log" == "${host_output}/inner-verification.log" ]] || {
        fail "inner verifier log identity is malformed"
        return 1
    }
    "$PYTHON" -B "$RUNNER_PATH" seal-operator \
        --session-root "$session_output" \
        --config "$CONFIG_PATH" \
        --launch-receipt "$launch_receipt" \
        --operator "${OPERATOR_ROOT}/run-authoritative-stability.sh" \
        --boot-id "$boot_id" \
        --session-nonce "$session_nonce" \
        --inner-verifier-log "$inner_verifier_log"
    "$PYTHON" -B "$RUNNER_PATH" verify-operator \
        --session-root "$session_output" \
        --config "$CONFIG_PATH" \
        --launch-receipt "$launch_receipt" \
        --operator "${OPERATOR_ROOT}/run-authoritative-stability.sh"
    for sealed_file in \
        "${session_output}/receipt.json" \
        "${session_output}/receipt.json.sha256" \
        "${session_output}/SHA256SUMS"; do
        require_root_immutable_file "$sealed_file"
    done
    /usr/bin/sync --file-system "$session_output"
}

terminate_with_signal_status() {
    local signal_number="$1"
    trap - HUP INT TERM
    exit "$((128 + signal_number))"
}

publish_terminal_status() {
    local exit_code=$?
    local result="failure"
    local completed_utc
    local reported_probe_request="none"
    local status_tmp="${STATUS_ROOT}/.terminal-status.${BASHPID}"
    local status_path="${STATUS_ROOT}/terminal-status"
    local reported_session="none"

    trap - EXIT HUP INT TERM
    if ! cleanup_container; then
        exit_code=1
    fi
    if ! cleanup_measurement_cgroup; then
        exit_code=1
    fi
    if ! cleanup_campaign_runtime; then
        exit_code=1
    fi
    if ! cleanup_probe_runtime; then
        exit_code=1
    fi
    if ! cleanup_consumed_probe_request; then
        exit_code=1
    fi
    if ! cleanup_consumed_campaign_request; then
        exit_code=1
    fi
    if [[ "$operator_mode" == "campaign" \
        && "$campaign_acceptance_complete" != "1" ]]; then
        exit_code=1
    fi
    if (( exit_code == 0 )); then
        result="success"
    fi
    if [[ -n "$session_output" ]]; then
        reported_session="$session_output"
    fi
    if [[ "$operator_mode" == "probe-only" && -n "$probe_request_nonce" ]]; then
        reported_probe_request="$probe_request_nonce"
    fi
    TZ=UTC printf -v completed_utc '%(%Y-%m-%dT%H:%M:%SZ)T' -1
    if /usr/bin/printf \
        'mode=%s\nprobe_request=%s\nresult=%s\nexit_code=%d\nsession=%s\ncompleted_utc=%s\n' \
        "$operator_mode" "$reported_probe_request" "$result" "$exit_code" \
        "$reported_session" "$completed_utc" \
        >"$status_tmp"; then
        /usr/bin/chmod 0600 -- "$status_tmp"
        /usr/bin/sync --file-system "$status_tmp"
        /usr/bin/mv --no-target-directory -- "$status_tmp" "$status_path"
        /usr/bin/sync --file-system "$STATUS_ROOT"
    fi
    if [[ "${CODESKEPTIC_TERMINAL_NOTIFY:-0}" == "1" ]]; then
        /usr/bin/printf '\a\a\a' >/dev/console 2>/dev/null || true
        /usr/bin/wall --nobanner "$status_path" 2>/dev/null || true
    fi
    exit "$exit_code"
}

(( EUID == 0 )) || fail "operator must run as root"
require_root_private_directory "$STATE_ROOT"
require_root_private_directory "$RUNTIME_ROOT"
ensure_root_private_directory "$STATUS_ROOT"
ensure_root_private_directory "$PODMAN_ROOT"
ensure_root_private_directory "$PODMAN_RUNROOT"
require_root_private_directory "$PODMAN_ENVIRONMENT_ROOT"
for podman_environment_name in home data cache config runtime tmp; do
    require_root_private_directory \
        "${PODMAN_ENVIRONMENT_ROOT}/${podman_environment_name}"
done
trap publish_terminal_status EXIT
trap 'terminate_with_signal_status 1' HUP
trap 'terminate_with_signal_status 2' INT
trap 'terminate_with_signal_status 15' TERM

exec {LOCK_FD}>"$LOCK_PATH"
/usr/bin/flock --nonblock "$LOCK_FD" || fail "another stability session holds the lock"
consume_launch_request

if [[ "$operator_mode" == "campaign" ]]; then
    ensure_root_private_directory "$SESSION_ROOT"
    ensure_root_private_directory "$LAUNCH_ROOTS"
    ensure_root_private_directory "$CONTAINER_RUNTIME_ROOT"
    ensure_root_private_directory "$RUNTIME_IDENTITY_ROOT"
    require_empty_private_directory "$CONTAINER_RUNTIME_ROOT"
    require_empty_private_directory "$RUNTIME_IDENTITY_ROOT"
fi

require_root_immutable_directory "$AUTHORITY_ROOT"
require_root_immutable_directory "$OPERATOR_ROOT"
require_closed_hooks_directory
require_root_immutable_directory "${AUTHORITY_ROOT}/source"
require_root_immutable_file "$CONFIG_PATH"
require_root_immutable_file "$CONFIG_SHA_PATH"
require_root_immutable_file "$RUNNER_PATH"
require_root_immutable_file "$PODMAN"
require_root_immutable_file "$ENV"
require_root_immutable_file "${OPERATOR_ROOT}/run-authoritative-stability.sh"

boot_id="$(/usr/bin/tr --delete '\n' </proc/sys/kernel/random/boot_id)"
[[ "$boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    fail "boot identity is malformed"
if [[ "$operator_mode" == "probe-only" ]]; then
    session_nonce="$probe_request_nonce"
else
    session_nonce="$campaign_request_nonce"
fi
[[ "$session_nonce" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    fail "session nonce is malformed"
TZ=UTC printf -v started_utc '%(%Y%m%dT%H%M%SZ)T' -1
config_measurement_cgroup="$(
    "$PYTHON" -B - "$CONFIG_PATH" "$CONFIG_SHA_PATH" "$MAX_CONFIG_BYTES" <<'PY'
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
expected = f"{hashlib.sha256(data).hexdigest()}  runtime.json\n".encode("ascii")
if sidecar_path.read_bytes() != expected:
    raise SystemExit("runtime config checksum mismatch")
value = json.loads(data.decode("utf-8", errors="strict"))
print(value["qualification"]["measurement_cgroup"])
PY
)"
[[ "$config_measurement_cgroup" == "$MEASUREMENT_CGROUP" ]] ||
    fail "runtime config measurement cgroup differs from the service subtree"

if [[ "$operator_mode" == "campaign" ]]; then
    session_name="${started_utc}-${boot_id}-${session_nonce}"
    session_output="${SESSION_ROOT}/${session_name}"
    evidence_output="${session_output}/campaign"
    host_output="${session_output}/host"
    launch_root="${LAUNCH_ROOTS}/${session_name}"
    container_runtime="${CONTAINER_RUNTIME_ROOT}/${session_name}"
    main_container_name="codeskeptic-p10-09-${session_nonce}"
    main_cidfile="${RUNTIME_ROOT}/${session_name}.cid"

    [[ ! -e "$session_output" && ! -L "$session_output" ]] ||
        fail "new session output already exists"
    /usr/bin/mkdir --mode=0700 -- "$session_output"
    require_root_private_directory "$session_output"
    for new_path in "$evidence_output" "$host_output" "$launch_root" \
        "$container_runtime"; do
        [[ ! -e "$new_path" && ! -L "$new_path" ]] ||
            fail "new session path already exists: ${new_path}"
        /usr/bin/mkdir --mode=0700 -- "$new_path"
        require_root_private_directory "$new_path"
    done
    [[ ! -e "$main_cidfile" && ! -L "$main_cidfile" ]] ||
        fail "container ID path already exists"
    /usr/bin/mkdir --mode=0700 -- \
        "${container_runtime}/home" \
        "${container_runtime}/tmp" \
        "${container_runtime}/xdg-cache"
    create_campaign_runtime_identity
else
    session_name="probe-${session_nonce}"
    session_output=""
    probe_root="${RUNTIME_ROOT}/probe-${session_nonce}"
    launch_root="${probe_root}/launch"
    evidence_output="${probe_root}/evidence"
    container_runtime="${probe_root}/runtime"
    [[ ! -e "$probe_root" && ! -L "$probe_root" ]] ||
        fail "probe runtime root already exists"
    /usr/bin/mkdir --mode=0700 -- "$probe_root"
    for new_path in "$launch_root" "$evidence_output" "$container_runtime"; do
        /usr/bin/mkdir --mode=0700 -- "$new_path"
        require_root_private_directory "$new_path"
    done
    /usr/bin/mkdir --mode=0700 -- \
        "${container_runtime}/home" \
        "${container_runtime}/tmp" \
        "${container_runtime}/xdg-cache"
fi

if [[ "$operator_mode" == "campaign" ]]; then
    capture_host_snapshot "pre"
fi
verify_pinned_image_and_empty_container_store
if [[ "$operator_mode" == "campaign" ]]; then
    "$PYTHON" -B "$RUNNER_PATH" seal-launch \
        --config "$CONFIG_PATH" --output "$launch_root" --boot-id "$boot_id"
    launch_receipt="${launch_root}/receipt.json"
    launch_receipt_sha="${launch_receipt}.sha256"
    require_root_immutable_file "$launch_receipt"
    require_root_immutable_file "$launch_receipt_sha"
    "$PYTHON" -B "$RUNNER_PATH" verify-launch \
        --config "$CONFIG_PATH" --receipt "$launch_receipt" --boot-id "$boot_id"
    /usr/bin/chmod 0400 -- "$launch_receipt" "$launch_receipt_sha"
    /usr/bin/chmod 0500 -- "$launch_root"
    /usr/bin/sync --file-system "$launch_receipt"
    /usr/bin/sync --file-system "$LAUNCH_ROOTS"
fi

readonly -a CONTAINER_BIND_MOUNTS=(
    "${AUTHORITY_ROOT}:/authority:ro"
    "${CONFIG_PATH}:/config/runtime.json:ro"
    "${CONFIG_SHA_PATH}:/config/runtime.json.sha256:ro"
    "${launch_root}:/launch:ro"
    "${evidence_output}:/evidence:rw"
    "${container_runtime}:/runtime:rw"
    "/sys/fs/cgroup:/sys/fs/cgroup:rw"
)

prepare_measurement_cgroup
run_rootful_preflight_probe

if [[ "$operator_mode" == "probe-only" ]]; then
    /usr/bin/printf 'CODESKEPTIC_ROOTFUL_PROBE_ACCEPTED %s\n' \
        "$probe_request_nonce"
    exit 0
fi

container_name="$main_container_name"
cidfile="$main_cidfile"
podman_run_args=("${PODMAN_CONTAINER_OPTIONS[@]}")
podman_run_args+=(--name "$container_name")
podman_run_args+=(--cidfile "$cidfile")
for bind_mount in "${CONTAINER_BIND_MOUNTS[@]}"; do
    podman_run_args+=(--volume "$bind_mount")
done
podman_run_args+=("$PINNED_EVIDENCE_IMAGE" "${RUNTIME_CONTROLLER_COMMAND[@]}")

runner_exit=0
/usr/bin/systemd-inhibit \
    --what=shutdown:sleep \
    --who=CodeSkeptic-P10-09 \
    --why='authoritative scope-bound stability evidence session' \
    --mode=block \
    run_podman "${podman_run_args[@]}" ||
    runner_exit=$?

# Without --rm the CID file and stopped container must both remain available
# for the EXIT trap to remove explicitly. A successful command without a CID
# cannot be reported as a successful, orphan-free operator run.
if (( runner_exit == 0 )) && [[ ! -f "$cidfile" || -L "$cidfile" ]]; then
    fail "successful Podman return did not retain its cleanup identity"
    runner_exit=1
fi
(( runner_exit == 0 )) || exit "$runner_exit"

main_container_id="$(read_bound_container_id)"
verify_bound_container_execution "$main_container_id" campaign
cleanup_container
container_name=""
cidfile=""
require_empty_cgroup "$MEASUREMENT_CGROUP"

run_inner_verifier
cleanup_measurement_cgroup
cleanup_campaign_runtime
write_cleanup_record
capture_host_snapshot "post"
seal_operator_evidence
campaign_acceptance_complete=1
exit 0
