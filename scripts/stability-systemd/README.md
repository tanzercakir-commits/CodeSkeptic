# P10-09 system control-plane contract

This bundle keeps the authoritative campaign outside graphical and interactive
user sessions. It is only a transport and lifecycle boundary: a zero service
exit does not prove any P10-09 gate. Acceptance belongs to the sealed campaign
receipt and its independent verifier.

## Scope contract

One accepted campaign contains exactly one cold round and one warm round. Each
round analyzes the three fixed projects three times, so the acceptance matrix
contains exactly 18 real-world analysis shards. The controller also enforces
the retained determinism, sanitizer, resource, descendant, restart,
checkpoint, fault-injection, performance, and semantic gates. Elapsed time is
metadata, not an acceptance threshold. The seven-day systemd ceiling is only
an outer runaway guard and cannot create an accepted receipt.
The real-world manifest's `window_minutes` value is likewise a bounded
scheduling envelope inherited from the campaign catalog, not a required
elapsed duration and not part of the P10-09 completion decision.

## Staged layout

The installed paths are fixed:

- `/opt/codeskeptic-p10-09/authority` is the root-owned authority tree. Its
  `source` directory contains the exact runner and repository snapshot.
- `/opt/codeskeptic-p10-09/operator` is the root-owned operator bundle and is
  also the deliberately closed OCI hook search directory. It must contain no
  `*.json` hook definition; the operator checks this before asking Podman to
  use the directory.
- `/etc/codeskeptic-p10-09/runtime.json` and
  `/etc/codeskeptic-p10-09/runtime.json.sha256` are the canonical root-owned
  runtime configuration pair. Both are mounted separately and read-only.
- `/var/lib/codeskeptic-p10-09/podman-root` is the dedicated rootful Podman
  image and container store. Provisioning must place the exact pinned evidence
  image in this store before running the unit; the operator never pulls.
- `/var/lib/codeskeptic-p10-09/podman-environment` is the matching private
  staging HOME/XDG/cache/runtime/temp authority. Every staging Podman command
  uses only these directories; it never writes `/root` or the producer's
  ambient working directory.
- `/run/codeskeptic-p10-09/podman-runroot` is the matching ephemeral Podman
  runroot. Neither path falls back to the host's ambient Podman store.
- `/var/lib/codeskeptic-p10-09/launches` retains the canonical launch receipt
  pairs. Each `/var/lib/codeskeptic-p10-09/sessions/<session>` envelope has a
  `campaign/` inner controller bundle and a `host/` contamination record, then
  seals one outer operator receipt and checksum manifest. The host record binds
  pre-run system and target-user journal cursors, post-cleanup exact cursor
  anchor records and raw JSONL deltas,
  endpoint coredump/helper/socket inventories, both container identities, and
  the exact cleanup result. Each activation creates new, previously absent
  directories.
- `/var/lib/codeskeptic-p10-09/runtime` holds the fresh disk-backed
  writable working tree for the controller. Shards reuse one strictly
  sequential workspace and remove it after every action; the exact session
  runtime tree is bound to a root-only boot/session/nonce marker outside the
  container mount and removed again by the operator's terminal trap. None of it is
  accepted evidence. Keeping clone/build data out of `/run` prevents the host
  tmpfs and RAM budget from becoming the campaign's storage ceiling.
- `/var/lib/codeskeptic-p10-09/status/terminal-status` is only a convenience
  report for the most recent operator result.

The portable disk guard is deliberately described as observed detection, not
as a kernel filesystem quota. Each action inherits an 8-GiB per-file hard
limit; the controller also watches evidence-tree and filesystem-allocation
budgets while holding a preallocated, unlinked 16-GiB emergency extent. On a
violation it first proves the exact writer tree stopped, then releases the
extent and verifies at least 8 GiB of recovery space before killing/reaping to
`ECHILD` and sealing the failure. If quiescence cannot be proved, the extent is
retained and acceptance is withheld. The authoritative operator therefore
requires the dedicated, idle host established by preflight and does not claim
to prevent a transient `ENOSPC` for unrelated concurrent workloads.

The staged config's fault-injection binary is consumed, not rebuilt, by this
operator. Its path is exactly the verified undefined-sanitizer `test_build`
plus `tests/codeskeptic_tests`; its checksum must match both the live bounded
file hash and the same binary recorded in the undefined-sanitizer receipt.
Generating a second test binary from the analyzer build authority would break
the campaign provenance contract.

The operator inspects the image in the dedicated store and requires the exact
reference, manifest digest, and image ID embedded in the controller. Before
starting Podman it invokes the pinned source runner's `seal-launch` command to
create `receipt.json` and `receipt.json.sha256` with exclusive canonical
writes. It then invokes `verify-launch` against the exact config checksum and
current boot ID, makes the launch pair non-writable, and mounts it read-only.
Provisioning is therefore a separate root-controlled staging operation: it
must populate the dedicated `--root` directly from the retained evidence-image
archive, using the matching dedicated `--runroot`, and must leave the pinned
reference resolving to the documented manifest digest and image ID. Copying or
falling back to the ambient Podman store is not admissible. Image inspection
and an actual `--pull=never` probe both fail closed when this contract is not
met.

The retained archive must preserve the pinned distribution manifest. A normal
compressed `podman save` rewrites that manifest and is not admissible even when
the resulting filesystem is similar. The accepted producer form is an OCI
archive created from the already verified local image with `skopeo copy
--preserve-digests --dest-compress=false`; the staging verifier then reloads
that archive into a fresh dedicated store and rederives both the manifest
digest and image ID before any installation path is changed.

## Staging lifecycle

`scripts/stage_stability_campaign.py` exposes exactly `prepare`, `seal`,
`verify`, `install`, and `verify-install`. `prepare` clones a clean, detached,
standalone exact-head source and creates only the fixed authority layout. It
deliberately leaves `authority/mirrors` absent so the real-world mirror sealer
can publish that authority create-new rather than reuse a producer placeholder.
Prerequisite producers populate that mutable layout and write the canonical
runtime config. `seal` binds every root-executed operator byte to its exact-head
source counterpart, validates the data-only config schema without importing
staged Python on the host, normalizes modes, and publishes a checksummed bundle
with an atomic no-replace rename. `verify` rederives the complete inventory and
executes the retained image and static-authority checks in bounded, networkless
containers.

`install` first copies the user-supplied bundle through no-follow directory
descriptors into a private snapshot. It performs the full archive/runtime
verification there before touching fixed host paths. A fresh installation is
create-new; late failure removes only objects whose device/inode identities
still match that invocation. The installation receipt is written last as the
commit marker. `verify`, `install`, and `verify-install` all require the
operator's out-of-band expected Git revision and bundle-receipt SHA-256; bundle
metadata cannot nominate its own trust root. `install` records that pair in the
root-owned installation receipt, and the guided entrypoint carries the same
pair into `verify-install` before executing any staged verifier. Both install
and verify-install create, use, and remove the exact service pathname
`/run/codeskeptic-p10-09/podman-runroot`. Recreating that same pathname after a
cold boot reopens the persistent dedicated store without changing Podman's
storage identity.

For example, after obtaining both values through the separately retained
exact-head authority record, the public lifecycle is invoked as follows (the
values shown are placeholders, not bundle-derived defaults):

```text
python3 scripts/stage_stability_campaign.py verify --bundle SEALED \
  --expected-revision EXPECTED_40_HEX \
  --expected-bundle-receipt-sha256 EXPECTED_64_HEX
sudo python3 scripts/stage_stability_campaign.py install --bundle SEALED \
  --expected-revision EXPECTED_40_HEX \
  --expected-bundle-receipt-sha256 EXPECTED_64_HEX
```

## One-command guided start

The checksummed exact-head staging step installs the authority, canonical config pair,
dedicated image store, operator bundle, and an exact copy of the service unit;
it must never synthesize authority from a dirty working tree. After that step,
one command starts and follows the operator:

```text
/opt/codeskeptic-p10-09/operator/guided-stability.sh
```

The guided entrypoint rings a triple bell only when the `sudo` password may be
needed and when the service reaches a terminal success or failure. It verifies
the root-owned, non-writable installed files, the canonical config checksum,
the exact loaded unit, and the required `systemd.unit=multi-user.target` boot
before calling `systemctl start --wait codeskeptic-stability.service`. It also
requires `UnitFileState=static`: the unit has no install target, must never be
enabled, and can only be started by this explicit guided invocation. Before
starting it also requires `graphical.target` inactive, the display manager
inactive/dead or absent, and no X11/Wayland/Mir login session. It fails instead
of asking systemd to close a graphical environment. A prior
failed unit state is reset automatically. At completion it prints only the
strictly parsed, 1024-byte-bounded terminal status plus a short success or
recovery message. It never reboots the host, never isolates a target, and never
starts a ladder of manual attempts. If staging or the boot precondition is
missing, it fails closed with one actionable
`CODESKEPTIC_GUIDED_STAGING_UNAVAILABLE` message.

Every full campaign start also creates one exclusive root-owned request that
binds a fresh nonce to the invoking non-root user and UID. The static service
refuses a full run without that exact guided request, consumes it atomically,
uses the user identity for the host DrKonqi guard, and removes only the
nonce-bound request in its terminal cleanup. A direct `systemctl start`, an
ambient/stale request, or simultaneous probe and campaign requests fail closed.

Before committing to the multi-hour campaign, the same entrypoint can perform
only the short rootful launch and cgroup validation:

```text
/opt/codeskeptic-p10-09/operator/guided-stability.sh --probe-only
```

This mode creates one root-private, exclusive probe request in `/run`, which
the operator atomically consumes and binds to the terminal status as
`mode=probe-only`. It uses the same unit, pinned image, Podman options, cgroup
topology, limits, hooks directory, and seven bind destinations, but substitutes
fresh ephemeral `/run` directories for the launch, evidence, and runtime
mounts. It exits immediately after the probe and full cleanup: it creates no
campaign evidence, no campaign launch receipt, and never starts the campaign
controller. Normal mode refuses a stale probe request, and cleanup removes a
request only when its exact schema, root ownership, mode, and nonce still match
the invocation that created or consumed it. Probe success proves only that the
host launch topology works; it is not campaign acceptance.

## Container boundary

The rootful container is launched with `network=none`, `cgroups=no-conmon`, the
host cgroup namespace, a private PID namespace, a read-only root filesystem,
user `0:0`, and exact soft/hard `nofile` limits of 4096. The unit also fixes
`LimitNOFILE=4096`, so the operator, probe, controller, and descendants cannot
inherit a wider descriptor ceiling. The
`no-conmon` mode avoids an extra conmon cgroup while preserving the delegated
container cgroup model required for the fixed measurement child; Podman's
incompatible `cgroups=disabled`/`cgroupns=host` combination is forbidden.
The absolute cgroup parent
`/system.slice/codeskeptic-stability.service/codeskeptic-p10-09` is created
below the systemd service cgroup, keeping every payload inside
`KillMode=control-group` coverage.
Pulling, host environment inheritance, proxy inheritance, image
volumes, writable implicit read-only tmpfs mounts, and ambient OCI hooks are
disabled. Its fixed bind topology is:

- `/authority` read-only;
- `/config/runtime.json` read-only;
- `/config/runtime.json.sha256` read-only;
- `/launch` read-only;
- `/evidence` read-write;
- `/runtime` read-write; and
- `/sys/fs/cgroup` read-write.

The exact in-container command is:

```text
/usr/bin/python3 -B /authority/source/scripts/run_stability_campaign.py run --config /config/runtime.json --output /evidence
```

The container is not auto-removed. Podman must create a fresh CID file; the
operator's terminal trap uses that exact ID to force-remove the container and
then removes the consumed CID file. Malformed cleanup identity or failed
cleanup changes the terminal result to failure.

After the controller exits successfully, the operator starts a second fresh
container from the same pinned image with the exact `verify` command. The
campaign evidence and runtime are read-only in that verifier. Its CID, name,
image ID, command, exact one-line success log, empty stderr, and removal are
bound into the outer cleanup and operator receipts. A controller success is
therefore not allowed to stand in for independent semantic verification.

Before the controller starts, the operator performs a short rootful probe with
the exact pinned image, dedicated store, global Podman options, container
limits, hooks directory, and bind topology. The probe requires PID 1 in the
private PID namespace, imports and exercises PyYAML, observes exact controller
affinity 4-11 and `RLIMIT_NOFILE=(4096,4096)`, and runs the real measurement
cgroup entry wrapper. That child must observe exact affinity 0-3 and exact
membership in the measurement cgroup; the cgroup must return to empty and
unfrozen before the authoritative controller launch. Any probe or cleanup
failure rejects the activation.

## systemd and evidence boundary

The service is eligible only after an explicit `multi-user.target` boot and
conflicts with graphical and sleep-family targets. It has null standard input
and cannot request a password, Enter key, TTY action, or graphical transition.
It is deliberately static and has no `[Install]` section, so reaching
`multi-user.target` can never start the campaign by itself.
The unit delegates its cgroup subtree, places its main operator in
`DelegateSubgroup=controller`, exposes `AllowedCPUs=0-11`, and confines the
operator/controller task affinity to logical CPUs 4-11. The payload parent and
its isolated measurement child are siblings of that systemd controller leaf,
all below the same service unit. The runtime config must identify the exact
measurement path
`/sys/fs/cgroup/system.slice/codeskeptic-stability.service/codeskeptic-p10-09/measurement`,
whose effective and exclusive CPU sets are both 0-3. The controller payload
inherits effective CPUs 4-11 after the isolated partition is established.

The controller must seal its pre-run receipt after validating the exact source,
build, image, workload, sanitizer, boot, cgroup, resource, thermal, coredump,
and prerequisite authorities. It writes heartbeat, cycle, failure, and
postflight evidence only into the new session directory. A terminal receipt is
published only after postflight observations and outer checksums are complete.

There is no resume contract. A stop, host interruption, failed preflight,
partial output, nonzero controller exit, or cleanup failure rejects the whole
session. A later activation starts distinct empty paths and cannot combine
receipts or shards from another attempt. `Restart=no`,
`KillMode=control-group`, and `OOMPolicy=stop` expose controller, descendant,
and memory failures. A nonblocking lock excludes concurrent campaigns, and
`systemd-inhibit` blocks shutdown and sleep only while Podman is attached.

Before the first Podman probe, the root operator captures opaque journal
cursors for both the system journal and the nonce-bound target user's journal.
Only after the controller, independent verifier, cgroups, dedicated container
inventory, and disk-backed runtime have been cleaned does it synchronize both
journals, prove each sealed cursor still names its exact anchor record, and
retain exact `--after-cursor` JSONL queries. Any direct coredump
message or lifecycle activation of `systemd-coredump`, the DrKonqi processor,
launcher, or launcher socket rejects the campaign even if the transient unit
has already returned to inactive and every endpoint snapshot looks unchanged.
Malformed, expired, wrong-boot, oversized, or unqueryable cursor evidence also
fails closed.

## Terminal notification

The staged service fixes `CODESKEPTIC_TERMINAL_NOTIFY=0`, and the guided
entrypoint rejects every systemd drop-in so the effective service authority
cannot be changed outside the staged unit. The guided entrypoint itself emits
a triple terminal bell when it returns. Notification delivery is never an
acceptance condition.
