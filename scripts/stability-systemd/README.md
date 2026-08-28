# P10-09 system control-plane contract

This bundle provides a one-command launch from the active graphical session,
then keeps the authoritative campaign outside graphical and interactive user
sessions. It is only a transport and lifecycle boundary: a zero service exit
does not prove any P10-09 gate. Acceptance belongs to the sealed campaign
receipt and its independent verifier.

## Scope contract

One accepted campaign contains exactly one cold round and one warm round. Each
round analyzes the three fixed projects three times, so the acceptance matrix
contains exactly 18 real-world analysis shards. The controller also enforces
the retained determinism, sanitizer, resource, descendant, restart,
checkpoint, fault-injection, performance, and semantic gates. Elapsed time is
metadata, not an acceptance threshold. The seven-day systemd ceiling is only
an outer runaway guard and cannot create an accepted receipt.
The cold round's first action is the exact final-HEAD 10-of-10 qualification.
No fault injection or real-world shard may start unless that action publishes
an accepted receipt. The warm round retains the matching post qualification,
so the final receipt binds both ends of the measured scope.
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
- `/var/lib/codeskeptic-p10-09/status/post-stop-status.txt` is the atomic,
  root-only outcome of whole-host recovery and the guarded graphical restoration
  decision. The permanent unit and operator remain installed after every run.

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

`scripts/stage_stability_campaign.py` exposes exactly `prepare`, `configure`,
`seal`, `verify`, `install`, `verify-install`, and
`verify-install-filesystem`. `prepare` clones a clean,
detached, standalone exact-head source and creates only the fixed authority
layout; the `config` root remains absent until publication. It
deliberately leaves `authority/mirrors` absent so the real-world mirror sealer
can publish that authority create-new rather than reuse a producer placeholder.
After all prerequisite producers populate the mutable layout, `configure`
derives every source, receipt, analyzer, mirror, policy, and fault-binary hash
from the fixed authority paths. It also replays the promoted determinism
baseline authority from its retained calibration evidence and binds the
manifest, baseline, and canonical projection hashes before atomically
publishing the config pair. There is deliberately no external pre-accepted
determinism receipt: requiring one before the final bundle exists would be a
circular authority. The campaign's cold-first 10-of-10 action is the first
live acceptance gate. `seal` binds every root-executed operator byte to its exact-head source
counterpart, validates the data-only config schema without importing staged
Python on the host, normalizes modes, and publishes a checksummed bundle with
an atomic no-replace rename. `verify` rederives the complete inventory and
executes the retained image and static-authority checks in bounded, networkless
containers.

### Authority population order

`prepare` is not an end-to-end authority producer. Before `configure`, the
mutable staging layout must be populated create-new at the exact revision. The
analyzer build authority precedes the quality-floor authority; the sealed
real-world mirror precedes the release-candidate authority; the sanitizer
authority producer also supplies the provenance-bound fault binary. Hosted
exact-head authority is captured only after that same revision is published
and all required hosted gates pass. The two public provisioner operations are
therefore explicit rather than hidden inside `configure`.

The release-candidate lane runs in this order (the online mirror form is shown;
an explicitly supplied offline source set is also supported):

```text
python3 scripts/seal_realworld_mirror.py --manifest STAGING/authority/source/scripts/realworld_manifest.json \
  --tier release-candidate --output STAGING/authority/mirrors --fetch-online
python3 scripts/provision_stability_authorities.py populate-release \
  --staging STAGING --revision EXPECTED_40_HEX
```

The sanitizer lane may run independently after `prepare`, but it must finish
before `configure` and must use the same exact revision:

```text
python3 scripts/provision_stability_authorities.py populate-sanitizers \
  --staging STAGING --revision EXPECTED_40_HEX
```

Both provisioner operations serialize mutation with the staging lifecycle
lock. Do not run either operation concurrently with another staging writer or
reuse a partially populated output. `configure` may run only after build,
quality-floor, mirror, release-candidate, sanitizer/fault-binary, determinism,
and hosted exact-head authorities are all present and independently
verifiable.

`install` first copies the user-supplied bundle through no-follow directory
descriptors into a private snapshot. It performs the full archive/runtime
verification there before touching fixed host paths. A fresh installation is
create-new; late failure removes only objects whose device/inode identities
still match that invocation. The installation receipt is written last as the
commit marker. `verify`, `install`, and `verify-install` all require the
operator's out-of-band expected Git revision and bundle-receipt SHA-256; bundle
metadata cannot nominate its own trust root. `install` records that pair in the
create-new, root-owned, mode-`0400`
`/var/lib/codeskeptic-p10-09/installation-authority.json` record before it
publishes the installation receipt as the final commit marker. The guided
entrypoint obtains the pair from that separate persistent record, and both the
receipt and the fully rederived installed bytes must agree with it before any
staged verifier executes. This protects against accidental or partial
installation drift within the root-controlled trust domain; it is not a trust
boundary against a malicious root administrator. Both install and
verify-install create, use, and remove the exact service pathname
`/run/codeskeptic-p10-09/podman-runroot`. Recreating that same pathname after a
cold boot reopens the persistent dedicated store without changing Podman's
storage identity.

`verify-install-filesystem` is the mutation-free recovery subset. It rederives
the receipt and sidecar, retained bundle metadata and manifests, mapped payload
inventory and ownership, exact-head source/operator/config/unit bytes, and the
retained image archive without listing, starting, or removing a Podman object
and without creating the runroot. Whole-host recovery runs this subset before
it trusts a recovery marker or container identity. The explicit staging/admin
`verify-install` action retains the full image-store execution checks, but the
guided launch does not call it: mutating Podman before durable recovery
authority would create an unowned crash window. During a guided launch, the
service instead checks the pinned image and empty dedicated container store
after publishing the host-recovery marker, then arms the cgroup marker and runs
the in-image source, policy, static-authority identity, PyYAML, namespace,
affinity, limit, and measurement-cgroup checks in its rootful preflight
container.

The `seal`, `verify`, and `install` command-line actions require an explicit
large temporary root rather than trusting ambient `TMPDIR`, which `sudo`
commonly discards. The absolute root must already be empty, mode `0700`, owned
by the invoking uid/gid, outside the staged or sealed input, and large enough
for the bundle snapshot, expanded VFS image store, four-GiB cleanup reserve,
and snapshot inode reserve. The producer creates one random, identity-bound
child and removes it on both success and failure; the selected root is empty
again after a successful cleanup. A root-owned operation must use a separately
root-owned temporary root. Direct Python callers may omit the override, in
which case the bundle/output parent is the fixed fallback; ambient `TMPDIR` is
never consulted.

For example, after obtaining both values through the separately retained
exact-head authority record, the public lifecycle is invoked as follows (the
values shown are placeholders, not bundle-derived defaults):

```text
python3 scripts/stage_stability_campaign.py configure --staging STAGING \
  --revision EXPECTED_40_HEX --repository OWNER/REPOSITORY
python3 scripts/stage_stability_campaign.py seal --staging STAGING \
  --revision EXPECTED_40_HEX --output SEALED \
  --temporary-root /absolute/empty/user-owned-disk-root
python3 scripts/stage_stability_campaign.py verify --bundle SEALED \
  --expected-revision EXPECTED_40_HEX \
  --expected-bundle-receipt-sha256 EXPECTED_64_HEX \
  --temporary-root /absolute/empty/user-owned-disk-root
sudo python3 scripts/stage_stability_campaign.py install --bundle SEALED \
  --expected-revision EXPECTED_40_HEX \
  --expected-bundle-receipt-sha256 EXPECTED_64_HEX \
  --temporary-root /absolute/empty/root-owned-disk-root
```

## One-command guided start

The checksummed exact-head staging step installs the authority, canonical config pair,
dedicated image store, operator bundle, and an exact copy of the service unit;
it must never synthesize authority from a dirty working tree. After that step,
one command starts and follows the operator:

```text
/opt/codeskeptic-p10-09/operator/guided-stability.sh
```

The guided entrypoint rings a triple bell when the one `sudo` authorization may
be needed. Its root re-exec first parses the separate installation authority
and runs only `verify-install-filesystem`. That mutation-free check completes
before it acquires the fixed global guided-lifecycle lock. The helper opens the
root-owned lock inode with `O_NOFOLLOW`, takes a nonblocking exclusive lock, and
re-execs guided with the still-locked descriptor; a concurrent guided launch
cannot publish, consume, or clean another invocation's request. While holding
that lock, guided verifies the canonical config checksum and exact loaded unit,
runs idempotent startup recovery, and only then requires active
`graphical.target` and an active/running display manager before publishing a
request and starting the service. It requires `UnitFileState=static`: the unit
has no install target, must never be enabled, and can only be started by this
explicit guided invocation. A prior failed unit state is reset automatically.
The unit's `ExecStartPre` repeats startup recovery as the final service-side
gate.

The installed guided command, optionally with `--probe-only`, is the sole
supported public launch entrypoint. The staging commands remain the separate
provisioning interface; direct or concurrent invocation of lifecycle helpers
such as `host-recovery.py`, `cgroup-authority.py`, `post-stop.sh`, or the runner
is an internal implementation path and has no public concurrency contract.

The guided process creates one nonce-bound request, calls
`systemctl start --no-block codeskeptic-stability.service`, and waits for at
most 60 seconds for `/run/codeskeptic-p10-09/guided-handoff.json`. The runner
publishes that create-new, canonical, root-owned mode-0400 acknowledgment only
after it has atomically consumed and validated the exact request and bound the
session name. The root guided process validates the file type, owner, group,
mode, bounded canonical bytes, mode, nonce, and session identity before
releasing its request cleanup ownership. This closes the race in which loss of
the graphical terminal could otherwise remove an unconsumed request.

That handoff is only phase one. Guided next publishes one create-new,
canonical, root-owned mode-0400 decision bound to the exact mode, nonce, and
session. The runner atomically consumes an `accept` decision before any
graphical isolation; `cancel`, a missing decision, or the 60-second decision
deadline rejects the run. If guided times out before a handoff, absence of the
second acknowledgment is itself fail-closed, so a delayed runner can never
isolate the desktop. If it fails after learning the session, it publishes the
same exact decision as `cancel`.

For a campaign, the runner first publishes a canonical, root-owned,
session-and-nonce-bound `restore-required` state under
`/var/lib/codeskeptic-p10-09`, synchronizes both the file and parent directory,
and only then requests the nonblocking transition to `multi-user.target`;
`IgnoreOnIsolate=yes` keeps the service alive. This
requires no manual isolate, no TTY, and no exit-code capture. When the
service stops, the immutable post-stop program first runs nonce/session-bound
cgroup recovery. Without the exact durable restoration state it never starts
a GUI. Only if shutdown, rescue, and emergency targets are each
exactly inactive with no queued job may it request graphical restoration. A
successful `start --no-block` is only an enqueue result, never restoration
success. Post-stop polls for at most 60 seconds and clears the durable state
only after exact proof that `graphical.target` is loaded/active/active with no
job and `display-manager.service` is loaded/active/running with no job. A kill,
timeout, reboot, asynchronous start failure, real transition, or unverified
state leaves the durable record for the next ExecStopPost or startup-recovery
attempt. Guided and the unit's `ExecStartPre` both run that idempotent startup
recovery before a new campaign. The permanent service unit and operator are
never removed.
The lifecycle never reboots or powers off the host.
If staging or handoff is missing, guided fails with one actionable
`CODESKEPTIC_GUIDED_STAGING_UNAVAILABLE` message.

Every full campaign start also creates one exclusive root-owned request that
binds a fresh nonce to the invoking non-root user and UID. The static service
refuses a full run without that exact guided request, consumes it atomically,
uses the user identity for the host DrKonqi guard, and removes only the
nonce-bound request in its terminal cleanup. A direct `systemctl start`, an
ambient/stale request, or simultaneous probe and campaign requests fail closed.

Before committing to the full campaign, the same entrypoint can perform
only the short rootful launch and cgroup validation:

```text
/opt/codeskeptic-p10-09/operator/guided-stability.sh --probe-only
```

This mode creates one root-private, exclusive probe request in `/run`, which
the operator atomically consumes and binds to both the handoff and terminal
status as `mode=probe-only`. It uses the same unit, pinned image, Podman options, cgroup
topology, limits, hooks directory, and eight bind destinations, but substitutes
fresh ephemeral `/run` directories for the launch, evidence, and runtime
mounts. It exits immediately after the probe and full cleanup: it creates no
campaign evidence, no campaign launch receipt, never starts the campaign
controller, and does not isolate the active graphical target. Normal mode refuses a stale probe request, and cleanup removes a
request only when its exact schema, root ownership, mode, and nonce still match
the invocation that created or consumed it. Probe success proves only that the
host launch topology works; it is not campaign acceptance.

## Container boundary

The rootful container is launched with `network=none`, cgroup creation disabled,
the host cgroup namespace selected by the immutable `containers.conf`, private
IPC, PID, and UTS namespaces, a read-only
root filesystem, user `0:0`, and exact soft/hard `nofile` limits of 4096. The unit also fixes
`LimitNOFILE=4096`; its inhibited command explicitly enters through
`prlimit --nofile=4096:4096` as well, so an inhibitor-manager limit cannot
silently narrow the operator, probe, controller, or descendant ceiling. The
`--cgroups=disabled` contract keeps every container process in the caller's
systemd-managed controller cgroup and prevents crun from propagating controllers
or creating `libpod-*` descendants. The host namespace is a pinned Podman
configuration default, not the incompatible `--cgroupns` CLI option; inspection
must still report `CgroupMode=host`. Every real container entry independently
requires the exact controller path. All dedicated Podman commands start from an
empty host environment and receive only the pinned config and runtime variables,
so an ambient `CONTAINERS_CONF_OVERRIDE` cannot replace this namespace policy.
The probe pins its own affinity, while the
controller and verifier enter through `taskset --cpu-list 4-11`. Recovery
requires empty `HostConfig.CgroupParent` and `HostConfig.CpusetCpus` claims and
the exact disabled cgroup mode. Before and after every Podman lifecycle edge,
the operator requires the qualified Fedora host's exact nine-controller root
availability, exact five-controller root delegation and `system.slice`
availability, and exact four-controller `system.slice`, service, and payload
delegation. A kernel or
controller-set change therefore requires explicit
requalification instead of becoming a live baseline. Measurement work alone
moves into the fixed
`/system.slice/codeskeptic-stability.service/codeskeptic-p10-09/measurement`
cgroup and remains constrained to the isolated 0-3 partition.
The sorted inventories are `cpu cpuset dmem hugetlb io memory misc pids rdma`
at root availability, `cpu cpuset io memory pids` at the root subtree and
`system.slice` availability boundary, and `cpu cpuset memory pids` at the
`system.slice` subtree and below the service boundary.
Before activation, an absent-service boundary is separately exact. A fresh
idle boundary has `cpu io memory pids` at the root subtree and `system.slice`
availability, `memory pids` at the `system.slice` subtree, and no
`system.slice` cpuset interfaces. An exact pre-enabled boundary may retain the
five/four-controller mapping and restored cpuset interfaces after a prior
activation or sibling realization. Only those two complete correlated
profiles are accepted after two identical reads; a mixed or changing
transition is rejected. Merely loading the
unit or running `daemon-reload` does not itself widen the fresh idle boundary.
Pulling, host environment inheritance, proxy inheritance, image
volumes, writable implicit read-only tmpfs mounts, and ambient OCI hooks are
disabled. Podman inspection must expose exactly eight environment claims:
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
`container=podman`, `HOME=/runtime/home`, `TMPDIR=/runtime/tmp`,
`XDG_CACHE_HOME=/runtime/xdg-cache`, `LANG=C`, `LC_ALL=C`, and `TZ=UTC`.
The label inventory is also exact: the pinned image's
`io.buildah.version=1.43.0` and `org.opencontainers.image.version=24.04`, plus
the four marker-derived CodeSkeptic owner, session, bundle-revision, and
container-kind labels. Any additional or missing environment claim or label is
foreign state. Its fixed base bind topology is:

- `/authority` read-only;
- `/operator` read-only;
- `/config/runtime.json` read-only;
- `/config/runtime.json.sha256` read-only;
- `/launch` read-only;
- `/evidence` and `/runtime` read-write for the preflight and campaign roles,
  but read-only for the verifier; and
- `/sys/fs/cgroup` read-only.

The preflight and campaign roles add one narrowly writable nested bind for the
exact
`/sys/fs/cgroup/system.slice/codeskeptic-stability.service/codeskeptic-p10-09/measurement/cgroup.procs`
pseudofile. The verifier does not receive that bind. The verifier therefore has
exactly eight semantic bind mounts, while the two mutable roles have exactly
nine. After those parent binds, every role overlays exactly the address and
undefined sanitizer `Testing/Temporary` directories with separate 16 MiB
`rw,nosuid,nodev,mode=1777` tmpfs mounts so CTest discovery can write its
documented scratch log without making any retained authority file writable.
The launch receipt records these mounts in order, and host recovery requires
Podman 5.8.4's exact `HostConfig.Tmpfs` projection, including `rprivate` and
`tmpcopyup`; no role can mutate any other authority or cgroup control file from
inside the container.

The exact in-container command is:

```text
/usr/bin/taskset --cpu-list 4-11 /usr/bin/python3 -B /operator/container-entry.py run
```

The container is not auto-removed. Podman must create a fresh CID file; the
operator binds it to the durable session marker and host recovery rederives the
effective command, process argv, the role's exact eight-or-nine semantic bind
mounts, the exact two bounded CTest tmpfs mounts, exact environment and labels,
image digest/name/ID, CID path, IPC/PID/UTS and
cgroup/network topology, rootfs mode, security options, user, workdir, runtime,
and resource limit from Podman inspection. Every Podman removal is centralized
in host recovery; the runner has no direct `podman rm`, name-only fallback, or
alternate cleanup authority. After validating the full installation, host,
cgroup, container, and CID chain, recovery durably unlinks the owned CID first
and only then force-removes the exact 64-hex Podman ID. An interruption can
therefore rediscover a surviving container from its exact dedicated-store
projection, while a complete CID can never outlive the container it names.
Normal successful preflight, controller, and verifier cleanup requires an
actual removed ID and rejects an `absent` result; only idempotent failure/EXIT
recovery may accept that the already-validated container is absent. Malformed
or partial cleanup identity, an additional environment claim or label, or any
execution-contract drift leaves the durable marker in place and changes the
terminal result to failure.

Before cgroup mutation or container removal, recovery supplies the exact live
Podman IDs to the cgroup authority. Podman cgroup creation is disabled, so the
cgroup helper permits only the fixed `measurement` child and rejects every
unexpected runtime child. The helper never terminates processes and never
writes `cgroup.kill`; Podman alone owns exact-ID process termination and
removal. After that removal, the helper requires `frozen 0`, `populated 0`, and
an empty `cgroup.procs` at every owned boundary. A populated, foreign, or orphan
subtree fails closed instead of being killed. Only after those gates pass does
the helper restore the ancestor CPU partition state, remove the exact empty
measurement and payload cgroups, and remove its marker last. Its recovery path
is cutpoint-aware and idempotent:
it can complete active, partially restored, or already-clean states, including
a strict unpublished-marker prefix only when the machine is otherwise proven
clean.
The cleanup-v5 record binds the ambient-environment reset, every dedicated
Podman environment claim, the immutable containers configuration, and the
pinned client version. After the host-recovery marker is removed, the operator
never invokes Podman directly. Live seal-time revalidation calls the installed
host-recovery helper instead; that helper publishes a separate durable Podman
inspection marker before reading the store, verifies version, image, and empty
inventory, clears runroot, and removes the inspection marker last.

After the controller exits successfully, the operator starts a second fresh
container from the same pinned image with the exact `verify` command. The
campaign evidence and runtime are read-only in that verifier. Its CID, name,
image ID, command, exact one-line success log, empty stderr, and removal are
bound into the outer cleanup and operator receipts. A controller success is
therefore not allowed to stand in for independent semantic verification.
Both real roles enter through the immutable `/operator/container-entry.py`.
That entrypoint independently requires PID 1, root identity, the exact systemd
controller cgroup, affinity 4-11, and the fixed open-file limit before it execs
the role-specific campaign command.

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

The service can be authorized from the normal active graphical boot. It is
ordered before and conflicts with shutdown, rescue, and emergency targets, and
survives the runner's deliberate isolate through `IgnoreOnIsolate=yes`. It has
null standard input and cannot request a password or Enter key. It is
deliberately static and has no `[Install]` section, so reaching
`multi-user.target` can never start the campaign by itself.
The unit delegates only `cpu`, `cpuset`, `memory`, and `pids`, places its main
operator in `DelegateSubgroup=controller`, exposes `AllowedCPUs=0-11`, and
confines the operator/controller task affinity to logical CPUs 4-11. The
bounded controller list prevents systemd from propagating unrelated `hugetlb`
and `misc` controllers into ancestor cgroups. The payload parent and
its isolated measurement child are siblings of that systemd controller leaf,
all below the same service unit. The runtime config must identify the exact
measurement path
`/sys/fs/cgroup/system.slice/codeskeptic-stability.service/codeskeptic-p10-09/measurement`,
whose effective and exclusive CPU sets are both 0-3. The controller payload
inherits effective CPUs 4-11 after the isolated partition is established.

During activation, systemd widens the idle ancestor boundary to the exact
five/four-controller mapping above, creates the service cgroup, and clears the
service's subtree controllers. Its
`ExecStartPre` recovery process therefore runs alone in a core-files-only
`.control` subgroup while the service subtree inventory is empty. After that
process exits, its empty core-only `.control` subgroup remains and `ExecStart`
begins in a new core-files-only `controller` sibling. The runner requires both
exact subgroups, including an empty `.control`, and only then enables the four
delegated service controllers. If main startup fails before that write,
`ExecStopPost` runs from `.control` and must instead prove the core-only
`controller` sibling empty. The same caller/sibling emptiness correlation is
required after delegation: main recovery requires empty `.control`, while
stop recovery requires empty `controller`. From that point onward,
`controller`, `.control` when present during stop/recovery, the payload, and
the measurement leaf expose only the phase-appropriate delegated interfaces.
The `.control` subgroup persists until systemd prunes the inactive unit.

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
and memory failures. A nonblocking lock excludes concurrent campaigns. The
unit wraps the exact-`nofile` runner in `systemd-inhibit --what=sleep`; shutdown is not
hidden by an inhibitor and instead stops the conflicting service so post-stop
can recover cgroups while refusing to restart graphics during the transition.

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
cannot be changed outside the staged unit. Guided emits a triple terminal bell
when its bounded handoff wait returns; post-stop also attempts the console bell
after persisting its exact outcome. Notification delivery is never an
acceptance condition, and no exit-code capture is required from the user.
