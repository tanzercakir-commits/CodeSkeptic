# CodeSkeptic P10-09 fixed launch boundary

This small subsystem removes recurring interactive `sudo` from P10-09 campaign
and probe launches without making the campaign rootless. The existing guided
entrypoint, cgroup, Podman, graphical-restoration, receipt, and lifecycle-lock
contracts remain authoritative.

An administrator installs this boundary once, after the existing core
installation passes its exact filesystem verifier. The installation binds one
numeric non-root UID and its primary group, the exact core authority and guided
script, the broker/client bytes, four systemd units, two unit-specific timeout
drop-ins, and two activation links into a root-owned checksummed receipt.

From the reviewed source checkout, the one administrative installation is:

```text
sudo /usr/bin/python3 -I -B scripts/stability-launch/install-launch-broker.py install
```

After installation, the bound operator runs:

```text
/opt/codeskeptic-p10-09-launch/launch-client.py
```

For a probe-only launch:

```text
/opt/codeskeptic-p10-09-launch/launch-client.py --probe-only
```

The client selects one of two fixed `SOCK_STREAM` paths, sends no payload,
and write-half-closes the connection. Both peers require the kernel's explicit
`POLLRDHUP` indication, so an open connection carrying a zero-length record
cannot impersonate a half-close or a completed response.
The root broker authorizes `SO_PEERCRED`, rederives the installation receipt,
verifies its actual systemd socket and per-connection service authority, and
invokes only the exact installed guided path with a fixed mode and scrubbed
environment. Caller-provided commands, paths, revisions, images, UIDs,
environment variables, timeouts, and file descriptors are rejected.

The provided installer is deliberately create-new and verify-only. It will not
overwrite, update, revoke, or recover foreign root-owned state. Those rarer
maintenance operations require a separately reviewed transactional procedure
and real administrator authorization. Routine campaign and probe launches do
not require `sudo`, a password prompt, or a TTY.

The create command is exception-transactional: every handled command failure
either rolls back the exact inode it created and durably syncs the removal, or
reports that cleanup is incomplete without deleting replacement/foreign state.
It does not claim atomic recovery across `SIGKILL`, kernel failure, or power
loss while the one-time installation spans `/opt`, `/etc`, and `/run`. If such
an abrupt interruption leaves partial root-owned state, a subsequent install
fails closed and requires a separate reviewed administrator recovery. This is
a one-time deployment gate, not a recurring launch requirement.
