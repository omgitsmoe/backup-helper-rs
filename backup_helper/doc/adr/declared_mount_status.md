# Declare disk mount status in the configuration

## Context

The scheduler refuses to run ready tasks whose disks report as not mounted,
failing with `ready tasks cannot run because their disks are unavailable`.

Disk availability used to be detected from the operating system: on Unix a
disk was considered mounted when `dev(path) != dev(parent)`, and on Windows by
comparing volume paths. Both approaches only recognize the configured path as
a mount *point*.

Real deployments mount disks inside a single share or bind-mount them into a
shared folder. For example a NAS shares one SMB/CIFS tree (`/mnt/smb_mini`),
the physical disks appear as subdirectories (`/mnt/smb_mini/p3`), and every
subdirectory shares the parent mount's device ID. The device comparison then
reports the disk as unmounted even though the share is mounted and reachable.

Device and volume heuristics are also platform-specific, special-case network
filesystems (`cifs`, `smb3`, `nfs`, ``fuse.sshfs``...), and are hard to test
deterministically without privileged mounts.

## Decision

Disk mount status is declared in the configuration. Each `disk` node requires a
boolean `mounted` property:

```kdl
disk "p3" {
    path "/mnt/smb_mini/p3"
    mounted #true
}
```

`Disk::is_mounted()` ignores operating-system mount information entirely and
returns `self.mounted && path exists as a directory`. The `mounted` flag is
persisted in the reconciled state alongside `path` and is reconciled from the
configuration like `path`.

This is fully cross-platform and removes the Unix device and Windows volume
detection code (and the `windows-sys` dependency).

## Alternatives considered

### Extend the device heuristic to network filesystems

Detect `statfs` `f_type` values (`SMB2_MAGIC`, `CIFS_MAGIC`, `NFS`, `FUSE`...)
or parse `/proc/self/mountinfo`. This fixes the CIFS-subdirectory case but
remains platform-specific, needs magic-number maintenance, and cannot
distinguish "a folder inside a mounted share" from other same-device
directories without a denylist of filesystem types.

### Compare against the root device

Treat any path on a device different from the root filesystem as mounted.
This misclassifies operating-system mounts (`tmpfs`, separate `/home` or data
partitions) as backup disks and makes the unit tests depend on the host's
mount layout.

### Per-disk mount-check option value

An enum such as `mount_check "device" | "exists"` keeps the heuristic for
some disks. It adds configuration surface while still shipping the fragile
device-detection code.

## Consequences

- The schedulers mount gate is declarative and works identically on every
  platform.
- A `mounted #true` disk is considered available when its path resolves; when
  the underlying share or disk is gone, the path stops existing or resolving
  and tasks are held until it returns.
- Existing state files without the `mounted` key keep loading (defaults to
  `false` until reconciled from the configuration).
- Disk availability no longer adapts automatically to a disk that is mounted
  but not declared; the configuration is the source of truth.
- Test configs must declare `mounted` for every disk.