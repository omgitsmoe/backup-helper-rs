# Inject mount status checks into the scheduler

## Context

The scheduler only starts tasks when every involved disk is mounted. On Unix
this is detected by comparing device IDs, and on Windows by comparing volume
paths. A temporary directory created by a normal test is not a mounted disk,
so a complete filesystem test cannot use ordinary temporary directories with
the production mount check.

Mounting a filesystem during every test requires platform-specific setup and,
on many systems, elevated privileges. It is also unsuitable as a requirement
for the default CI test suite.

## Decision

Inject a `DiskMountChecker` into the scheduler. The default scheduler
constructor uses `SystemDiskMountChecker`, which delegates to
`Disk::is_mounted()`. Tests can provide a deterministic checker without
changing the filesystem behavior being tested.

The real `Disk::is_mounted()` implementation remains covered by focused
platform-specific tests. End-to-end workflow tests use ordinary temporary
directories and an explicitly injected checker that reports their fixture
disks as mounted.

## Alternatives considered

### Privileged mount tests

These would provide the most realistic Unix coverage, but require mount
capabilities, add cleanup and isolation concerns, and do not provide a
portable Windows solution. They may be added as optional platform-specific
tests later.

### Existing host mount points

Using paths such as `/dev/shm` is environment-dependent, does not reliably
provide multiple writable disks, and is not portable.

### Environment-variable or test-only bypasses

These would make production behavior depend on hidden process configuration
and could accidentally weaken real executions. They are rejected in favor of
an explicit constructor dependency.

## Consequences

- End-to-end scheduler tests are deterministic and unprivileged.
- Production continues to use the operating-system mount check by default.
- Mount-checking and workflow execution are tested independently.
- Scheduler construction has an additional dependency and constructor path.
- Verification mismatches remain successful verification tasks with error counts
  recorded in `VerifiedInfo`; callers can inspect persisted verification state
  without treating the scheduler run itself as a task failure.
