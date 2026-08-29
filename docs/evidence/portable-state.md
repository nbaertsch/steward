# Content-addressed filesystem evidence

## Status

**Open.** The approved Local Stack portable-object implementation is a
content-addressed filesystem with explicit peer replication and completeness
receipts. Deterministic object protocol tests can establish atomicity and
integrity; clean-machine replication, disk-fault, migration, and long-duration
spool tests remain before E-07 closes.

## Object protocol

1. The producer writes immutable content to a private temporary file in the
   configured root.
2. It enforces quotas and rejects traversal, reparse-point escape, and
   unbounded metadata.
3. It flushes bytes and metadata to stable storage.
4. It computes and verifies the whole-object content hash and length.
5. It atomically publishes the file under a deterministic hash-derived path.
6. Replication compares manifests and copies only missing objects to configured
   peer roots.
7. The receiver writes privately, flushes, verifies hash/length, and atomically
   publishes.
8. Only after verification does it durably issue a completeness receipt tied
   to object, destination root identity, and producer lineage.

An existing object with the same hash and length is reused only after
verification. Partial files, manifests, and temporary names are never visible
as complete objects. A manifest is complete only when every referenced object
has a valid required receipt.

## Replication and failure domains

Each deployment names local and peer roots plus their declared failure domains.
A mounted filesystem is allowed only as a user-managed filesystem path; Core
does not infer independence or durability from it.

Replication is asynchronous. The Node writes logs/checkpoints to its bounded
local spool first, and a disconnected peer never blocks child output
indefinitely. Planned Host replacement, deletion, or Agent migration waits for
the configured receipt policy. Forced action records exact unreplicated loss.

The adapter has no remote object-service endpoint or storage credential.

## StewardAgent migration

Agent checkpoints include compacted context, lineage, git bundle, dirty patch,
environment manifest, and pending turns. They exclude credentials, process
state, host caches, installed tools, and unbounded artifacts.

Migration commits:

1. source object/manifest receipts;
2. destination restore and readiness receipt;
3. Agent placement-generation update; and
4. source workspace release.

Only one placement generation accepts new turns.

## Executable matrix

1. Crash after every write, flush, rename, manifest, copy, and receipt step.
2. Corrupt, truncate, reorder, substitute, duplicate, and delete objects.
3. Attempt absolute paths, traversal, symlink/junction/reparse escapes, reserved
   names, oversized metadata, and path-length exhaustion.
4. Race two writers of the same and different content.
5. Disconnect and reconnect each peer during sustained output.
6. Fill the spool while preserving configured OS disk reserve.
7. Change ACLs and prove cross-Task and unprivileged-user denial.
8. Race two Agent migration destinations.
9. Stop/replace/delete with complete and incomplete receipts.
10. Backup and restore SQLite plus its referenced object manifest.

## Deployment evidence

Record root configuration, volume identity, ACLs, quotas, declared failure
domains, object counts/hashes, interrupted replication logs, and recovery
times. Egress and dependency inspection must show no cloud object-storage
service, credential, or client in the active Local Stack path.

## Contract consequence

Core retains only neutral `PortableObject`, stream, hash, and completeness
receipt contracts. Paths and replication peers are Local Stack extension data.
Lifecycle safety depends on declared receipt policy, never a hard-coded storage
product.

## Sources

- [File.Replace method](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace)
- [FileStream.Flush method](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.flush)
- [Windows file security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
- [Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points)
