# Steward managed Windows terminals

`TerminalSessionService` is the Node-side boundary for schema `1.0` terminal
leases. It validates host/incarnation/actor/revocation/time bindings, canonical
workspace containment, and reparse points before recording durable intent. It
does **not** wire Control transport, Node composition, CLI, or MCP.

The runtime uses Windows ConPTY with anonymous pipes whose parent ends are
non-inheritable. `CreateProcessW` receives an argument vector encoded with the
Windows quoting rules and an otherwise empty inherited-handle set. The process
is created suspended, assigned to a kill-on-close Job, identity-journaled, and
then resumed. Close first writes `exit`, then terminates the complete Job tree.

The configured service account is the execution identity. Elevated leases are
accepted only when `AllowElevatedServiceIdentity` is explicitly enabled **and**
the service token is actually elevated. UAC is never invoked. Injected-token
launch is not implemented and must be deployment evidence/wiring added later.

## Retention and mutation policy

Transcript `None` writes no transcript rows. `Metadata` writes bounded
sequence/offset/length/hash rows without content. `Full` additionally retains
content up to its explicit byte bound; it performs no guessed redaction.
Authority and request records contain no argument values (only fingerprints).

Operational replay is stored in a separate SQLite spool with an authority-bound
TTL and byte quota. It is not audit retention. Zero TTL/quota means historical
content is deliberately unavailable and replay reports a cursor gap. Output
notifications are per-reader, bounded, drop-oldest wakeups; they never carry the
authoritative bytes and never backpressure ConPTY. Readers replay from SQLite by
sequence/offset before following notifications, so reconnecting and concurrent
readers do not steal data from one another.

Any non-empty input to a terminal attached to a managed task is conservatively
recorded as `terminal-input-conservative-policy`, even if the command appears
read-only. Readiness and reconciliation should treat the workspace/process
observation as suspect.

## Limits and known gaps

Contracts cap leases at eight hours, input at 64 MiB, output/transcripts at
256 MiB, dimensions at 1000×1000, and arguments at 128. Runtime message,
channel, concurrent-session, transcript-row, and journal-row limits are also
finite and configurable. File transfer is deliberately denied even when its
future capability flag is present. ConPTY handles cannot survive a service
restart; durable sessions become `Interrupted` or `Recovering`, never silently
absent or automatically duplicated.

Input, resize, and close use durable `Accepted`/`Applied`/
`SideEffectUncertain` request records. An accepted operation without a durable
outcome is never resent automatically. Active revocation is delivered durably
over the terminal transport and polled at the configured Node monitor interval;
it terminates the Job tree with `authority-revoked`. The small polling interval
is the explicit maximum revocation latency after delivery.
