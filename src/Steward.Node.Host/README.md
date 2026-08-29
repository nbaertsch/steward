# Steward Node production host

`Steward.Node.Host` is the Windows service entry point. It uses the durable
Node, execution, and evaluation SQLite journals, `WindowsProcessExecutor`,
`NamedPipeJobHandleKeeper`, bounded disk spooling, the Local Stack
content-addressed object store, and authenticated direct peer transport.

Copy `appsettings.example.json` to the service configuration directory and
replace every placeholder identifier, direct endpoint, and key path. The
endpoint must already be reachable through the user's approved network path;
Steward does not provision networking or an intermediary. Protect private keys
and Local Stack data roots with the Node service identity.

Identity-backed work is rejected unless the direct Control session and
OS-protected Local Stack credential delivery are available. Portable objects
commit locally and replicate directly to the peer content-addressed store.
No hosted broker, cloud object store, SAS, or relay token is supported.

Install and start `Steward.HandleKeeper` before this host. Configure the
Windows Service Control Manager so Node depends on HandleKeeper. Run both
services under dedicated least-privilege identities and grant their data
directories only to those identities and administrators.
