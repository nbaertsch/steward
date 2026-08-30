# Steward Handle Keeper service

Install `Steward.HandleKeeper.exe` as an auto-start Windows service under a
dedicated, non-interactive virtual service account. Deny that account network
logon and do not grant it provider, cloud, repository, or identity-broker
credentials. Configure `STEWARD_NODE_ACCOUNT` to the Node service SID/account
and optionally `STEWARD_KEEPER_PIPE`.

Configure SCM recovery to restart the service after failures and configure the
Node service to depend on it. The service intentionally retains kernel Job
handles only; it does not persist handles, and therefore cannot preserve work
through keeper termination or Host reboot. The named pipe is single-instance,
has an explicit DACL, authenticates the connected process identity, and is
local-only.

The IPC protocol is versioned and length-bounded. Requests use a stable
request ID across transport retries; the keeper caches responses by request
ID, authenticated client PID and creation time, command, and payload hash.
Each response uses a confirmed acknowledgement handshake; the Node does not
accept success until the keeper confirms that it recorded the acknowledgement.
Until that confirmation, only the keeper may close an `Open` target handle.
The Node never closes a provisional numeric handle directly; if retries are
exhausted it sends an idempotent, caller-bound `abandon` request so the keeper
can revoke the handle exactly once without racing Windows handle-value reuse.
Health reports the cumulative provisional-handle revocation count so this
single-close authority is diagnosable and testable without assuming a
particular Windows handle-allocation order.
Acknowledged entries expire after the configured TTL. An unacknowledged
`Open` is revoked in the client process on expiry so a lost response does not
leak a Job handle. Retained leases and cached requests have independent hard
limits (`--max-leases`, `--cache-capacity`, and
`--cache-ttl-seconds`).

Example installation outline (replace both accounts and paths):

```powershell
sc.exe create StewardHandleKeeper start= auto obj= "NT SERVICE\StewardHandleKeeper" `
  binPath= '"C:\Program Files\Steward\Steward.HandleKeeper.exe" --node-account "NT SERVICE\StewardNode"'
sc.exe failure StewardHandleKeeper reset= 86400 actions= restart/5000/restart/15000/restart/60000
sc.exe config StewardNode depend= StewardHandleKeeper
```

Grant the service identity only `Log on as a service`, deny network logon, and
do not place secrets in its environment or command line. Installer work must
create and ACL the two service identities before starting either service.
