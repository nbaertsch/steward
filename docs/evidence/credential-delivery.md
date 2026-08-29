# Local credential protection and delivery evidence

## Status

**Open.** The selected Local Stack mechanism stores credentials under the
local operating-system user boundary and delivers short-lived, task-bound
material directly to a Node over its authenticated peer session. Vault,
expiry, cleanup, isolation, and disk-theft tests remain before E-03 closes.

There is no hosted credential or token service in this architecture.

## Credential model

Task and Agent definitions contain capability references, never values. An
IdentityGrant binds a vault reference to:

- exact audience and scope;
- Workload, Task/Agent, Host, and Node incarnation;
- issuance, credential expiry, and absolute grant expiry;
- maximum uses and delivery adapter; and
- `checkpointAndPause`, `fail`, or `continueWithoutCapability` when renewal is
  unavailable.

Control resolves the reference from Windows Credential Manager or a
DPAPI-protected local store. It transmits only the material required by the
bound runtime over the authenticated peer session. The Node places it in a
protected file/handle, environment indirection, or runtime-native secret mount,
then records cleanup and scrubs it.

## Offline limitation

The Local Stack cannot renew a credential when Control is offline unless the
credential's own supported mechanism is independently available to the Task.
Steward does not move refresh-token caches, copy device-bound credentials, or
silently substitute a service identity.

Before Delegation, scheduling proves one of:

1. the delegated credential lifetime covers the offline operation;
2. the Task can checkpoint and pause before expiry;
3. expiry is a declared Task failure; or
4. the Task can continue without the capability.

Nodes cannot mint a grant, broaden a scope, or ask a third party to do so.

## Workload-target adapters

Private GitHub, package feeds, model endpoints, Microsoft Foundry, and similar
services may be explicit Workload targets. Their credentials are ordinary
Task capabilities:

- use the narrowest supported scope and lifetime;
- isolate credential-helper and package caches to the Task;
- avoid command-line and repository configuration persistence;
- redact as defense in depth, not as the primary protection;
- stop or pause on revocation/expiry according to contract; and
- re-deliver from Control after migration instead of copying bytes.

Support for a target API does not make that API Steward infrastructure.

The separate Dev Box provider similarly uses the locally signed-in user's
OS-protected developer credential. That credential is provider-scoped and
cannot be exposed to Tasks or used for subscription/infrastructure operations.

## Executable matrix

1. Store, resolve, rotate, and delete representative vault entries.
2. Reject another OS user and an incorrectly bound Node/incarnation/Task.
3. Deliver by every enabled runtime mechanism without command-line exposure.
4. Search process metadata, logs, events, dumps, checkpoints, and portable
   objects for canary credentials.
5. Crash before and after delivery and cleanup.
6. Disconnect Control before expiry and prove each declared expiry behavior.
7. Revoke material during execution and reject identity substitution.
8. Migrate a Task/Agent and prove fresh delivery rather than copied bytes.
9. Inspect a removed/stolen Host disk for reusable plaintext material.
10. Exercise private source/package and one external workload target.

## Deployment evidence

The clean Local Stack must start and run ordinary work with no hosted broker
URL, client credential, remote vault, workload identity, or cloud token-cache
configuration. Process and egress inventory must show no credential service.
Configuration samples contain references only.

## Contract consequence

Local Stack renewal modes are `localControl` and `none`. Core can support
future credential adapters only through the same explicit interface and
evidence; no such adapter is implied by the current architecture.

## Sources

- [Windows Credential Locker](https://learn.microsoft.com/en-us/windows/apps/develop/security/credential-locker)
- [Windows Data Protection API](https://learn.microsoft.com/en-us/windows/win32/secauthn/data-protection)
- [Git Credential Manager](https://github.com/git-ecosystem/git-credential-manager)
