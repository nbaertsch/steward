# Security and threat model

## Objective

Steward executes private code, evaluations, tools, persistent Agents, and
terminal sessions on remote Hosts while local Control may be disconnected. It
must preserve identity scope, task boundaries, execution truth, replicated
state, and lifecycle safety.

Security controls live in neutral Core contracts and concrete adapter
boundaries. The Local Stack must satisfy them without a Steward cloud service.

## Trust boundaries

```text
User / parent Agent
        |
CLI, Copilot, MCP, loopback RPC     untrusted-output boundary
        |
local Control + SQLite + OS vault   local OS-user boundary
        |
authenticated direct peer session  network boundary
        |
enrolled Node + local journal       Host/incarnation boundary
        |
Task / Agent / terminal runtime     repository/content boundary
        |
filesystem replication roots       confidentiality/integrity boundary

Optional edges:
Control -> Dev Box user API/SDK      provider boundary
Task    -> external workload API     workload-target boundary
```

A peer network, Host, provider, filesystem root, repository, package,
container, evaluation input, Agent response, terminal output, and external API
is not trusted merely because communication succeeded.

## Assets and adversaries

Protected assets include Control intent, attempt fences, Node journals,
source, evaluation data/results, credentials, Agent conversations/worktrees,
logs, artifacts, checkpoints, provider lifecycle authority, terminal
capability, update packages, and replicated filesystem objects.

Threats include:

1. a stolen or compromised Host or disk;
2. a malicious repository, dependency, container, model output, or Agent
   response;
3. a stale or compromised Node incarnation;
4. peer impersonation, replay, downgrade, observation, or denial of service;
5. cross-Task file, process, cache, or credential access;
6. destructive Host lifecycle or terminal mutation;
7. stale Control state after crash, restore, or disconnection;
8. runaway execution, output, retries, Pool growth, or external API use;
9. command, fact, notification, or object corruption/reordering; and
10. a malicious or incompatible adapter/update.

Permanent loss of Control plus every backup is outside the recovery model.

## Security invariants

- Only an enrolled, nonrevoked Node incarnation accepts its bound Delegation.
- Only Control creates desired intent, plan revisions, placement, and new
  attempt generations.
- Offline Node authority is explicit, finite, expiring, and bounded.
- Missing or conflicting evidence cannot authorize a duplicate effect.
- Credential values never enter definitions, command lines, logs,
  notifications, or portable checkpoints.
- Task/Agent identity is distinct from Node service identity.
- Destructive lifecycle cannot silently discard protected work or
  unreplicated required objects.
- Untrusted content remains data at privileged boundaries.
- Terminal authority is explicit and cannot forge execution facts.
- Resource, spool, generation, Pool, and external-rate bounds remain effective
  while Control is offline.
- No component may gain cloud-infrastructure authority through a transport,
  storage, credential, provider, or workload-target adapter.

## Direct peer transport

Direct sessions must provide mutual endpoint authentication, incarnation
binding, transcript/channel binding, confidentiality and integrity, replay
protection, key rotation, downgrade rejection, bounded frames, stream
fairness, and durable cursor resumption.

Endpoint keys are OS-protected. Enrollment claims are short-lived,
single-purpose, and bound to the expected Host and new incarnation. A stale
session cannot mutate current state.

There is no trusted intermediary. Direct reachability can be denied or
misconfigured, so transport loss is normal: it pauses new dispatch and
replication but does not erase accepted Node authority or execution facts.

The optional RDP DVC carrier preserves the same boundary. Its first
PING/PONG and every carrier PDU are bounded and HMAC authenticated to the
expected Steward session, Host, Node incarnation, exact RDP session ID, fresh
nonce, and contiguous sequence. The normal signed ECDH handshake and encrypted
`TransportFrame` protocol still run above it. Microsoft Windows App, the RDP
gateway, the interactive Windows user, and successful DVC creation do not
authenticate a Steward peer.

The client component is an HKCU-registered out-of-process COM LocalServer.
Registration validates a regular non-reparse executable with a safe writer
ACL and verifies exact values. The remote service fails closed when active
session selection is ambiguous and never substitutes `WTS_CURRENT_SESSION`.
Local broker pipes are restricted to the current user; service-side key files
must be restricted to LocalSystem/`Steward.Node`.

## Authorization and offline authority

The local OS user is Control's default actor boundary. Every mutation checks a
typed capability. Agent-generated text is never authorization.

A Delegation names exact Tasks, generation caps, dependency subset, resources,
concurrency, spool quota, external-rate allocation, identity grants, object
policy, and deadlines. The Node persists acceptance before acknowledgement and
cannot broaden it.

Commands use idempotency keys, expected revisions, attempt fences, and Node
incarnations. Timeout means uncertainty. Reconciliation precedes replacement
execution.

## Credential lifecycle

Control stores credentials in the OS credential vault or a DPAPI-protected
store. Nodes retain only task-bound material needed for the active authority
window, protected using OS facilities and isolated from other Tasks.

Grants bind scope, audience, Host, incarnation, Task/Agent, expiry, and maximum
uses. Delivery occurs over the mutually authenticated peer session into a
protected file/handle, environment indirection, or runtime-native secret mount.
Cleanup records a scrub fact.

The Local Stack has no hosted renewal path. Before dispatch, Control verifies
that credential lifetime covers the delegated operation or that the Task has a
safe `checkpointAndPause`, `fail`, or `continueWithoutCapability` behavior.
Nodes cannot substitute identities or request broader scope while offline.
Migration carries references and re-delivers fresh capability material; it
never copies credential bytes.

External APIs are Workload targets. Their access credentials are subject to
the same Task binding and lifetime rules and cannot become Control, transport,
storage, or provider credentials.

## Runtime isolation and durable jobs

Each TaskAttempt receives an isolated workspace and declared runtime identity.
Host admission rejects a required isolation level that Windows cannot supply.
Filesystem ACLs, process identities, Job Objects, container boundaries, and
resource limits enforce the selected level.

Windows process launch establishes containment and durable launch evidence
before resuming. PID-only adoption is prohibited. Cancellation escalates from
graceful shutdown to complete managed-tree termination. A retained Job Object
handle may preserve control across Node service restart; Host reboot remains a
checkpoint/restart/interruption boundary.

Agent checkpoints receive the same confidentiality and integrity treatment as
private artifacts. They exclude credentials, raw process state, host caches,
and undeclared tools.

## Filesystem portable state

Portable objects are immutable and content addressed. Producers use bounded
paths, reject traversal and reparse-point escape, write privately, fsync,
verify hashes, and atomically publish. Replication re-verifies destination
bytes before issuing a receipt.

ACLs separate Steward state from Task workspaces. Object metadata is bounded
and cannot select an arbitrary destination path. Partial, corrupt, substituted,
or hash-colliding content fails closed. At-rest confidentiality uses
OS/filesystem protection appropriate to the declared data classification.

Spools reserve OS disk and enforce global and per-Workload limits. Child output
cannot block forever because Control or a peer root is unavailable. Planned
replacement/deletion verifies required receipts; forced action records an
exact loss manifest.

## Untrusted output and terminal

Repository text, process output, evaluation cases, model responses, logs,
artifacts, and Agent messages retain provenance and are separated from commands
and privileged prompts. Renderers neutralize terminal escapes, unsafe links,
and binary/control content. Structured remediation requires independent
authorization.

A terminal is authenticated, explicitly elevated if requested, leased,
revocable, and bound to a Host/workspace. File transfer is separately scoped.
Transcript retention is configurable; lifecycle evidence remains mandatory.
Unmanaged terminal mutations mark related readiness and observations suspect
until reconciliation.

## Dev Box provider safety

The Dev Box adapter's credential permits only calls accepted by the Microsoft
Dev Box developer/user-facing API for the user's existing authorization.
Interactive local user authentication is preferred; credential material stays
OS protected.

Code, configuration, tests, and deployment traces must prove that the adapter:

- uses `Azure.Developer.DevCenter` and the Dev Center user endpoint only;
- accepts pre-existing endpoint/project/Pool values;
- persists and authenticates user-API operation handles;
- fails closed on unsupported lifecycle capabilities; and
- contains no subscription, ARM, resource-group, Azure VM deployment, `az`,
  cloud storage, intermediary, or infrastructure-provisioning path.

Pool hard maximums constrain user-facing box creation. Stop, replace, and
delete still pass Core drain and loss checks. Provider success never asserts
Node enrollment or Task success.

## No-cloud-infrastructure control

The Local Stack must run with no Steward cloud credentials or service
endpoints. Its dependency graph resolves transport, object storage,
credentials, state, and runtime to local adapters. Installation artifacts must
contain no infrastructure-as-code, subscription-level permissions, or scripts
that create cloud resources.

Egress inspection distinguishes:

- configured direct peer traffic;
- optional Microsoft Dev Box user API calls;
- explicit Workload-target traffic; and
- package/update retrieval documented by deployment.

Any other required remote dependency violates the invariant. A future adapter
cannot be enabled silently; it requires a new explicit binding, threat model,
evidence, and user deployment decision.

## Backup, update, and evidence

SQLite backup uses a consistent snapshot plus a content-addressed object
manifest. Restore performs integrity checks and reconciles known Nodes before
placement. This is operational evidence, not a claim of tamper protection from
a fully compromised local administrator.

Packages are signed and versioned; releases produce an SBOM. Adapter
compatibility and required features fail closed across version skew.

Required evidence includes direct-peer impersonation/replay tests, stale
incarnation and generation rejection, offline Delegation overreach, credential
expiry/scrub/disk-theft tests, filesystem traversal/corruption/exhaustion tests,
cross-Task isolation, malicious output, process-tree escape, terminal
authorization, restore/re-adoption, and the no-cloud deployment checks above.

No injected fault may produce an unauthorized or silently duplicated effect.

## Related documents

- [Architecture](architecture.md)
- [Contracts and state model](contracts.md)
- [Evidence-gated implementation plan](implementation-plan.md)
- [Validation and evidence register](open-questions.md)
