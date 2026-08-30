# Contracts and state model

## Contract principles

Steward contracts describe Host, Pool, Workload, Task, TaskAttempt, Delegation,
StewardAgent, portable-object, identity-capability, and terminal behavior.
They do not depend on a transport, store, identity provider, database,
provisioning product, operating system, evaluation harness, Agent runtime, CLI,
HTTP, or MCP.

Every persisted or transmitted contract has:

- a schema name and semantic version;
- strongly typed stable identifiers;
- a monotonic revision where state can change;
- idempotency identity for side effects;
- explicit required and optional capabilities;
- bounded collections and payload references; and
- a versioned extension envelope for adapter-specific data.

Readers reject unknown required features. Times express evidence and
deadlines; they never replace generation fencing.

## Core ports

Core consumes these behavioral ports:

| Port | Required neutral behavior |
| --- | --- |
| Transport | Authenticated peer sessions, bounded frames/streams, reconnect and cursor resume |
| Portable object store | Put/get/inspect/replicate immutable objects and issue verifiable completeness receipts |
| Credential vault/delivery | Resolve a capability reference, enforce binding/lifetime, deliver and scrub |
| Durable repositories | Transactional revisions, durable outboxes, migrations, backup and integrity checks |
| Host provider | Capability discovery and idempotent asynchronous Host lifecycle |
| Host runtime | Capability discovery, execution, observation, containment, cancellation, files and terminal |
| Evaluation harness | Deterministic case planning, progress/result parsing and reduction |
| Agent runtime | Durable turn execution, checkpointing, cancellation and response capture |

Every adapter declares `kind`, semantic `version`, capabilities, and bounded
configuration. Adapter handles are opaque to Core, authenticated when they
cross a trust boundary, and never interpreted as execution truth.

## Local Stack bindings

The Local Stack fixes these bindings without changing Core contracts:

| Port | Binding |
| --- | --- |
| Transport | `direct-websocket` authenticated direct peer |
| Portable object store | `content-addressed-filesystem` |
| Credential delivery | `direct-session-os-vault` |
| Durable repositories | SQLite WAL |
| Host runtime | Windows |

Direct transport configuration names dial direction and a validated endpoint.
Filesystem configuration names absolute roots, quotas, replication peers, and
declared failure domains. Credential configuration names OS-vault references,
never values. SQLite and Windows details remain adapter-private.

## Glossary and identities

| Term | Meaning |
| --- | --- |
| Control | Local application core and source of desired intent |
| Host | Execution capacity with provider identity and capabilities |
| Node | Steward daemon on a Host, identified by an incarnation |
| Pool | Placement and Host lifecycle policy |
| Provider | Neutral Host discovery/lifecycle implementation |
| HostRuntime | Process, container, workspace, file, resource, and terminal primitives |
| Workload | Durable aggregate intent and immutable plan revisions |
| Task | Finite typed unit in a Workload plan |
| TaskAttempt | One generation-fenced Task execution |
| Delegation | Bounded authority for offline Node execution |
| StewardAgent | Durable multi-turn Agent with portable declared state |
| IdentityGrant | Scoped, expiring authority to materialize a capability |
| PortableObject | Content-addressed log, artifact, checkpoint, or Agent state |

Opaque IDs include `WorkloadId`, `PlanRevisionId`, `TaskId`, `TaskAttemptId`,
`StewardAgentId`, `AgentTurnId`, `HostId`, `NodeIncarnationId`, `PoolId`,
`DelegationId`, `CommandId`, `IdentityGrantId`, `PortableObjectId`,
`ProviderOperationId`, and `NotificationId`.

`HostId` survives expected power cycles. `NodeIncarnationId` changes after
replacement, identity reset, or reenrollment. `TaskId` survives retries;
attempt generation increases monotonically.

## Workload and Task

A Workload records normalized inputs, desired and derived state, planner
version, current immutable plan revision, Task DAG, resource and external-rate
policy, progress/reduction policy, notifications, supporting Agents, and
portable-object catalog.

Desired Workload states are:

```text
active | paused | cancelling | cancelled
```

Derived states are:

```text
planning | queued | running | paused | recovering |
succeeded | partiallySucceeded | failed | cancelled
```

A Task records its Workload/plan, TaskType and typed input, dependencies,
deterministic logical key, capabilities/resources, identity and network
requirements, placement, retry cap, interruption class, desired state, and
accepted generation.

A TaskType declares preparation, execution, observation, checkpoint,
pause/resume, cancellation, restart, cleanup, progress, logs, artifacts,
retry classification, offline eligibility, credential-expiry behavior, and
portability. Capability absence is explicit.

Task observed states are:

```text
blocked | queued | preparing | ready | running | pausing | paused |
checkpointing | cancelling | recovering |
succeeded | failed | cancelled | interrupted
```

`recovering` means evidence is incomplete or conflicting. It is not permission
to launch a replacement.

## TaskAttempt and exactly-once reconciliation

A TaskAttempt records Task/generation, Host/incarnation, command and
Delegation IDs, execution fence, resource/rate allocation, runtime execution
identity, setup evidence, launch facts, completion facts, stream cursors, and
portable-object receipts.

```text
reserved -> dispatched -> accepted -> preparing -> launching -> running
running -> checkpointed | succeeded | failed | cancelled | interrupted
any nonterminal -> recovering
recovering -> running | checkpointed | succeeded | failed |
              cancelled | interrupted
```

One nonterminal generation owns the execution right. Control, Node, and
side-effecting handlers verify that generation. An unknown launch outcome
enters recovery; a newer generation does not prove the old effect absent.

Commands include `CommandId`, idempotency key, expected aggregate revision,
expected generation or incarnation, deadline, actor capability, and typed
payload. A receiver durably records receipt and outcome. Replays return the
same result.

Node events carry a local sequence and evidence reference. Control acknowledges
a contiguous cursor. Gaps trigger replay. Reconciliation applies:

1. Control desired intent and plan revision.
2. Node-observed process and local-effect facts.
3. Content hashes and portable-store completeness receipts.
4. Provider lifecycle observations.
5. Deterministic reducers.
6. Recovery for incomplete or contradictory evidence.

## Delegation

A Delegation is immutable after acceptance and contains:

- Control, Host, and Node-incarnation identities;
- plan revision and normalized Task definitions;
- allowed Task IDs and generation ranges;
- satisfiable dependency edges;
- resource, concurrency, spool, and attempt limits;
- external-rate slices and expiry behavior;
- IdentityGrant references;
- no-new-starts, drain, and authority-expiry deadlines;
- stream/portable-object policy and cursors; and
- peer-session binding and revocation revision.

The Node persists acceptance before acknowledgement. Offline it cannot invent a
Task, change a plan, increase a limit, obtain a new identity, provision a Host,
or transfer authority. Expiry prevents new starts. Active work follows the
declared interruption and credential-expiry policies.

## StewardAgent

A StewardAgent records stable identity, runtime kind/version, state, placement,
migration policy, compacted conversation, checkpoint lineage, repository and
worktree identity, declared tools/environment, related Workloads/Tasks,
identity references, pending turns, responses, and notification cursors.

```text
creating -> ready -> handlingTurn -> ready
ready | handlingTurn -> checkpointing -> migrating -> restoring -> ready
any nonterminal -> suspended | recovering
suspended -> restoring | terminated
```

Turn states are `queued`, `delegated`, `running`, `responded`, `notified`,
`failed`, or `cancelled`. Response delivery may replay without rerunning a
turn. Checkpoints exclude credential values, raw processes, host caches,
undeclared tools, and unbounded artifacts.

## Host, Pool, provider, and runtime

A Host records provider identity, Pool, lifecycle, capabilities, resources,
power observation, current Node incarnation, and portable-state obligations.
A Pool records provider binding, allowed TaskTypes, constraints, warm minimum,
hard maximum, idle timeout, placement, and lifecycle policy.

```text
discovered -> provisioning -> bootstrapping -> enrolling -> ready
ready -> draining -> stopped -> starting -> ready
draining -> replacing -> bootstrapping
draining -> deleting -> deleted
any active state -> degraded | recovering
```

Destructive lifecycle first evaluates:

- noninterruptible Tasks, which block;
- checkpoint-resumable Tasks, which checkpoint and replicate;
- restartable Tasks, which record interruption;
- Agents, which checkpoint/migrate as required; and
- spooled objects, which require completeness receipts.

A forced operation includes explicit user intent and a loss manifest.

`IHostProvider` exposes capability discovery plus `Discover`, `Inspect`,
`Create`, `Start`, `Stop`, optional lifecycle methods, `Replace`, `Delete`, and
`Reconcile`. Effects are asynchronous and use durable
`ProviderOperationId`s. Unsupported operations fail closed.

`IHostRuntime` advertises process, container, workspace, file, checkpoint,
resource-control, and terminal capabilities. Windows Job Object, service, ACL,
and ConPTY details cannot appear in Core contracts.

### Dev Box extension

The Dev Box extension configuration contains only the user-facing Dev Center
endpoint and already-approved project, Pool, user, and box identity. Its
operation extension stores a protected user-API long-running-operation handle.
It may not contain subscription, resource-group, ARM deployment, Azure VM,
storage-account, relay, or infrastructure-provisioning fields.

The adapter uses the Microsoft Dev Box user API/SDK only. A lifecycle intent
unsupported by that API is absent or implemented as an explicit recoverable
sequence of supported user operations. Provider capability discovery controls
which path is legal.

## Portable objects

Chunks are identified by producer lineage, stream, sequence, offset, length,
and hash. A `PortableObject` records content hash, size, type, producer,
attempt/Agent lineage, retention, classification, local spool reference,
replication receipts, and completeness.

The filesystem adapter:

1. writes and fsyncs immutable content;
2. verifies whole-object hash and bounded metadata;
3. atomically publishes under the content-addressed name;
4. copies missing objects to configured peer roots;
5. re-verifies destination bytes; and
6. durably records a destination completeness receipt.

Partial, corrupt, or unverified files never become complete. Node spool
admission reserves OS disk and enforces per-Workload bounds. A disconnected
sink cannot block process output indefinitely.

## Identity and secrets

An `IdentityRequirement` names capability, audience, scope, delivery
mechanism, minimum lifetime, renewal need, and behavior when renewal is
unavailable:

```text
checkpointAndPause | fail | continueWithoutCapability
```

An `IdentityGrant` binds a vault reference to Host, Node incarnation,
Workload/Task/Agent, audience, scope, expiry, and maximum uses. Local Stack
renewal is `localControl` or `none`. There is no remote renewal service.

Control resolves and protects values through the OS. Delivery uses an
authenticated direct session and a protected file, handle, environment
indirection, or runtime-native mount. Credential values never appear in Task
definitions, Delegations, command lines, logs, events, artifacts, or
checkpoints.

External model, source, package, and similar APIs are optional Workload
targets. Their identities are Task capabilities, not Steward deployment
identities.

## Terminal and interface contracts

A terminal request names Host, workspace, optional Task context, actor,
elevation capability, lease, retention mode, and transfer permissions.
Lifecycle and unmanaged-mutation facts are journaled. A terminal cannot set
authoritative Task status.

All user interfaces map to shared handlers:

- CLI for Host, Pool, Workload, Task, Agent, logs, artifacts, terminal,
  identity, doctor, backup, and recovery;
- loopback HTTP/local RPC for the typed application surface;
- MCP and Copilot adapters for submit, inspect, notify, and remediate.

Output treats repository, evaluation, process, and Agent text as untrusted data
with explicit provenance.

## No-cloud-infrastructure contract

The Local Stack deployment descriptor must resolve every required Steward port
to direct peer, filesystem, OS-vault, SQLite, or Windows bindings. Validation
rejects a descriptor that introduces a Steward cloud endpoint or cloud state
dependency.

The only approved external provider binding is the separate Dev Box user
adapter, and its schema excludes infrastructure-management identifiers and
operations. All other external endpoints must be declared by a Workload as
targets. Contract fixtures and dependency tests enforce this distinction.

## Related documents

- [Architecture](architecture.md)
- [Security and threat model](security.md)
- [Evidence-gated implementation plan](implementation-plan.md)
- [Validation and evidence register](open-questions.md)
