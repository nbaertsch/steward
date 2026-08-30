# Evidence-gated implementation plan

## Delivery rule

This plan delivers the complete Steward system. Workstreams are dependency and
evidence gates, not permission to narrow durable remote jobs, offline
authority, Harbor/Saber evaluations, persistent Agents, or managed terminal
access.

Core contracts freeze only after their behavior is demonstrated independently
of concrete adapters. The Local Stack is then proven as one explicit
composition. The Dev Box provider is a separate optional adapter with a
strictly smaller user-facing boundary.

## Final outcomes

1. Real Harbor and Saber Workloads run on one Host and across a Pool.
2. Durable multi-turn StewardAgents survive Control disconnection and replay
   responses without rerunning turns.
3. General Tasks expose lifecycle, progress, logs, artifacts, declared
   checkpoint/pause/resume, and explicit terminal access.
4. Nodes continue bounded accepted work while Control is offline and
   reconcile exactly once.
5. Host and Pool lifecycle is provider neutral; the approved Dev Box adapter
   uses only the Microsoft user-facing API/SDK.
6. The Local Stack uses direct peer transport, content-addressed filesystem
   replication, OS-protected credentials, SQLite, and Windows.
7. Deployment evidence proves that Steward provisions and operates no cloud
   infrastructure.

## Dependency path

```text
neutral contracts and executable evidence
  -> durable Core state/authority
  -> Local Stack adapters and composition
  -> provider/runtime-neutral scheduling
  -> Dev Box user adapter
  -> evals, Agents, terminal, interfaces
  -> deployment and release evidence
```

## Workstream 0: Freeze boundaries

Deliver:

- neutral port contracts for transport, portable objects, credential
  delivery, persistence, providers, runtime, evals, and Agents;
- authority and state-machine fixtures;
- architecture dependency tests that keep concrete technologies out of Core;
- a Local Stack composition descriptor; and
- the no-cloud-infrastructure invariant as a validation rule.

Gate:

- Core has no transport/storage/identity/provider/runtime implementation
  dependency;
- extension schemas reject unknown required features;
- the Dev Box extension schema has no subscription, ARM, resource-group,
  deployment, VM, storage, intermediary, or infrastructure field.

## Workstream 1: Prove direct peer and offline authority

Implement and test:

- mutually authenticated direct sessions in both supported dial directions;
- enrollment, incarnation binding, key rotation, replay/downgrade rejection;
- bounded multiplexing for commands, facts, streams, Agents, and terminal;
- reconnect and durable cursor resume after sleep, network loss, and restart;
- Node durable Delegation acceptance, generation/resource/rate/expiry limits;
- exact reconciliation and ambiguous-launch recovery.

Gate:

A multi-hour synthetic Workload continues within its Delegation after Control
disconnects. Reconnect replays exactly once. No intermediary process or remote
service is required. No route is handled as ordinary unavailability rather
than delegated-authority loss.

## Workstream 2: Build durable local state

Implement:

- SQLite WAL Control repositories, migrations, transactions, outboxes, and
  integrity checks;
- Node inbox, journal, cursors, and spool metadata;
- backup/export/import and Node re-adoption;
- deterministic clocks/IDs and crash injection.

Gate:

Crash every intent/effect/outbox boundary. Stores remain valid, no duplicate
TaskAttempt appears, and restore reconciles live Nodes before placement.

## Workstream 3: Build filesystem portable state

Implement:

- content-addressed immutable objects and bounded metadata;
- safe path handling, private temporary writes, fsync, atomic publish;
- missing-object replication between configured roots;
- destination hash verification and durable completeness receipts;
- spool quotas, OS disk reserve, retention, and migration interlocks.

Gate:

Interrupt every write/copy boundary, corrupt and substitute objects, exhaust
spool quota, and disconnect replication. Partial bytes never become complete;
process output remains bounded; Task and Agent checkpoints migrate only after
verified receipts.

## Workstream 4: Build local credentials

Implement:

- OS credential-vault/DPAPI protection;
- capability references and task/incarnation-bound grants;
- direct-session protected delivery and cleanup;
- expiry planning and `checkpointAndPause`, `fail`, or
  `continueWithoutCapability`;
- private source, package, and workload-target adapters.

Gate:

A remote Task uses narrowly scoped credentials without exposing them in
definitions, command lines, logs, checkpoints, or other Tasks. With Control
offline, expiry follows the declared behavior and no Node obtains a new or
broader identity. Disk-theft and cleanup checks find no reusable plaintext
credential.

## Workstream 5: Build Windows runtime and terminal

Implement:

- Windows service topology and process execution;
- atomic Job Object containment and truthful recovery;
- process/container/workspace/file/resource capabilities;
- bounded output, cancellation, and cleanup;
- ConPTY terminal, lease, elevation, revocation, and scoped transfer.

Gate:

Tasks survive RDP disconnect and behave according to interruption class across
Node restart and Host reboot. Cancellation owns the complete process tree.
Terminal mutation cannot forge Task state and forces readiness/reconciliation.

## Workstream 6: Build provider-neutral Pool scheduling

Implement:

- `IHostProvider` capabilities and durable operation reconciliation;
- Pool warm/hard bounds, idle policy, demand, drain, and placement;
- composite Host resources and external Workload API rate slices;
- lifecycle interlocks for Tasks, Agents, and portable receipts.

Gate:

Simulator tests prove scale races, stale callbacks, hard maximum, Host loss,
drain blocking, migration, and external throttling without any provider SDK in
Core.

## Workstream 7: Add the approved Dev Box adapter

Implement only:

- `Azure.Developer.DevCenter` SDK and Microsoft Dev Box developer/user API;
- discovery of visible projects, Pools, and boxes;
- capability-supported create, inspect, start, stop, restart, repair/restore,
  replacement sequence, and delete;
- durable user-API long-running-operation handles;
- bootstrap/enrollment handoff with no infrastructure authority.

Explicitly exclude:

- subscription and ARM management clients;
- `az`, Azure PowerShell, templates, and deployment scripts;
- Azure VM create/deploy APIs;
- creation of Dev Centers, projects, Pools, networks, identities, storage, or
  other resources;
- transport, state, credential, or Control cloud services.

Gate:

Static dependency checks and captured integration traffic prove that the
adapter calls only the approved endpoint/API/SDK. Tests use a pre-existing
authorized project and Pool. Unsupported capabilities fail closed and restart
reconciles the same operation.

## Workstream 8: Implement evaluations and scheduling

Implement deterministic Workload DAGs, dependency release, safe Host packing,
cross-Host sharding, result reduction, partial failure, and external-rate
allocation. Add Harbor and Saber harness adapters.

Gate:

A 300-child synthetic Workload and real Harbor/Saber suites run locally and
distributed. Host loss resumes only eligible unfinished children. Results
contain each logical child once. A throttling storm stays within the declared
external API rate and is not mistaken for Task failure.

External model/evaluation APIs used in these tests are Workload targets. Their
availability is not a Steward deployment requirement.

## Workstream 9: Implement StewardAgents

Implement durable Agent identity, turn queues, runtime adapter, worktree,
compaction, response/notification cursors, checkpointing, migration,
re-brokering of local credential references, and Copilot/MCP/local-RPC
adapters.

Gate:

An Agent handles multiple delegated turns while Control is disconnected,
replays responses on reattach, migrates with declared state, and remediates a
failed evaluation through managed commands. No credential or raw process is in
its checkpoint.

## Workstream 10: Complete interfaces and operations

Complete CLI, loopback HTTP/local RPC, MCP, Copilot adapter, logs, artifacts,
terminal UX, backup/restore, diagnostics, updates, and stable errors over
shared handlers.

Gate:

All defining journeys work without RDP or database edits. Interfaces agree on
state, authorization, cursors, and errors.

## Workstream 11: Produce deployment evidence

Record one reproducible evidence bundle per supported deployment:

- date, owner, OS/build/component versions, package hashes, and topology;
- clean installation from release artifacts;
- Local Stack configuration with every required port resolved;
- process and endpoint inventory;
- dependency/SBOM scan for prohibited infrastructure clients;
- repository/package scan for infrastructure templates and deployment calls;
- egress capture classified as direct peer, optional Dev Box user API,
  explicit Workload target, or documented package/update retrieval;
- durable offline Workload, reconnect/replay, filesystem corruption, vault
  leakage, backup/restore, Agent, evaluation, and terminal results;
- Dev Box API trace and negative tests, when that adapter is enabled; and
- an attestation that no Steward cloud resource was provisioned or operated.

The clean Local Stack run must succeed with no cloud service endpoint,
subscription credential, storage credential, or remote broker configuration.

## Final acceptance

Release only when the evidence register proves:

1. durable remote Tasks and offline reconciliation;
2. real local/distributed evals;
3. persistent Agent turns, notifications, and migration;
4. managed terminal safety;
5. complete Local Stack adapter behavior;
6. provider-neutral Core boundaries;
7. Dev Box's user-API-only boundary;
8. no unauthorized or silently duplicated effect under fault injection; and
9. the no-cloud-infrastructure invariant from package to observed deployment.

## Related documents

- [Architecture](architecture.md)
- [Contracts and state model](contracts.md)
- [Security and threat model](security.md)
- [Validation and evidence register](open-questions.md)
