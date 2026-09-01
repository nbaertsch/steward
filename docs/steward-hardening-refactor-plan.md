# Steward production hardening and refactor plan

## Status

Date: 2026-09-01

This plan supersedes the production-hardening portions of
`implementation-plan.md`. It does not discard the existing implementation or
the proven Steward.Node installation path. Refactoring proceeds through
compatibility lanes, migration gates, and live evidence.

## Non-negotiable preservation rule

The existing endpoint installation pattern is the migration anchor:

1. A GitHub Actions release builds the self-contained endpoint payload.
2. The release publishes a bounded catalog containing the MSI, release
   manifest, and GitHub artifact attestation.
3. The Dev Box catalog customization runs once in system context to download
   and verify that release.
4. `Steward.Endpoint.Provisioner` transactionally installs or upgrades the
   endpoint while preserving durable state.
5. The provisioner preserves `HostId`, `NodeIncarnationId`, Node signing key,
   Control trust, journals, workspaces, spool state, and receipts unless the
   operation is an explicit reenrollment.
6. Exact-user AtLogOn and RemoteConnect tasks establish the working
   user-session DVC endpoint and HandleKeeper.
7. Failed upgrades restore the prior endpoint state, files, and scheduled
   tasks.

No refactor may remove or bypass this path until an installed 1.0.23 endpoint
has completed an identity-preserving upgrade, reconnect, task reconciliation,
rollback test, and second upgrade through the replacement architecture.

Dev Box customization remains bootstrap-only. After onboarding, upgrades,
diagnostics, WSL/Docker setup, recovery, and ordinary operation must use
authenticated Steward capabilities.

## Anti-overengineering constraints

The refactor must fix demonstrated failures without replacing working
subsystems merely to reach a cleaner theoretical architecture.

1. Keep the existing signed P-256 ECDH and AES-GCM transport. Do not add a
   second carrier encryption layer, directional carrier traffic keys, a new
   carrier record protocol, or cryptographic session resumption.
2. Replace finite reconnect nonces with only the minimum required mechanism:
   a durable monotonic generation plus fresh random challenge-response using
   the existing DVC HMAC secret, followed by the existing signed ECDH
   handshake.
3. Bind the generation/challenge transcript hash into the existing signed
   handshake. Do not create a parallel authentication framework.
4. Preserve the current exact-user DVC endpoint and HandleKeeper tasks until a
   specific capability proves that a service is required. Do not introduce a
   general Node supervisor merely for architectural symmetry.
5. If elevation is required, add one narrow LocalSystem maintenance/update
   service with a typed allowlist. It must not become a generic remote shell,
   a second scheduler, or a second Node runtime.
6. Preserve the working per-node ConnectionHost deployment. Multi-node support
   must not require consolidating every connection into one process. Shared
   hosting remains optional and evidence-driven.
7. Steward has one active local Control in the current product. Do not add
   quorum, distributed leases, disaster-recovery epochs, recovery authorities,
   or automatic split-brain takeover until a real multi-Control requirement
   exists.
8. Defer endpoint-key rotation, carrier-secret rotation, hardware-backed keys,
   resumption tickets, canary fleet orchestration, and telemetry backends.
   Keep version fields so these can be added later without implementing them
   now.
9. Prefer extending existing SQLite stores, state machines, transports, tasks,
   and MSI/provisioner transactions over creating new projects and daemons.
10. Every new component must remove a demonstrated blocker for three-node
    Docker/Harbor execution or a high-confidence security/correctness defect.

## Inputs reviewed

This plan incorporates:

- the prior ProductionNodeRuntime correctness review;
- the prior durable connectivity and lifecycle refactor report;
- `architecture.md`, `contracts.md`, `security.md`,
  `rdp-dvc-transport.md`, and the evidence register;
- the current dirty worktree and project dependency graph;
- the endpoint MSI, catalog, release workflow, provisioner, and scheduled
  task implementation;
- the DVC server, production Node runtime, HandleKeeper, ConnectionHost,
  Control session worker, scheduler, orchestration, persistence, terminal,
  Agent, evaluation, and Dev Box provider compositions; and
- the three-node live evidence accumulated through 2026-08-31.

## Independent review findings

### P0 - production blockers

| ID | Finding | Current evidence | Required disposition |
| --- | --- | --- | --- |
| P0-01 | Production ConnectionHost currently requires a .NET startup hook, Harmony patches, and a native shim to trigger Windows App's effective third-party DVC plug-in path. The direct Steward RDCore factory could establish RDCore but did not trigger the required plug-in code. | `Steward.ConnectionHost.Windows` references `Steward.WindowsApp.RdCoreHook`; `WindowsAppIsolatedConnectionLeaseFactory.CreateEnvironmentBlock` sets `DOTNET_STARTUP_HOOKS`; `StartupHook` patches Microsoft assemblies. This is the currently working transport mechanism, but it remains a compatibility risk and cannot be silently replaced with the known-nonworking direct path. | Preserve and regression-test this mechanism as a quarantined compatibility lane. Remove it only after a supported replacement proves the same DVC activation, headlessness, reconnect, and multi-node behavior live. |
| P0-02 | ConnectionHost holds and uses Control's signing private key, so it terminates the Node's signed ECDH session as Control. | `ProtectedFileRdpDvcLocalCarrier` creates `EcdsaEndpointSigningKey(controlIdentity, controlKey)`. | Move Control authentication and secure-session termination into Control. ConnectionHost must route bounded opaque carrier records or use a distinct broker identity. |
| P0-03 | Reconnect authorization is finite and terminal. | Endpoint state provisions 32 nonces; the DVC server reaches `Completed` or `Exhausted`. | Replace inventories with per-attempt random challenge-response, durable monotonic generations, and a full signed ECDH handshake on every reconnect. |
| P0-04 | One failed channel or secure handshake can terminate the endpoint process, and the scheduled tasks explicitly have no restart policy. | The DVC server's attempt setup is outside its expected-disconnect catch; endpoint task health requires `RestartCount == 0`. | Put the complete attempt lifecycle inside a durable reconnect supervisor and add bounded crash restart independent of logon/RemoteConnect triggers. |
| P0-05 | Node identity, Control trust, journals, credentials, and arbitrary process workloads share the same assigned-user security boundary. | Endpoint state grants the Node user inheritable FullControl; the Node and HandleKeeper run as that user; process tasks execute through the same runtime identity. | Split service identity, per-user DVC helper, and workload identities. Workloads must not be able to modify Node identity, trust, journals, updater state, or another task's workspace. |
| P0-06 | ConnectionHost state is not durable enough to recover connections. | Whole-store JSON persists runtime IDs and state, while live lease ownership exists only in memory. Process restart normally reconciles to disconnected. Auto-connect requires a separate descriptor. | Replace JSON snapshots with transactional SQLite desired-connection, attempt, route, attachment, and outbox state. Recover desired connections automatically. |
| P0-07 | The auto-connect descriptor persists a Control authorization token and connection nonce as ordinary JSON without validating owner or DACL. | `ConnectionHostAutoConnectOptions` reads the plaintext fields after only path, reparse, and size checks. | Eliminate bearer-token/nonce persistence. Until removed, require protected storage and fail closed on ACL or ownership mismatch. |
| P0-08 | ConnectionHost serializes all nodes through one actor. | `ConnectionHostOrchestrator` has one bounded channel and one reader for Resolve, Prepare, Connect, View, and Disconnect across every node. | Use one bounded actor per node plus a small global coordinator only for Microsoft operations proven to require serialization. |

### P1 - correctness and durability gaps

| ID | Finding | Required disposition |
| --- | --- | --- |
| P1-01 | `ProductionNodeRuntime.LoadBootIdentity` still uses `UtcNow - TickCount64` with a five-second tolerance and marks the result verified. Suspend/resume can appear to be a reboot and invalidate recoverable jobs. | Use an OS-backed boot identity, record verification provenance, and treat uncertain identity as unverified rather than destructive proof. |
| P1-02 | DVC carrier authentication and signed secure transport are not cryptographically bound to the same carrier generation/transcript. Host identity is not in the signed `SessionHello`. | Add a typed carrier binding containing Host, incarnation, reconnect generation, attempt, WTS session, and transcript hash to both signed hellos. |
| P1-03 | Connection generations are process-local and initialized from wall-clock ticks. | Persist generation reservation in SQLite with compare-and-swap. Wall clock is diagnostic only. |
| P1-04 | Control node freshness is registration-time data rather than authenticated-session liveness. Scheduler host snapshots are copied into every workload and become stale independently. | Make authenticated session state the liveness authority. Maintain one central capacity catalog and evaluate current capacity at scheduling time. |
| P1-05 | Workload submission can commit durable intent, then fail HTTP 500 during provider reconciliation. | Separate workload acceptance from asynchronous capacity reconciliation. Return a durable accepted result and expose reconciliation failure as typed operation state. |
| P1-06 | Queued workloads do not have a durable background scheduling loop driven by capacity/session changes. | Add event-driven and periodic scheduling reconciliation over ready tasks and current capacity. |
| P1-07 | The DVC server and `ProductionNodeWorker` implement separate reconnect ownership models. | Unify production Node lifecycle under one supervised runtime; retain separate executables only as compatibility adapters or diagnostics. |
| P1-08 | HandleKeeper is a user-session scheduled process, not a stable service, and has no independent restart policy. | Move retained-handle ownership to the restricted supervisor/service boundary and prove crash/reboot semantics. |
| P1-09 | Agents are forcibly disabled in the installed endpoint configuration. | Preserve disabled-by-default rollout, but add a signed capability/configuration update path and prove Agent isolation before enabling. |
| P1-10 | Privileged host preparation is missing. Current process tasks run at limited user privilege, so WSL, Docker, endpoint upgrades, and machine recovery cannot be completed as typed Steward operations. | Add a narrowly scoped privileged maintenance service. It accepts signed typed operations only, never arbitrary command strings. |
| P1-11 | SQLite native-provider package versions are inconsistent across projects. | Centralize package versions and native SQLite initialization, then test a single published endpoint/Control process for native-library compatibility. |

### P2 - release, evidence, and maintainability gaps

| ID | Finding | Required disposition |
| --- | --- | --- |
| P2-01 | The validation matrix labels real Harbor as covered using planner/fake tests and a validated submission script, but the required 108 accepted live replicas have not run. | Distinguish unit, integration, live, and production evidence. Do not close Harbor until one native three-node run accepts exactly 108 valid replicas. |
| P2-02 | The evidence documents describe both prohibited hooks and claimed production headlessness. | Update evidence from observed facts only. Unsupported instrumentation cannot satisfy a release gate. |
| P2-03 | The old Base64/chunked customization deployment remains callable in production tools. | Freeze it as legacy migration evidence, remove normal callers, and prevent new deployments. Do not delete it until MSI migration tests cover retained endpoints. |
| P2-04 | Endpoint release CI runs the endpoint test project but not the complete production dependency, clean-install, upgrade, rollback, and secret-scan gates. | Expand release gates before publishing an endpoint artifact. |
| P2-05 | Large composition classes combine state machines, persistence, transport, provider calls, and recovery. | Split by authority and transaction boundary, not by arbitrary file size. |
| P2-06 | Current worktree contains validated live fixes and unfinished liveness changes in one broad uncommitted set. | Establish reviewed baseline commits by subsystem without reverting working behavior. |

## Target topology

```text
Per Dev Box, installed by the existing Steward Endpoint MSI
  Existing exact-user Steward Node/DVC task
    - AtLogOn and RemoteConnect activation
    - exact WTS session selection
    - DVC reconnect loop
    - existing signed ECDH transport
    - existing durable Node runtime

  Existing HandleKeeper task
    - retained Job handles
    - restart-on-failure

  Optional minimal Steward maintenance service
    - only typed signed update/repair/WSL/Docker operations
    - no general process execution
    - no Control or Node transport ownership

Per local Control user
  Steward.ConnectionHost.Windows
    - existing supported Microsoft connection owner
    - existing hook/Harmony/shim compatibility activation
    - connection-specific DVC broker/configuration
    - bounded per-connection queues
    - durable SQLite desired connections/routes/outbox
    - headless/View lifecycle
    - opaque carrier routing only

  Steward.Control
    - Control signing key
    - signed ECDH endpoint
    - current capacity/session catalog
    - scheduling/reconciliation
    - Workloads, Agents, terminal, updates, and evidence
```

Do not introduce another Node/session-host process unless the current
exact-user endpoint cannot support a required capability. Control keeps
Control keys, the optional maintenance service keeps only its narrow machine
authority, and workloads inherit neither.

## Refactor sequence

### Phase 0 - freeze the proven baseline

1. Create baseline commits grouped by endpoint install, DVC transport,
   ConnectionHost, Control/orchestration, and tests.
2. Add a golden `StewardEndpointInstallContract` fixture covering:
   - catalog shape and provenance;
   - MSI upgrade code and per-machine scope;
   - exact endpoint payload allowlist;
   - identity and key preservation;
   - state copy, ACL inheritance, reparse rejection, and rollback;
   - exact-user AtLogOn and RemoteConnect triggers;
   - no execution time limit;
   - existing receipt verification; and
   - healthy same-version no-op.
3. Preserve the 1.0.23 release artifacts and three verified receipts as
   migration fixtures with secrets removed.
4. Mark chunked customization APIs obsolete and reject new non-migration use.
5. Update evidence labels so no fake/offline test is described as live proof.

Gate:

- A clean 1.0.23 install and same-version repair pass.
- A 1.0.23 to compatibility-build upgrade preserves exact identities,
  journals, nonce high-water state, tasks, and receipts.
- Failed compatibility-build activation restores 1.0.23.

### Phase 1 - isolate the working hook path and prove its replacement

1. Preserve the current hook/Harmony/shim mechanism unchanged as the
   compatibility transport that is known to trigger the required Windows App
   DVC path.
2. Put it behind an explicit compatibility adapter and feature declaration so
   no new code depends directly on hook environment variables or Harmony.
3. Add regression tests for the exact injected plug-in activation sequence,
   package fingerprint, route isolation, headlessness, and cleanup.
4. Keep replacement characterization outside the production composition.
5. Test supported Microsoft alternatives for concurrent RDCore/Windows 365
   connections and standard DVC registration.
6. Select a replacement only after two real Dev Boxes remain connected
   concurrently with distinct routes, authenticated DVC, and zero visible UI.
7. Remove the hook, Harmony, shim, and capability patch only after the
   replacement passes the same tests and an installed-node rollback exercise.

Gate:

- The working compatibility adapter remains isolated and explicitly reported
  while it is required.
- Two-node live test proves independent connect, reconnect, disconnect, and
  View with no route crossover.
- A replacement is not accepted merely because it creates an RDCore
  connection; it must trigger the Steward DVC plug-in and authenticated
  transport.

### Phase 2 - harden the working Node lifecycle

1. Keep the current exact-user HandleKeeper and DVC/Node tasks.
2. Add restart-on-failure, authenticated reconnect, and read-only health
   verification to those tasks.
3. Preserve current `HostId`, `NodeIncarnationId`, Node key, Control trust,
   reconnect high-water state, journals, workspaces, spool, and task state
   across MSI repair and upgrade.
4. Block upgrade while HandleKeeper owns active Job leases unless the tasks
   have been drained.
5. Add a service only in Phase 3 if a demonstrated privileged operation cannot
   run safely through the current Node identity.

Gate:

- Existing 1.0.23 endpoint upgrades through the same catalog/MSI path.
- Node reconnects and executes the prior smoke workload.
- Killing Node, DVC endpoint, and HandleKeeper at each supported boundary
  converges automatically.
- Rollback returns to the old user-session Node without identity reset.

### Phase 3 - add only required privileged maintenance

1. First prove which required operations fail under the current limited Node
   identity.
2. If required, add one restricted LocalSystem service through the existing
   MSI/provisioner.
3. Give it a SYSTEM/Administrators-only state directory separate from the
   user-writable Node workspace.
4. Accept only typed privileged operations for:
   - verified MSI/update activation;
   - WSL feature/package installation;
   - WSL distribution import and configuration;
   - Docker Engine installation/configuration;
   - service/task repair;
   - diagnostic collection; and
   - reboot with durable continuation.
5. Reject arbitrary elevated executable/script requests and unknown required
   operation versions.
6. Keep ordinary process, compose, evaluation, Agent, and terminal work in the
   existing Node runtime.

Gate:

- A malicious process task cannot read or modify Node keys, Control trust,
  updater state, another task workspace, or supervisor IPC.
- WSL and Docker are installed through typed Steward operations on a clean
  node without post-bootstrap customization.

### Phase 4 - remove reconnect exhaustion without duplicating transport

1. Reuse the existing DVC HMAC secret and message framing.
2. Reserve a signed 64-bit reconnect generation transactionally.
3. Generate fresh Node and broker challenges for each attempt.
4. HMAC the bounded identity, generation, attempt ID, WTS session, and both
   challenges with the existing DVC secret.
5. Hash that challenge transcript and include the hash, generation, and
   attempt ID in the existing signed secure-transport hello.
6. Run the existing P-256 ECDH/AES-GCM handshake unchanged.
7. Resume existing application cursors after authentication.
8. Remove finite nonce inventory plus terminal `Completed` and `Exhausted`
   reconnect states.

Explicitly do not add carrier traffic encryption, carrier traffic keys,
carrier record sequencing, or resumption tickets. The signed secure transport
already provides confidentiality, integrity, and encrypted record sequencing.

Gate:

- 10,000 simulated reconnects without exhaustion or state reset.
- Crash injection at every reserve/authenticate/commit boundary converges.
- Replay, cross-node routing, wrong WTS, wrong Host/incarnation, downgrade,
  and transcript substitution fail closed.
- A seven-day simulated Control outage does not consume authorization state.

### Phase 5 - harden the existing ConnectionHost

1. Use one bounded actor per connection and bounded parallel IPC handlers.
2. Replace JSON snapshots with SQLite WAL tables for desired connections,
   attempts, DVC routes, Control attachments, presentation leases, and outbox.
3. Remove single-use environment authorization tokens and plaintext
   auto-connect descriptors.
4. Use a distinct broker pipe/configuration per connection to preserve the
   currently working injected DVC activation.
5. Persist desired state, not raw provider-signed URIs or bearer material.
6. Refresh provider resources in memory using the approved Dev Box user API.
7. Recreate missing connections automatically where current WAM/provider
   credentials permit silent recovery.
8. Keep View and TakeControl generation- and node-bound.

Gate:

- Three fake and three real nodes demonstrate fairness and independent
  cancellation.
- One hung startup cannot block another node's status or disconnect.
- ConnectionHost restart restores desired headless connections automatically.

### Phase 6 - Control authority and scheduler refactor

1. Make authenticated session liveness the sole source of Node availability.
2. Replace per-workload copied host snapshots with a central durable capacity
   catalog plus session observations.
3. Add a durable scheduling reconciler triggered by:
   - workload acceptance;
   - Node session online/offline;
   - capacity/capability change;
   - task terminal/retry transition;
   - Pool/provider observation; and
   - periodic repair.
4. Separate workload commit from provider reconciliation and return typed
   accepted/reconciling states.
5. Split `ControlOrchestrator` into transaction-focused services:
   - workload/task projection;
   - placement;
   - dispatch/outbox;
   - fact reduction;
   - recovery;
   - authority fencing; and
   - provider demand.
6. Keep the existing single-Control identity model. On restore, require
   reconciliation before placement; do not implement multi-Control takeover.

Gate:

- A ready workload schedules when a live node appears without replaying the
  submission.
- Stale registration timestamps cannot trigger duplicate provider actions.
- Post-commit provider failure never returns an ambiguous generic 500.
- Restored Control reconciles Node cursors and active attempts before issuing
  new placement.

### Phase 7 - finish recovery in the existing Node runtime

1. Keep production ownership in the current DVC server plus
   `ProductionNodeRuntime`.
2. Remove duplicate reconnect loops only where they are actually active in the
   same deployment.
3. Treat uncertain boot identity as ambiguous and add an OS-backed provider
   only if retained-Job recovery requires stronger proof.
4. Add bounded jittered reconnect and crash-loop policies.
5. Preserve durable inbox, delegation, execution, terminal, portable object,
   and Agent cursors across reconnect and process restart.
6. Define disk-full and corruption states that preserve evidence and fail
   closed without resetting identity.

Gate:

- Process, compose, evaluation, terminal, and Agent tasks survive every
  supported disconnect/restart boundary according to their interruption
  contracts.
- No PID-only adoption or duplicate launch occurs.

### Phase 8 - minimal signed updates and rollback

1. Define a signed update manifest independent of the active transport key.
2. Stage immutable versions under the existing MSI/provisioner-owned root.
3. Drain/checkpoint, commit activation intent, atomically switch, health-gate,
   and commit or roll back.
4. Use expand/contract database migrations during the rollback window.
5. Preserve existing Node/Control keys during ordinary updates. Key rotation
   is deferred to a separately approved requirement.
6. Never decrement reconnect generation, update version, or application
   cursor during rollback.

Gate:

- Good update reconnects and becomes known-good.
- Bad signature, downgrade, corrupt artifact, migration failure, crash loop,
  and Control-unavailable health timeout all converge safely.
- The same endpoint identity survives update and rollback.

### Phase 9 - complete product capabilities

1. Prove Docker Engine and Compose on b1, then b2, then b3 through typed
   Steward maintenance.
2. Publish accurate capabilities only after native smoke proof.
3. Enable Agents through signed configuration after task isolation passes.
4. Complete terminal elevation through the typed privileged boundary.
5. Run one useful process and container workload on every node.
6. Run the complete Harbor workload only when all three nodes are
   simultaneously connected, fresh, Docker-capable, and smoke-proven.

Harbor gate:

- One native workload.
- All 36 task IDs.
- Replica count 3.
- Exactly 108 accepted, independently identified results.
- No wrapper-based duplicate submission.
- Required artifacts and retry generations preserved.

### Phase 10 - release evidence and retirement

1. Run independent code, security, and architecture reviews.
2. Resolve all high-confidence findings.
3. Produce a clean-machine release bundle with SBOM, signatures, dependency
   scan, secret scan, egress trace, upgrade/rollback evidence, and no-cloud
   attestation.
4. Inventory all v1 endpoints and remaining nonce state.
5. Stop creating v1 endpoints.
6. Remove chunked customization and finite-nonce code only after every
   retained endpoint is migrated or explicitly decommissioned.

## Migration lanes

### Lane A - current connected 1.0.23 endpoint

Use the authenticated current Node to stage the next CI-attested MSI through
the typed update capability. The existing provisioner preserves state and
installs the supervisor. Establish v2, reconcile cursors, then mark migration
committed.

### Lane B - reachable endpoint with remaining v1 reconnect generation

Use one v1 generation to establish authenticated Control, then perform Lane A.
Do not replenish or replace nonce files.

### Lane C - endpoint cannot establish any authenticated v1 session

Use the same approved Dev Box catalog MSI bootstrap once as repair/transition.
Preserve the existing state root and identity. If identity cannot be validated,
stop and require explicit reenrollment rather than silently minting a new
incarnation.

## Test strategy

Every phase starts with failing tests at the relevant authority boundary.

Required suites:

- endpoint install, repair, upgrade, rollback, and ACL tests;
- protocol parser, fuzz, replay, transcript-binding, and crash-boundary tests;
- supervisor activation and crash matrix;
- task/user/service isolation tests;
- multi-node ConnectionHost fairness and route-isolation tests;
- Control restart, stale restore, authority fence, and scheduling repair tests;
- Node offline delegation and exact reconciliation tests;
- update/key-rotation overlap tests;
- Docker, terminal, Agent, Harbor, and Saber integration tests; and
- real Dev Box headless acceptance.

Tests must use isolated build output while live binaries are running. Evidence
must state whether it is unit, fake-backed integration, local live, Dev Box
live, or full product acceptance.

## Immediate implementation order

1. Commit and tag the reviewed baseline without reverting working live fixes.
2. Add golden tests for the current MSI/provisioner install contract.
3. Isolate and regression-test the working hook/Harmony/shim compatibility
   adapter; do not replace it with the known-nonworking direct RDCore path.
4. Harden the current Node tasks and identity-preserving upgrade path.
5. Add the narrow maintenance service only for operations proven to require
   elevation.
6. Replace finite reconnect nonces with challenge/generation authentication
   feeding the existing signed transport.
7. Refactor ConnectionHost persistence/concurrency.
8. Refactor Control liveness/scheduling and authority fencing.
9. Add typed maintenance, updates, Docker, Agents, and terminal elevation.
10. Execute live multi-node and Harbor acceptance, independent review, and
    final release validation.

## Stop conditions

Stop rollout and preserve evidence if any phase:

- changes Host or Node incarnation identity unexpectedly;
- loses journals, cursors, task state, or portable objects;
- requires copying a Node private key or carrier secret between machines;
- requires post-bootstrap Dev Box customization for ordinary operation;
- expands the quarantined hook/injection compatibility boundary or replaces
  it without equivalent live DVC evidence;
- adds a second encryption/record layer below the existing signed secure
  transport;
- introduces a new daemon, database, authority protocol, or key hierarchy
  without a demonstrated blocker;
- allows arbitrary privileged command execution;
- creates concurrent authoritative Node runtimes for one incarnation; or
- claims live acceptance from fake/offline tests.
