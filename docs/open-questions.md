# Validation and evidence register

## Evidence standard

Every result records date, owner, environment, versions, repeatable procedure,
positive and negative observations, diagnostics, security/performance impact,
selected mechanism, rejected alternatives, fallback, contract consequence,
and whether the item is open, narrowed, or closed.

An architectural requirement remains required while its implementation
evidence is open. External APIs exercised by a Workload are labeled as targets,
not deployment dependencies.

## Load-bearing evidence

| ID | Status | Required proof | Decision unlocked |
| --- | --- | --- | --- |
| E-01 | Open | Direct authenticated peer sessions: both dial directions, enrollment, reconnect, cursor resume, multiplexing, terminal latency, key rotation, replay/downgrade and no-route behavior. See [direct peer evidence](evidence/direct-peer-transport.md). | Transport binding and deployment prerequisites |
| E-02 | Open | Disconnect Control during a durable multi-Task Delegation; prove generation/resource/rate/identity/deadline limits, crash recovery, exact journal replay, and no duplicate effects. | Delegation and reconciliation freeze |
| E-03 | Open | OS-vault protection, direct-session delivery, expiry, scrub, disk theft, cross-Task denial, and no renewal while Control is unavailable. See [credential evidence](evidence/credential-delivery.md). | IdentityGrant and delivery binding |
| E-04 | Open | Private source/package and external Workload-target credentials use only Task-bound local grants; expiry never substitutes identity. | Workload credential adapters |
| E-05 | Narrowed | Local Job Object spike proves retained-handle requirements. Complete SCM, upgrade, reboot, atomic launch, nested-job and supported-Host matrix. See [Windows continuity evidence](evidence/windows-job-continuity.md). | Windows service topology |
| E-06 | Open | Disconnect filesystem peers while producing sustained output; prove spool reserve, quotas, exact replay, and nonblocking output policy. | Spool limits |
| E-07 | Open | Interrupt filesystem write/replication boundaries; prove safe paths, atomic publication, hash verification, deduplication, receipts, corruption handling, migration races and restore. See [portable-state evidence](evidence/portable-state.md). | Portable-object binding |
| E-08 | Narrowed | Dev Box user API/SDK supports Pool/box discovery and user lifecycle LROs. Prove live identity, capability mapping, restart reconciliation, bootstrap handoff, and the prohibited-infrastructure negative boundary. See [Dev Box evidence](evidence/dev-box-provider.md). | Optional provider release |
| E-09 | Narrowed | Copilot public custom-agent/MCP mechanisms support the adapter but not native remote registration. Prove durable local response replay. See [Copilot evidence](evidence/copilot-cli-bridge.md). | Copilot adapter |
| E-10 | Open | Clean-machine deployment, dependency and egress inventory, no-cloud configuration, and negative infrastructure scans. See the [deployment evidence record](evidence/no-cloud-deployment.md). | No-cloud-infrastructure release attestation |
| E-11 | Narrowed | Production DVC LocalServer, exact-session WTS endpoint, authenticated PING/PONG, reconnect, and secure stream mapping are offline tested. The `ms-avd:connect` protocol activation path remains disqualified (visible fullscreen). The replacement `WindowsAppIsolatedConnectionLeaseFactory` launches Windows App on an isolated Windows desktop with Job Object containment, producing zero visible UI until explicit `ShowAsync` activation. RDCore `ConnectionFactory` sets `PopupUIParentWindowHandle=0`, `SessionWindowHandle=0`, `SilentConnectionMode`, and validates all settings are retained. Prove HKCU AddIns activation, cross-session LocalSystem channel open, live isolated-desktop headless evidence, and DVC secure-peer transport over the isolated connection. See [RDP DVC transport](rdp-dvc-transport.md) and [live evidence](evidence/dev-box-rdp-live-acceptance.md). | Dev Box headless reverse-connect release |

## No-cloud deployment evidence

E-10 closes only when an evidence bundle shows:

1. **Composition:** every required Core port resolves to direct peer,
   content-addressed filesystem, OS-vault/direct delivery, SQLite, or Windows.
2. **Clean install:** Control and Node install and run from release artifacts on
   clean Windows systems without cloud service configuration.
3. **No hidden service:** accepted remote work, reconnect/replay, object
   replication, backup/restore, evals, Agents, and terminal work with no
   Steward remote endpoint.
4. **Dependency inspection:** package/SBOM and source dependency reports contain
   no required infrastructure-management client in the Local Stack path.
5. **Artifact inspection:** no ARM/Bicep/Terraform templates, subscription
   setup, `az`/PowerShell provisioning, VM deployment, cloud database,
   intermediary, object-storage, or remote identity-service instructions are
   required.
6. **Egress inspection:** observed traffic is classified as a direct Steward
   peer, optional Dev Box user endpoint, explicit Workload target, or
   documented package/update retrieval.
7. **Negative credentials:** ordinary Local Stack startup succeeds without
   subscription, cloud storage, hosted broker, or intermediary credentials.
8. **Dev Box boundary:** when enabled, captured calls use the Microsoft Dev Box
   developer/user API and `Azure.Developer.DevCenter` SDK only, against a
   pre-existing project and Pool.
9. **Provisioning ledger:** the run creates no Steward cloud resource. A Dev
   Box created inside an existing Pool is recorded as consumed Host capacity,
   not Steward infrastructure.

The bundle includes configurations with secrets redacted, package hashes,
process/endpoint inventories, test logs, traces, failures, and reviewer signoff.

## System validation matrix

| ID | Scenario | Passing evidence |
| --- | --- | --- |
| V-01 | Control crash at each SQLite/outbox boundary | Valid store; deterministic recovery; no duplicate attempt |
| V-02 | Backup/export, restore, and live Node re-adoption | Integrity verified; placement waits for reconciliation |
| V-03 | Control sleeps during multi-hour accepted Workload | Bounded delegated work completes and reconciles once |
| V-04 | Stale Node session/incarnation reconnects | No current aggregate, identity, attempt, or Host mutation |
| V-05 | Unknown process launch result | Recovery; no replacement until absence is proven |
| V-06 | Process Task through RDP disconnect and Node restart | Declared interruption behavior; complete tree ownership |
| V-07 | Filesystem peer unavailable under sustained output | OS reserve and quotas hold; exact later replication |
| V-08 | Object corruption/traversal/substitution | Rejected; no completeness receipt |
| V-09 | 300-child Workload across three Hosts | Exact result set after Host loss |
| V-10 | External target returns throttling | Rate bound respected; no false Task failure |
| V-11 | Pool scale races and hard maximum | Idempotent capacity; safe drain; no over-provisioning |
| V-12 | Stop/replace/delete by interruption class | Correct block, checkpoint/migrate, or interruption |
| V-13 | Real Harbor locally and distributed | Reproducible plan and reduction |
| V-14 | Real Saber locally and distributed | Reproducible plan and reduction |
| V-15 | Failed evaluation remediation by Agent | Durable notification, managed fix, explicit retry |
| V-16 | Agent disconnect, reattach, and migration | No turn rerun; declared state restored |
| V-17 | Credential expiry while Control unavailable | Declared pause/fail/continue; no substitution |
| V-18 | Stolen Host disk and cleanup inspection | No reusable plaintext credentials |
| V-19 | Cross-Task files/processes/cache/credentials | Required isolation or rejected placement |
| V-20 | Malicious repository/package/output | No implicit authority; safe rendering |
| V-21 | Peer impersonation/replay/downgrade | Content and endpoint identities protected |
| V-22 | Terminal mutation and revocation | Lifecycle fact; readiness/reconciliation rerun |
| V-23 | Version skew and update | Required mismatch fails closed; safe drain |
| V-24 | CLI, MCP, local RPC, Copilot | Same handlers, state, cursors, and errors |
| V-25 | Clean Local Stack deployment | E-10 evidence bundle complete |
| V-26 | Dev Box enabled | Only approved user API/SDK observed |

## Contract consistency checklist

- [ ] Core contains no concrete transport, store, identity, provider, runtime,
      database, eval harness, or Agent runtime dependency.
- [ ] Local Stack bindings are explicit and validate bounded configuration.
- [ ] Workload state is reduced from durable Task facts.
- [ ] Task and TaskAttempt remain distinct and generation fenced.
- [ ] StewardAgent remains a durable entity distinct from Task.
- [ ] Host identity and Node incarnation have distinct lifetimes.
- [ ] Delegation lists exact work, generations, dependencies, limits, grants,
      object policy, and expiry.
- [ ] Recovery never implies safe relaunch.
- [ ] Portable objects use content hashes and completeness receipts.
- [ ] Credential values never enter portable or execution contracts.
- [ ] External API quotas remain Workload scheduling resources.
- [ ] Terminal authority and unmanaged mutations are visible.
- [ ] Dev Box fields contain only user endpoint/project/Pool/user/box and
      protected user-operation handles.
- [ ] No Local Stack descriptor can require a Steward cloud endpoint.
- [ ] Unknown required features reject safely.

## Confirmed decisions

- Control is local and SQLite WAL is its default authoritative store.
- Local Stack uses authenticated direct peers, filesystem replication,
  OS-protected credentials, SQLite, and Windows.
- Accepted work continues under bounded Delegation while Control is offline.
- Steward Core is transport/storage/identity/provider/runtime neutral.
- Harbor/Saber, persistent Agents, and managed terminal remain required.
- Dev Box is a separate optional provider over its user-facing API/SDK only.
- Dev Box projects, Pools, networks, policies, and authorization are
  pre-existing and outside Steward.
- External APIs are Workload targets only.
- Steward deploys no cloud infrastructure.

## Final acceptance

The system is accepted when E-01–E-11 and V-01–V-26 are closed, including real
evaluation and Agent journeys, no unauthorized or silently duplicated effect,
supported recovery for every ambiguous execution, protected private content,
usable normal interfaces, and the signed no-cloud deployment evidence bundle.

## Related documents

- [Architecture](architecture.md)
- [Contracts and state model](contracts.md)
- [Security and threat model](security.md)
- [Evidence-gated implementation plan](implementation-plan.md)
