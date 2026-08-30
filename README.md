# Steward

Steward is a personal-first distributed task and agent execution system. A
local **Control** records intent, schedules work, and reconciles durable facts
from remote **Nodes**. Nodes may continue accepted work while Control is
offline, but only within finite delegated authority.

Steward Core is deliberately neutral about transport, portable storage,
credential delivery, persistence, host providers, host runtimes, evaluation
harnesses, and Agent runtimes. Core defines versioned interfaces and owns the
state machines, authority rules, scheduling, generation fencing, replay, and
recovery semantics above those interfaces.

## Local Stack

The supported default deployment is the explicit **Local Stack**:

| Core interface | Local Stack implementation |
| --- | --- |
| Control-to-Node transport | Authenticated direct peer transport |
| Portable-object store | Content-addressed filesystem replication |
| Credential vault and delivery | OS-protected credentials, delivered over the authenticated peer session |
| Durable Control state | SQLite in WAL mode |
| Host runtime | Windows services, processes, Job Objects, files, and ConPTY |

The Local Stack has no Steward-hosted service. It does not require a relay,
cloud object store, hosted token broker, cloud database, or cloud control
plane. Direct transport requires network reachability supplied by the user's
existing network, VPN, port-forwarding policy, or other independently managed
connectivity; Steward does not provision that connectivity.

## Optional Dev Box provider

`Steward.Providers.DevBox` is a separate, approved `IHostProvider` adapter. It
uses only the Microsoft Dev Box user-facing Dev Center API and
`Azure.Developer.DevCenter` SDK to:

- discover projects and Pools already visible to the signed-in user;
- list and inspect the user's Dev Boxes;
- create a box in an existing authorized Pool; and
- start, stop, restart where supported, repair/restore where supported, and
  delete boxes through capability-negotiated lifecycle operations.

The adapter does **not** use subscription or ARM management APIs, `az`, Azure
VM deployment APIs, or infrastructure provisioning. Dev Centers, projects,
Pools, networking, policies, and identity configuration must already exist and
remain outside Steward. Unsupported operations fail closed.

## What Steward manages

- **Workloads**: durable aggregate intent, including Harbor and Saber
  evaluations.
- **Tasks**: finite, typed, schedulable units in an immutable plan.
- **TaskAttempts**: generation-fenced executions on a Host and Node
  incarnation.
- **StewardAgents**: durable multi-turn remote coding Agents with replayable
  turns and portable declared state.
- **Hosts and Pools**: execution capacity, placement, and lifecycle policy.
- **Terminals**: explicit, leased, auditable managed terminal sessions.

Steward supports one-shot commands, long-running processes, Docker Compose
work, distributed evaluations, persistent remote Agents, and elevated managed
terminal access.

## Core guarantees

- Accepted work does not depend on RDP or routine Control connectivity.
- Control owns desired intent; a Node owns facts it directly observes.
- Only one nonterminal attempt generation owns a Task's execution right.
- Ambiguous execution blocks automatic relaunch until evidence resolves it.
- Delegation is durable, finite, bounded, expiring, and cannot create
  undeclared work.
- Logs, artifacts, checkpoints, Agent state, and notifications use replayable,
  bounded cursors and content hashes.
- Host lifecycle honors active work and required replicated state; forced
  operations record the exact expected loss.
- Credentials are references with explicit scope and lifetime. They are
  protected by the OS, delivered only to the bound runtime, and never copied
  into portable state.

Permanent loss of Control and every backup remains outside the recovery
guarantee. Routine backup, restore, integrity checks, restart, and live Node
re-adoption are in scope.

## Architecture

```text
CLI / Windows Desktop / Copilot adapter / MCP / loopback HTTP
                    |
             Steward.Control
       application core + SQLite WAL
                    |
       authenticated direct peer session
                    |
              Steward.Node
          journal + bounded spool
                    |
            Windows HostRuntime
        Tasks + Agents + terminal
                    |
       content-addressed filesystem
              replication

Optional, separate provider edge:
Control -- IHostProvider --> Microsoft Dev Box user API/SDK
```

External model, source, package, evaluation, and similar APIs may be targets of
a Workload. They are not Steward deployment dependencies or infrastructure.
Their quotas and credential expiry are explicit Task scheduling constraints.

## No-cloud-infrastructure invariant

A conforming Steward deployment:

1. runs Control, Node, state, portable-object replication, credential
   protection, and runtime supervision without a Steward cloud service;
2. contains no path that provisions subscriptions, ARM resources, Azure VMs,
   storage accounts, relays, hosted identity services, or cloud databases;
3. treats Dev Box only as an optional user-facing Host provider over an
   already-approved project and Pool; and
4. treats every other external API only as a Workload-selected target.

Deployment evidence must include a clean Local Stack installation, an
offline-Control durable-work run, direct-peer reconnect/replay, filesystem
replication and corruption tests, OS-vault leakage tests, dependency and egress
inspection, and a Dev Box trace proving use of only the approved user-facing
API/SDK. See the
[deployment evidence record](docs/evidence/no-cloud-deployment.md) and
[validation and evidence register](docs/open-questions.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Contracts and state model](docs/contracts.md)
- [Security and threat model](docs/security.md)
- [Evidence-gated implementation plan](docs/implementation-plan.md)
- [Validation and evidence register](docs/open-questions.md)
- [Windows Desktop operations UI](docs/windows-desktop.md)
- [Windows RDP DVC transport](docs/rdp-dvc-transport.md)

## Windows Desktop

`Steward.Desktop.Windows` is the native WinForms operations adapter. It uses
the same loopback Control handlers as the CLI and MCP adapter through the
protocol-neutral typed client in `Steward.Control.Client`; it never opens the
Control SQLite database. The UI provides:

- explicit WAM sign-in and Dev Box Pool discovery;
- complete discovered and registered Pool details with capability-gated
  registration, reconciliation, and member lifecycle actions;
- generation-fenced Node inspection and exact destructive confirmations;
- a first-class remote-viewing hub that validates the provider-issued
  `ms-avd:connect` shape and offers explicit Windows App or HTTPS web-viewer
  activation without rendering the signed resource, tracks only the official
  same-session Windows App package window, and can explicitly surface or
  transfer foreground focus to it;
- a guarded per-user `Steward.ConnectionHost.Windows` with a Windows App
  native-WAM identity bound to `devbox/default`, a verified installed-package
  RDCore loader, AVD workspace discovery, bounded single-use signed RDP
  content, silent connection configuration, and authenticated DVC lifecycle;
- managed ConPTY terminal sessions opened only through Steward terminal
  authority, with lease/elevation state, bounded output, resize, and close;
  and
- restrained Workload, Task/event, artifact, Agent-notification, and health
  views for operations.

Pool discovery remains explicit by default. Set
`STEWARD_DESKTOP_DISCOVER_POOLS_ON_STARTUP=true` or pass
`--discover-pools` to opt into discovery at startup. RDP is not Steward peer
identity, signed remote resources are never displayed, and the UI does not
claim embedded Dev Box viewing, Steward-controlled input, or in-app
fullscreen. Those controls remain broker-owned because current live Dev Box
evidence returns `ms-avd:connect`, not the gateway/load-balance metadata
required by mstscax. Launching that resource through the official
`MicrosoftCorporationII.Windows365` package and opening the real Dev Box in
fullscreen Windows App is proven. The production out-of-process DVC
components are implemented separately. The UI reports and can repair their
exact HKCU registration, but does not claim COM activation or a working
carrier until RDCore, COM plug-in, channel, HMAC, and secure-peer evidence
all pass for the same connection generation.
The observed `ms-avd` protocol activation opens a visible fullscreen Windows
App session and therefore fails the required headless transport criterion.
The replacement `WindowsAppIsolatedConnectionLeaseFactory` launches
Windows App on an isolated Windows desktop with Job Object containment,
producing zero visible UI until explicit `ShowAsync` activation. RDCore's
`ConnectionFactory` sets `PopupUIParentWindowHandle=0`,
`SessionWindowHandle=0`, `SilentConnectionMode`, and validates all settings
are retained. The ConnectionHost and RDCore integration gates
(`STEWARD_CONNECTION_HOST_ENABLE_LIVE`, `STEWARD_RDCORE_INTEGRATION_ENABLED`)
must be enabled for live headless connections. The authenticated DVC evidence
publisher and ECDSA-signed secure-peer transport are required for production
transport over the isolated connection.

.NET 10 is the implementation platform. The repository's deterministic tests
can prove contracts and Local Stack behavior without live external
credentials. Live Dev Box tests are separate deployment evidence and do not
imply that Steward deploys cloud infrastructure.
