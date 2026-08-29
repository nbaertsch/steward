# Steward architecture

## Mission and boundaries

Steward turns reachable Hosts into durable extensions of a local CLI harness.
Laptop-hosted Control is the default source of user intent. A Node can continue
already accepted work during ordinary Control outages within an immutable,
finite Delegation.

Steward owns Workload planning, Task execution truth, remote Agent continuity,
portable execution evidence, scheduling, and safe Host lifecycle coordination.
It does not own network provisioning, provider administration, identity
providers, source control, package feeds, evaluation harnesses, model APIs, or
other workload targets.

## Neutral core and ports

Steward Core contains no concrete transport, storage, identity provider,
provisioning provider, runtime, operating system, database, evaluation
harness, or Agent-process dependency. Its versioned ports are:

| Port | Core responsibility above the port |
| --- | --- |
| Transport session/carrier | Message schemas, endpoint identity, streams, cursors, replay, bounds |
| Portable-object store | Object identity, lineage, completeness receipts, migration gates |
| Credential vault/delivery | Capability references, scope, binding, expiry, cleanup facts |
| Durable state repositories | Transactions, revisions, outboxes, migrations, recovery |
| `IHostProvider` | Host intent, operation identity, capabilities, lifecycle reconciliation |
| `IHostRuntime` | Task requirements, containment, observation, cancellation, terminal policy |
| Evaluation harness adapter | Deterministic planning, child identity, progress, reduction |
| Agent runtime adapter | Durable turns, checkpoints, notifications, cancellation |

Adapters advertise a stable kind, semantic version, capabilities, and bounded
configuration. Unknown required features are rejected. Provider observations
do not become Task truth, and storage or transport availability does not
change authority.

## System context

```text
              User or parent Agent
                       |
      CLI / Windows Desktop / Copilot / MCP / loopback HTTP
                       |
                Steward.Control
   handlers | scheduler | reducers | reconciliation
              durable-state ports
                       |
              transport-session port
                       |
                 Steward.Node
       inbox | journal | spool | local limits
                       |
              HostRuntime port
            Tasks / Agents / terminal
                       |
            portable-store port

Optional provider edge:
Control -- IHostProvider --> approved Host service
```

Every interface invokes the same application handlers. CLI, MCP, Copilot, and
loopback HTTP therefore share state, authorization, cursors, and errors.

The Windows Desktop is a concrete adapter in `Steward.Desktop.Windows`. Its
protocol-neutral HTTP client is `Steward.Control.Client`; state-changing UI
commands use the same loopback handlers and local mutation token as the CLI.
The adapter composes native WAM and provider-issued remote-viewer activation
from `Steward.DevBox.Windows` plus managed terminal contracts. Real Dev Box
evidence currently returns a signed `ms-avd:connect` resource, not the
gateway/load-balance metadata required by mstscax. The Desktop therefore
launches Windows App or the provider's HTTPS `WebUri` out of process and does
not claim embedded viewing, Steward-controlled input, or in-app fullscreen.
The Windows adapter uses `Steward.ConnectionHost.Windows` as a durable
per-user connection owner. `Steward.RdCore.Windows` verifies and pins one
installed Microsoft-signed Windows App package generation, binds its managed
projection and native RDCore dependencies in an isolated load context, and
uses `IWorkspaceDownloader` for AVD resources. A separate Windows App WAM
context is bound to the same tenant/home account as `devbox/default`. The
resolver selects one exact workspace/resource tuple, requires
`SilentlyConnectible`, retrieves signed RDP content with the AVD audience,
normalizes it to bounded single-use memory, and never persists broker
material. The connection host configures `ConnectionMode.Silent`, zero popup
HWND, no fullscreen, third-party DVC loading, claims-challenge forwarding, and
generation-bound lifecycle. Both integration gates default off.
It may track and foreground only a same-session `Windows365.exe` top-level
window whose package identity is the official
`MicrosoftCorporationII.Windows365` publisher. This is broker-window state,
not DVC or Steward peer evidence. The historical provider-issued resource launch and fullscreen Windows App
view were observed; the Desktop exposes Show, foreground
Take Control, and Release-to-Steward state around that external window without
claiming input interception. The Desktop may inspect or explicitly repair the
official-sample-compatible HKCU DVC LocalServer registration, but registration
does not satisfy transport readiness. Readiness requires ordered evidence for
RDCore connected, WTS plug-in enumeration, Steward COM activation, plug-in
initialization, channel open, HMAC PING/PONG, and signed ECDH peer
authentication for one connection generation.
WinForms, WAM, Windows App, mstscax, and Dev Box SDK types do not enter
Domain, Contracts, or Application. The Desktop never opens Control or Node
SQLite state directly.

## Local Stack composition

The default deployment selects concrete local implementations:

```text
Steward Core
  +-- direct authenticated peer transport
  +-- content-addressed filesystem object store and replication
  +-- OS-protected credential vault and direct-session delivery
  +-- SQLite WAL repositories and outboxes
  +-- Windows HostRuntime
```

### Direct peer transport

Control and Node establish a mutually authenticated direct connection. Either
side may dial when its configured endpoint is reachable. The protocol
multiplexes commands, facts, logs, artifacts, Agent turns, and terminal data,
and resumes from durable cursors after interruption.

The Local Stack does not operate an intermediary. Existing network
reachability is a deployment prerequisite, not something Steward provisions.
When no route exists, work already accepted under Delegation continues within
its bounds and reconciliation waits.

On Windows, `Steward.Transport.Rdp.Windows` is an optional reverse-connect
carrier for an already-established RDP session. The Microsoft RDP client
activates an out-of-process per-user COM LocalServer; the remote Node opens the
named DVC for an exact enumerated active RDP session. The adapter exposes a
bounded bidirectional stream to the same signed/encrypted transport protocol,
so RDP identity is never accepted as Steward peer identity. Core has no WTS,
COM, Windows App, or RDP dependency. See
[RDP DVC transport](rdp-dvc-transport.md).

### Content-addressed filesystem replication

Nodes spool immutable chunks locally. The filesystem adapter names objects by
hash, verifies bytes at every boundary, writes through a temporary file, fsyncs,
and atomically publishes complete objects. Replication copies only missing
verified objects between configured peer roots and records a completeness
receipt. Partial files never satisfy a drain or migration gate.

Filesystem roots can be local disks or user-managed mounted filesystems, but
Core does not infer durability from a path. The deployment declares failure
domains and replication count explicitly.

### OS-protected credentials

Control stores credential material in the OS credential vault or a
DPAPI-protected local store. Nodes receive only capability material bound to a
Task/Agent, Host, Node incarnation, scope, and expiry over the authenticated
session. Material is kept outside definitions, command lines, logs, and
checkpoints and is scrubbed after use.

There is no remote token authority in the Local Stack. If Control is offline,
work can use only already delegated credentials until their declared expiry.
The Task then checkpoints and pauses, fails, or continues without that
capability according to its TaskType.

### SQLite and Windows

Control uses SQLite WAL transactions for intent, facts, and outboxes. Nodes
keep durable inbox, journal, cursor, and spool metadata. Backup/export captures
a consistent database snapshot plus a manifest of referenced filesystem
objects.

Windows supplies service lifetime, process containment through Job Objects,
filesystem/ACL primitives, resource observation, and ConPTY terminal sessions.
These details remain behind `IHostRuntime`.

## Domain relationships

```text
Pool 1 --- * Host 1 --- 1 Node incarnation
 |             |
 | placement   +--- * TaskAttempt
 +--- provider             |
                           * executes one Task generation

Workload 1 --- * Task 1 --- * TaskAttempt
    |
    +--- immutable Task DAG revisions
    +--- * supporting StewardAgent

StewardAgent --- durable turns, worktree, checkpoint lineage,
                 placement, notifications, migration policy
```

A Task is finite. A TaskAttempt is one generation-fenced execution. A
StewardAgent is a durable multi-turn entity; a turn may dispatch a Task without
collapsing the Agent into that Task.

## Authority and reconciliation

| Fact or decision | Authority |
| --- | --- |
| Desired Workload, Task, Host state | Control |
| Plan revision and placement | Control planner/scheduler |
| Process existence and local effects | Observing Node journal |
| Attempt outcome | Node evidence reconciled by Control |
| Replicated bytes | Hash plus portable-store completeness receipt |
| Credential scope and expiry | Control grant plus issuer fact |
| Provider lifecycle outcome | Provider observation reconciled by Control |
| Aggregate Workload result | Deterministic reducer |

Commands are idempotent and generation/incarnation fenced. Gaps cause replay;
conflicts cause recovery. Missing evidence never proves absence and never
permits speculative duplicate execution.

## Bounded offline authority

A Delegation contains the immutable plan revision, permitted Tasks and
generation ranges, dependency subset, resource/concurrency/spool limits,
external-rate slices, credential references, upload policy, and deadlines. A
Node journals acceptance before acknowledging it.

Offline, the Node can run only declared work. It cannot revise the plan, mint
credentials, increase capacity, create a new Host, or transfer authority.
Expiry prevents new starts. Active work follows its declared interruption and
credential-expiry policy.

## Scheduling and execution

Placement considers runtime capability, explicit Host constraints, CPU,
memory, disk, GPU, process/container/VM capacity, setup fingerprints, affinity,
interruption class, Pool policy, and external API quotas. External quotas are
Workload resources, not infrastructure capacity.

Windows process launch establishes Job Object containment and durable launch
evidence before execution continues. Cancellation proceeds from graceful stop
to complete managed-tree termination. Ambiguous launch enters recovery.

Harbor and Saber adapters deterministically enumerate evaluation children,
report progress, and reduce results. Nodes can finish delegated children while
Control is offline. Completed children are not rerun after reconciliation.

StewardAgents retain durable turn queues, response and notification cursors,
compacted conversation, declared worktree state, and environment manifests.
Portable checkpoints exclude credentials, raw processes, undeclared tools, and
unbounded artifacts.

Terminal access is an explicit capability with Host/workspace binding, lease,
elevation decision, revocation, and lifecycle facts. Terminal activity cannot
directly rewrite managed Task truth.

## Optional Dev Box provider boundary

The Dev Box adapter is separate from the Local Stack and implements only the
provider port. It calls the Microsoft Dev Box developer/user-facing API through
the `Azure.Developer.DevCenter` SDK for already-authorized projects, Pools, and
the user's Dev Boxes.

It may discover Pools and boxes and perform capability-supported user
lifecycle operations. Long-running operation identities are persisted and
reconciled after restart. Replacement is modeled as a durable delete/create
workflow when no atomic operation exists.

It must not:

- query or mutate Azure subscriptions or ARM resources;
- invoke `az`, Azure PowerShell, or deployment tooling;
- create Dev Centers, projects, Pools, networks, identities, storage, or VMs;
- bootstrap cloud infrastructure for transport, state, credentials, or
  Control; or
- treat an external API as Steward infrastructure.

The endpoint, project, Pool, network, policy, and user authorization are
pre-existing deployment inputs. Node installation/enrollment is a separately
approved Host bootstrap action and cannot smuggle infrastructure authority
into the provider adapter.

## No-cloud-infrastructure invariant

The default Steward system is complete with local Control, direct peers,
filesystem replication, OS-protected credentials, SQLite, and Windows. No
Steward-managed cloud service is needed for transport, storage, identity,
state, orchestration, or recovery.

Dev Box is optional consumed capacity, not Steward infrastructure. Model,
source, package, and evaluation APIs are Workload-selected targets only.
Deployment validation must prove both the positive Local Stack composition and
the absence of subscription-management, cloud-provisioning, intermediary
service, and cloud-state dependencies.

## Related documents

- [Contracts and state model](contracts.md)
- [Security and threat model](security.md)
- [Evidence-gated implementation plan](implementation-plan.md)
- [Validation and evidence register](open-questions.md)
- [RDP DVC transport](rdp-dvc-transport.md)
