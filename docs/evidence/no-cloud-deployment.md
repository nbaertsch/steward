# No-cloud-infrastructure deployment evidence

## Status

**Narrowed (E-10).** Static dependency analysis, package inventory, code
scan, and loopback binding validation are complete. Remaining: signed release
evidence bundle from clean Windows install, runtime egress trace, and reviewer
signoff.

## Static evidence (2026-08-29)

### Package inventory

All NuGet package references in `src/` are classified:

| Category | Packages |
| --- | --- |
| Data/state | Microsoft.Data.Sqlite 10.0.4, SQLitePCLRaw.bundle_e_sqlite3 |
| Identity (WAM) | Azure.Identity 1.17.0, Azure.Identity.Broker 1.3.0, Microsoft.Identity.Client 4.77.0, Microsoft.Identity.Client.Broker 4.77.0, Microsoft.Identity.Client.Extensions.Msal 4.77.0 |
| Dev Box user SDK | Azure.Developer.DevCenter 1.0.0 |
| Framework | Microsoft.Extensions.Hosting, .Configuration.Binder, .DI.Abstractions, .Logging.Abstractions |
| Crypto/ACL | System.Security.Cryptography.ProtectedData 10.0.0, System.IO.FileSystem.AccessControl 5.0.0 |
| MCP | ModelContextProtocol.AspNetCore 2.2.0 |
| RDCore hook | Lib.Harmony 2.4.2 |
| Azure core (auth) | Azure.Core 1.49.0 |

**Prohibited packages found: 0** — no Azure.ResourceManager, Azure.Storage,
Azure.Messaging, Azure.SignalR, or Microsoft.Azure.Management references.

### Infrastructure provisioning code

**None found.** Scanned `src/` and `scripts/` for `az` CLI, ARM templates,
Bicep, Terraform, and Azure PowerShell provisioning commands.

### Local Stack port resolution

| Core port | Local Stack binding |
| --- | --- |
| Transport | Direct WebSocket peer (`LocalDirectTransportFactory`) |
| Portable objects | Content-addressed filesystem (`LocalStackContentAddressedObjectStore`) |
| Credentials | DPAPI OS vault (`DpapiProtectedIdentityVault`) |
| Durable state | SQLite WAL (`SqliteControlStore`, `NodeJournal`) |
| Host runtime | Windows Job Objects, processes, ConPTY |

### Loopback binding

Control binds to `http://127.0.0.1:5112` by default with
`LoopbackBindingValidator.Validate()` and `AllowedHosts` restricted to
`localhost`, `127.0.0.1`, `[::1]`.

### Core neutrality

Domain and Contracts depend only on `System.*` — zero concrete transport,
storage, identity, provider, or runtime dependency. Scheduling depends on
`Steward.Domain`, `Steward.Contracts`, and `Steward.Providers.Abstractions`
(all neutral interfaces).

## Invariant under test

The complete Local Stack resolves Steward transport, portable objects,
credentials, durable state, and Host runtime to:

- authenticated direct peer connections;
- content-addressed filesystem replication;
- OS-protected credential storage and direct-session delivery;
- SQLite WAL; and
- Windows.

It provisions or operates no Steward remote service. The optional Dev Box
adapter consumes user-authorized boxes in an existing project and Pool through
the Microsoft developer/user API and SDK only. Other external endpoints are
declared Workload targets.

## Evidence bundle

Store the following release evidence together:

| Artifact | Required contents |
| --- | --- |
| Build identity | Commit, release/package hashes, SBOM, SDK/runtime versions |
| Topology | Redacted hosts, processes, services, listeners, SQLite/object roots and declared failure domains |
| Composition | Validated configuration showing every required Core port and no unbound fallback |
| Clean install | Repeatable install/start/stop procedure on clean Windows Control and Node systems |
| Durable-work run | Delegation, Control disconnect, Node completion, direct reconnect and exact reconciliation |
| Filesystem run | Interrupted replication, corruption rejection, receipts, spool quotas and recovery |
| Credential run | Vault reference, bounded delivery, expiry, scrub, cross-Task denial and leakage scan |
| Product journeys | Harbor/Saber, multi-turn Agent replay/migration and managed terminal results |
| Dependency scan | Active project/package closure and prohibited infrastructure-client negative results |
| Artifact scan | Negative results for infrastructure templates, deployment scripts and subscription/VM provisioning calls |
| Egress capture | Every destination classified as direct peer, Dev Box user endpoint, Workload target, or documented package/update source |
| Dev Box trace | When enabled: SDK/API versions, allowed hosts/paths, capabilities, LRO recovery and negative-boundary tests |
| Provisioning ledger | Every created object, with confirmation that no Steward remote resource was created |

Secrets, private source, tokens, certificate keys, tenant data, and unredacted
user identifiers must not be placed in the evidence bundle.

## Required negative tests

1. Start ordinary Local Stack work with no subscription, remote storage,
   intermediary, remote credential-service, or cloud database configuration.
2. Remove direct reachability and verify there is no alternate connection.
3. Search the active dependency closure and process tree for prohibited
   infrastructure-management clients and tools.
4. Reject a Dev Box configuration containing infrastructure-management fields.
5. Deny or remove Dev Box access and verify only provider operations fail;
   local Control, existing direct Nodes, local state, Agents, eval planning, and
   terminal remain functional.
6. Configure an external model/source/package endpoint only inside a Workload
   and verify it is absent from Steward deployment health requirements.
7. Compare the provisioning ledger before and after the run.

## Passing statement

E-10 may close only with a statement of this form:

> On the recorded release, topology, configuration, dependency, artifact,
> credential, egress, and provisioning evidence shows that Steward ran its
> complete Local Stack without provisioning or operating cloud
> infrastructure. Optional Dev Box traffic was limited to the approved
> Microsoft user-facing API/SDK against pre-existing administrative resources,
> and all other external traffic was attributable to explicit Workload targets
> or documented package/update retrieval.

Any exception keeps E-10 open and blocks the no-cloud-infrastructure claim.

## Related evidence

- [Direct peer transport](direct-peer-transport.md)
- [Filesystem portable state](portable-state.md)
- [Local credential delivery](credential-delivery.md)
- [Dev Box user provider](dev-box-provider.md)
- [Validation and evidence register](../open-questions.md)
