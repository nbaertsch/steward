# Microsoft Dev Box user-provider evidence

## Status

**Narrowed, not closed.** The Microsoft Dev Box developer/user-facing API and
`Azure.Developer.DevCenter` SDK expose discovery and user lifecycle operations
for already-authorized projects, Pools, and Dev Boxes. Live identity,
capability, long-running-operation, bootstrap, and negative-boundary evidence
remain before E-08 closes.

This adapter is optional and separate from the Local Stack. It consumes
approved Host capacity; it does not provision Steward infrastructure.

## Approved surface

The adapter may use only the Microsoft Dev Box developer/user endpoint and SDK
to:

- list projects and Pools visible to the current user where supported;
- list and inspect the user's boxes;
- create a named box in an existing Pool;
- start, stop, restart, repair, or restore when the selected API/SDK advertises
  the capability;
- delete a box; and
- inspect and reconcile the resulting user-API long-running operation.

Every mutation produces a durable `ProviderOperationId`. Control persists an
authenticated opaque operation handle and reconciles after restart rather than
holding an in-memory SDK wait.

Capability absence is explicit. A user request for unsupported replacement
behavior may be modeled as a visible, resumable sequence of supported delete
and create operations after Core drain gates pass. It is not represented as an
atomic provider effect.

## Prohibited surface

The adapter must not:

- call subscription or ARM management endpoints;
- depend on subscription IDs, resource groups, ARM resource IDs, or deployment
  credentials;
- invoke `az`, Azure PowerShell, Bicep, ARM templates, Terraform, or another
  provisioning tool;
- call Azure VM create/deploy/manage APIs;
- create or modify Dev Centers, projects, Pools, networks, policies, identity
  infrastructure, storage, databases, or intermediary services;
- provide Steward transport, portable storage, credential renewal, Control
  hosting, or recovery infrastructure; or
- use an external API that is unrelated to the Dev Box user lifecycle.

Endpoint, project, Pool, network, policy, and authorization are pre-existing
inputs owned by the user's organization. The adapter fails closed when they do
not exist or the user lacks permission.

## Native identity and inventory boundary

Steward has exactly one versioned named user context: `devbox/default`.
`steward identity devbox login` runs only its WAM
account picker on an STA thread and uses `Azure.Identity.Broker`; it has no
browser, default-credential, CLI, PowerShell, azd, environment, workload, or
managed-identity fallback. The Azure Identity `AuthenticationRecord` is
atomically committed with typed context metadata. Tokens use the dedicated
DPAPI-protected `steward.devbox.default.msal.cache` cache and are never written
to Steward state.

`status`, `discover`, and provider composition reload the record and call
`GetTokenAsync` with automatic interactive authentication disabled. They never
call `AuthenticateAsync`. Login is the sole authentication entry point.
Logout removes the matching account through MSAL's WAM broker, clears and
deletes the isolated cache, verifies removal, and only then removes the
context.

`steward devbox discover` calls only
`https://{tenantId}.discovery.devcenter.azure.com/projects` with
`https://devcenter.azure.com/.default`, bounds every discovery `nextLink` to
that HTTPS tenant origin and `/projects` path, validates returned Dev Center
service endpoints, then uses the typed `Azure.Developer.DevCenter` clients to
enumerate Pools and `me` Dev Boxes. Its immutable versioned output includes
the complete Pool sizing/image/policy data and existing membership needed by
later policy selection. Discovery does not mutate or provision resources.

Provider credentials are never sent to a Node or Task. Listing a box does not
prove authority to mutate it; each operation honors the API result.

## Node bootstrap boundary

The provider may hand a newly available Host to an approved Node bootstrap and
enrollment workflow. That workflow must:

1. install a signed Node package through an approved Host-level mechanism;
2. contain no reusable Control or provider credential;
3. establish the configured direct peer route without creating network
   infrastructure;
4. bind enrollment to Host, provider resource, Node key, and new incarnation;
5. repeat after replacement; and
6. report partial installation without converting provider success into Node
   readiness.

Bootstrap cannot use subscription/ARM/VM deployment authority. If no approved
user-level mechanism exists, automatic bootstrap is unsupported and the Host
remains unenrolled.

## Executable matrix

1. With an intended user identity, discover a pre-existing project/Pool and
   existing boxes.
2. Create the same name twice and record idempotency and exact LRO behavior.
3. Exercise each advertised lifecycle capability and one unsupported
   capability.
4. Restart Control after every operation boundary and reconcile the same
   protected handle.
5. Replace a box through the explicit supported sequence and prove a new Node
   incarnation.
6. Exercise unauthorized project/Pool/user, stale callback, throttling, and
   provider outage.
7. Bootstrap/enroll without subscription or infrastructure authority.
8. Capture HTTP hosts, paths, methods, SDK assemblies, processes, and
   configuration fields.
9. Run static scans for management-plane SDKs, `az`, deployment templates,
   resource-group/subscription/VM provisioning calls, and prohibited fallback
   credentials.
10. Record latency, failure modes, and user-visible recovery steps.

## Deployment evidence

The evidence bundle identifies the pre-existing Dev Center endpoint, project,
and Pool without publishing secrets. It records:

- `Azure.Developer.DevCenter` package and API versions;
- the allowed endpoint/path set and redacted request trace;
- operation capability and LRO results;
- dependency and artifact negative scans;
- process/egress inventory;
- confirmation that no Steward cloud resource was created; and
- a ledger distinguishing any created Dev Box from infrastructure (it is a
  user-requested Host inside an already-administered Pool).

## Contract consequence

Dev Box-specific endpoint, project, Pool, user, box, and protected operation
handle data stays inside provider extensions. Core lifecycle and Pool contracts
remain generic. Provider observations never imply Node readiness or Task
success.

## Sources

- [Azure Dev Center developer REST API](https://learn.microsoft.com/en-us/rest/api/devcenter/developer/)
- [Dev Box developer operations](https://learn.microsoft.com/en-us/rest/api/devcenter/developer/dev-boxes)
- [Azure.Developer.DevCenter .NET package](https://www.nuget.org/packages/Azure.Developer.DevCenter)
- [Azure.Developer.DevCenter API overview](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/developer.devcenter-readme)
