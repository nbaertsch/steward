# Dev Box RDP reverse-connect live acceptance

## Evidence status

**Partially run on 2026-08-27.** The retained harness created and recovered
`steward-rdp-20260827-b1` in `MDE / 1ES-Enhanced-WUS2`. The provider returned a
signed `ms-avd:connect` resource reference, not an HTTPS `.rdp` profile.
Activating that reference launched Microsoft Windows App
`MicrosoftCorporationII.Windows365` and opened the real Dev Box desktop. The
session was visible and fullscreen, so it fails the required headless/no
visible session criterion. There is no supported Windows App headless
activation contract available to Steward; minimized, hidden, off-screen, or
fullscreen activation is not accepted.

The production Steward dynamic virtual channel (DVC) components are
implemented and offline tested. The supported Windows App shell path remains
disqualified. A separate fail-closed runner now targets the lower RDCore
`ConnectionHost` path in silent mode without shell/protocol activation. Its
fake suite has passed; the live RDCore run has deliberately not been started.

The original ActiveX profile hypothesis is not the Dev Box path for this Pool.
`Steward.Rdp.Windows` remains valid only for providers that return a signed
HTTPS `.rdp` profile. Dev Box transport work now targets Windows App's
documented out-of-process DVC plug-in registration and the provider-issued
`ms-avd` resource.

The RDCore live extension is
`tests/Steward.RdpDvc.LiveAcceptance/Steward.RdpDvc.LiveAcceptance.csproj`.
It obtains the existing provider resource in memory from typed
`DevBoxesClient.GetRemoteConnectionAsync`, passes it only as typed
`ConnectionHost` `Resolve` data, and never shell- or protocol-activates it.
The AVD feed is derived from the tenant bound to `devbox/default`. It independently
verifies installed package compatibility, the `devbox/default`-bound
connection identity, exact DVC registration, a signed pre-connect bootstrap
deployment receipt, locally created wildcard-WTS tickets, and explicit
live/cloud-read consent. It monitors all top-level
windows, foreground state, and processes before `Connect`, never invokes
`View`, and fails closed on any visible-surface change. Production design,
the strict bootstrap schema, and the eventual live command are in
[RDP DVC transport](../rdp-dvc-transport.md).

The harness is
`tests/Steward.DevBox.LiveAcceptance/Steward.DevBox.LiveAcceptance.csproj`.
Reusable parsing, download-boundary, mstscax hosting, configuration, event
capture, classification, and gateway-socket proof live in
`src/Steward.Rdp.Windows`.

## Safety and lifecycle contract

- The only cloud client is `Azure.Developer.DevCenter` 1.0.0 against the
  configured developer endpoint.
- Identity is the existing production WAM-backed `devbox/default` context.
  There is no fallback identity.
- The first mutation creates exactly one named Dev Box in an existing Pool.
  `WaitUntil.Started` is followed by `UpdateStatusAsync` on that exact SDK
  operation, and the operation ID must remain unchanged.
- `state.json` is durably written before and immediately after submission. A
  pre-existing box is never adopted. If a process ends in `CreateStarted`, the
  next run refuses to submit another create because SDK 1.0.0 cannot rehydrate
  that exact operation instance. Inspect the preserved box and state before a
  deliberate recovery.
- A failed box is always preserved. Deletion occurs only when
  `--delete-evidence-box` (or its exact environment equivalent) is present and
  Test 4 has passed.
- Signed URLs, RDP content, authorization headers, access tokens, and raw
  exception messages are not logged or persisted.
- No infrastructure, VM, storage, relay, tunnel, or management-plane tooling
  is used.

## Prerequisites

1. A compatible installed Windows 365/Windows App package containing the
   pinned RDCore artifacts. The RDCore runner does not invoke its packaged
   `ms-avd` protocol handler. The built-in `mstscax.dll` control is tested
   separately for providers that return HTTPS `.rdp` profiles.
2. A completed `steward identity devbox login` for `devbox/default`.
3. An existing Dev Center endpoint, project, Pool, and authorized user.
4. A unique evidence box name and a new/private evidence directory.
5. A dual-signed bootstrap deployment receipt proving the scheduled endpoint
   package/task/process is waiting for its first active RDP session, plus the
   authenticated DVC evidence publisher. The runner creates two single-use
   wildcard-WTS nonce tickets locally. Windows App protocol activation does
   not satisfy this prerequisite.

For Dev Box, Windows App owns the AVD resource connection and reverse-connect
gateway session. Steward validates the provider-issued `ms-avd` metadata but
does not activate it in headless acceptance because its supported activation
is visible. Steward's client-side DVC component uses the documented per-user
out-of-process COM AddIns model and does not inject, hide windows, or
reconstruct gateway settings.

### COM provenance

No third-party hook or RDP package and no generated AxInterop assembly is used.
The IIDs, CLSID, DISPIDs, and signatures in `MstscInterop.cs` are the public
Microsoft mstscax type-library contracts. They were checked against the
installed Microsoft `%WINDIR%\System32\mstscax.dll` type library using
`LoadTypeLibEx`/`ITypeLib` on Windows. Relevant Microsoft documentation:

- <https://learn.microsoft.com/windows/win32/termserv/using-the-remote-desktop-activex-control>
- <https://learn.microsoft.com/windows/win32/termserv/imsrdpclienttransportsettings4>
- <https://learn.microsoft.com/windows/win32/termserv/imsrdpextendedsettings>
- <https://learn.microsoft.com/windows/win32/termserv/imstscaxevents-interface>

## Exact live command

From the repository root in a normal interactive Windows session:

```powershell
dotnet run --configuration Release `
  --project tests\Steward.DevBox.LiveAcceptance\Steward.DevBox.LiveAcceptance.csproj `
  -- `
  --endpoint https://CONTOSO-DEVCENTER.DEVCENTER.AZURE.COM/ `
  --project PROJECT `
  --pool POOL `
  --user me `
  --box-name steward-rdp-evidence-UNIQUE `
  --evidence-directory artifacts\devbox-rdp-evidence-UNIQUE `
  --allow-billable-create
```

Equivalent typed configuration variables are:

| Argument | Environment variable |
|---|---|
| `--endpoint` | `STEWARD_DEVBOX_ENDPOINT` |
| `--project` | `STEWARD_DEVBOX_PROJECT` |
| `--pool` | `STEWARD_DEVBOX_POOL` |
| `--user` | `STEWARD_DEVBOX_USER` |
| `--box-name` | `STEWARD_DEVBOX_BOX_NAME` |
| `--evidence-directory` | `STEWARD_DEVBOX_EVIDENCE_DIRECTORY` |

Environment opt-in requires the exact value:

```text
STEWARD_DEVBOX_LIVE_ACCEPTANCE=I_UNDERSTAND_THIS_CREATES_A_BILLABLE_DEV_BOX
```

Set `STEWARD_DEVBOX_DELETE_EVIDENCE_BOX=true` or add
`--delete-evidence-box` only when successful gateway evidence no longer needs
the box. Cleanup is never inferred.

## Gates and criteria

1. **Exact create LRO** passes only when the typed SDK returns the configured
   box, project, and Pool from the same operation ID.
2. **Typed remote connection** passes only when `GetRemoteConnection` returns
   a bounded `ms-avd:connect` resource with the expected environment,
   workspace, resource, username, version, and preview parameter names.
3. **Headless Windows App resource activation** is blocked. The provider
   returned bounded `ms-avd:connect` metadata, but supported activation opened
   a visible fullscreen Windows App window. Subsequent no-resource
   `ConnectionShell` characterization also created presentation surfaces and
   disrupted the active workstation session. This shell/protocol route stays
   prohibited; the lower silent RDCore path is evaluated separately.
4. **AVD gateway connectivity** was observed through `msrdc` TLS connections,
   but fails acceptance because its owning session was visible.
5. **Fail-closed RDCore ConnectionHost** is implemented but not live-run.
   Success requires no visible-window-set or foreground change, ordered
   RDCore/WTS/COM/plugin/exact-channel/HMAC/ECDH evidence, then disconnect and
   reconnect with a strictly newer generation and different attested nonce.
   The normal signed/encrypted Steward transport handshake remains above DVC;
   RDP security is not treated as Steward peer identity.

Exit codes:

- `0`: every implemented and required RDCore gate passed for two fresh
  generations; not exercised during implementation.
- `1`: failed; preserve the box and inspect evidence.
- `2`: the legacy Dev Box create/gateway harness passed its gateway gate and
  directs the operator to the separate RDCore extension.
- `3`: reserved for the older blocked Windows App/DVC-only harness evidence.
- `64`: the RDCore runner did not run because either exact live-connect or
  cloud-read consent was absent.
- `130`: cancelled; durable state and any box are preserved.

Evidence is written as `state.json` plus immutable
`evidence-<run-id>.json`. A Test 4 pass requires
`RDP_GATEWAY_LOGIN_SUCCEEDED`, `GatewayUseObserved: true`, and both connection
events. Raw URLs and tokens must not appear.

## Offline validation

```powershell
$dotnet = 'C:\Users\noahbaertsch\.dotnet\dotnet.exe'
& $dotnet test `
  tests\Steward.RdpDvc.LiveAcceptance\Steward.RdpDvc.LiveAcceptance.csproj `
  --configuration Release
& $dotnet test `
  tests\Steward.Transport.Rdp.Windows.Tests\Steward.Transport.Rdp.Windows.Tests.csproj `
  --configuration Release
& $dotnet build Steward.slnx `
  --configuration Release
& $dotnet test Steward.slnx `
  --configuration Release --no-build
```

These tests cover parser injection, duplicates and size bounds; download
origin, redirect and response bounds; token non-disclosure; fake-backed
ActiveX mapping; and timeout/error classification. They do not call Dev Box or
prove a live gate.

The RDCore live project has fake tests for independent consent, typed
Resolve/Prepare/Connect/Disconnect ordering, absence of View/TakeControl,
fail-closed visible-surface handling, typed Dev Box remote-resource
retrieval, signed pre-connect receipt verification, wildcard-WTS binding,
ordered evidence, fresh generation/nonce enforcement, and evidence secret
rejection. These tests do not invoke RDCore or make a live/cloud call.

## Implementation verification record

On 2026-08-27, the available machine had .NET SDK 9.0.317 but not the
repository-pinned .NET SDK 10.0.400. For offline source validation only, the
new projects and their existing project-reference chain were temporarily
retargeted to `net9.0`/`net9.0-windows`, then restored to their committed
`net10.0` targets:

- 18 `Steward.Rdp.Windows.Tests` tests passed;
- the live acceptance executable and all references built with zero warnings
  and zero errors; and
- a no-consent invocation exited 64 before constructing the live runner or
  making any network/API call.

The pinned .NET 10.0.400 SDK is now the required build/test tool. The
load-bearing blocker is now explicit:

- the complete solution built with zero warnings and zero errors under SDK
  10.0.400;
- the complete solution build/test passed, and the final focused production
  DVC run passed;
- self-contained win-x64 client and server publishes succeeded and contained
  the preserved Microsoft MIT license; and
- no live cloud API, signed URI, current session, or retained evidence-box
  mutation was used during implementation validation.

1. obtain a supported AVD connection mechanism that creates no visible
   window;
2. then prove it loads the standard HKCU AddIns LocalServer;
3. prove `NT SERVICE\Steward.Node`/LocalSystem can open the exact session; and
4. record authenticated PING/PONG across disconnect/reconnect.

Stop now for the Windows App path. Do not use an in-process hook, window-hiding
automation, minimized launch, or a user-session helper to manufacture
headlessness.
