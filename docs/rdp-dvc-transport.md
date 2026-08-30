# Steward RDP dynamic virtual channel transport

## Boundary

The Windows-only reverse-connect carrier is implemented in three production
projects:

| Project | Responsibility |
| --- | --- |
| `Steward.RdpDvc.Client.Windows` | Per-user, out-of-process COM LocalServer loaded by the RDP client |
| `Steward.Transport.Rdp.Windows` | DVC protocol, authenticated stream adapter, WTS session/channel endpoint, registration, reconnect |
| `Steward.RdpDvc.Server.Windows` | Session-0-safe remote console/service diagnostic host |

The carrier exposes `ITransportStreamConnector`/`ITransportStreamAcceptor`.
`SecureStreamCarrier` and `SecureStreamConnectionAcceptor` run the existing
Steward signed ECDH handshake, encryption, `TransportFrame` multiplexing,
bounds, and sequence checks above that stream. RDP security and the DVC HMAC
PING/PONG are not substitutes for Steward peer enrollment or secure transport.

The implementation is out of process. It contains no in-process RDP DLL,
injection, API hook, or reconstructed AVD gateway connection.

## Stable identity

- COM CLSID: `{6F26730D-9E8C-4D94-A7F6-79A2ED5CB28D}`
- DVC name: `steward::transport::v1`
- protocol version: `1`
- AddIns name: `StewardRdpDvcTransport`
- local broker pipe: `Steward.RdpDvc.Transport.v1.<per-user SID hash>`

The pipe is current-user-only and carries bounded, length-prefixed DVC PDUs.
Each PDU authenticates version, Steward session, Host, Node incarnation,
actual RDP session ID, incarnation nonce, contiguous sequence, timestamp, and
payload with HMAC-SHA-256. PING/PONG is time bounded. Data remains bounded and
then receives the normal Steward signed/encrypted session protection above it.

## Client registration

Publish and register on the machine running Microsoft Windows App:

```powershell
$dotnet = 'dotnet'
& $dotnet publish `
  src\Steward.RdpDvc.Client.Windows\Steward.RdpDvc.Client.Windows.csproj `
  -c Release -r win-x64 --self-contained true `
  -o artifacts\rdp-dvc-client
& artifacts\rdp-dvc-client\Steward.RdpDvc.Client.Windows.exe /register
```

Registration is per-user only and writes exactly:

```text
HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\StewardRdpDvcTransport
  Name = {6F26730D-9E8C-4D94-A7F6-79A2ED5CB28D}
HKCU\Software\Classes\CLSID\{6F26730D-9E8C-4D94-A7F6-79A2ED5CB28D}
  (Default) = Steward RDP DVC Transport v1
HKCU\Software\Classes\CLSID\{6F26730D-9E8C-4D94-A7F6-79A2ED5CB28D}\LocalServer32
  (Default) = "<absolute executable>" -Embedding
```

Before writing, registration rejects relative or missing executables, empty
files, any reparse point in the path, and executables writable by an
untrusted principal. It reads all three values back with exact type/content.
`/unregister` deletes only those two Steward-owned key trees. No elevation is
used. Run `--diagnostics` to host the same COM class in the foreground.

Registration must occur before starting or fully reconnecting the RDP client.
The Windows Desktop remote-viewer tab reads this exact registration and can
explicitly repair it from the published sibling executable. It continues to
display `DvcPluginRegisteredActivationPending` until live Windows App COM
activation and the remote session-0 endpoint pass; registration alone is
never shown as a working DVC.

## Remote endpoint

`WtsRdpDvcWireChannelSource` enumerates WTS sessions, filters to active RDP
sessions, and refuses zero or multiple matches unless an exact requested
session ID produces one match. It passes that numeric ID to
`WTSVirtualChannelOpenEx`; it never passes `WTS_CURRENT_SESSION`.

The endpoint uses bounded PDU reassembly and serialized writes. Reads use
short WTS timeouts so cancellation and disconnect are observed. A hidden
session-0 message window subscribes with
`WTSRegisterSessionNotificationEx(..., NOTIFY_FOR_ALL_SESSIONS)` where that
API/window station is available; the adapter falls back to bounded polling.
Disconnect closes the channel. Reconnect re-enumerates and reauthenticates
with a fresh nonce.

The server diagnostic can run as LocalSystem or `NT SERVICE\Steward.Node`:

```powershell
Steward.RdpDvc.Server.Windows.exe `
  --session-id STEWARD_SESSION_GUID `
  --host-id HOST_GUID `
  --incarnation-id NODE_INCARNATION_GUID `
  --auth-key-file C:\ProgramData\Steward\keys\rdp-dvc.key `
  --once
```

The key file contains 32–64 random bytes and must be ACL-protected for the
Node service identity. IDs, numeric RDP session, sequence, RTT, and reconnect
count are safe diagnostics. Keys, PDU payloads, signed `ms-avd` URIs, and
tokens are never logged.

## Fail-closed RDCore live acceptance

`tests\Steward.RdpDvc.LiveAcceptance` exercises the lower RDCore
`ConnectionHost` path. It never invokes `ms-avd` through `Process.Start`,
ShellExecute, a packaged protocol handler, `ConnectionShell`, or Windows App.
The provider resource is passed only in a typed `Resolve` command over a
random current-user-only `ConnectionHost` pipe. The runner then sends typed
`Prepare`, `Connect`, and `Disconnect` commands; it never sends `View` or
`TakeControl`.

Before the first `Connect`, the runner snapshots every process, every
top-level window, the visible top-level-window set, and the foreground
window. It continues sampling while both generations run. A visible-window
set or foreground change fails acceptance immediately. It retains process
handles only for newly observed `msrdc`/Windows App/RDCore package processes
and terminates only those exact handles on a violation; unrelated processes
are never terminated.

The runner fails before connection unless all of these checks pass:

1. the installed Windows 365/RDCore package matches the pinned compatibility
   fingerprint;
2. the WAM connection identity is ready and still matches `devbox/default`;
3. the HKCU AddIns/COM registration is the exact Steward CLSID, AddIns name,
   description, and LocalServer command;
4. `DevBoxIdentityService` opens the existing `devbox/default` identity and
   typed `DevBoxesClient.GetRemoteConnectionAsync` returns the exact bounded
   `ms-avd:connect` shape for the configured endpoint/project/user/box;
5. a dual-signed bootstrap deployment receipt proves the exact endpoint
   bundle, scheduled task, running endpoint process, session/Host/incarnation,
   and two distinct unused nonces in `waitingForActiveRdpSession`; it must not
   contain a DVC-ready flag, WTS ID, or authenticated-generation collection;
6. the runner creates two deterministic nonce references and current-user
   DPAPI tickets from that receipt, reads each back as the exact base route
   with WTS left unspecified (`0`); and
7. the independent live-connect and cloud-read consent phrases are exact.

The AVD feed URI is not supplied by the operator. It is derived from the
bound tenant as
`https://www.wvd.microsoft.com/api/arm/feeddiscovery?aadtenant=<tenant>`.
Neither that feed nor the provider-issued `ms-avd` value is printed or
persisted.

For each generation, `ConnectionHost` accepts readiness only after ordered
evidence for RDCore connected, WTS plug-ins loaded, Steward COM activation,
`IWTSPlugin.Initialize`, exact `steward::transport::v1` channel open,
HMAC-authenticated PING/PONG, and signed ECDH peer authentication. The runner
disconnects, reconnects with a different single-use authorization token and
receipt-derived nonce reference, and requires both a strictly newer connection
generation and a different nonce.

Configure sensitive values through environment variables rather than shell
history:

```powershell
$env:STEWARD_DEVBOX_ENDPOINT = 'https://CONTOSO-DEVCENTER.DEVCENTER.AZURE.COM/'
$env:STEWARD_DEVBOX_PROJECT = 'PROJECT'
$env:STEWARD_DEVBOX_USER = 'me'
$env:STEWARD_DEVBOX_BOX_NAME = 'EXISTING-BOX'
$env:STEWARD_RDCORE_SESSION_ID = '...'
$env:STEWARD_RDCORE_HOST_ID = '...'
$env:STEWARD_RDCORE_NODE_INCARNATION_ID = '...'
$env:STEWARD_DVC_EVIDENCE_PIPE_NAME = 'Steward.RdpDvc.Evidence.v1'
$env:STEWARD_DVC_EVIDENCE_KEY_FILE = 'C:\PROTECTED\evidence.key'
$env:STEWARD_DVC_EVIDENCE_TICKET_DIRECTORY = 'C:\PROTECTED\tickets'
$env:STEWARD_RDCORE_CONTROL_SIGNING_PUBLIC_KEY_FILE = 'C:\PROTECTED\control.pub'
$env:STEWARD_RDCORE_CONTROL_IDENTITY = 'control-identity'
$env:STEWARD_RDCORE_NODE_SIGNING_PUBLIC_KEY_FILE = 'C:\PROTECTED\node.pub'
$env:STEWARD_RDCORE_NODE_IDENTITY = 'node-identity'
$env:STEWARD_RDCORE_BOOTSTRAP_RECEIPT = 'C:\PROTECTED\bootstrap-attested.json'
$env:STEWARD_RDCORE_BOOTSTRAP_OPERATION_ID = '...'
$env:STEWARD_RDCORE_BOOTSTRAP_BUNDLE_VERSION = '1.0.0'
$env:STEWARD_RDCORE_BOOTSTRAP_ARCHIVE_SHA256 = '64_HEX_CHARACTERS'
$env:STEWARD_RDCORE_LIVE_EVIDENCE_DIRECTORY = 'artifacts\rdcore-live'
$env:STEWARD_RDCORE_LIVE_ACCEPTANCE = 'I_UNDERSTAND_RDCORE_LIVE_ACCEPTANCE_CONNECTS_WITHOUT_VIEW'
$env:STEWARD_RDCORE_LIVE_CLOUD_READ = 'I_UNDERSTAND_RDCORE_LIVE_ACCEPTANCE_READS_EXISTING_CONNECTION_METADATA'

& dotnet run `
  --configuration Release `
  --project tests\Steward.RdpDvc.LiveAcceptance\Steward.RdpDvc.LiveAcceptance.csproj
```

The receipt is the `AttestedDevBoxRdpDvcBootstrapReceipt` emitted by
`tools\Steward.DevBox.BootstrapDeploy`. The runner may consume an existing
receipt, or invoke that exact tool first by setting
`STEWARD_RDCORE_BOOTSTRAP_DEPLOY_EXECUTABLE` and
`STEWARD_RDCORE_BOOTSTRAP_DEPLOY_ARGUMENTS_FILE`, with the exact executable or
managed-tool digest in `STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TOOL_SHA256`. The
arguments file is a JSON string array and must target the same endpoint/project/user/box,
operation/session/Host/incarnation, attested receipt, and signing identities.
It must contain the deployment tool's own exact consent. Invocation also
requires:

```text
STEWARD_RDCORE_BOOTSTRAP_DEPLOY_CONSENT=I_UNDERSTAND_BOOTSTRAP_DEPLOY_MUTATES_THE_RETAINED_DEV_BOX_CUSTOMIZATION
```

The optional deployment timeout defaults to 1800 seconds and is bounded by
`STEWARD_RDCORE_BOOTSTRAP_DEPLOY_TIMEOUT_SECONDS`. Tool output is suppressed;
failure reports only the bounded failure type.

Bootstrap deployment mutates only customization on the named retained box and
remains separately gated. The runner contains no create/delete API and cannot
provision another box. Cloud metadata reads and live RDCore connection remain
independently consent-gated. Evidence records package and
registration metadata, hashed window/process sets and nonces, generations,
ordered event names, and bounded timing only; signed URIs, authorization
tokens, keys, payloads, usernames, and raw exception messages are excluded.
Exit `64` means consent was absent, `130` means cancellation, `1` means
fail-closed rejection, and `0` means both generations passed.

The DVC components remain delivered and offline-testable, but the interactive
Windows App path is blocked for production acceptance. The supported
`ms-avd:connect` activation contract is interactive and the observed launch
created a visible fullscreen window. No supported Windows App option or API
available to Steward establishes that AVD session without a visible window.
Hidden, minimized, fullscreen, off-screen, or automatically dismissed windows
do not satisfy the headless requirement.

Windows App version `2.0.1315.0` contains package metadata for an internal
`ConnectionService` whose WinRT metadata includes `ConnectionMode.Silent`.
That runtime class is scoped to the Windows App package graph: activation from
an unpackaged Steward process returns `REGDB_E_CLASSNOTREG`. The package's
hidden `ConnectionShell` application creates presentation windows even
without a resource. It cannot run on the user's interactive desktop.
Static inspection identified the lower RDCore boundary used by Windows App.
`Steward.RdCore.Windows` now pins and verifies the installed package, resolves
the AVD workspace feed, creates RDCore connections with
`ConnectionMode.Silent`, forwards claims challenges through account-bound WAM,
and configures third-party DVC loading without invoking the Windows App shell.
`Steward.ConnectionHost.Windows` owns multiple generation-bound connections,
single-use broker material, restart metadata, and current-user-only IPC.

`WindowsAppIsolatedDesktopHost` is retained as an internal, disabled
containment probe only. It rejects any pre-existing Windows App process,
creates a named non-default desktop, and checks the returned process threads,
but packaged protocol activation can receive the URI before that post-launch
inspection. A PID also does not own Windows App's brokered `msrdc` process
group. Those gaps prevent the probe from satisfying production headless
acceptance or being wired into Desktop/Control. The production session broker
must guarantee placement before dispatch and retain ownership of the complete
connection process group.

Transport readiness is monotonic and requires RDCore connected, WTS plug-in
enumeration, Steward COM activation, `IWTSPlugin.Initialize`, exact channel
open, HMAC PING/PONG, and secure ECDH peer authentication for the same
generation. WTS plug-in enumeration alone never establishes readiness.
Production composition fails before RDCore creation unless its authenticated
DVC evidence publisher, protected route ticket, and evidence reference are
configured. Connect carries only the opaque evidence reference; the
current-user DPAPI ticket is bound before RDCore Connect to connection ID,
runtime ID, generation, and the exact session/Host/incarnation/nonce base
route with wildcard WTS `0`. Broker routing protocol v2 authenticates that
base plus nonce. Only a fully HMAC-validated first PING may supply the actual
positive WTS session, which is then written immutably into the bound ticket
for that generation. The unbound ticket is consumed once; the bound file is
removed when the generation completes or fails. It contains neither the DVC
or publication key nor the provider URI.
The COM LocalServer and local DVC/secure-transport callbacks publish bounded,
HMAC-authenticated, sequenced events over a current-user-only pipe. The first
real Connect and zero-visible-window evidence remain explicit live acceptance
gates. Deterministic validation uses local pipes and in-memory DVC streams
only; do not run the live command until remote bootstrap has supplied those
artifacts.

Do not adopt an in-process hook or a window-hiding workaround. If the second
Windows API gate later proves prohibited, the only permitted fallback is a
signed, least-privilege per-session helper that owns only the WTS channel and
hands its bounded stream to the Node service over an ACL-restricted
authenticated pipe.

## Microsoft sample attribution

The COM interface declarations, LocalServer/class-factory sequence, and WTS
PDU/channel patterns are adapted from Microsoft's official
`microsoft/rdp-dvc-plugin-samples` Simple/Advanced .NET samples. Those samples
are MIT licensed. The Microsoft copyright headers remain on adapted source,
and the complete license is preserved as
`src/Steward.Transport.Rdp.Windows/Microsoft.RdpDvcSamples.LICENSE.txt`.
