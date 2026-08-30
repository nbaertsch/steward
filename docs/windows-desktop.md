# Steward Windows Desktop

`Steward.Desktop.Windows` is the native Windows operations adapter. The Local
Stack installer publishes it and creates a Start menu shortcut named
**Steward**. For development:

```powershell
dotnet run --project src\Steward.Desktop.Windows\Steward.Desktop.Windows.csproj
```

The client reads `STEWARD_CONTROL_URL` (default
`http://127.0.0.1:5112/`) and uses the existing
`STEWARD_CONTROL_MUTATION_TOKEN` or
`STEWARD_CONTROL_MUTATION_TOKEN_FILE` reference. Only loopback Control
endpoints are accepted.

## Operations model

- **Refresh** reads typed, bounded snapshots from Control. An older refresh
  can never overwrite a newer one.
- **Discover Pools** is explicit and uses the single `devbox/default` WAM
  context. Startup discovery is opt-in through
  `STEWARD_DESKTOP_DISCOVER_POOLS_ON_STARTUP=true` or `--discover-pools`.
- Pool and Node context menus show unavailable commands disabled with a
  reason. Pool reconciliation scales toward its registered warm policy.
  Mutations are disabled while another command is running.
- Drain, stop, recreate, and delete confirmations name the exact Host,
  provider resource, Node incarnation, active TaskAttempts, and incomplete
  portable objects. The provider resource name must be typed to continue.
  The Node incarnation is sent to Control as a mutation fence.
- Operations tabs intentionally show only bounded Workload/Task status,
  event metadata, artifact downloads, Agent notification kinds, and health.
  Raw fact payloads, provider administration, policy editing, and database
  tools are excluded.

## Dev Box ConnectionHost and RDCore

The Remote Viewer tab is now a typed client of the per-user
`Steward.ConnectionHost.Windows` named pipe. ConnectionHost, not Desktop,
owns RDCore resolution, preparation, the headless connection, connection
generation, authenticated DVC evidence, and same-connection presentation.

Desktop startup may connect to the existing pipe and issue **Status** only.
It never issues **Resolve**, **Prepare**, or **Connect** automatically, and it
never launches Windows App, an `ms-avd:` URI, or a browser. Opening a Node's
Remote Viewer tab also begins with Status only. The user must explicitly run
the ordered workflow:

1. enroll the AVD connection identity;
2. **Resolve** the exact provider resource;
3. **Prepare** RDCore and DVC configuration;
4. **Connect** the headless transport;
5. use capability-gated **View**, **Take Control**, **Release Control**,
   **Fullscreen**, or **Disconnect** commands against the reported generation.

The pipe name defaults to `Steward.ConnectionHost.v1` and can be overridden
with `STEWARD_CONNECTION_HOST_PIPE_NAME`. Connect remains disabled unless a
Control-issued single-use authorization token and opaque evidence reference
are supplied through
`STEWARD_CONNECTION_HOST_CONTROL_AUTHORIZATION_TOKEN` and
`STEWARD_CONNECTION_HOST_DVC_EVIDENCE_REFERENCE`. Their values are never
rendered.

### AVD connection identity

`devbox/default` remains the Dev Center discovery identity. A separate
`devbox/connection` identity uses native WAM with the installed Windows App
client registration and is bound to the same tenant and account. Desktop
displays its explicit state:

- **Ready** — silent AVD access is available;
- **InteractionRequired** — explicit native WAM enrollment is required; or
- **AccountMismatch** — the AVD account differs from `devbox/default`.

Enrollment is always user initiated and receives the real Desktop HWND.
Connection-identity sign-out is also explicit and clears the isolated account
and cache. Neither action launches Windows App or a browser.

### Status, generation, and DVC evidence

The UI renders ConnectionHost state, generation, DVC connectivity, verified
View/Control flags, evidence code, and update time. It also renders ordered
readiness states for identity, provider resolution, RDCore/DVC preparation,
headless transport, authenticated DVC evidence, same-connection View, and
same-connection Control. It never renders the raw provider URI, signed RDP
content, authorization token, evidence key, or evidence reference.

**View**, **Take Control**, and **Fullscreen** remain disabled with a visible
reason until ConnectionHost reports the applicable same-connection
capability, authenticated DVC evidence, and a positive generation. Every
presentation/control command carries that exact generation. External viewer
activity never enables these commands or counts as transport evidence.

### Advanced Interactive Fallback

Historical Windows App and browser activation remains available only in the
explicitly labeled **Advanced Interactive Fallback — not transport evidence**
section. Loading the fallback resource is explicit. Each external launch
requires a strong warning confirmation with the safe default set to cancel.
The fallback can still explicitly register the DVC LocalServer, but
registration and external broker-window observations do not modify
ConnectionHost status, generation, capabilities, or evidence.

Installed layouts resolve the DVC client from the sibling
`Steward.RdpDvc.Client.Windows` publish directory. Development layouts may set
`STEWARD_RDP_DVC_CLIENT_PATH` to an absolute published executable; relative,
missing, reparse-point, or untrusted-writable executables are rejected.

## Managed shell

Managed shells use Control terminal authority and the existing Node
ConPTY-backed terminal APIs for open, input, output, resize, close, and
revocation. They do not use an RDP shell, a local process, PowerShell
remoting, or direct unmanaged command execution.

The connection dialog displays only Control-authorized workspace roots and
lease bounds. Elevation is disabled unless both policy and the Node's
`terminal.elevated-service` capability permit it, and remains an explicit
request. The UI does not echo or retain entered commands. Rendered output is
bounded to one million characters, labels live versus retained Node
provenance, strips terminal control sequences, and uses metadata-only
transcript policy by default.
