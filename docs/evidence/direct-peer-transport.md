# Direct peer transport evidence

## Status

**Open.** The approved Local Stack transport is an authenticated direct peer
connection. Protocol, reconnect, and deterministic loopback tests can establish
most behavior; clean-machine network and long-duration tests remain required
before E-01 closes.

This evidence selects a local implementation of the neutral transport port. It
does not change command durability, Delegation, or reconciliation contracts.

## Deployment model

Control and Node connect directly over a configured endpoint. The binding
states which side dials:

- `ControlDialsNode` when the Node has a reachable listener; or
- `NodeDialsControl` when Control has a reachable listener.

Production traffic uses authenticated encrypted WebSockets. Unencrypted
WebSockets are allowed only on loopback for deterministic tests. Existing LAN,
VPN, DNS, firewall, and port-forwarding policy may supply reachability, but
Steward neither provisions nor operates that network.

When neither endpoint can reach the other, there is no fallback intermediary.
Already accepted work continues within its Delegation; new dispatch, stream
transfer, replication, and reconciliation wait.

## Required protocol evidence

The peer session must prove:

- endpoint and Node-incarnation authentication;
- enrollment and key rotation;
- channel/transcript binding and downgrade rejection;
- confidentiality, integrity, replay rejection, and bounded frame parsing;
- multiplexed commands, facts, logs, objects, Agent turns, and terminal data;
- independent stream backpressure and fairness;
- durable contiguous cursors, duplicate suppression, and reconnect replay;
- Control/Node restart and laptop sleep/network-change recovery;
- bounded connection attempts, jitter, timeouts, buffers, and memory;
- acceptable terminal latency and sustained stream throughput; and
- safe behavior when configured endpoints are unavailable or malicious.

The transport does not queue authority. Commands become durable only in the
Control outbox and Node inbox/journal.

## No-intermediary evidence

A release evidence bundle must include:

1. process and listener inventory on Control and Node;
2. packet/endpoint capture showing a direct Control-to-Node connection;
3. a run with no Steward remote service endpoint configured;
4. failure after removing direct reachability, with no alternate connection;
5. continued bounded execution of an already accepted Workload;
6. later direct reconnect and exact replay; and
7. package/dependency inspection confirming the Local Stack transport path
   requires no managed intermediary.

Use redacted endpoint and certificate identifiers; never publish private keys.

## Executable matrix

1. Exercise both dial directions over loopback and two Windows systems.
2. Enroll a new Node and reject wrong Host, incarnation, key, and expired
   enrollment claims.
3. Interrupt every frame and acknowledgement boundary.
4. Reorder, duplicate, truncate, enlarge, replay, and corrupt frames.
5. Restart each endpoint with unacknowledged commands and facts.
6. Sleep/wake Control and change network reachability.
7. Saturate each stream class while using an interactive terminal.
8. Rotate endpoint keys and revoke a Node.
9. Remove the route during accepted work and restore it after completion.
10. Record latency, throughput, memory, reconnect time, and failure diagnostics.

## Contract consequence

Core sees only a mutually authenticated session with bounded versioned streams.
Direct endpoint and dial-direction configuration belong to the Local Stack
extension. No network topology field belongs in Domain aggregates.

If direct transport does not meet a deployment's reachability needs, that
deployment is unsupported until a separately approved transport adapter and
evidence exist. It is not permission to introduce hidden infrastructure.

## Sources

- [WebSockets in .NET](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/websockets)
- [TLS best practices with .NET](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls)
- [ASP.NET Core certificate authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth)
