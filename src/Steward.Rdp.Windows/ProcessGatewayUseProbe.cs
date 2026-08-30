using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Steward.Rdp.Windows;

[SupportedOSPlatform("windows")]
public sealed class ProcessGatewayUseProbe : IGatewayUseProbe
{
    public async Task<GatewayUseObservation> ObserveAsync(
        string gatewayHostname,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var (host, port) = ParseGateway(gatewayHostname);
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken)
            .ConfigureAwait(false);
        if (addresses.Length == 0)
            return new(false, null);
        var deadline = DateTimeOffset.UtcNow + timeout;
        do
        {
            var match = TcpOwnerTable.GetConnections().FirstOrDefault(x =>
                x.ProcessId == Environment.ProcessId &&
                x.State == 5 &&
                x.RemotePort == port &&
                addresses.Contains(x.RemoteAddress));
            if (match is not null)
                return new(true, $"{host}:{match.RemotePort}");
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken)
                .ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);
        return new(false, null);
    }

    private static (string Host, int Port) ParseGateway(string gatewayHostname)
    {
        if (!Uri.TryCreate($"https://{gatewayHostname}", UriKind.Absolute, out var uri) ||
            string.IsNullOrWhiteSpace(uri.IdnHost) ||
            uri.UserInfo.Length != 0 ||
            uri.AbsolutePath != "/")
            throw new InvalidDataException("The RDP gateway hostname is invalid.");
        return (uri.IdnHost, uri.IsDefaultPort ? 443 : uri.Port);
    }
}

internal sealed record OwnedTcpConnection(
    int ProcessId,
    int State,
    IPAddress RemoteAddress,
    int RemotePort);

[SupportedOSPlatform("windows")]
internal static class TcpOwnerTable
{
    private const int AddressFamilyIpv4 = 2;
    private const int AddressFamilyIpv6 = 23;
    private const int OwnerPidConnections = 4;
    private const int InsufficientBuffer = 122;

    public static IReadOnlyList<OwnedTcpConnection> GetConnections()
    {
        var connections = new List<OwnedTcpConnection>();
        ReadIpv4(connections);
        ReadIpv6(connections);
        return connections;
    }

    private static void ReadIpv4(List<OwnedTcpConnection> output)
    {
        var buffer = Allocate(AddressFamilyIpv4, out var size);
        try
        {
            var rows = Marshal.ReadInt32(buffer);
            var offset = sizeof(int);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            for (var index = 0; index < rows; index++, offset += rowSize)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                    IntPtr.Add(buffer, offset));
                output.Add(new(
                    checked((int)row.OwningPid),
                    checked((int)row.State),
                    new IPAddress(row.RemoteAddress),
                    NetworkPort(row.RemotePort)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ReadIpv6(List<OwnedTcpConnection> output)
    {
        var buffer = Allocate(AddressFamilyIpv6, out var size);
        try
        {
            var rows = Marshal.ReadInt32(buffer);
            var offset = sizeof(int);
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            for (var index = 0; index < rows; index++, offset += rowSize)
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(
                    IntPtr.Add(buffer, offset));
                output.Add(new(
                    checked((int)row.OwningPid),
                    checked((int)row.State),
                    new IPAddress(row.RemoteAddress, row.RemoteScopeId),
                    NetworkPort(row.RemotePort)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr Allocate(int addressFamily, out int size)
    {
        size = 0;
        var result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            false,
            addressFamily,
            OwnerPidConnections,
            0);
        if (result != InsufficientBuffer)
            throw new Win32Exception(checked((int)result));
        var buffer = Marshal.AllocHGlobal(size);
        result = GetExtendedTcpTable(
            buffer,
            ref size,
            false,
            addressFamily,
            OwnerPidConnections,
            0);
        if (result == 0)
            return buffer;
        Marshal.FreeHGlobal(buffer);
        throw new Win32Exception(checked((int)result));
    }

    private static int NetworkPort(uint value) =>
        unchecked((ushort)IPAddress.NetworkToHostOrder(unchecked((short)value)));

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddress;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }
}
