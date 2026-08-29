using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Steward.Transport.Rdp.Windows;

public static class StewardRdpDvc
{
    public const string AddInName = "StewardRdpDvcTransport";
    public const string ChannelName = "steward::transport::v1";
    public const string PipeName = "Steward.RdpDvc.Transport.v1";
    public const ushort ProtocolVersion = 1;
    public const int MaximumPayloadBytes = 1024 * 1024;
    public const int MaximumPingPayloadBytes = 4096;
    public const int MaximumBufferedPdus = 64;

    public static readonly Guid PluginClsid = new(
        "6F26730D-9E8C-4D94-A7F6-79A2ED5CB28D");

    public static string CurrentUserPipeName()
    {
        using var identity = WindowsIdentity.GetCurrent(
            TokenAccessLevels.Query);
        var sid = identity.User?.Value ??
            throw new InvalidOperationException(
                "The current Windows user SID is unavailable.");
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sid));
        return $"{PipeName}.{Convert.ToHexString(hash.AsSpan(0, 8))}";
    }
}
