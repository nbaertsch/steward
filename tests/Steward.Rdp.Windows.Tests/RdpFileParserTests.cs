using System.Text;
using Steward.Rdp.Windows;

namespace Steward.Rdp.Windows.Tests;

public sealed class RdpFileParserTests
{
    [Fact]
    public void ParsesSignedAllowlistedProfile()
    {
        var profile = RdpFileParser.Parse(Encoding.UTF8.GetBytes(ValidRdp()));

        Assert.Equal("box.internal:3389", profile.FullAddress);
        Assert.Equal("gateway.example:443", profile.GatewayHostname);
        Assert.Equal(1, profile.GatewayUsageMethod);
        Assert.Equal("tsv://payload", profile.LoadBalanceInfo);
        Assert.True(profile.EnableRdsAadAuth);
    }

    [Fact]
    public void RejectsCaseInsensitiveDuplicate()
    {
        var content = ValidRdp() + "Full Address:s:attacker.example\r\n";

        var error = Assert.Throws<InvalidDataException>(
            () => RdpFileParser.Parse(Encoding.UTF8.GetBytes(content)));

        Assert.Contains("duplicated", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RejectsInjectedUnknownLine()
    {
        var content = ValidRdp().Replace(
            "gatewayhostname:s:gateway.example:443",
            "gatewayhostname:s:gateway.example:443\r\nauthorization:s:Bearer stolen",
            StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(
            () => RdpFileParser.Parse(Encoding.UTF8.GetBytes(content)));
    }

    [Fact]
    public void RejectsOversizedContent()
    {
        var content = new byte[RdpFileParser.MaximumBytes + 1];

        Assert.Throws<InvalidDataException>(() => RdpFileParser.Parse(content));
    }

    [Fact]
    public void RejectsUnsignedRequiredGatewayField()
    {
        var content = ValidRdp().Replace(
            "signscope:s:full address,gatewayhostname,loadbalanceinfo",
            "signscope:s:full address,loadbalanceinfo",
            StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(
            () => RdpFileParser.Parse(Encoding.UTF8.GetBytes(content)));
    }

    internal static string ValidRdp() =>
        """
        full address:s:box.internal:3389
        gatewayhostname:s:gateway.example:443
        gatewayusagemethod:i:1
        gatewayprofileusagemethod:i:1
        gatewaycredentialssource:i:5
        gatewaybrokeringtype:i:1
        loadbalanceinfo:s:tsv://payload
        enablerdsaadauth:i:1
        enablecredsspsupport:i:1
        autoreconnection enabled:i:1
        redirectclipboard:i:0
        drivestoredirect:s:*
        signature:s:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd
        signscope:s:full address,gatewayhostname,loadbalanceinfo

        """;
}
