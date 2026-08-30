using Steward.Rdp.Windows;

namespace Steward.Rdp.Windows.Tests;

public sealed class RdpActiveXConfigurationTests
{
    [Fact]
    public void MapsGatewayAadReconnectAndDisablesRedirection()
    {
        var profile = RdpFileParser.Parse(
            System.Text.Encoding.UTF8.GetBytes(RdpFileParserTests.ValidRdp()));
        var target = new FakeTarget();

        RdpActiveXConfigurator.Apply(profile, target);

        Assert.Equal(profile.FullAddress, target.Server);
        Assert.Equal(profile.GatewayHostname, target.GatewayHostname);
        Assert.Equal((uint)1, target.GatewayUsageMethod);
        Assert.Equal((uint)1, target.GatewayBrokeringType);
        Assert.Equal("tsv://payload", target.LoadBalanceInfo);
        Assert.True(target.EnableRdsAadAuth);
        Assert.True(target.EnableAutoReconnect);
        Assert.False(target.GatewayCredentialSharing);
        Assert.True(target.DisableCredentialsDelegation);
        Assert.False(target.RedirectClipboard);
        Assert.False(target.RedirectDrives);
        Assert.False(target.RedirectDevices);
        Assert.False(target.RedirectDirectX);
        Assert.False(target.AudioCaptureRedirection);
        Assert.Equal((uint)2, target.AudioRedirectionMode);
        Assert.Equal(
            RdpActiveXConfigurator.DisabledVisualEffects,
            target.PerformanceFlags);
    }

    private sealed class FakeTarget : IRdpActiveXConfigurationTarget
    {
        public string Server { get; set; } = "";
        public string GatewayHostname { get; set; } = "";
        public uint GatewayUsageMethod { get; set; }
        public uint GatewayProfileUsageMethod { get; set; }
        public uint GatewayCredentialsSource { get; set; }
        public uint GatewayBrokeringType { get; set; }
        public bool GatewayCredentialSharing { get; set; }
        public bool DisableCredentialsDelegation { get; set; }
        public string LoadBalanceInfo { get; set; } = "";
        public bool EnableRdsAadAuth { get; set; }
        public bool EnableCredSspSupport { get; set; }
        public bool EnableAutoReconnect { get; set; }
        public int MaximumReconnectAttempts { get; set; }
        public bool RedirectClipboard { get; set; }
        public bool RedirectDrives { get; set; }
        public bool RedirectPrinters { get; set; }
        public bool RedirectPorts { get; set; }
        public bool RedirectSmartCards { get; set; }
        public bool RedirectDevices { get; set; }
        public bool RedirectPointOfServiceDevices { get; set; }
        public bool RedirectDirectX { get; set; }
        public uint AudioRedirectionMode { get; set; }
        public bool AudioCaptureRedirection { get; set; }
        public uint VideoPlaybackMode { get; set; }
        public uint PerformanceFlags { get; set; }
    }
}
