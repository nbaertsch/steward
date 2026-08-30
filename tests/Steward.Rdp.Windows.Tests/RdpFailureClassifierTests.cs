using Steward.Rdp.Windows;

namespace Steward.Rdp.Windows.Tests;

public sealed class RdpFailureClassifierTests
{
    [Theory]
    [InlineData(false, false, false, null, null, false, RdpFailureKind.ConnectionTimeout)]
    [InlineData(true, false, false, null, null, false, RdpFailureKind.LoginTimeout)]
    [InlineData(true, true, false, null, null, false, RdpFailureKind.GatewayNotObserved)]
    [InlineData(false, false, false, 4, null, false, RdpFailureKind.Disconnected)]
    [InlineData(true, false, false, null, 2308, false, RdpFailureKind.Fatal)]
    [InlineData(true, true, true, null, null, false, RdpFailureKind.None)]
    [InlineData(true, true, true, null, null, true, RdpFailureKind.Cancelled)]
    public void ClassifiesExactTerminalCondition(
        bool connected,
        bool loginComplete,
        bool gatewayObserved,
        int? disconnectReason,
        int? fatalErrorCode,
        bool cancelled,
        RdpFailureKind expected)
    {
        Assert.Equal(
            expected,
            RdpFailureClassifier.Classify(
                connected,
                loginComplete,
                gatewayObserved,
                disconnectReason,
                fatalErrorCode,
                cancelled));
    }
}
