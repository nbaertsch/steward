using Steward.Transport.Rdp.Windows;

namespace Steward.Transport.Rdp.Windows.Tests;

public sealed class RdCoreDvcContractTests
{
    [Fact]
    public void Configuration_requires_every_headless_and_dvc_precondition()
    {
        var exactRegistration = ExactRegistration();

        AssertRejected(
            Request(
                silentMode: false,
                allowThirdPartyPlugins: true,
                exactRegistration),
            "RDCORE_SILENT_MODE_REQUIRED");
        AssertRejected(
            Request(
                silentMode: true,
                allowThirdPartyPlugins: false,
                exactRegistration),
            "RDCORE_ALLOW_THIRD_PARTY_PLUGINS_REQUIRED");
        AssertRejected(
            Request(
                silentMode: true,
                allowThirdPartyPlugins: true,
                new(
                    true,
                    true,
                    "almost-" +
                    RdpDvcPluginRegistration
                        .RegisteredActivationPendingCode)),
            "RDCORE_EXACT_STEWARD_DVC_REGISTRATION_REQUIRED");

        var accepted =
            RdCoreDvcContract.ValidateConfiguration(
                Request(
                    silentMode: true,
                    allowThirdPartyPlugins: true,
                    exactRegistration));

        Assert.True(accepted.Accepted);
        Assert.Equal(
            RdCoreDvcContract.ConfigurationReadyCode,
            accepted.Code);
        Assert.Null(accepted.ConnectionGeneration);
    }

    [Fact]
    public void Evidence_requires_complete_ordered_authenticated_chain()
    {
        var request = ValidRequest();
        var evidence = new RdCoreDvcEvidenceSequence(17);
        evidence.Record(RdCoreDvcEvidenceEvent.RdCoreConnected);
        evidence.Record(RdCoreDvcEvidenceEvent.WtsPluginsLoaded);

        AssertEvidenceRejected(
            request,
            evidence,
            "RDCORE_DVC_AUTHENTICATED_EVIDENCE_CHAIN_REQUIRED");

        Complete(evidence);
        var verified =
            RdCoreDvcContract.ValidateEvidence(request, evidence);

        Assert.True(verified.Accepted);
        Assert.Equal(
            RdCoreDvcContract.EvidenceVerifiedCode,
            verified.Code);
        Assert.Equal(17, verified.ConnectionGeneration);
    }

    [Fact]
    public void Contracts_do_not_render_plugin_or_channel_identity()
    {
        var request = ValidRequest();
        var evidence = new RdCoreDvcEvidenceSequence(1);
        CompleteAll(evidence);
        var result =
            RdCoreDvcContract.ValidateEvidence(request, evidence);

        Assert.DoesNotContain(
            StewardRdpDvc.AddInName,
            request.ToString(),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            StewardRdpDvc.ChannelName,
            evidence.ToString(),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            StewardRdpDvc.PluginClsid.ToString(),
            result.ToString(),
            StringComparison.Ordinal);
    }

    private static RdCoreDvcConfigurationRequest ValidRequest() =>
        Request(
            silentMode: true,
            allowThirdPartyPlugins: true,
            ExactRegistration());

    private static RdCoreDvcConfigurationRequest Request(
        bool silentMode,
        bool allowThirdPartyPlugins,
        DvcPluginRegistrationStatus registration) =>
        new(
            silentMode,
            allowThirdPartyPlugins,
            registration);

    private static DvcPluginRegistrationStatus ExactRegistration() =>
        new(
            true,
            true,
            RdpDvcPluginRegistration
                .RegisteredActivationPendingCode);

    private static void Complete(
        RdCoreDvcEvidenceSequence evidence)
    {
        evidence.Record(
            RdCoreDvcEvidenceEvent.StewardComClassActivated);
        evidence.Record(
            RdCoreDvcEvidenceEvent.StewardPluginInitialized,
            StewardRdpDvc.AddInName,
            StewardRdpDvc.PluginClsid);
        evidence.Record(
            RdCoreDvcEvidenceEvent.StewardChannelOpened,
            channelName: StewardRdpDvc.ChannelName);
        evidence.Record(
            RdCoreDvcEvidenceEvent.DvcHmacAuthenticated);
        evidence.Record(
            RdCoreDvcEvidenceEvent.SecurePeerAuthenticated);
    }

    private static void CompleteAll(
        RdCoreDvcEvidenceSequence evidence)
    {
        evidence.Record(RdCoreDvcEvidenceEvent.RdCoreConnected);
        evidence.Record(RdCoreDvcEvidenceEvent.WtsPluginsLoaded);
        Complete(evidence);
    }

    private static void AssertRejected(
        RdCoreDvcConfigurationRequest request,
        string code)
    {
        var result =
            RdCoreDvcContract.ValidateConfiguration(request);
        Assert.False(result.Accepted);
        Assert.Equal(code, result.Code);
        Assert.Null(result.ConnectionGeneration);
    }

    private static void AssertEvidenceRejected(
        RdCoreDvcConfigurationRequest request,
        RdCoreDvcEvidenceSequence evidence,
        string code)
    {
        var result =
            RdCoreDvcContract.ValidateEvidence(
                request,
                evidence);
        Assert.False(result.Accepted);
        Assert.Equal(code, result.Code);
        Assert.Null(result.ConnectionGeneration);
    }
}
