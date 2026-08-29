namespace Steward.Transport.Rdp.Windows;

public enum HeadlessRdpCapabilityState
{
    Unavailable,
    Available
}

public sealed record HeadlessRdpCapability(
    HeadlessRdpCapabilityState State,
    string Code,
    string Description)
{
    public bool IsAvailable => State == HeadlessRdpCapabilityState.Available;
}

public static class RdpDvcHeadlessCapability
{
    public static HeadlessRdpCapability WindowsAppMsAvd() =>
        new(
            HeadlessRdpCapabilityState.Unavailable,
            "HEADLESS_MS_AVD_UNSUPPORTED_VISIBLE_ACTIVATION_REQUIRED",
            "Windows App exposes interactive ms-avd protocol activation; Steward has no supported headless AVD session establishment API.");

    public static HeadlessRdpCapability WindowsAppIsolatedDesktop() =>
        new(
            HeadlessRdpCapabilityState.Available,
            "HEADLESS_ISOLATED_DESKTOP_AVAILABLE",
            "Windows App launched on an isolated Windows desktop with Job Object containment produces zero visible UI until explicit ShowAsync activation.");
}
