using System.Runtime.InteropServices;

namespace Steward.Rdp.Windows;

[ComImport]
[Guid("7ED92C39-EB38-4927-A70A-708AC5A59321")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface IMsRdpClient10
{
    [DispId(1)]
    string Server { get; [param: MarshalAs(UnmanagedType.BStr)] set; }

    [DispId(30)]
    void Connect();

    [DispId(31)]
    void Disconnect();

    [DispId(103)]
    int ExtendedDisconnectReason { get; }

    [DispId(600)]
    IMsRdpClientAdvancedSettings8 AdvancedSettings8 { get; }

    [DispId(800)]
    IMsRdpClientTransportSettings4 TransportSettings4 { get; }
}

[ComImport]
[Guid("89ACB528-2557-4D16-8625-226A30E97E9A")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface IMsRdpClientAdvancedSettings8
{
    [DispId(190)]
    string LoadBalanceInfo { get; [param: MarshalAs(UnmanagedType.BStr)] set; }

    [DispId(191)]
    bool RedirectDrives { get; set; }

    [DispId(192)]
    bool RedirectPrinters { get; set; }

    [DispId(193)]
    bool RedirectPorts { get; set; }

    [DispId(194)]
    bool RedirectSmartCards { get; set; }

    [DispId(200)]
    int PerformanceFlags { get; set; }

    [DispId(206)]
    bool EnableAutoReconnect { get; set; }

    [DispId(207)]
    int MaxReconnectAttempts { get; set; }

    [DispId(213)]
    bool RedirectClipboard { get; set; }

    [DispId(215)]
    uint AudioRedirectionMode { get; set; }

    [DispId(218)]
    bool RedirectDevices { get; set; }

    [DispId(219)]
    bool RedirectPOSDevices { get; set; }

    [DispId(17)]
    bool EnableCredSspSupport { get; set; }

    [DispId(228)]
    bool AudioCaptureRedirectionMode { get; set; }

    [DispId(229)]
    uint VideoPlaybackMode { get; set; }

    [DispId(234)]
    bool RedirectDirectX { get; set; }
}

[ComImport]
[Guid("011C3236-4D81-4515-9143-067AB630D299")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface IMsRdpClientTransportSettings4
{
    [DispId(210)]
    string GatewayHostname { get; [param: MarshalAs(UnmanagedType.BStr)] set; }

    [DispId(211)]
    uint GatewayUsageMethod { get; set; }

    [DispId(212)]
    uint GatewayProfileUsageMethod { get; set; }

    [DispId(213)]
    uint GatewayCredsSource { get; set; }

    [DispId(222)]
    bool GatewayCredSharing { get; set; }

    [DispId(231)]
    uint GatewayBrokeringType { set; }
}

[ComImport]
[Guid("302D8188-0052-4807-806A-362B628F9AC5")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IMsRdpExtendedSettings
{
    void put_Property(
        [MarshalAs(UnmanagedType.BStr)] string propertyName,
        [In, MarshalAs(UnmanagedType.Struct)] ref object value);

    void get_Property(
        [MarshalAs(UnmanagedType.BStr)] string propertyName,
        [MarshalAs(UnmanagedType.Struct)] out object value);
}

[ComVisible(true)]
[Guid("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
internal interface IMsTscAxEventsSink
{
    [DispId(2)]
    void OnConnected();

    [DispId(3)]
    void OnLoginComplete();

    [DispId(4)]
    void OnDisconnected(int disconnectReason);

    [DispId(10)]
    void OnFatalError(int errorCode);

    [DispId(22)]
    void OnLogonError(int errorCode);
}
