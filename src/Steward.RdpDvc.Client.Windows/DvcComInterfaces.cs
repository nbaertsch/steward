// Adapted from microsoft/rdp-dvc-plugin-samples Simple/dotnet.
// Copyright (c) Microsoft Corporation. Licensed under the MIT License.
using System.Runtime.InteropServices;

namespace Steward.RdpDvc.Client.Windows;

[ComImport]
[Guid("A1230201-1439-4E62-A414-190D0AC3D40E")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWTSPlugin
{
    [PreserveSig]
    int Initialize(
        [In, MarshalAs(UnmanagedType.Interface)]
        IWTSVirtualChannelManager channelManager);

    [PreserveSig]
    int Connected();

    [PreserveSig]
    int Disconnected(uint disconnectCode);

    [PreserveSig]
    int Terminated();
}

[ComImport]
[Guid("A1230205-D6A7-11D8-B9FD-000BDBD1F198")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWTSVirtualChannelManager
{
    [PreserveSig]
    int CreateListener(
        [In, MarshalAs(UnmanagedType.LPStr)] string channelName,
        uint flags,
        [In, MarshalAs(UnmanagedType.Interface)]
        IWTSListenerCallback listenerCallback,
        [Out, MarshalAs(UnmanagedType.Interface)]
        out IWTSListener listener);
}

[ComImport]
[Guid("A1230206-9A39-4D58-8674-CDB4DFF4E73B")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWTSListener
{
    [PreserveSig]
    int GetConfiguration(
        [Out, MarshalAs(UnmanagedType.Interface)]
        out object propertyBag);
}

[ComImport]
[Guid("A1230203-D6A7-11D8-B9FD-000BDBD1F198")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWTSListenerCallback
{
    [PreserveSig]
    int OnNewChannelConnection(
        [In, MarshalAs(UnmanagedType.Interface)]
        IWTSVirtualChannel channel,
        [In, MarshalAs(UnmanagedType.BStr)] string data,
        [Out, MarshalAs(UnmanagedType.Bool)] out bool accept,
        [Out, MarshalAs(UnmanagedType.Interface)]
        out IWTSVirtualChannelCallback callback);
}

[ComImport]
[Guid("A1230207-D6A7-11D8-B9FD-000BDBD1F198")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWTSVirtualChannel
{
    [PreserveSig]
    int Write(uint size, IntPtr buffer, IntPtr reserved);

    [PreserveSig]
    int Close();
}

[ComImport]
[Guid("A1230204-D6A7-11D8-B9FD-000BDBD1F198")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IWTSVirtualChannelCallback
{
    [PreserveSig]
    int OnDataReceived(uint size, IntPtr buffer);

    [PreserveSig]
    int OnClose();
}

[ComImport]
[Guid("00000001-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IClassFactory
{
    [PreserveSig]
    int CreateInstance(
        IntPtr outer,
        ref Guid interfaceId,
        out IntPtr instance);

    [PreserveSig]
    int LockServer([MarshalAs(UnmanagedType.Bool)] bool shouldLock);
}
