using System.Runtime.InteropServices;

namespace Steward.Runtime.Windows;

public sealed record WindowsBootIdentityEvidence(
    int Version,
    string Identity,
    bool Verified,
    string Source);

public static class WindowsBootIdentity
{
    private const int SystemTimeOfDayInformation = 3;
    private const string KernelSource =
        "NtQuerySystemInformation.SystemTimeOfDayInformation";

    public static WindowsBootIdentityEvidence Capture()
    {
        if (!OperatingSystem.IsWindows())
            return Unverified("platform-unavailable");
        var information = new SystemTimeOfDay();
        var status = NativeMethods.NtQuerySystemInformation(
            SystemTimeOfDayInformation,
            ref information,
            checked((uint)Marshal.SizeOf<SystemTimeOfDay>()),
            out var returned);
        if (status != 0 ||
            returned < Marshal.SizeOf<SystemTimeOfDay>() ||
            information.BootTime <= 0)
            return Unverified($"ntstatus-0x{status:X8}");
        return new WindowsBootIdentityEvidence(
            1,
            $"windows-kernel-boot/{information.BootTime:X16}",
            true,
            KernelSource);
    }

    private static WindowsBootIdentityEvidence Unverified(string source) =>
        new(
            1,
            $"unverified/{Guid.NewGuid():N}",
            false,
            source);

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTimeOfDay
    {
        internal long BootTime;
        internal long CurrentTime;
        internal long TimeZoneBias;
        internal uint CurrentTimeZoneId;
        internal uint Reserved;
        internal ulong BootTimeBias;
        internal ulong SleepTimeBias;
    }

    private static class NativeMethods
    {
#pragma warning disable SYSLIB1054
        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(
            int informationClass,
            ref SystemTimeOfDay information,
            uint informationLength,
            out uint returnLength);
#pragma warning restore SYSLIB1054
    }
}



