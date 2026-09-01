using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Steward.Maintenance.Windows;

internal static class AssignedUserProcessRunner
{
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint MaximumAllowed = 0x02000000;

    internal static async Task<ProcessResult> RunAsync(
        AssignedUserIdentity user,
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        using var token = FindActiveUserToken(user.Sid);
        if (!NativeMethods.DuplicateTokenEx(
                token,
                MaximumAllowed,
                IntPtr.Zero,
                2,
                1,
                out var primary))
            NativeMethods.ThrowLastError(nameof(NativeMethods.DuplicateTokenEx));
        using (primary)
        {
            if (!NativeMethods.CreateEnvironmentBlock(
                    out var environment,
                    primary,
                    false))
                NativeMethods.ThrowLastError(
                    nameof(NativeMethods.CreateEnvironmentBlock));
            try
            {
                var startup = new NativeMethods.StartupInfo
                {
                    Size = checked((uint)Marshal.SizeOf<
                        NativeMethods.StartupInfo>()),
                    Desktop = "winsta0\\default"
                };
                var commandLine = string.Join(
                    " ",
                    new[] { Quote(executable) }.Concat(
                        arguments.Select(Quote)));
                if (!NativeMethods.CreateProcessAsUser(
                        primary,
                        executable,
                        commandLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        CreateNoWindow | CreateUnicodeEnvironment,
                        environment,
                        Path.GetDirectoryName(executable),
                        ref startup,
                        out var information))
                    NativeMethods.ThrowLastError(
                        nameof(NativeMethods.CreateProcessAsUser));
                using var processHandle = new SafeFileHandle(
                    information.Process,
                    ownsHandle: true);
                using var threadHandle = new SafeFileHandle(
                    information.Thread,
                    ownsHandle: true);
                using var process = Process.GetProcessById(
                    checked((int)information.ProcessId));
                try
                {
                    await process.WaitForExitAsync(cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    if (!process.HasExited)
                        process.Kill(entireProcessTree: true);
                    throw;
                }
                return new ProcessResult(process.ExitCode, string.Empty);
            }
            finally
            {
                if (!NativeMethods.DestroyEnvironmentBlock(environment))
                    NativeMethods.ThrowLastError(
                        nameof(NativeMethods.DestroyEnvironmentBlock));
            }
        }
    }

    private static SafeFileHandle FindActiveUserToken(string expectedSid)
    {
        if (!NativeMethods.WTSEnumerateSessions(
                IntPtr.Zero,
                0,
                1,
                out var sessions,
                out var count))
            NativeMethods.ThrowLastError(
                nameof(NativeMethods.WTSEnumerateSessions));
        try
        {
            var size = Marshal.SizeOf<NativeMethods.WtsSessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<
                    NativeMethods.WtsSessionInfo>(
                    IntPtr.Add(sessions, index * size));
                if (session.SessionId == 0 || session.State != 0 ||
                    !NativeMethods.WTSQueryUserToken(
                        checked((uint)session.SessionId),
                        out var token))
                    continue;
                var keep = false;
                try
                {
                    using var identity = new System.Security.Principal
                        .WindowsIdentity(token.DangerousGetHandle());
                    keep = string.Equals(
                        identity.User?.Value,
                        expectedSid,
                        StringComparison.Ordinal);
                    if (keep)
                        return token;
                }
                finally
                {
                    if (!keep)
                        token.Dispose();
                }
            }
        }
        finally
        {
            NativeMethods.WTSFreeMemory(sessions);
        }
        throw new MaintenanceProtocolException(
            "assigned_user_unavailable",
            "The assigned user has no active Windows session for WSL provisioning.");
    }

    private static string Quote(string value)
    {
        if (value.Length > 32 * 1024 || value.Contains('\0'))
            throw new ArgumentException(
                "Assigned-user process argument is invalid.");
        if (value.Length > 0 && !value.Any(character =>
                char.IsWhiteSpace(character) || character == '"'))
            return value;
        var result = new System.Text.StringBuilder().Append('"');
        var slashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                slashes++;
                continue;
            }
            if (character == '"')
            {
                result.Append('\\', slashes * 2 + 1).Append('"');
                slashes = 0;
                continue;
            }
            result.Append('\\', slashes).Append(character);
            slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WtsSessionInfo
        {
            internal int SessionId;
            internal IntPtr StationName;
            internal int State;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct StartupInfo
        {
            internal uint Size;
            internal string? Reserved;
            internal string? Desktop;
            internal string? Title;
            internal uint X;
            internal uint Y;
            internal uint XSize;
            internal uint YSize;
            internal uint XCountChars;
            internal uint YCountChars;
            internal uint FillAttribute;
            internal uint Flags;
            internal ushort ShowWindow;
            internal ushort Reserved2Length;
            internal IntPtr Reserved2;
            internal IntPtr StandardInput;
            internal IntPtr StandardOutput;
            internal IntPtr StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessInformation
        {
            internal IntPtr Process;
            internal IntPtr Thread;
            internal uint ProcessId;
            internal uint ThreadId;
        }

#pragma warning disable SYSLIB1054
        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSEnumerateSessions(
            IntPtr server,
            int reserved,
            int version,
            out IntPtr sessions,
            out int count);

        [DllImport("wtsapi32.dll")]
        internal static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WTSQueryUserToken(
            uint sessionId,
            out SafeFileHandle token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateTokenEx(
            SafeFileHandle existingToken,
            uint desiredAccess,
            IntPtr tokenAttributes,
            int impersonationLevel,
            int tokenType,
            out SafeFileHandle newToken);

        [DllImport(
            "advapi32.dll",
            EntryPoint = "CreateProcessAsUserW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcessAsUser(
            SafeFileHandle token,
            string applicationName,
            string commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string? currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateEnvironmentBlock(
            out IntPtr environment,
            SafeFileHandle token,
            [MarshalAs(UnmanagedType.Bool)] bool inherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyEnvironmentBlock(
            IntPtr environment);
#pragma warning restore SYSLIB1054

        internal static void ThrowLastError(string operation) =>
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                operation);
    }
}
