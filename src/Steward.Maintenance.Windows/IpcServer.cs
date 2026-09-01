using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Steward.Maintenance.Windows;

internal static class MaintenancePipeSecurity
{
    internal static PipeSecurity CreateDescriptor(string nodeUserSid)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        AddPipeRule(
            security,
            new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid,
                null),
            PipeAccessRights.FullControl);
        AddPipeRule(
            security,
            new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid,
                null),
            PipeAccessRights.FullControl);
        AddPipeRule(
            security,
            new SecurityIdentifier(nodeUserSid),
            PipeAccessRights.ReadWrite);
        return security;
    }

    private static void AddPipeRule(
        PipeSecurity security,
        SecurityIdentifier sid,
        PipeAccessRights rights) =>
        security.AddAccessRule(new PipeAccessRule(
            sid,
            rights,
            AccessControlType.Allow));
}

internal sealed class MaintenancePipeServer(
    MaintenanceIpcOptions options,
    string nodeUserSid,
    MaintenanceSessionAuthenticator sessionAuthenticator,
    MaintenanceCoordinator coordinator)
{
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeRejectRemoteClients = 0x00000008;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var first = CreatePipe(firstInstance: true);
        var listeners = new List<Task>(options.MaximumConcurrentConnections)
        {
            ListenAsync(first, cancellationToken)
        };
        for (var index = 1;
             index < options.MaximumConcurrentConnections;
             index++)
            listeners.Add(ListenAsync(null, cancellationToken));
        await Task.WhenAll(listeners).ConfigureAwait(false);
    }

    private async Task ListenAsync(
        NamedPipeServerStream? initialPipe,
        CancellationToken cancellationToken)
    {
        var next = initialPipe;
        while (!cancellationToken.IsCancellationRequested)
        {
            var pipe = next ?? CreatePipe(firstInstance: false);
            next = null;
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken)
                    .ConfigureAwait(false);
                using var timeout = CancellationTokenSource
                    .CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(options.RequestTimeout);
                await HandleConnectionAsync(pipe, timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception exception) when (exception is
                IOException or ObjectDisposedException)
            {
            }
            finally
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task HandleConnectionAsync(
        NamedPipeServerStream pipe,
        CancellationToken cancellationToken)
    {
        MaintenanceResponse response;
        MaintenanceRequestBody? body = null;
        try
        {
            var challenge = sessionAuthenticator.CreateChallenge();
            await MaintenanceIpcProtocol.WriteChallengeAsync(
                    pipe,
                    challenge,
                    options.MaximumFrameBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            var submission = await MaintenanceIpcProtocol
                .ReadSubmissionAsync(
                    pipe,
                    options.MaximumFrameBytes,
                    cancellationToken)
                .ConfigureAwait(false);
            body = submission.Request.Body;
            var client = ReadClientProcessEvidence(pipe);
            sessionAuthenticator.Verify(
                challenge,
                submission.Request,
                submission.Proof,
                client.ProcessId,
                client.WtsSessionId);
            response = await coordinator.ExecuteSessionAsync(
                    submission.Request,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (MaintenanceProtocolException exception)
        {
            response = Error(body, exception.Code, exception.Message);
        }
        catch (Exception exception) when (
            exception is InvalidDataException or IOException or
            UnauthorizedAccessException or FormatException or
            ArgumentException or Win32Exception)
        {
            response = Error(
                body,
                "malformed_request",
                "Maintenance request was malformed or unauthorized.");
        }
        try
        {
            await MaintenanceIpcProtocol.WriteResponseAsync(
                    pipe,
                    response,
                    options.MaximumFrameBytes,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is
            IOException or ObjectDisposedException or
            OperationCanceledException)
        {
        }
    }

    private static MaintenanceClientProcessEvidence ReadClientProcessEvidence(
        NamedPipeServerStream pipe)
    {
        if (!NativeMethods.GetNamedPipeClientProcessId(
                pipe.SafePipeHandle,
                out var processId) ||
            processId == 0 || processId > int.MaxValue)
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                nameof(NativeMethods.GetNamedPipeClientProcessId));
        using var process = Process.GetProcessById(checked((int)processId));
        return new MaintenanceClientProcessEvidence(
            checked((int)processId),
            process.SessionId);
    }

    private NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        var security = MaintenancePipeSecurity.CreateDescriptor(nodeUserSid);
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var descriptorPointer = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(
                descriptor,
                0,
                descriptorPointer,
                descriptor.Length);
            var attributes = new NativeMethods.SecurityAttributes
            {
                Length = checked((uint)Marshal.SizeOf<
                    NativeMethods.SecurityAttributes>()),
                SecurityDescriptor = descriptorPointer
            };
            var mode = PipeAccessDuplex | FileFlagOverlapped;
            if (firstInstance)
                mode |= FileFlagFirstPipeInstance;
            var handle = NativeMethods.CreateNamedPipe(
                $@"\\.\pipe\{options.PipeName}",
                mode,
                PipeRejectRemoteClients,
                checked((uint)options.MaximumConcurrentConnections),
                checked((uint)options.MaximumFrameBytes),
                checked((uint)options.MaximumFrameBytes),
                0,
                ref attributes);
            if (handle.IsInvalid)
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    nameof(NativeMethods.CreateNamedPipe));
            return new NamedPipeServerStream(
                PipeDirection.InOut,
                isAsync: true,
                isConnected: false,
                handle);
        }
        finally
        {
            Marshal.FreeHGlobal(descriptorPointer);
        }
    }

    private static MaintenanceResponse Error(
        MaintenanceRequestBody? body,
        string code,
        string message) =>
        new(
            MaintenanceContract.ProtocolVersion,
            body?.RequestId ?? Guid.Empty,
            body?.OperationId ?? Guid.Empty,
            MaintenanceOperationStatus.Failed,
            false,
            code.Length <= 64 ? code : code[..64],
            message.Length <= 160 ? message : message[..160],
            body is null
                ? null
                : MaintenanceOperationDigest.Create(body.Operation));

    private sealed record MaintenanceClientProcessEvidence(
        int ProcessId,
        int WtsSessionId);

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes
        {
            internal uint Length;
            internal IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool InheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetNamedPipeClientProcessId(
            Microsoft.Win32.SafeHandles.SafePipeHandle pipe,
            out uint clientProcessId);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateNamedPipeW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        internal static extern Microsoft.Win32.SafeHandles.SafePipeHandle
            CreateNamedPipe(
                string name,
                uint openMode,
                uint pipeMode,
                uint maximumInstances,
                uint outputBufferSize,
                uint inputBufferSize,
                uint defaultTimeout,
                ref SecurityAttributes securityAttributes);
    }
}
