using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

const string JobName = "Local\\Steward.JobObjectSpike";
const uint JobObjectAllAccess = 0x1F001F;

if (args.Length == 0)
{
    Console.Error.WriteLine(
        "Usage: create | create-wait <pid-file> <release-file> | hold <ready-file> <stop-file> | open <pid> | terminate | kill <pid>");
    return 2;
}

switch (args[0])
{
    case "create":
        {
            var job = NativeMethods.CreateJobObject(IntPtr.Zero, JobName);
            ThrowIfInvalid(job, nameof(NativeMethods.CreateJobObject));
            using var child = StartChild();
            Assign(job, child);
            Console.WriteLine(child.Id);
            NativeMethods.CloseHandle(job);
            return 0;
        }

    case "create-wait":
        {
            var job = NativeMethods.CreateJobObject(IntPtr.Zero, JobName);
            ThrowIfInvalid(job, nameof(NativeMethods.CreateJobObject));
            using var child = StartChild();
            Assign(job, child);
            File.WriteAllText(args[1], child.Id.ToString());
            if (!SpinWait.SpinUntil(() => File.Exists(args[2]), TimeSpan.FromSeconds(30)))
            {
                child.Kill(entireProcessTree: true);
                throw new TimeoutException("Release file was not created.");
            }

            NativeMethods.CloseHandle(job);
            return 0;
        }

    case "hold":
        {
            var job = NativeMethods.OpenJobObject(JobObjectAllAccess, false, JobName);
            ThrowIfInvalid(job, nameof(NativeMethods.OpenJobObject));
            File.WriteAllText(args[1], Environment.ProcessId.ToString());
            if (!SpinWait.SpinUntil(() => File.Exists(args[2]), TimeSpan.FromMinutes(5)))
            {
                throw new TimeoutException("Stop file was not created.");
            }

            NativeMethods.CloseHandle(job);
            return 0;
        }

    case "open":
        {
            var pid = int.Parse(args[1]);
            var job = NativeMethods.OpenJobObject(JobObjectAllAccess, false, JobName);
            ThrowIfInvalid(job, nameof(NativeMethods.OpenJobObject));
            using var child = Process.GetProcessById(pid);
            if (!NativeMethods.IsProcessInJob(child.Handle, job, out var isInJob))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    nameof(NativeMethods.IsProcessInJob));
            }

            Console.WriteLine($"open=true; pid={pid}; isInJob={isInJob}");
            NativeMethods.CloseHandle(job);
            return isInJob ? 0 : 1;
        }

    case "terminate":
        {
            var job = NativeMethods.OpenJobObject(JobObjectAllAccess, false, JobName);
            ThrowIfInvalid(job, nameof(NativeMethods.OpenJobObject));
            if (!NativeMethods.TerminateJobObject(job, 1))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    nameof(NativeMethods.TerminateJobObject));
            }

            NativeMethods.CloseHandle(job);
            Console.WriteLine("terminated=true");
            return 0;
        }

    case "kill":
        {
            using var process = Process.GetProcessById(int.Parse(args[1]));
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            Console.WriteLine("killed=true");
            return 0;
        }

    default:
        Console.Error.WriteLine($"Unknown mode: {args[0]}");
        return 2;
}

static Process StartChild() =>
    Process.Start(new ProcessStartInfo
    {
        FileName = "powershell.exe",
        Arguments = "-NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 300\"",
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
    }) ?? throw new InvalidOperationException("Failed to start child.");

static void Assign(IntPtr job, Process child)
{
    if (NativeMethods.AssignProcessToJobObject(job, child.Handle))
    {
        return;
    }

    var error = Marshal.GetLastWin32Error();
    child.Kill(entireProcessTree: true);
    throw new Win32Exception(error, nameof(NativeMethods.AssignProcessToJobObject));
}

static void ThrowIfInvalid(IntPtr handle, string operation)
{
    if (handle == IntPtr.Zero)
    {
        throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }
}

internal static partial class NativeMethods
{
    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW",
        SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr CreateJobObject(
        IntPtr securityAttributes,
        string? name);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenJobObjectW",
        SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr OpenJobObject(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        string name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AssignProcessToJobObject(
        IntPtr job,
        IntPtr process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsProcessInJob(
        IntPtr process,
        IntPtr job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool TerminateJobObject(IntPtr job, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);
}
