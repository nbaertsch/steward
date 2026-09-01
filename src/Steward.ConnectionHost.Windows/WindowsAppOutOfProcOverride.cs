using System.Text.Json;
using Microsoft.Win32;

namespace Steward.ConnectionHost.Windows;

internal sealed class WindowsAppOutOfProcOverride : IDisposable
{
    private const string KeyPath = @"SOFTWARE\Microsoft\Windows365";
    private const string ValueName = "EnableOutOfProcConnections";
    private static readonly string BreadcrumbPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Steward",
        "connection-host",
        "windows-app-outofproc-override.json");
    private static readonly string LockPath = BreadcrumbPath + ".lock";
    private readonly FileStream lockFile;
    private readonly int previousValue;
    private readonly bool existed;
    private int disposed;

    private WindowsAppOutOfProcOverride(
        FileStream lockFile,
        int previousValue,
        bool existed)
    {
        this.lockFile = lockFile;
        this.previousValue = previousValue;
        this.existed = existed;
    }

    internal static WindowsAppOutOfProcOverride Disable(
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(BreadcrumbPath)!);
        FileStream? lockFile = null;
        try
        {
            lockFile = AcquireLock(LockPath, cancellationToken);
            RestoreStaleBreadcrumb();
            using var machine = Registry.LocalMachine.OpenSubKey(
                KeyPath,
                writable: false);
            if (machine?.GetValue(ValueName) is not null)
                throw new InvalidOperationException(
                    "A machine Windows App policy prevents in-process connection.");
            using var key = Registry.CurrentUser.CreateSubKey(
                KeyPath,
                writable: true) ??
                throw new InvalidOperationException(
                    "Windows App local settings are unavailable.");
            var existed = key.GetValueNames().Contains(
                ValueName,
                StringComparer.OrdinalIgnoreCase);
            if (existed &&
                (key.GetValueKind(ValueName) != RegistryValueKind.DWord ||
                 key.GetValue(ValueName) is not int))
                throw new InvalidOperationException(
                    "The Windows App override has an unsupported type.");
            var value = existed ? (int)key.GetValue(ValueName)! : 0;
            WriteBreadcrumb(new(1, existed, value));
            key.SetValue(ValueName, 0, RegistryValueKind.DWord);
            return new(lockFile, value, existed);
        }
        catch
        {
            lockFile?.Dispose();
            throw;
        }
    }

    internal static FileStream AcquireLock(
        string path,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None);
            }
            catch (Exception exception)
                when (exception is IOException or UnauthorizedAccessException)
            {
                if (cancellationToken.WaitHandle.WaitOne(100))
                    cancellationToken.ThrowIfCancellationRequested();
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        try
        {
            Restore(new(1, existed, previousValue));
            File.Delete(BreadcrumbPath);
        }
        finally
        {
            lockFile.Dispose();
        }
    }

    private static void RestoreStaleBreadcrumb()
    {
        if (!File.Exists(BreadcrumbPath))
            return;
        var breadcrumb = JsonSerializer.Deserialize<Breadcrumb>(
            File.ReadAllBytes(BreadcrumbPath));
        if (breadcrumb is null || breadcrumb.Version != 1)
            throw new InvalidDataException(
                "The Windows App override breadcrumb is invalid.");
        Restore(breadcrumb);
        File.Delete(BreadcrumbPath);
    }

    private static void WriteBreadcrumb(Breadcrumb breadcrumb)
    {
        var temporary = BreadcrumbPath + "." +
            Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(
                temporary,
                JsonSerializer.SerializeToUtf8Bytes(breadcrumb));
            File.Move(temporary, BreadcrumbPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static void Restore(Breadcrumb breadcrumb)
    {
        using var key = Registry.CurrentUser.CreateSubKey(
            KeyPath,
            writable: true) ??
            throw new InvalidOperationException(
                "Windows App local settings are unavailable.");
        if (breadcrumb.Existed)
            key.SetValue(
                ValueName,
                breadcrumb.Value,
                RegistryValueKind.DWord);
        else
            key.DeleteValue(ValueName, throwOnMissingValue: false);
    }

    private sealed record Breadcrumb(
        int Version,
        bool Existed,
        int Value);
}
