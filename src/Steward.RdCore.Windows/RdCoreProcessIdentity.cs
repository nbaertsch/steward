using System.Runtime.InteropServices;

namespace Steward.RdCore.Windows;

public static class RdCoreProcessIdentity
{
    private const int AppModelErrorNoPackage = 15700;
    private const int ErrorInsufficientBuffer = 122;

    public static bool HasPackageIdentity()
    {
        uint length = 0;
        var result = GetCurrentPackageFullName(
            ref length,
            null);
        return result switch
        {
            ErrorInsufficientBuffer => true,
            AppModelErrorNoPackage => false,
            _ => throw new InvalidOperationException(
                $"Package identity detection failed with error {result}.")
        };
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "GetCurrentPackageFullName",
        CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(
        ref uint packageFullNameLength,
        char[]? packageFullName);
}
