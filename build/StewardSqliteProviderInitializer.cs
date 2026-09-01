using System.Runtime.CompilerServices;

internal static class StewardSqliteProviderInitializer
{
#pragma warning disable CA2255
    [ModuleInitializer]
    internal static void Initialize() =>
        Steward.Sqlite.StewardSqliteProvider.Initialize();
#pragma warning restore CA2255
}

