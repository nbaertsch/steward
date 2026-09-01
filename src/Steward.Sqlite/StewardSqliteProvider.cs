namespace Steward.Sqlite;

public static class StewardSqliteProvider
{
    private static int initialized;

    public static void Initialize()
    {
        if (Interlocked.CompareExchange(ref initialized, 1, 0) != 0)
            return;
        try
        {
            SQLitePCL.Batteries_V2.Init();
        }
        catch
        {
            Volatile.Write(ref initialized, 0);
            throw;
        }
    }
}
