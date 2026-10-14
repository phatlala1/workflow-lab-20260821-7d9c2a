using Microsoft.Diagnostics.NETCore.Client;
using System.Text.Json;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 2 || !int.TryParse(args[0], out var pid))
        {
            Console.Error.WriteLine("Client <pid> <absolute-hook-path>");
            return 64;
        }

        var hook = Path.GetFullPath(args[1]);
        var started = DateTimeOffset.UtcNow;
        try
        {
            var client = new DiagnosticsClient(pid);
            client.ApplyStartupHook(hook);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                status = "REQUEST_ACCEPTED",
                pid,
                hook,
                started,
                completed = DateTimeOffset.UtcNow
            }));
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                status = "REQUEST_REJECTED",
                pid,
                hook,
                started,
                completed = DateTimeOffset.UtcNow,
                type = ex.GetType().FullName,
                ex.Message,
                ex.HResult
            }));
            return 1;
        }
    }
}
