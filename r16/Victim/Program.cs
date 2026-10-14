using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("Victim <ready.json> <stop-file>");
            return 64;
        }

        var ready = Path.GetFullPath(args[0]);
        var stop = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(Path.GetDirectoryName(ready)!);
        var status = File.ReadAllText("/proc/self/status");
        var payload = new
        {
            pid = Environment.ProcessId,
            uid = Native.getuid(),
            euid = Native.geteuid(),
            gid = Native.getgid(),
            egid = Native.getegid(),
            dumpable = Native.prctl(3, 0, 0, 0, 0), // PR_GET_DUMPABLE
            executable = Environment.ProcessPath,
            baseDirectory = AppContext.BaseDirectory,
            runtime = RuntimeInformation.FrameworkDescription,
            status
        };
        File.WriteAllText(ready, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(payload));
        Console.Out.Flush();

        var sw = Stopwatch.StartNew();
        while (!File.Exists(stop) && sw.Elapsed < TimeSpan.FromSeconds(120))
        {
            Thread.Sleep(100);
        }
        return 0;
    }
}

internal static class Native
{
    [DllImport("libc", SetLastError = true)] internal static extern uint getuid();
    [DllImport("libc", SetLastError = true)] internal static extern uint geteuid();
    [DllImport("libc", SetLastError = true)] internal static extern uint getgid();
    [DllImport("libc", SetLastError = true)] internal static extern uint getegid();
    [DllImport("libc", SetLastError = true)] internal static extern int prctl(int option, ulong arg2, ulong arg3, ulong arg4, ulong arg5);
}
