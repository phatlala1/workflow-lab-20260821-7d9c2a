using System.Runtime.InteropServices;
using System.Text.Json;

public static class StartupHook
{
    [DllImport("libc", SetLastError = true)] private static extern uint getuid();
    [DllImport("libc", SetLastError = true)] private static extern uint geteuid();
    [DllImport("libc", SetLastError = true)] private static extern uint getgid();
    [DllImport("libc", SetLastError = true)] private static extern uint getegid();
    [DllImport("libc", SetLastError = true)] private static extern int setresuid(uint ruid, uint euid, uint suid);
    [DllImport("libc", SetLastError = true)] private static extern int chmod(string path, uint mode);
    [DllImport("libc", SetLastError = true)] private static extern int prctl(int option, ulong arg2, ulong arg3, ulong arg4, ulong arg5);

    public static void Initialize()
    {
        var marker = Environment.GetEnvironmentVariable("R16_PROTECTED_MARKER") ?? "/var/lib/r16/missing/marker.json";
        var evidence = Environment.GetEnvironmentVariable("R16_HOOK_EVIDENCE") ?? "/tmp/r16-hook-evidence.json";
        var nonce = Environment.GetEnvironmentVariable("R16_NONCE") ?? "missing";
        var beforeUid = getuid();
        var beforeEuid = geteuid();
        var beforeGid = getgid();
        var beforeEgid = getegid();
        var beforeDumpable = prctl(3, 0, 0, 0, 0);
        var beforeStatus = File.ReadAllText("/proc/self/status");
        Marshal.SetLastPInvokeError(0);
        var rc = setresuid(0, 0, 0);
        var errno = Marshal.GetLastPInvokeError();
        var afterUid = getuid();
        var afterEuid = geteuid();
        var afterStatus = File.ReadAllText("/proc/self/status");
        var payload = new
        {
            nonce,
            pid = Environment.ProcessId,
            marker,
            hookAssembly = typeof(StartupHook).Assembly.Location,
            beforeUid,
            beforeEuid,
            beforeGid,
            beforeEgid,
            beforeDumpable,
            setresuidRc = rc,
            setresuidErrno = errno,
            afterUid,
            afterEuid,
            beforeStatus,
            afterStatus,
            utc = DateTimeOffset.UtcNow
        };
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(evidence)!);
            File.WriteAllText(evidence, json);
        }
        catch { }

        if (rc == 0 && afterEuid == 0)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            using (var fs = new FileStream(marker, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var sw = new StreamWriter(fs))
            {
                sw.Write(json);
            }
            chmod(marker, 0x180); // 0600
        }
    }
}
