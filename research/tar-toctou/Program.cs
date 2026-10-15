using System.Formats.Tar;
using System.Text.Json;

static int Usage()
{
    Console.Error.WriteLine("extract-once <archive> <dest> | extract-loop <archive> <dest> <outsideMarker> <payload> <iterations>");
    return 64;
}

if (args.Length < 3)
{
    return Usage();
}

if (args[0] == "extract-once")
{
    TarFile.ExtractToDirectory(args[1], args[2], overwriteFiles: true);
    return 0;
}

if (args[0] != "extract-loop" || args.Length != 6 || !int.TryParse(args[5], out int iterations))
{
    return Usage();
}

string archive = args[1];
string destination = args[2];
string outsideMarker = args[3];
string payload = args[4];
int completed = 0;
int rejected = 0;
var exceptionTypes = new Dictionary<string, int>(StringComparer.Ordinal);
bool escaped = false;

for (int i = 0; i < iterations; i++)
{
    try
    {
        TarFile.ExtractToDirectory(archive, destination, overwriteFiles: true);
        completed++;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        rejected++;
        string key = ex.GetType().FullName ?? ex.GetType().Name;
        exceptionTypes[key] = exceptionTypes.TryGetValue(key, out int count) ? count + 1 : 1;
    }

    if (File.Exists(outsideMarker))
    {
        try
        {
            if (File.ReadAllText(outsideMarker) == payload)
            {
                escaped = true;
                break;
            }
        }
        catch (IOException)
        {
        }
    }
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    escaped,
    completed,
    rejected,
    iterationsRequested = iterations,
    exceptionTypes,
    effectiveUser = Environment.UserName,
}));
return escaped ? 42 : 0;
