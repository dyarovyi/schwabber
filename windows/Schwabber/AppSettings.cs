using System.IO;

namespace Schwabber;

/// <summary>Small persisted preferences (key=value lines in %LOCALAPPDATA%\Schwabber\settings.txt).</summary>
public static class AppSettings
{
    private static readonly string FilePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Schwabber", "settings.txt");

    private static Dictionary<string, string> Read()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            if (!File.Exists(FilePath)) return values;
            foreach (var line in File.ReadAllLines(FilePath))
            {
                var separator = line.IndexOf('=');
                if (separator > 0) values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return values;
    }

    public static bool GetBool(string key, bool fallback) =>
        Read().TryGetValue(key, out var value) && bool.TryParse(value, out var parsed) ? parsed : fallback;

    public static void SetBool(string key, bool value)
    {
        var values = Read();
        values[key] = value.ToString();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllLines(FilePath, values.Select(pair => $"{pair.Key}={pair.Value}"));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
