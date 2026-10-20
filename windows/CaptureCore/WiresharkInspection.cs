using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace CaptureCore;

/// <summary>A node of Wireshark's decoded field tree. Start/Length locate bytes in data source SourceIndex (0 = the frame).</summary>
public sealed class WiresharkField
{
    public required string Name { get; init; }
    public required string Label { get; init; }
    public required string Value { get; init; }
    public required IReadOnlyList<WiresharkField> Children { get; init; }
    public required int SourceIndex { get; init; }
    public int Start { get; init; } = -1;
    public int Length { get; init; }
    public WiresharkField? Parent { get; internal set; }
    public bool HasRange => Start >= 0 && Length > 0;
}

/// <summary>Reassembled or decrypted bytes Wireshark produced for a frame, such as "Reassembled TCP" or "Decrypted QUIC".</summary>
public sealed record PacketDataSource(string Name, byte[] Bytes);

public sealed class WiresharkDissection
{
    public required IReadOnlyList<WiresharkField> Fields { get; init; }
    public required IReadOnlyList<PacketDataSource> AdditionalSources { get; init; }
}

/// <summary>
/// Optional full-capture analysis with Wireshark's sharkd: reassembly and TLS/QUIC decryption (given a key log)
/// for the selected frame. The built-in dissector keeps working without Wireshark.
/// </summary>
public static class WiresharkInspection
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    public static string? FindSharkd()
    {
        var folders = new List<string>();
        if (OperatingSystem.IsWindows())
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe");
            if (key?.GetValue(null) is string wireshark && Path.GetDirectoryName(wireshark.Trim('"')) is { } folder) folders.Add(folder);
        }
        catch (System.Security.SecurityException) { }
        foreach (var root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            folders.Add(Path.Combine(Environment.GetFolderPath(root), "Wireshark"));
        return folders.Select(f => Path.Combine(f, "sharkd.exe")).FirstOrDefault(File.Exists);
    }

    public static Task<WiresharkDissection> InspectAsync(Packet packet, Capture capture, string? keyLog, CancellationToken cancellation) =>
        Task.Run(() => InspectCore(packet, capture, keyLog, cancellation), cancellation);

    private static async Task<WiresharkDissection> InspectCore(Packet packet, Capture capture, string? keyLog, CancellationToken cancellation)
    {
        var executable = FindSharkd() ?? throw new CaptureException(
            "Install Wireshark with sharkd for reassembled/decrypted sources and linked fields. Captured bytes remain available.");
        if (!File.Exists(capture.SourcePath)) throw new CaptureException("The source capture is no longer available. Reopen it before inspecting packets.");

        var requests = new List<string>();
        void Request(string method, object parameters) =>
            requests.Add(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = requests.Count + 1, method, @params = parameters }));
        foreach (var preference in new[] { "tcp.desegment_tcp_streams", "tls.desegment_ssl_records", "tls.desegment_ssl_application_data", "http.desegment_headers", "http.desegment_body" })
            Request("setconf", new { name = preference, value = "true" });
        Request("setconf", new { name = "tls.keylog_file", value = keyLog ?? "" });
        Request("load", new { file = capture.SourcePath });
        Request("analyse", new { });
        Request("frame", new { frame = packet.Id, proto = true, bytes = true });

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable, "-")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
            },
        };
        process.Start();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(Timeout);
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errors = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.StandardInput.WriteAsync(string.Join("\n", requests) + "\n");
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            var text = await output;
            if (process.ExitCode != 0) throw new CaptureException("Wireshark: " + (await errors).Trim());
            return ParseResponses(text, requests.Count, packet.RawBytes);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            cancellation.ThrowIfCancellationRequested();
            throw new CaptureException("Wireshark analysis timed out. Try a smaller capture.");
        }
    }

    internal static WiresharkDissection ParseResponses(string output, int lastId, byte[] expectedFrame)
    {
        JsonElement? result = null;
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            using var document = JsonDocument.Parse(line);
            var response = document.RootElement;
            if (response.TryGetProperty("error", out var error))
                throw new CaptureException("Wireshark: " + (error.TryGetProperty("message", out var message) ? message.GetString() : "Analysis failed"));
            if (response.TryGetProperty("id", out var id) && id.GetInt32() == lastId && response.TryGetProperty("result", out var value))
                result = value.Clone();
        }
        if (result is null) throw new CaptureException("Wireshark returned no packet details.");
        return ParseFrame(result.Value, expectedFrame);
    }

    /// <summary>Parses sharkd's "frame" result: tree nodes l (label), f (filter), h ([start, length]), ds (source), g (generated), n (children).</summary>
    public static WiresharkDissection ParseFrame(JsonElement result, byte[] expectedFrame)
    {
        if (!result.TryGetProperty("bytes", out var encoded) || !Convert.FromBase64String(encoded.GetString() ?? "").AsSpan().SequenceEqual(expectedFrame))
            throw new CaptureException("The source capture changed since import. Reopen it before inspecting packets.");
        var sources = new List<PacketDataSource>();
        if (result.TryGetProperty("ds", out var dataSources))
        {
            var index = 0;
            foreach (var source in dataSources.EnumerateArray())
            {
                index++;
                if (!source.TryGetProperty("bytes", out var sourceBytes)) throw new CaptureException("Wireshark returned an invalid data source.");
                var name = source.TryGetProperty("name", out var n) ? n.GetString() ?? "Data" : "Data";
                sources.Add(new PacketDataSource($"{index}. {name}", Convert.FromBase64String(sourceBytes.GetString() ?? "")));
            }
        }
        var sizes = new[] { expectedFrame.Length }.Concat(sources.Select(s => s.Bytes.Length)).ToArray();

        WiresharkField Field(JsonElement node)
        {
            var sourceIndex = node.TryGetProperty("ds", out var ds) ? ds.GetInt32() : 0;
            var generated = node.TryGetProperty("g", out var g) && g.ValueKind == JsonValueKind.True;
            int start = -1, length = 0;
            if (!generated && node.TryGetProperty("h", out var span) && span.GetArrayLength() == 2 && sourceIndex >= 0 && sourceIndex < sizes.Length)
            {
                int s = span[0].GetInt32(), l = span[1].GetInt32();
                if (s >= 0 && l > 0 && s <= sizes[sourceIndex] && l <= sizes[sourceIndex] - s) { start = s; length = l; }
            }
            var filter = node.TryGetProperty("f", out var f) ? f.GetString() ?? "" : "";
            var children = node.TryGetProperty("n", out var nodes) ? nodes.EnumerateArray().Select(Field).ToList() : new List<WiresharkField>();
            var field = new WiresharkField
            {
                Name = filter.Split(' ')[0], Label = node.TryGetProperty("l", out var l2) ? l2.GetString() ?? filter : filter, Value = filter,
                Children = children, SourceIndex = sourceIndex, Start = start, Length = length,
            };
            foreach (var child in children) child.Parent = field;
            return field;
        }
        var tree = result.TryGetProperty("tree", out var t) ? t.EnumerateArray().Select(Field).ToList() : new List<WiresharkField>();
        return new WiresharkDissection { Fields = tree, AdditionalSources = sources };
    }
}
