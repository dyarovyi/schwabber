namespace CaptureCore;

public sealed class ProtocolInfo
{
    public ProtocolInfo(string name, string summary) { Name = name; Summary = summary; }
    public string Name { get; }
    public string Summary { get; }
}

public sealed class DnsMessage
{
    public required int Id { get; init; }
    public required bool IsResponse { get; init; }
    public required string Status { get; init; }
    public required IReadOnlyList<string> Questions { get; init; }
    public required IReadOnlyList<string> Answers { get; init; }
    public required bool Truncated { get; init; }

    public string Summary =>
        $"{(IsResponse ? "Response" : "Query")} #{Id} " + string.Join(", ", Questions) +
        (IsResponse ? $" · {Status}" : "") +
        (Answers.Count == 0 ? "" : " → " + string.Join("; ", Answers)) +
        (Truncated ? " · truncated" : "");
}

public sealed class Packet
{
    public required int Id { get; init; }
    public required double Time { get; init; }
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public required int Length { get; init; }
    public required string Flags { get; init; }
    public required IReadOnlyList<DnsMessage> Dns { get; init; }
    public required ProtocolInfo? Application { get; init; }
    public required byte[] RawBytes { get; init; }
    public required uint Seconds { get; init; }
    public required uint Microseconds { get; init; }
    /// <summary>Transport payload within RawBytes (link, IP and TCP/UDP/ICMP headers excluded).</summary>
    public int PayloadStart { get; init; }
    public int PayloadEnd { get; init; }
    public ReadOnlySpan<byte> Payload => RawBytes.AsSpan(PayloadStart, Math.Max(0, PayloadEnd - PayloadStart));

    private string? details;
    public string Details => details ??= string.Join(" · ", new[]
    {
        Flags,
        Application is null ? "" : $"{Application.Name}: {Application.Summary}",
        string.Join(" | ", Dns.Select(d => d.Summary)),
    }.Where(s => s.Length > 0));
}

public sealed class Session
{
    public Session(int id, string transport, string endpointA, string endpointB, Packet first)
    {
        Id = id; Transport = transport; EndpointA = endpointA; EndpointB = endpointB;
        packets.Add(first);
    }
    private readonly List<Packet> packets = new();
    public int Id { get; }
    public string Transport { get; }
    public string EndpointA { get; }
    public string EndpointB { get; }
    public IReadOnlyList<Packet> Packets => packets;
    internal void Append(Packet packet) { packets.Add(packet); Invalidate(); }

    public double Start => packets[0].Time;
    public double End => packets[^1].Time;

    private bool? hasDns;
    public bool HasDns => hasDns ??= packets.Any(p => p.Dns.Count > 0);

    private IReadOnlyList<string>? applicationProtocols;
    public IReadOnlyList<string> ApplicationProtocols => applicationProtocols ??=
        packets.Where(p => p.Application is not null).Select(p => p.Application!.Name)
            .Concat(HasDns ? new[] { "DNS" } : Array.Empty<string>())
            .Distinct().OrderBy(s => s, StringComparer.Ordinal).ToList();

    public string ProtocolLabel => string.Join(" / ", ApplicationProtocols.Append(Transport));
    public string Summary => packets.FirstOrDefault(p => p.Application is not null || p.Dns.Count > 0 || Transport.StartsWith("ICMP", StringComparison.Ordinal))?.Details ?? "";

    /// <summary>Case-insensitive match against endpoints and per-packet protocol details.</summary>
    public bool Matches(string query)
    {
        var compare = System.Globalization.CultureInfo.CurrentCulture.CompareInfo;
        bool Has(string text) => compare.IndexOf(text, query, System.Globalization.CompareOptions.IgnoreCase) >= 0;
        return Has(EndpointA) || Has(EndpointB) || packets.Any(p => Has(p.Details));
    }

    private string? searchText;
    public string SearchText => searchText ??= $"{EndpointA} {EndpointB} " + string.Join(" ", packets.Select(p => p.Details));

    public string DnsSummary => packets.SelectMany(p => p.Dns).FirstOrDefault() is { } m ? string.Join(", ", m.Questions) : "";

    private long? bytes;
    public long Bytes => bytes ??= packets.Sum(p => (long)p.Length);

    private void Invalidate() { hasDns = null; applicationProtocols = null; searchText = null; bytes = null; }
}

public sealed class Capture
{
    public required IReadOnlyList<Session> Sessions { get; init; }
    public required int LinkType { get; init; }
    public required int TotalPackets { get; init; }
    public required int SkippedPackets { get; init; }
    /// <summary>Sum of original lengths of every packet in the file, including unsupported ones.</summary>
    public long TotalBytes { get; init; }
    /// <summary>The file the capture was read from (or the live recording file); Wireshark analysis reopens it.</summary>
    public string SourcePath { get; init; } = "";
    public double Start => Sessions.Count == 0 ? 0 : Sessions.Min(s => s.Start);
    public double End => Sessions.Count == 0 ? Start : Sessions.Max(s => s.End);
}

public sealed class CaptureException : Exception
{
    public CaptureException(string message) : base(message) { }
}
