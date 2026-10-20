using System.Globalization;
using System.Text;

namespace CaptureCore;

/// <summary>Packet-local decoding: never infers an encrypted application from its port.</summary>
internal static class ProtocolDecoder
{
    private static readonly string[] HttpMethods = { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE" };
    private static readonly string[] HttpVersions = { "HTTP/1.0", "HTTP/1.1" };
    private static readonly Dictionary<int, string> TlsRecords = new()
    {
        [20] = "ChangeCipherSpec", [21] = "Alert", [22] = "Handshake", [23] = "Encrypted application data", [24] = "Heartbeat",
    };
    private static readonly Dictionary<int, string> Handshakes = new()
    {
        [1] = "ClientHello", [2] = "ServerHello", [11] = "Certificate", [12] = "ServerKeyExchange",
        [14] = "ServerHelloDone", [16] = "ClientKeyExchange", [20] = "Finished",
    };

    private static string Hex(byte[] b, int start, int end) => Convert.ToHexString(b, start, end - start).ToLowerInvariant();

    public static ProtocolInfo? Decode(byte[] b, bool tcp)
    {
        if (tcp && Http2Decoder.Decode(b) is { } http2) return new ProtocolInfo(http2.Name, http2.Summary);
        if (RealtimeDecoder.Decode(b, tcp) is { } message) return new ProtocolInfo(message.Name, message.Summary);
        int Word(int i) => b[i] << 8 | b[i + 1];
        if (b.Length >= 20 && (b[0] & 0xc0) == 0 && b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xa4 && b[7] == 0x42)
        {
            var length = Word(2);
            if (length % 4 != 0 || length + 20 > b.Length) return null;
            var type = Word(0);
            var method = (type & 15) | ((type & 0xe0) >> 1) | ((type & 0x3e00) >> 2);
            var kind = ((type >> 4) & 1) | ((type >> 7) & 2);
            var fields = new List<string>
            {
                $"{(method switch { 1 => "Binding", 3 => "Allocate", 4 => "Refresh", 6 => "Send", 7 => "Data", 8 => "CreatePermission", 9 => "ChannelBind", _ => $"Method {method}" })} {new[] { "request", "indication", "success", "error" }[kind]}",
                $"transaction {Hex(b, 8, 20)}",
            };
            var p = 20;
            while (p < 20 + length)
            {
                if (p + 4 > 20 + length) return null;
                int attribute = Word(p), size = Word(p + 2);
                p += 4;
                if (p + size > 20 + length) return null;
                if (attribute == 0x20 && size == 8 && b[p + 1] == 1)
                {
                    byte[] cookie = { 0x21, 0x12, 0xa4, 0x42 };
                    var start = p;
                    var ip = string.Join(".", Enumerable.Range(0, 4).Select(i => (b[start + 4 + i] ^ cookie[i]).ToString()));
                    fields.Add($"mapped {ip}:{Word(p + 2) ^ 0x2112}");
                }
                p += (size + 3) & ~3;
                if (p > 20 + length) return null;
            }
            return new ProtocolInfo("STUN", string.Join(" · ", fields));
        }
        if (!tcp && b.Length >= 12 && (b[0] >> 6) == 2 && !((b[1] & 127) >= 64 && (b[1] & 127) <= 95))
        {
            var header = 12 + (b[0] & 15) * 4;
            if (header > b.Length) return null;
            if ((b[0] & 16) != 0)
            {
                if (header + 4 > b.Length) return null;
                header += 4 + Word(header + 2) * 4;
                if (header > b.Length) return null;
            }
            var padding = (b[0] & 32) != 0 ? b[^1] : 0;
            if (((b[0] & 32) != 0 && padding == 0) || padding > b.Length - header) return null;
            var stamp = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(4, 4));
            return new ProtocolInfo("RTP", $"PT {b[1] & 127} · sequence {Word(2)} · timestamp {stamp} · SSRC {Hex(b, 8, 12)} · {b.Length - header - padding} media bytes · heuristic");
        }
        if (tcp)
        {
            var text = Encoding.UTF8.GetString(b, 0, Math.Min(b.Length, 16384));
            if (text.StartsWith("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", StringComparison.Ordinal))
                return new ProtocolInfo("HTTP", "HTTP/2 connection preface");
            var lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (lineEnd >= 0)
            {
                var line = text[..lineEnd];
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var request = parts.Length == 3 && HttpMethods.Contains(parts[0]) && HttpVersions.Contains(parts[2]);
                var response = parts.Length >= 2 && HttpVersions.Contains(parts[0]) && parts[1].Length == 3 &&
                               int.TryParse(parts[1], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _);
                if (request || response)
                {
                    var headers = text.Split("\r\n\r\n")[0].Split("\r\n");
                    var host = headers.FirstOrDefault(h => h.ToLowerInvariant().StartsWith("host:", StringComparison.Ordinal));
                    return new ProtocolInfo("HTTP", line + (host is null ? "" : $" · {host}"));
                }
            }
            if (b.Length >= 5 && b[0] >= 20 && b[0] <= 24 && b[1] == 3 && b[2] <= 3 && Word(3) <= 18432)
            {
                var size = Word(3);
                var summary = $"{TlsRecords[b[0]]} · record version 3.{b[2]} · {size} bytes";
                if (size + 5 > b.Length) summary += " · incomplete record";
                else if (b[0] == 22 && size >= 4)
                {
                    var handshake = Handshakes.TryGetValue(b[5], out var h) ? h : $"Handshake {b[5]}";
                    summary = handshake + " · " + summary;
                    if (b[5] == 1) summary += ClientHello(b[5..(size + 5)]);
                }
                return new ProtocolInfo("TLS", summary);
            }
        }
        else if (b.Length >= 7 && (b[0] & 0xc0) == 0xc0)
        {
            var version = (uint)b[1] << 24 | (uint)b[2] << 16 | (uint)b[3] << 8 | b[4];
            if (version != 1 && version != 0x6b3343cf) return null;
            int dcidLength = b[5];
            if (dcidLength > 20 || 6 + dcidLength >= b.Length) return null;
            int p = 6 + dcidLength, scidLength = b[p];
            if (scidLength > 20 || p + 1 + scidLength >= b.Length) return null;
            var kind = (b[0] >> 4) & 3;
            var types = version == 1 ? new[] { "Initial", "0-RTT", "Handshake", "Retry" } : new[] { "Retry", "Initial", "0-RTT", "Handshake" };
            return new ProtocolInfo("QUIC", $"{(version == 1 ? "v1" : "v2")} {types[kind]} long header · DCID {Hex(b, 6, p)} · SCID {Hex(b, p + 1, p + 1 + scidLength)} · encrypted payload");
        }
        return null;
    }

    private static string ClientHello(byte[] b)
    {
        if (b.Length < 39) return "";
        var length = b[1] << 16 | b[2] << 8 | b[3];
        if (length + 4 > b.Length) return " · incomplete ClientHello";
        var end = length + 4;
        int Word(int i) => b[i] << 8 | b[i + 1];
        var p = 38;
        int sessionLength = b[p]; p += 1 + sessionLength;
        if (p + 2 > end) return "";
        var cipherLength = Word(p); p += 2 + cipherLength;
        if (p >= end) return "";
        int compressionLength = b[p]; p += 1 + compressionLength;
        if (p + 2 > end) return "";
        var extensionsEnd = p + 2 + Word(p); p += 2;
        if (extensionsEnd > end) return "";
        var fields = new List<string>();
        while (p + 4 <= extensionsEnd)
        {
            int type = Word(p), size = Word(p + 2); p += 4;
            var next = p + size;
            if (next > extensionsEnd) return "";
            if (type == 0 && size >= 5 && Word(p) == size - 2 && b[p + 2] == 0)
            {
                var count = Word(p + 3);
                if (p + 5 + count <= next) fields.Add("SNI " + Encoding.UTF8.GetString(b, p + 5, count));
            }
            else if (type == 16 && size >= 3 && Word(p) == size - 2)
            {
                var q = p + 2;
                var names = new List<string>();
                while (q < next)
                {
                    int count = b[q]; q += 1;
                    if (count == 0 || q + count > next) return "";
                    names.Add(Encoding.UTF8.GetString(b, q, count)); q += count;
                }
                fields.Add("ALPN " + string.Join(", ", names));
            }
            p = next;
        }
        return fields.Count == 0 ? "" : " · " + string.Join(" · ", fields);
    }
}
