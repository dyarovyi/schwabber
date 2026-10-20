using System.Text;

namespace CaptureCore;

/// <summary>
/// Packet-local HTTP/2 frame recognition (RFC 9113): the connection preface, or a complete sequence of
/// well-formed frames. HEADERS/PUSH_PROMISE/CONTINUATION payloads stay raw HPACK blocks.
/// </summary>
internal static class Http2Decoder
{
    private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    private static readonly string[] Names = { "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION" };

    public static RealtimeMessage? Decode(byte[] b)
    {
        var hasPreface = b.AsSpan().StartsWith(Preface);
        var p = hasPreface ? Preface.Length : 0;
        var fields = new List<RealtimeField>();
        var names = new List<string>();
        long U(int at, int n) { long v = 0; for (var i = 0; i < n; i++) v = v << 8 | b[at + i]; return v; }
        void Add(string name, int at, int size, string? value = null) => fields.Add(new RealtimeField(name, value ?? U(at, size).ToString(), at, size));
        if (hasPreface) Add("Connection Preface", 0, p, "HTTP/2");
        while (p < b.Length)
        {
            if (p + 9 > b.Length)
                return hasPreface ? new RealtimeMessage("HTTP/2", "Connection preface · partial frame header", fields) : null;
            var length = (int)U(p, 3);
            int type = b[p + 3], flags = b[p + 4];
            var stream = U(p + 5, 4) & 0x7fffffff;
            if (type > 9) return null;
            if (type is 0 or 1 or 2 or 3 or 5 or 9 && stream == 0) return null;
            if (type is 4 or 6 or 7 && stream != 0) return null;
            if ((type == 2 && length != 5) || (type == 3 && length != 4) || (type == 6 && length != 8) || (type == 8 && length != 4) ||
                (type == 7 && length < 8) || (type == 4 && (length % 6 != 0 || ((flags & 1) != 0 && length != 0)))) return null;
            var name = Names[type];
            names.Add($"{name} stream {stream}");
            Add("Frame Length", p, 3); Add("Frame Type", p + 3, 1, name); Add("Flags", p + 4, 1, $"0x{flags:x2}"); Add("Stream ID", p + 5, 4, stream.ToString());
            int body = p + 9, end = p + 9 + length;
            if (end > b.Length)
            {
                if (!hasPreface) return null;
                if (body < b.Length) Add("Partial Frame Payload", body, b.Length - body, $"{length} bytes expected");
                break;
            }
            if (type == 4)
            {
                for (var q = body; q < end; q += 6) { Add("Setting ID", q, 2); Add("Setting Value", q + 2, 4); }
            }
            else if (type == 8) Add("Window Increment", body, 4, (U(body, 4) & 0x7fffffff).ToString());
            else if (type == 3) Add("Error Code", body, 4);
            else if (type == 7)
            {
                Add("Last Stream ID", body, 4, (U(body, 4) & 0x7fffffff).ToString()); Add("Error Code", body + 4, 4);
                if (length > 8) Add("Debug Data", body + 8, length - 8, $"{length - 8} bytes");
            }
            else if (length > 0)
            {
                Add(type is 1 or 5 or 9 ? "Header Block / Frame Payload (HPACK not decoded)" : "Frame Payload", body, length, $"{length} bytes");
            }
            p = end;
        }
        if (!hasPreface && names.Count == 0) return null;
        return new RealtimeMessage("HTTP/2", names.Count == 0 ? "Connection preface" : string.Join(" · ", names), fields);
    }
}
