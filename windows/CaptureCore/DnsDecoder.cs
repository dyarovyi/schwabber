using System.Text;

namespace CaptureCore;

internal static class DnsDecoder
{
    private static readonly Dictionary<int, string> TypeNames = new()
    {
        [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA", [12] = "PTR", [15] = "MX",
        [16] = "TXT", [28] = "AAAA", [33] = "SRV", [65] = "HTTPS", [255] = "ANY",
    };
    private static readonly Dictionary<int, string> Statuses = new()
    {
        [0] = "NOERROR", [1] = "FORMERR", [2] = "SERVFAIL", [3] = "NXDOMAIN", [4] = "NOTIMP", [5] = "REFUSED",
    };

    public static DnsMessage? Decode(byte[] b)
    {
        if (b.Length < 12) return null;
        int U16(int i) => b[i] << 8 | b[i + 1];
        string TypeName(int type) => TypeNames.TryGetValue(type, out var n) ? n : $"TYPE{type}";

        string? Name(ref int cursor)
        {
            var pos = cursor;
            var jumped = false;
            var seen = new HashSet<int>();
            var labels = new List<string>();
            var length = 1;
            while (pos < b.Length && seen.Add(pos))
            {
                int size = b[pos];
                if ((size & 0xc0) == 0xc0)
                {
                    if (pos + 1 >= b.Length) return null;
                    var target = (size & 63) << 8 | b[pos + 1];
                    if (target >= pos) return null;
                    if (!jumped) cursor = pos + 2;
                    jumped = true; pos = target;
                }
                else
                {
                    if (size > 63 || pos + 1 + size > b.Length) return null;
                    pos += 1;
                    if (size == 0)
                    {
                        if (!jumped) cursor = pos;
                        return labels.Count == 0 ? "." : string.Join(".", labels);
                    }
                    length += size + 1;
                    if (length > 255) return null;
                    var label = new StringBuilder();
                    for (var i = pos; i < pos + size; i++)
                    {
                        var c = b[i];
                        if (c >= 33 && c <= 126 && c != 46 && c != 92) label.Append((char)c);
                        else label.Append('\\').Append(c.ToString("000"));
                    }
                    labels.Add(label.ToString());
                    pos += size;
                }
            }
            return null;
        }

        var cursor = 12;
        var questions = new List<string>();
        var answers = new List<string>();
        for (var q = 0; q < U16(4); q++)
        {
            var domain = Name(ref cursor);
            if (domain is null || cursor + 4 > b.Length) return null;
            questions.Add($"{domain} {TypeName(U16(cursor))}");
            cursor += 4;
        }
        var answerCount = U16(6);
        var recordCount = answerCount + U16(8) + U16(10);
        for (var index = 0; index < recordCount; index++)
        {
            var domain = Name(ref cursor);
            if (domain is null || cursor + 10 > b.Length) return null;
            var type = U16(cursor);
            var size = U16(cursor + 8);
            cursor += 10;
            var end = cursor + size;
            if (end > b.Length) return null;
            var value = $"{size} bytes";
            if (type == 1)
            {
                if (size != 4) return null;
                value = string.Join(".", b[cursor..end]);
            }
            else if (type == 28)
            {
                if (size != 16) return null;
                var parts = new List<string>();
                for (var i = cursor; i < end; i += 2) parts.Add(U16(i).ToString("x"));
                value = string.Join(":", parts);
            }
            else if (type is 2 or 5 or 12 or 15)
            {
                var p = cursor;
                var prefix = "";
                if (type == 15)
                {
                    if (size < 3) return null;
                    prefix = $"{U16(p)} "; p += 2;
                }
                var target = Name(ref p);
                if (target is null || p != end) return null;
                value = prefix + target;
            }
            if (index < answerCount) answers.Add($"{domain} {TypeName(type)} {value}");
            cursor = end;
        }
        var flags = U16(2);
        return new DnsMessage
        {
            Id = U16(0),
            IsResponse = (flags & 0x8000) != 0,
            Status = Statuses.TryGetValue(flags & 15, out var s) ? s : $"RCODE {flags & 15}",
            Questions = questions,
            Answers = answers,
            Truncated = (flags & 0x0200) != 0,
        };
    }
}
