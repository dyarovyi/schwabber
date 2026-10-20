namespace CaptureCore;

/// <summary>PayloadStart/PayloadEnd bound the transport payload (ICMP: after its 8-byte header) within the captured bytes.</summary>
internal sealed record DecodedPacket(string Transport, string Source, string Destination, string Flags, IReadOnlyList<DnsMessage> Dns, ProtocolInfo? Application,
    int PayloadStart = 0, int PayloadEnd = 0);

public static class CaptureReader
{
    private static readonly int[] SupportedLinkTypes = { 1, 0, 108, 12, 101, 113, 276 };

    public static Capture Read(string path)
    {
        using var file = CaptureFile.Open(path);
        var link = file.LinkType;
        if (!SupportedLinkTypes.Contains(link))
            throw new CaptureException($"Unsupported capture link type: {link}. Try an Ethernet, loopback, raw IP or Linux cooked capture.");
        var decoded = new List<(string Transport, string Source, string Destination, Packet Packet)>();
        var total = 0;
        long totalBytes = 0;
        while (file.Next() is { } record)
        {
            total += 1;
            totalBytes += record.OriginalLength;
            if (Decode(record.Data, link) is { } p)
            {
                var time = record.Seconds + record.Microseconds / 1_000_000.0;
                decoded.Add((p.Transport, p.Source, p.Destination, new Packet
                {
                    Id = total, Time = time, Source = p.Source, Destination = p.Destination,
                    Length = (int)Math.Min(record.OriginalLength, int.MaxValue), Flags = p.Flags, Dns = p.Dns,
                    Application = p.Application, RawBytes = record.Data, PayloadStart = p.PayloadStart, PayloadEnd = p.PayloadEnd,
                    Seconds = (uint)Math.Clamp(record.Seconds, 0, uint.MaxValue),
                    Microseconds = (uint)Math.Clamp(record.Microseconds, 0, uint.MaxValue),
                }));
            }
        }
        decoded.Sort((a, b) => a.Packet.Time == b.Packet.Time ? a.Packet.Id.CompareTo(b.Packet.Id) : a.Packet.Time.CompareTo(b.Packet.Time));
        var sessions = new List<Session>();
        var active = new Dictionary<string, int>();
        foreach (var (transport, source, destination, packet) in decoded)
        {
            var low = string.CompareOrdinal(source, destination) <= 0 ? source : destination;
            var high = ReferenceEquals(low, source) ? destination : source;
            var key = $"{transport}|{low}|{high}";
            if (active.TryGetValue(key, out var index) && packet.Time - sessions[index].End <= 60)
            {
                sessions[index].Append(packet);
            }
            else
            {
                active[key] = sessions.Count;
                sessions.Add(new Session(sessions.Count, transport, source, destination, packet));
            }
        }
        return new Capture { Sessions = sessions, LinkType = link, TotalPackets = total, SkippedPackets = total - decoded.Count, TotalBytes = totalBytes,
                             SourcePath = Path.GetFullPath(path) };
    }

    // Bounds checks also reject truncated headers and non-initial fragments.
    internal static DecodedPacket? Decode(byte[] b, int link)
    {
        try { return DecodeUnchecked(b, link); }
        catch (IndexOutOfRangeException) { return null; }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static DecodedPacket? DecodeUnchecked(byte[] b, int link)
    {
        int U16(int i) => b[i] << 8 | b[i + 1];
        int offset;
        switch (link)
        {
            case 1:
                if (b.Length < 14) return null;
                offset = 14;
                var type = U16(12);
                while (type is 0x8100 or 0x88a8 or 0x9100)
                {
                    if (b.Length < offset + 4) return null;
                    type = U16(offset + 2); offset += 4;
                }
                if (type is not (0x0800 or 0x86dd)) return null;
                break;
            case 0:
            case 108:
                offset = 4;
                break;
            case 113:
                if (b.Length < 16 || U16(14) is not (0x0800 or 0x86dd)) return null;
                offset = 16;
                break;
            case 276:
                if (b.Length < 20 || U16(0) is not (0x0800 or 0x86dd)) return null;
                offset = 20;
                break;
            default:
                offset = 0;
                break;
        }
        if (b.Length <= offset) return null;
        int proto;
        string source, destination;
        int limit;
        if (b[offset] >> 4 == 4)
        {
            if (b.Length < offset + 20) return null;
            var size = (b[offset] & 15) * 4;
            if (size < 20 || b.Length < offset + size || U16(offset + 2) < size || (U16(offset + 6) & 0x1fff) != 0) return null;
            limit = Math.Min(b.Length, offset + U16(offset + 2));
            source = string.Join(".", b[(offset + 12)..(offset + 16)]);
            destination = string.Join(".", b[(offset + 16)..(offset + 20)]);
            proto = b[offset + 9]; offset += size;
        }
        else if (b[offset] >> 4 == 6)
        {
            if (b.Length < offset + 40) return null;
            limit = Math.Min(b.Length, offset + 40 + U16(offset + 4));
            string Ipv6(int start)
            {
                var parts = new string[8];
                for (var i = 0; i < 8; i++) parts[i] = U16(start + i * 2).ToString("x");
                return "[" + string.Join(":", parts) + "]";
            }
            source = Ipv6(offset + 8); destination = Ipv6(offset + 24);
            proto = b[offset + 6]; offset += 40;
            while (proto is 0 or 43 or 44 or 51 or 60)
            {
                if (limit < offset + 8) return null;
                int next = b[offset];
                int size;
                if (proto == 44)
                {
                    if ((U16(offset + 2) & 0xfff8) != 0) return null;
                    size = 8;
                }
                else if (proto == 51) size = (b[offset + 1] + 2) * 4;
                else size = (b[offset + 1] + 1) * 8;
                if (limit < offset + size) return null;
                offset += size; proto = next;
            }
        }
        else return null;
        if (proto is 1 or 58)
        {
            if (limit < offset+8) return null;
            var name = proto == 1 ? "ICMP" : "ICMPv6";
            int type = b[offset], code = b[offset+1];
            var summary = $"{Icmp.Name(type,proto == 58)} · type {type} code {code}";
            if ((proto == 1 && (type is 0 or 8)) || (proto == 58 && (type is 128 or 129))) summary += $" · id {U16(offset+4)} sequence {U16(offset+6)}";
            return new DecodedPacket(name,source,destination,summary,new List<DnsMessage>(),null, offset + 8, limit);
        }
        if (!(proto == 6 || proto == 17) || limit < offset + (proto == 6 ? 20 : 8)) return null;
        var isDns = U16(offset) == 53 || U16(offset + 2) == 53;
        source += $":{U16(offset)}"; destination += $":{U16(offset + 2)}";
        var flags = "";
        var dns = new List<DnsMessage>();
        ProtocolInfo? application = null;
        int payloadStart, payloadEnd;
        if (proto == 6)
        {
            var size = (b[offset + 12] >> 4) * 4;
            if (size < 20 || limit < offset + size) return null;
            payloadStart = offset + size; payloadEnd = limit;
            application = ProtocolDecoder.Decode(b[(offset + size)..limit], tcp: true);
            var f = b[offset + 13];
            flags = string.Join(" ", new (int Bit, string Name)[] { (2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH"), (32, "URG") }
                .Where(x => (f & x.Bit) != 0).Select(x => x.Name));
            if (isDns)
            {
                var p = offset + size;
                while (p + 2 <= limit)
                {
                    var length = U16(p); p += 2;
                    if (length <= 0 || p + length > limit) break;
                    if (DnsDecoder.Decode(b[p..(p + length)]) is { } message) dns.Add(message);
                    p += length;
                }
            }
        }
        else
        {
            var length = U16(offset + 4);
            if (length < 8) return null;
            payloadStart = offset + 8; payloadEnd = Math.Min(limit, offset + length);
            if (offset + length <= limit) application = ProtocolDecoder.Decode(b[(offset + 8)..(offset + length)], tcp: false);
            if (isDns && offset + length <= limit && DnsDecoder.Decode(b[(offset + 8)..(offset + length)]) is { } message)
                dns.Add(message);
        }
        return new DecodedPacket(proto == 6 ? "TCP" : "UDP", source, destination, flags, dns, application, payloadStart, Math.Max(payloadStart, payloadEnd));
    }
}
