using System.Globalization;
using System.Net;
using System.Text;

namespace CaptureCore;

public enum LayerKind { Frame, Header, Payload }

/// <summary>A node in the packet details tree. Offset/Length locate its bytes in the frame (Length 0 = no bytes).</summary>
public sealed class PacketField
{
    internal PacketField(string name, string label, int offset, int length, PacketField? parent, LayerKind kind)
    {
        Name = name; Label = label; Offset = offset; Length = length; Parent = parent; Kind = kind;
    }
    public string Name { get; }
    public string Label { get; internal set; }
    public int Offset { get; }
    public int Length { get; internal set; }
    public PacketField? Parent { get; }
    public LayerKind Kind { get; }
    /// <summary>True for single-bit/sub-byte fields that share their parent's bytes.</summary>
    public bool IsBits { get; internal init; }
    internal readonly List<PacketField> children = new();
    public IReadOnlyList<PacketField> Children => children;
    public bool HasBytes => Length > 0;
    public string Path => Parent is null ? Name : Parent.Path + " › " + Name;
}

public sealed class PacketDissection
{
    public required IReadOnlyList<PacketField> Layers { get; init; }
    public required int CapturedLength { get; init; }
    public required int WireLength { get; init; }
    /// <summary>Header layers in order with their sizes, for example Ethernet 14, IPv4 20, TCP 32.</summary>
    public required IReadOnlyList<(string Name, int Length)> HeaderParts { get; init; }
    public int HeaderLength => HeaderParts.Sum(p => p.Length);
    /// <summary>Transport payload (application data) present in the capture.</summary>
    public required int PayloadOffset { get; init; }
    public required int PayloadLength { get; init; }
    /// <summary>Transport payload size on the wire according to the IP/UDP length fields.</summary>
    public required int PayloadWireLength { get; init; }
    public required int TrailerLength { get; init; }

    /// <summary>The most specific field covering a byte; bit fields are skipped, so a flags byte selects "Flags".</summary>
    public PacketField? FieldAt(int offset)
    {
        PacketField? best = null;
        void Visit(PacketField field)
        {
            if (field.HasBytes && !field.IsBits && offset >= field.Offset && offset < field.Offset + field.Length &&
                (best is null || field.Length <= best.Length))
                best = field;
            foreach (var child in field.children) Visit(child);
        }
        foreach (var layer in Layers) Visit(layer);
        return best;
    }
}

public static class PacketDissector
{
    private sealed class StopException : Exception
    {
        public StopException(string message) : base(message) { }
    }

    /// <summary>Bounds-checked reader over [0, End) that appends fields to the tree.</summary>
    private sealed class Reader
    {
        public Reader(byte[] bytes, int end) { B = bytes; End = end; }
        public byte[] B { get; }
        public int End { get; }
        public void Check(int at, int count)
        {
            if (at < 0 || count < 0 || at + count > End) throw new StopException("[Truncated: field extends past the captured data]");
        }
        public int U8(int i) { Check(i, 1); return B[i]; }
        public int U16(int i) { Check(i, 2); return B[i] << 8 | B[i + 1]; }
        public int U24(int i) { Check(i, 3); return B[i] << 16 | B[i + 1] << 8 | B[i + 2]; }
        public uint U32(int i) { Check(i, 4); return (uint)(B[i] << 24 | B[i + 1] << 16 | B[i + 2] << 8 | B[i + 3]); }
        public string Hex(int at, int count, int max = 64)
        {
            Check(at, count);
            var text = Convert.ToHexString(B, at, Math.Min(count, max)).ToLowerInvariant();
            return count > max ? text + "…" : text;
        }
        public string Ascii(int at, int count)
        {
            Check(at, count);
            var builder = new StringBuilder(count);
            for (var i = at; i < at + count; i++) builder.Append(B[i] >= 32 && B[i] < 127 ? (char)B[i] : '.');
            return builder.ToString();
        }
        public string Utf8(int at, int count) { Check(at, count); return Encoding.UTF8.GetString(B, at, count); }

        public PacketField Add(PacketField parent, string name, string? value, int offset, int length)
        {
            Check(offset, length);
            var field = new PacketField(name, value is null ? name : $"{name}: {value}", offset, length, parent, parent.Kind);
            parent.children.Add(field);
            return field;
        }
        public PacketField Note(PacketField parent, string label)
        {
            var field = new PacketField(label, label, 0, 0, parent, parent.Kind);
            parent.children.Add(field);
            return field;
        }
        /// <summary>A bit field in Wireshark style: "...1 .... = Acknowledgment: Set".</summary>
        public PacketField Bits(PacketField parent, int offset, int length, long value, long mask, string name, string text)
        {
            var bits = length * 8;
            var pattern = new StringBuilder();
            for (var bit = bits - 1; bit >= 0; bit--)
            {
                var m = 1L << bit;
                pattern.Append((mask & m) == 0 ? '.' : (value & m) != 0 ? '1' : '0');
                if (bit % 4 == 0 && bit > 0) pattern.Append(' ');
            }
            Check(offset, length);
            var field = new PacketField(name, $"{pattern} = {name}: {text}", offset, length, parent, parent.Kind) { IsBits = true };
            parent.children.Add(field);
            return field;
        }
        public PacketField Group(PacketField parent, string name, int offset)
        {
            var field = new PacketField(name, name, offset, 0, parent, parent.Kind);
            parent.children.Add(field);
            return field;
        }
    }

    private static string Set(bool on) => on ? "Set" : "Not set";
    private static string N(long value) => value.ToString(CultureInfo.InvariantCulture);

    public static PacketDissection Dissect(Packet packet, int linkType, double captureStart)
    {
        var b = packet.RawBytes;
        var r = new Reader(b, b.Length);
        var layers = new List<PacketField>();
        var headers = new List<(string, int)>();
        int payloadOffset = b.Length, payloadLength = 0, payloadWire = 0, trailer = 0;

        PacketField NewLayer(string name, string label, int offset, int length, LayerKind kind)
        {
            var layer = new PacketField(name, label, offset, Math.Clamp(length, 0, Math.Max(0, b.Length - offset)), null, kind);
            layers.Add(layer);
            return layer;
        }

        var frame = NewLayer("Frame", $"Frame {packet.Id}: {packet.Length} bytes on wire ({packet.Length * 8} bits), {b.Length} bytes captured ({b.Length * 8} bits)", 0, b.Length, LayerKind.Frame);
        var arrival = DateTimeOffset.FromUnixTimeSeconds(packet.Seconds).AddTicks(packet.Microseconds * 10L).ToLocalTime();
        r.Note(frame, $"Arrival Time: {arrival.ToString("yyyy-MM-dd HH:mm:ss.ffffff zzz", CultureInfo.InvariantCulture)}");
        r.Note(frame, $"Epoch Arrival Time: {packet.Seconds}.{packet.Microseconds:000000}");
        r.Note(frame, $"Time relative to first packet: {(packet.Time - captureStart).ToString("F6", CultureInfo.InvariantCulture)} seconds");
        r.Note(frame, $"Frame Length: {packet.Length} bytes ({packet.Length * 8} bits)");
        r.Note(frame, $"Capture Length: {b.Length} bytes ({b.Length * 8} bits)");
        r.Note(frame, $"Encapsulation type: {LinkName(linkType)} ({linkType})");
        if (packet.Flags.Length > 0 || packet.Application is not null || packet.Dns.Count > 0) r.Note(frame, $"Summary: {packet.Details}");

        PacketField? current = frame;
        try
        {
            var offset = DissectLink(r, linkType, NewLayer, headers, ref current);
            if (offset < 0) return Result();
            var limit = DissectIp(r, offset, NewLayer, headers, ref current, out var proto, out var transportOffset, out var ipWireEnd);
            if (limit < 0) return Result();
            trailer = b.Length - limit;
            int start, end, wire;
            bool tcp = proto == 6;
            if (tcp)
            {
                var size = DissectTcp(r, transportOffset, limit, ipWireEnd, NewLayer, headers, ref current);
                start = transportOffset + size; end = limit; wire = ipWireEnd - start;
            }
            else if (proto == 17)
            {
                var udpLength = DissectUdp(r, transportOffset, NewLayer, headers, ref current);
                start = transportOffset + 8; end = Math.Min(transportOffset + udpLength, limit); wire = udpLength - 8;
            }
            else if (proto is 1 or 58)
            {
                int o = transportOffset; var name = proto == 1 ? "ICMP" : "ICMPv6";
                var node = current = NewLayer(name, Icmp.Name(r.U8(o),proto == 58),o,8,LayerKind.Header);
                r.Add(node,"Type",N(r.U8(o)),o,1); r.Add(node,"Code",N(r.U8(o+1)),o+1,1); r.Add(node,"Checksum (not verified)",$"0x{r.U16(o+2):x4}",o+2,2);
                int type = r.U8(o);
                if ((proto == 1 && (type is 0 or 8 or 13 or 14)) || (proto == 58 && (type is 128 or 129))) {
                    r.Add(node,"Identifier",N(r.U16(o+4)),o+4,2); r.Add(node,"Sequence Number",N(r.U16(o+6)),o+6,2);
                } else if (proto == 58 && type == 2) r.Add(node,"MTU",N(r.U32(o+4)),o+4,4);
                else if (proto == 1 && type == 3 && r.U8(o+1) == 4) { r.Add(node,"Unused",N(r.U16(o+4)),o+4,2); r.Add(node,"Next-hop MTU",N(r.U16(o+6)),o+6,2); }
                else r.Add(node,"Message-specific Data",$"0x{r.U32(o+4):x8}",o+4,4);
                headers.Add((name,8)); start = o+8; end = limit; wire = ipWireEnd-start;
                payloadOffset=start; payloadLength=Math.Max(0,end-start); payloadWire=Math.Max(0,wire);
                if (end>start) DataLayer(r,NewLayer,start,end,"ICMP Data");
                AddTrailer(limit); return Result();
            }
            else
            {
                var rest = NewLayer("Data", $"Data ({limit - transportOffset} bytes)", transportOffset, limit - transportOffset, LayerKind.Payload);
                r.Add(rest, "Data", r.Hex(transportOffset, limit - transportOffset), transportOffset, limit - transportOffset);
                AddTrailer(limit);
                return Result();
            }
            payloadOffset = start;
            payloadLength = Math.Max(0, end - start);
            payloadWire = Math.Max(0, wire);
            if (payloadLength > 0) DissectApplication(new Reader(b, end), start, end, tcp, packet, NewLayer, ref current);
            AddTrailer(limit);
        }
        catch (StopException stop)
        {
            if (current is not null) r.Note(current, stop.Message);
        }
        return Result();

        void AddTrailer(int limit)
        {
            if (limit >= b.Length) return;
            var pad = NewLayer("Trailer", $"Trailer / padding ({b.Length - limit} bytes)", limit, b.Length - limit, LayerKind.Header);
            r.Add(pad, "Data", r.Hex(limit, b.Length - limit), limit, b.Length - limit);
        }

        PacketDissection Result() => new()
        {
            Layers = layers,
            CapturedLength = b.Length,
            WireLength = packet.Length,
            HeaderParts = headers,
            PayloadOffset = payloadOffset,
            PayloadLength = payloadLength,
            PayloadWireLength = payloadWire,
            TrailerLength = trailer,
        };
    }

    private delegate PacketField LayerFactory(string name, string label, int offset, int length, LayerKind kind);

    private static string LinkName(int link) => link switch
    {
        1 => "Ethernet", 0 => "Null/Loopback", 108 => "OpenBSD loopback", 12 or 101 => "Raw IP",
        113 => "Linux cooked-mode capture v1", 276 => "Linux cooked-mode capture v2", _ => "Unknown",
    };

    private static string EtherTypeName(int type) => type switch
    {
        0x0800 => "IPv4", 0x86dd => "IPv6", 0x0806 => "ARP", 0x8100 => "802.1Q Virtual LAN", 0x88a8 => "802.1ad Provider Bridge",
        0x9100 => "VLAN (0x9100)", 0x8847 => "MPLS", 0x8864 => "PPPoE Session", _ => "Unknown",
    };

    private static string Mac(Reader r, int at) => string.Join(":", Enumerable.Range(at, 6).Select(i => r.U8(i).ToString("x2")));

    // MARK: Link layer

    private static int DissectLink(Reader r, int link, LayerFactory layer, List<(string, int)> headers, ref PacketField? current)
    {
        switch (link)
        {
            case 1:
            {
                var type = r.U16(12);
                var size = 14;
                while (type is 0x8100 or 0x88a8 or 0x9100) { type = r.U16(size + 2); size += 4; }
                var eth = current = layer("Ethernet II", $"Ethernet II, Src: {Mac(r, 6)}, Dst: {Mac(r, 0)}", 0, 14, LayerKind.Header);
                var destination = r.Add(eth, "Destination", Mac(r, 0), 0, 6);
                r.Bits(destination, 0, 1, r.U8(0), 0x02, "LG bit", (r.U8(0) & 2) != 0 ? "Locally administered address" : "Globally unique address (factory default)");
                r.Bits(destination, 0, 1, r.U8(0), 0x01, "IG bit", (r.U8(0) & 1) != 0 ? "Group address (multicast/broadcast)" : "Individual address (unicast)");
                r.Add(eth, "Source", Mac(r, 6), 6, 6);
                var outer = r.U16(12);
                r.Add(eth, "Type", $"{EtherTypeName(outer)} (0x{outer:x4})", 12, 2);
                headers.Add(("Ethernet", 14));
                var at = 14;
                while (at < size)
                {
                    var tci = r.U16(at);
                    var inner = r.U16(at + 2);
                    var vlan = current = layer("802.1Q", $"802.1Q Virtual LAN, PRI: {tci >> 13}, DEI: {(tci >> 12) & 1}, ID: {tci & 0xfff}", at, 4, LayerKind.Header);
                    var tciField = r.Add(vlan, "Tag Control Information", $"0x{tci:x4}", at, 2);
                    r.Bits(tciField, at, 2, tci, 0xe000, "Priority", N(tci >> 13));
                    r.Bits(tciField, at, 2, tci, 0x1000, "DEI", N((tci >> 12) & 1));
                    r.Bits(tciField, at, 2, tci, 0x0fff, "ID", N(tci & 0xfff));
                    r.Add(vlan, "Type", $"{EtherTypeName(inner)} (0x{inner:x4})", at + 2, 2);
                    headers.Add(("802.1Q", 4));
                    at += 4;
                }
                if (type is not (0x0800 or 0x86dd)) return -1;
                return size;
            }
            case 0:
            case 108:
            {
                var big = r.U32(0);
                var little = (uint)(r.B[0] | r.B[1] << 8 | r.B[2] << 16 | r.B[3] << 24);
                var family = link == 108 || little > 0xffff ? big : little;
                var name = family switch { 2 => "IPv4", 10 or 24 or 28 or 30 => "IPv6", _ => "Unknown" };
                var loop = current = layer("Loopback", $"Null/Loopback, Family: {name}", 0, 4, LayerKind.Header);
                r.Add(loop, "Family", $"{name} ({family})", 0, 4);
                headers.Add(("Loopback", 4));
                return 4;
            }
            case 113:
            {
                var sll = current = layer("Linux cooked capture v1", "Linux cooked capture v1", 0, 16, LayerKind.Header);
                var kind = r.U16(0);
                r.Add(sll, "Packet type", kind switch { 0 => "Unicast to us (0)", 1 => "Broadcast (1)", 2 => "Multicast (2)", 3 => "Unicast to another host (3)", 4 => "Sent by us (4)", _ => N(kind) }, 0, 2);
                r.Add(sll, "Link-layer address type", N(r.U16(2)), 2, 2);
                var addressLength = r.U16(4);
                r.Add(sll, "Link-layer address length", N(addressLength), 4, 2);
                r.Add(sll, "Source", r.Hex(6, Math.Min(8, addressLength)), 6, 8);
                var protocol = r.U16(14);
                r.Add(sll, "Protocol", $"{EtherTypeName(protocol)} (0x{protocol:x4})", 14, 2);
                headers.Add(("Linux cooked", 16));
                return protocol is 0x0800 or 0x86dd ? 16 : -1;
            }
            case 276:
            {
                var sll = current = layer("Linux cooked capture v2", "Linux cooked capture v2", 0, 20, LayerKind.Header);
                var protocol = r.U16(0);
                r.Add(sll, "Protocol", $"{EtherTypeName(protocol)} (0x{protocol:x4})", 0, 2);
                r.Add(sll, "Reserved", $"0x{r.U16(2):x4}", 2, 2);
                r.Add(sll, "Interface index", N(r.U32(4)), 4, 4);
                r.Add(sll, "Link-layer address type", N(r.U16(8)), 8, 2);
                r.Add(sll, "Packet type", N(r.U8(10)), 10, 1);
                r.Add(sll, "Link-layer address length", N(r.U8(11)), 11, 1);
                r.Add(sll, "Source", r.Hex(12, Math.Min(8, r.U8(11))), 12, 8);
                headers.Add(("Linux cooked v2", 20));
                return protocol is 0x0800 or 0x86dd ? 20 : -1;
            }
            default:
                return 0;
        }
    }

    // MARK: Network layer

    private static string ProtocolName(int proto) => proto switch
    {
        0 => "IPv6 Hop-by-Hop Option", 1 => "ICMP", 2 => "IGMP", 6 => "TCP", 17 => "UDP", 41 => "IPv6", 43 => "Routing Header for IPv6",
        44 => "Fragment Header for IPv6", 47 => "GRE", 50 => "ESP", 51 => "AH", 58 => "ICMPv6", 59 => "No Next Header for IPv6",
        60 => "Destination Options for IPv6", 132 => "SCTP", _ => "Unknown",
    };

    private static string IPv4(Reader r, int at) => $"{r.U8(at)}.{r.U8(at + 1)}.{r.U8(at + 2)}.{r.U8(at + 3)}";
    private static string IPv6(Reader r, int at) { r.Check(at, 16); return new IPAddress(r.B.AsSpan(at, 16)).ToString(); }

    /// <summary>Returns the end of IP data within the capture, or -1 when there is nothing more to dissect.</summary>
    private static int DissectIp(Reader r, int o, LayerFactory layer, List<(string, int)> headers, ref PacketField? current,
                                 out int proto, out int transport, out int wireEnd)
    {
        proto = -1; transport = o; wireEnd = o;
        var version = r.U8(o) >> 4;
        if (version == 4)
        {
            var b0 = r.U8(o);
            var size = (b0 & 15) * 4;
            var total = r.U16(o + 2);
            proto = r.U8(o + 9);
            var ip = current = layer("IPv4", $"Internet Protocol Version 4, Src: {IPv4(r, o + 12)}, Dst: {IPv4(r, o + 16)}", o, size, LayerKind.Header);
            var vh = r.Add(ip, "Version / Header Length", $"0x{b0:x2}", o, 1);
            r.Bits(vh, o, 1, b0, 0xf0, "Version", "4");
            r.Bits(vh, o, 1, b0, 0x0f, "Header Length", $"{size} bytes ({b0 & 15})");
            var ds = r.U8(o + 1);
            var dsField = r.Add(ip, "Differentiated Services Field", $"0x{ds:x2} (DSCP: {ds >> 2}, ECN: {ds & 3})", o + 1, 1);
            r.Bits(dsField, o + 1, 1, ds, 0xfc, "Differentiated Services Codepoint", N(ds >> 2));
            r.Bits(dsField, o + 1, 1, ds, 0x03, "Explicit Congestion Notification", N(ds & 3));
            r.Add(ip, "Total Length", N(total), o + 2, 2);
            var id = r.U16(o + 4);
            r.Add(ip, "Identification", $"0x{id:x4} ({id})", o + 4, 2);
            var ff = r.U16(o + 6);
            var flagsText = string.Join(", ", new[] { (ff & 0x4000) != 0 ? "Don't fragment" : null, (ff & 0x2000) != 0 ? "More fragments" : null }.Where(s => s is not null));
            var flags = r.Add(ip, "Flags / Fragment Offset", $"0x{ff:x4}{(flagsText.Length > 0 ? $" ({flagsText})" : "")}", o + 6, 2);
            r.Bits(flags, o + 6, 2, ff, 0x8000, "Reserved bit", Set((ff & 0x8000) != 0));
            r.Bits(flags, o + 6, 2, ff, 0x4000, "Don't fragment", Set((ff & 0x4000) != 0));
            r.Bits(flags, o + 6, 2, ff, 0x2000, "More fragments", Set((ff & 0x2000) != 0));
            r.Bits(flags, o + 6, 2, ff, 0x1fff, "Fragment Offset", $"{(ff & 0x1fff) * 8} bytes");
            r.Add(ip, "Time to Live", N(r.U8(o + 8)), o + 8, 1);
            r.Add(ip, "Protocol", $"{ProtocolName(proto)} ({proto})", o + 9, 1);
            r.Add(ip, "Header Checksum", $"0x{r.U16(o + 10):x4} [not verified]", o + 10, 2);
            r.Add(ip, "Source Address", IPv4(r, o + 12), o + 12, 4);
            r.Add(ip, "Destination Address", IPv4(r, o + 16), o + 16, 4);
            if (size > 20) r.Add(ip, "Options", $"({size - 20} bytes) {r.Hex(o + 20, size - 20)}", o + 20, size - 20);
            headers.Add(("IPv4", size));
            transport = o + size;
            wireEnd = o + total;
            return Math.Min(r.End, o + total);
        }
        if (version == 6)
        {
            var first = r.U32(o);
            var payload = r.U16(o + 4);
            proto = r.U8(o + 6);
            var ip = current = layer("IPv6", $"Internet Protocol Version 6, Src: {IPv6(r, o + 8)}, Dst: {IPv6(r, o + 24)}", o, 40, LayerKind.Header);
            var head = r.Add(ip, "Version / Traffic Class / Flow Label", $"0x{first:x8}", o, 4);
            r.Bits(head, o, 4, first, 0xf0000000, "Version", "6");
            r.Bits(head, o, 4, first, 0x0ff00000, "Traffic Class", $"0x{(first >> 20) & 0xff:x2}");
            r.Bits(head, o, 4, first, 0x000fffff, "Flow Label", $"0x{first & 0xfffff:x5}");
            r.Add(ip, "Payload Length", N(payload), o + 4, 2);
            r.Add(ip, "Next Header", $"{ProtocolName(proto)} ({proto})", o + 6, 1);
            r.Add(ip, "Hop Limit", N(r.U8(o + 7)), o + 7, 1);
            r.Add(ip, "Source Address", IPv6(r, o + 8), o + 8, 16);
            r.Add(ip, "Destination Address", IPv6(r, o + 24), o + 24, 16);
            var limit = Math.Min(r.End, o + 40 + payload);
            var at = o + 40;
            while (proto is 0 or 43 or 44 or 51 or 60)
            {
                var next = r.U8(at);
                var size = proto == 44 ? 8 : proto == 51 ? (r.U8(at + 1) + 2) * 4 : (r.U8(at + 1) + 1) * 8;
                var ext = r.Add(ip, ProtocolName(proto), $"({size} bytes)", at, size);
                r.Add(ext, "Next Header", $"{ProtocolName(next)} ({next})", at, 1);
                if (proto == 44)
                {
                    var fo = r.U16(at + 2);
                    r.Add(ext, "Reserved", N(r.U8(at + 1)), at + 1, 1);
                    var offsetField = r.Add(ext, "Offset / Flags", $"0x{fo:x4}", at + 2, 2);
                    r.Bits(offsetField, at + 2, 2, fo, 0xfff8, "Offset", $"{(fo >> 3) * 8} bytes");
                    r.Bits(offsetField, at + 2, 2, fo, 0x0001, "More Fragments", (fo & 1) != 0 ? "Yes" : "No");
                    r.Add(ext, "Identification", $"0x{r.U32(at + 4):x8}", at + 4, 4);
                }
                else
                {
                    r.Add(ext, "Length", N(r.U8(at + 1)), at + 1, 1);
                    r.Add(ext, "Data", r.Hex(at + 2, size - 2), at + 2, size - 2);
                }
                ip.Length += size;
                at += size; proto = next;
            }
            headers.Add(("IPv6", at - o));
            transport = at;
            wireEnd = o + 40 + payload;
            return limit;
        }
        return -1;
    }

    // MARK: Transport layer

    private static int DissectTcp(Reader r, int o, int limit, int wireEnd, LayerFactory layer, List<(string, int)> headers, ref PacketField? current)
    {
        var source = r.U16(o);
        var destination = r.U16(o + 2);
        var seq = r.U32(o + 4);
        var ack = r.U32(o + 8);
        var size = (r.U8(o + 12) >> 4) * 4;
        var flags = r.U16(o + 12) & 0x0fff;
        var names = new (int Bit, string Short, string Name)[]
        {
            (0x800, "", "Reserved"), (0x100, "AE", "Accurate ECN"), (0x080, "CWR", "Congestion Window Reduced"), (0x040, "ECE", "ECN-Echo"),
            (0x020, "URG", "Urgent"), (0x010, "ACK", "Acknowledgment"), (0x008, "PSH", "Push"), (0x004, "RST", "Reset"),
            (0x002, "SYN", "Syn"), (0x001, "FIN", "Fin"),
        };
        // Wireshark lists set flags from the lowest bit up, e.g. "(PSH, ACK)".
        var set = string.Join(", ", names.Reverse().Where(f => f.Short.Length > 0 && (flags & f.Bit) != 0).Select(f => f.Short));
        var payload = Math.Max(0, wireEnd - o - size);
        var tcp = current = layer("TCP", $"Transmission Control Protocol, Src Port: {source}, Dst Port: {destination}, Seq: {seq}, Ack: {ack}, Len: {payload}", o, size, LayerKind.Header);
        r.Add(tcp, "Source Port", N(source), o, 2);
        r.Add(tcp, "Destination Port", N(destination), o + 2, 2);
        r.Add(tcp, "Sequence Number (raw)", N(seq), o + 4, 4);
        r.Add(tcp, "Acknowledgment Number (raw)", N(ack), o + 8, 4);
        r.Add(tcp, "Header Length", $"{size} bytes ({size / 4})", o + 12, 1);
        var flagField = r.Add(tcp, "Flags", $"0x{flags:x3}{(set.Length > 0 ? $" ({set})" : "")}", o + 12, 2);
        r.Bits(flagField, o + 12, 2, flags, 0x0e00, "Reserved", Set((flags & 0x0e00) != 0));
        foreach (var f in names.Skip(1)) r.Bits(flagField, o + 12, 2, flags, f.Bit, f.Name, Set((flags & f.Bit) != 0));
        r.Add(tcp, "Window", N(r.U16(o + 14)), o + 14, 2);
        r.Add(tcp, "Checksum", $"0x{r.U16(o + 16):x4} [not verified]", o + 16, 2);
        r.Add(tcp, "Urgent Pointer", N(r.U16(o + 18)), o + 18, 2);
        if (size > 20)
        {
            var options = r.Add(tcp, "Options", $"({size - 20} bytes)", o + 20, size - 20);
            var p = o + 20;
            var end = o + size;
            while (p < end)
            {
                var kind = r.U8(p);
                if (kind is 0 or 1)
                {
                    r.Add(options, kind == 0 ? "End of Option List (EOL)" : "No-Operation (NOP)", null, p, 1);
                    p += 1;
                    if (kind == 0) { if (p < end) r.Add(options, "Padding", null, p, end - p); break; }
                    continue;
                }
                var length = r.U8(p + 1);
                if (length < 2 || p + length > end) { r.Add(options, "Malformed option", r.Hex(p, end - p), p, end - p); break; }
                PacketField option;
                switch (kind)
                {
                    case 2 when length == 4:
                        option = r.Add(options, "Maximum segment size", $"{r.U16(p + 2)} bytes", p, length);
                        r.Add(option, "MSS Value", N(r.U16(p + 2)), p + 2, 2);
                        break;
                    case 3 when length == 3:
                        option = r.Add(options, "Window scale", $"{r.U8(p + 2)} (multiply by {1 << Math.Min(30, r.U8(p + 2))})", p, length);
                        r.Add(option, "Shift count", N(r.U8(p + 2)), p + 2, 1);
                        break;
                    case 4:
                        option = r.Add(options, "SACK permitted", null, p, length);
                        break;
                    case 5:
                        option = r.Add(options, "SACK", $"{(length - 2) / 8} block(s)", p, length);
                        for (var q = p + 2; q + 8 <= p + length; q += 8)
                        {
                            r.Add(option, "Left edge", N(r.U32(q)), q, 4);
                            r.Add(option, "Right edge", N(r.U32(q + 4)), q + 4, 4);
                        }
                        break;
                    case 8 when length == 10:
                        option = r.Add(options, "Timestamps", $"TSval {r.U32(p + 2)}, TSecr {r.U32(p + 6)}", p, length);
                        r.Add(option, "Timestamp value", N(r.U32(p + 2)), p + 2, 4);
                        r.Add(option, "Timestamp echo reply", N(r.U32(p + 6)), p + 6, 4);
                        break;
                    case 30:
                        option = r.Add(options, "Multipath TCP", null, p, length);
                        if (length > 2) r.Add(option, "Data", r.Hex(p + 2, length - 2), p + 2, length - 2);
                        break;
                    case 34:
                        option = r.Add(options, "TCP Fast Open Cookie", length > 2 ? r.Hex(p + 2, length - 2) : "request", p, length);
                        break;
                    default:
                        option = r.Add(options, $"Option kind {kind}", null, p, length);
                        if (length > 2) r.Add(option, "Data", r.Hex(p + 2, length - 2), p + 2, length - 2);
                        break;
                }
                option.children.Insert(0, new PacketField("Kind", $"Kind: {kind}", p, 1, option, option.Kind));
                option.children.Insert(1, new PacketField("Length", $"Length: {length}", p + 1, 1, option, option.Kind));
                p += length;
            }
        }
        headers.Add(("TCP", size));
        return size;
    }

    private static int DissectUdp(Reader r, int o, LayerFactory layer, List<(string, int)> headers, ref PacketField? current)
    {
        var source = r.U16(o);
        var destination = r.U16(o + 2);
        var length = r.U16(o + 4);
        var udp = current = layer("UDP", $"User Datagram Protocol, Src Port: {source}, Dst Port: {destination}", o, 8, LayerKind.Header);
        r.Add(udp, "Source Port", N(source), o, 2);
        r.Add(udp, "Destination Port", N(destination), o + 2, 2);
        r.Add(udp, "Length", N(length), o + 4, 2);
        r.Add(udp, "Checksum", $"0x{r.U16(o + 6):x4} [not verified]", o + 6, 2);
        r.Note(udp, $"UDP payload ({Math.Max(0, length - 8)} bytes)");
        headers.Add(("UDP", 8));
        return length;
    }

    // MARK: Application layer

    private static void DissectApplication(Reader r, int start, int end, bool tcp, Packet packet, LayerFactory layer, ref PacketField? current)
    {
        var payload = r.B[start..end];
        var info = ProtocolDecoder.Decode(payload, tcp);
        var isDnsPort = packet.Source.EndsWith(":53", StringComparison.Ordinal) || packet.Destination.EndsWith(":53", StringComparison.Ordinal);
        if (isDnsPort && packet.Dns.Count > 0)
        {
            if (tcp)
            {
                var p = start;
                while (p + 2 <= end)
                {
                    var length = r.U16(p);
                    if (length == 0 || p + 2 + length > end) break;
                    var dns = current = layer("DNS", "Domain Name System", p, 2 + length, LayerKind.Payload);
                    r.Add(dns, "Length", N(length), p, 2);
                    DissectDns(new Reader(r.B, p + 2 + length), p + 2, dns);
                    p += 2 + length;
                }
                if (p < end) DataLayer(r, layer, p, end, "Data");
            }
            else
            {
                var dns = current = layer("DNS", "Domain Name System", start, end - start, LayerKind.Payload);
                DissectDns(r, start, dns);
            }
            return;
        }
        if (info?.Name is "RTCP" or "SIP" or "DTLS" or "TURN" or "HTTP/2")
        {
            if ((info.Name == "HTTP/2" ? Http2Decoder.Decode(payload) : RealtimeDecoder.Decode(payload, tcp)) is { } message)
            {
                current = layer(message.Name, message.Summary, start, end-start, LayerKind.Payload);
                foreach (var field in message.Fields) r.Add(current, field.Name, field.Value, start+field.Offset, field.Length);
            }
            return;
        }
        switch (info?.Name)
        {
            case "RTP": current = DissectRtp(r, start, end, layer); break;
            case "STUN": current = DissectStun(r, start, end, layer); break;
            case "HTTP": current = DissectHttp(r, start, end, layer); break;
            case "TLS": DissectTls(r, start, end, layer, ref current); break;
            case "QUIC": current = DissectQuic(r, start, end, layer); break;
            default: current = DataLayer(r, layer, start, end, "Data"); break;
        }
    }

    private static PacketField DataLayer(Reader r, LayerFactory layer, int start, int end, string name)
    {
        var data = layer(name, $"{name} ({end - start} bytes)", start, end - start, LayerKind.Payload);
        r.Add(data, "Data", r.Hex(start, end - start), start, end - start);
        var text = r.Ascii(start, Math.Min(end - start, 64));
        r.Note(data, $"Text: {text}{(end - start > 64 ? "…" : "")}");
        return data;
    }

    // DNS

    private static readonly Dictionary<int, string> DnsTypes = new()
    {
        [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA", [12] = "PTR", [15] = "MX", [16] = "TXT", [28] = "AAAA",
        [33] = "SRV", [41] = "OPT", [43] = "DS", [46] = "RRSIG", [47] = "NSEC", [48] = "DNSKEY", [64] = "SVCB", [65] = "HTTPS", [255] = "ANY",
    };
    private static string DnsType(int type) => DnsTypes.TryGetValue(type, out var name) ? name : $"TYPE{type}";
    private static string DnsClass(int value) => value switch { 1 => "IN", 3 => "CH", 4 => "HS", 255 => "ANY", _ => $"0x{value:x4}" };

    private static (string Name, int End) DnsName(Reader r, int message, int at)
    {
        var labels = new List<string>();
        var pos = at;
        var end = -1;
        var jumps = 0;
        while (true)
        {
            var length = r.U8(pos);
            if ((length & 0xc0) == 0xc0)
            {
                if (end < 0) end = pos + 2;
                if (++jumps > 64) throw new StopException("[Malformed: DNS name compression loop]");
                pos = message + ((length & 0x3f) << 8 | r.U8(pos + 1));
                continue;
            }
            if (length > 63) throw new StopException("[Malformed: invalid DNS label length]");
            if (length == 0) { if (end < 0) end = pos + 1; break; }
            labels.Add(r.Ascii(pos + 1, length));
            pos += 1 + length;
        }
        return (labels.Count == 0 ? "<Root>" : string.Join(".", labels), end);
    }

    private static void DissectDns(Reader r, int m, PacketField dns)
    {
        var flags = r.U16(m + 2);
        var response = (flags & 0x8000) != 0;
        var rcode = flags & 15;
        var rcodeName = rcode switch { 0 => "No error", 1 => "Format error", 2 => "Server failure", 3 => "No such name", 4 => "Not implemented", 5 => "Refused", _ => $"RCODE {rcode}" };
        dns.Label = $"Domain Name System ({(response ? "response" : "query")})";
        r.Add(dns, "Transaction ID", $"0x{r.U16(m):x4}", m, 2);
        var f = r.Add(dns, "Flags", $"0x{flags:x4} {(response ? "Standard query response" : "Standard query")}{(response ? $", {rcodeName}" : "")}", m + 2, 2);
        r.Bits(f, m + 2, 2, flags, 0x8000, "Response", response ? "Message is a response" : "Message is a query");
        r.Bits(f, m + 2, 2, flags, 0x7800, "Opcode", N((flags >> 11) & 15));
        if (response) r.Bits(f, m + 2, 2, flags, 0x0400, "Authoritative", Set((flags & 0x0400) != 0));
        r.Bits(f, m + 2, 2, flags, 0x0200, "Truncated", Set((flags & 0x0200) != 0));
        r.Bits(f, m + 2, 2, flags, 0x0100, "Recursion desired", Set((flags & 0x0100) != 0));
        if (response) r.Bits(f, m + 2, 2, flags, 0x0080, "Recursion available", Set((flags & 0x0080) != 0));
        r.Bits(f, m + 2, 2, flags, 0x0040, "Z", "reserved");
        r.Bits(f, m + 2, 2, flags, 0x0020, "Answer authenticated", Set((flags & 0x0020) != 0));
        r.Bits(f, m + 2, 2, flags, 0x0010, "Non-authenticated data", Set((flags & 0x0010) != 0));
        if (response) r.Bits(f, m + 2, 2, flags, 0x000f, "Reply code", $"{rcodeName} ({rcode})");
        var counts = new[] { r.U16(m + 4), r.U16(m + 6), r.U16(m + 8), r.U16(m + 10) };
        r.Add(dns, "Questions", N(counts[0]), m + 4, 2);
        r.Add(dns, "Answer RRs", N(counts[1]), m + 6, 2);
        r.Add(dns, "Authority RRs", N(counts[2]), m + 8, 2);
        r.Add(dns, "Additional RRs", N(counts[3]), m + 10, 2);
        var p = m + 12;
        if (counts[0] > 0)
        {
            var queries = r.Group(dns, "Queries", p);
            for (var i = 0; i < counts[0]; i++)
            {
                var (name, end) = DnsName(r, m, p);
                var type = r.U16(end);
                var query = r.Add(queries, $"{name}: type {DnsType(type)}, class {DnsClass(r.U16(end + 2))}", null, p, end + 4 - p);
                r.Add(query, "Name", name, p, end - p);
                r.Add(query, "Type", $"{DnsType(type)} ({type})", end, 2);
                r.Add(query, "Class", $"{DnsClass(r.U16(end + 2))} (0x{r.U16(end + 2):x4})", end + 2, 2);
                p = end + 4;
            }
            queries.Length = p - queries.Offset;
        }
        foreach (var (title, count) in new[] { ("Answers", counts[1]), ("Authoritative nameservers", counts[2]), ("Additional records", counts[3]) })
        {
            if (count == 0) continue;
            var section = r.Group(dns, title, p);
            for (var i = 0; i < count; i++) p = DnsRecord(r, m, p, section);
            section.Length = p - section.Offset;
        }
    }

    private static int DnsRecord(Reader r, int m, int p, PacketField section)
    {
        var (name, end) = DnsName(r, m, p);
        var type = r.U16(end);
        var cls = r.U16(end + 2);
        var ttl = r.U32(end + 4);
        var length = r.U16(end + 8);
        var data = end + 10;
        r.Check(data, length);
        string value;
        switch (type)
        {
            case 1 when length == 4: value = IPv4(r, data); break;
            case 28 when length == 16: value = IPv6(r, data); break;
            case 2 or 5 or 12: value = DnsName(r, m, data).Name; break;
            case 15 when length >= 3: value = $"{r.U16(data)} {DnsName(r, m, data + 2).Name}"; break;
            case 16:
            {
                var parts = new List<string>();
                for (var q = data; q < data + length;) { var n = r.U8(q); parts.Add("\"" + r.Ascii(q + 1, Math.Min(n, data + length - q - 1)) + "\""); q += 1 + n; }
                value = string.Join(" ", parts);
                break;
            }
            default: value = $"{length} bytes"; break;
        }
        var record = type == 41
            ? r.Add(section, $"<Root>: type OPT", null, p, data + length - p)
            : r.Add(section, $"{name}: type {DnsType(type)}, class {DnsClass(cls)}, {value}", null, p, data + length - p);
        r.Add(record, "Name", name, p, end - p);
        r.Add(record, "Type", $"{DnsType(type)} ({type})", end, 2);
        if (type == 41) r.Add(record, "UDP payload size", N(cls), end + 2, 2);
        else r.Add(record, "Class", $"{DnsClass(cls)} (0x{cls:x4})", end + 2, 2);
        r.Add(record, type == 41 ? "Extended RCODE / flags" : "Time to live", type == 41 ? $"0x{ttl:x8}" : $"{ttl} ({TimeSpan.FromSeconds(ttl)})", end + 4, 4);
        r.Add(record, "Data length", N(length), end + 8, 2);
        if (length > 0)
        {
            var label = type switch { 1 => "Address", 28 => "AAAA Address", 5 => "CNAME", 2 => "Name Server", 12 => "Domain Name", 15 => "Mail Exchange", 16 => "TXT", _ => "Data" };
            r.Add(record, label, type is 1 or 28 or 2 or 5 or 12 or 15 or 16 ? value : r.Hex(data, length), data, length);
        }
        return data + length;
    }

    private static PacketField DissectRtp(Reader r, int s, int end, LayerFactory layer)
    {
        var node = layer("RTP", "Real-time Transport Protocol (heuristic)", s, end - s, LayerKind.Payload);
        var flags = r.Add(node, "Flags", $"0x{r.U8(s):x2}", s, 1);
        r.Bits(flags, s, 1, r.U8(s), 192, "Version", "2");
        r.Bits(flags, s, 1, r.U8(s), 32, "Padding", ((r.U8(s) & 32) != 0).ToString());
        r.Bits(flags, s, 1, r.U8(s), 16, "Extension", ((r.U8(s) & 16) != 0).ToString());
        r.Add(node, "CSRC count", N(r.U8(s) & 15), s, 1);
        r.Add(node, "Marker", ((r.U8(s + 1) & 128) != 0).ToString(), s + 1, 1);
        r.Add(node, "Payload Type", N(r.U8(s + 1) & 127), s + 1, 1);
        r.Add(node, "Sequence Number", N(r.U16(s + 2)), s + 2, 2);
        r.Add(node, "Timestamp", N(r.U32(s + 4)), s + 4, 4);
        r.Add(node, "SSRC", $"0x{r.U32(s + 8):x8}", s + 8, 4);
        var p = s + 12;
        for (var i = 0; i < (r.U8(s) & 15); i++, p += 4) r.Add(node, "CSRC", $"0x{r.U32(p):x8}", p, 4);
        if ((r.U8(s) & 16) != 0)
        {
            var size = r.U16(p + 2) * 4;
            r.Add(node, "Extension Profile", $"0x{r.U16(p):x4}", p, 2);
            r.Add(node, "Extension Length (words)", N(r.U16(p + 2)), p + 2, 2);
            r.Add(node, "Extension Data", r.Hex(p + 4, size), p + 4, size); p += 4 + size;
        }
        var padding = (r.U8(s) & 32) != 0 ? r.U8(end - 1) : 0;
        r.Add(node, "Media Payload", r.Hex(p, end - p - padding), p, end - p - padding);
        if (padding > 0) r.Add(node, "Padding", N(padding), end - padding, padding);
        return node;
    }

    // STUN

    private static readonly Dictionary<int, string> StunAttributes = new()
    {
        [0x0001] = "MAPPED-ADDRESS", [0x0006] = "USERNAME", [0x0008] = "MESSAGE-INTEGRITY", [0x0009] = "ERROR-CODE",
        [0x000A] = "UNKNOWN-ATTRIBUTES", [0x000C] = "CHANNEL-NUMBER", [0x000D] = "LIFETIME", [0x0012] = "XOR-PEER-ADDRESS",
        [0x0013] = "DATA", [0x0014] = "REALM", [0x0015] = "NONCE", [0x0016] = "XOR-RELAYED-ADDRESS", [0x0019] = "REQUESTED-TRANSPORT",
        [0x001C] = "MESSAGE-INTEGRITY-SHA256", [0x001D] = "PASSWORD-ALGORITHM", [0x001E] = "USERHASH", [0x0020] = "XOR-MAPPED-ADDRESS",
        [0x0024] = "PRIORITY", [0x0025] = "USE-CANDIDATE", [0x8022] = "SOFTWARE", [0x8023] = "ALTERNATE-SERVER",
        [0x8028] = "FINGERPRINT", [0x8029] = "ICE-CONTROLLED", [0x802A] = "ICE-CONTROLLING", [0xC057] = "NETWORK COST",
    };

    private static PacketField DissectStun(Reader r, int s, int end, LayerFactory layer)
    {
        var type = r.U16(s);
        var length = r.U16(s + 2);
        var method = (type & 15) | ((type & 0xe0) >> 1) | ((type & 0x3e00) >> 2);
        var kind = ((type >> 4) & 1) | ((type >> 7) & 2);
        var methodName = method switch { 1 => "Binding", 3 => "Allocate", 4 => "Refresh", 6 => "Send", 7 => "Data", 8 => "CreatePermission", 9 => "ChannelBind", _ => $"Method {method}" };
        var className = new[] { "Request", "Indication", "Success Response", "Error Response" }[kind];
        var total = Math.Min(end, s + 20 + length);
        var stun = layer("STUN", $"Session Traversal Utilities for NAT, {methodName} {className}", s, total - s, LayerKind.Payload);
        var typeField = r.Add(stun, "Message Type", $"0x{type:x4} ({methodName} {className})", s, 2);
        r.Bits(typeField, s, 2, type, 0x0110, "Message Class", $"{className} (0x{kind:x2})");
        r.Bits(typeField, s, 2, type, 0x3eef, "Message Method", $"{methodName} (0x{method:x3})");
        r.Add(stun, "Message Length", N(length), s + 2, 2);
        r.Add(stun, "Message Cookie", $"0x{r.U32(s + 4):x8}", s + 4, 4);
        r.Add(stun, "Message Transaction ID", r.Hex(s + 8, 12), s + 8, 12);
        if (length == 0) return stun;
        var attributes = r.Group(stun, "Attributes", s + 20);
        var p = s + 20;
        while (p + 4 <= total)
        {
            var at = r.U16(p);
            var size = r.U16(p + 2);
            var name = StunAttributes.TryGetValue(at, out var known) ? known : $"Unknown (0x{at:x4})";
            var padded = (size + 3) & ~3;
            var value = StunValue(r, s, at, p + 4, size);
            var attribute = r.Add(attributes, name, value, p, Math.Min(4 + padded, total - p));
            r.Add(attribute, "Attribute Type", $"{name} (0x{at:x4})", p, 2);
            r.Add(attribute, "Attribute Length", N(size), p + 2, 2);
            if (size > 0) StunValueFields(r, s, at, p + 4, size, attribute);
            if (padded > size && p + 4 + padded <= total) r.Add(attribute, "Padding", N(padded - size), p + 4 + size, padded - size);
            p += 4 + padded;
        }
        attributes.Length = Math.Min(p, total) - attributes.Offset;
        return stun;
    }

    private static string? StunValue(Reader r, int s, int type, int v, int size)
    {
        switch (type)
        {
            case 0x0001 or 0x8023 or 0x0020 or 0x0012 or 0x0016:
            {
                var xor = type is 0x0020 or 0x0012 or 0x0016;
                if (size < 8) return null;
                var family = r.U8(v + 1);
                var port = r.U16(v + 2) ^ (xor ? 0x2112 : 0);
                if (family == 1) return $"{XorAddress(r, s, v + 4, 4, xor)}:{port}";
                if (family == 2 && size >= 20) return $"[{XorAddress(r, s, v + 4, 16, xor)}]:{port}";
                return null;
            }
            case 0x0006 or 0x0014 or 0x0015 or 0x8022: return r.Utf8(v, size);
            case 0x0009 when size >= 4: return $"{(r.U8(v + 2) & 7) * 100 + r.U8(v + 3)} {r.Utf8(v + 4, size - 4)}";
            case 0x0024 when size == 4: return N(r.U32(v));
            case 0x000D when size == 4: return $"{r.U32(v)} seconds";
            case 0x8028 when size == 4: return $"0x{r.U32(v):x8}";
            case 0x0025: return null;
            default: return size > 0 ? r.Hex(v, size, 32) : null;
        }
    }

    private static string XorAddress(Reader r, int s, int at, int size, bool xor)
    {
        var bytes = new byte[size];
        for (var i = 0; i < size; i++) bytes[i] = (byte)(r.U8(at + i) ^ (xor ? r.U8(s + 4 + i) : 0));
        return new IPAddress(bytes).ToString();
    }

    private static void StunValueFields(Reader r, int s, int type, int v, int size, PacketField attribute)
    {
        if (type is 0x0001 or 0x8023 or 0x0020 or 0x0012 or 0x0016 && size >= 8)
        {
            var xor = type is 0x0020 or 0x0012 or 0x0016;
            r.Add(attribute, "Reserved", N(r.U8(v)), v, 1);
            var family = r.U8(v + 1);
            r.Add(attribute, "Protocol Family", family == 1 ? "IPv4 (0x01)" : family == 2 ? "IPv6 (0x02)" : $"0x{family:x2}", v + 1, 1);
            r.Add(attribute, xor ? "X-Port" : "Port", $"0x{r.U16(v + 2):x4} ({r.U16(v + 2) ^ (xor ? 0x2112 : 0)})", v + 2, 2);
            var length = family == 2 ? 16 : 4;
            if (v + 4 + length <= v + size)
                r.Add(attribute, xor ? "X-Address" : "Address", $"{r.Hex(v + 4, length)} ({XorAddress(r, s, v + 4, length, xor)})", v + 4, length);
            return;
        }
        if (type == 0x0009 && size >= 4)
        {
            r.Add(attribute, "Reserved", null, v, 2);
            r.Add(attribute, "Error Class", N(r.U8(v + 2) & 7), v + 2, 1);
            r.Add(attribute, "Error Number", N(r.U8(v + 3)), v + 3, 1);
            if (size > 4) r.Add(attribute, "Error Reason Phrase", r.Utf8(v + 4, size - 4), v + 4, size - 4);
            return;
        }
        var label = type switch { 0x0006 => "Username", 0x0014 => "Realm", 0x0015 => "Nonce", 0x8022 => "Software", 0x0008 => "HMAC-SHA1", 0x8028 => "CRC-32", 0x0024 => "Priority", 0x8029 or 0x802A => "Tie breaker", _ => "Value" };
        var text = type is 0x0006 or 0x0014 or 0x0015 or 0x8022 ? r.Utf8(v, size) : type == 0x0024 && size == 4 ? N(r.U32(v)) : r.Hex(v, size);
        r.Add(attribute, label, text, v, size);
    }

    // HTTP

    private static PacketField DissectHttp(Reader r, int s, int end, LayerFactory layer)
    {
        var http = layer("HTTP", "Hypertext Transfer Protocol", s, end - s, LayerKind.Payload);
        const string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if (end - s >= preface.Length && r.Ascii(s, preface.Length) == preface.Replace("\r", ".").Replace("\n", "."))
        {
            http.Label = "HyperText Transfer Protocol 2";
            r.Add(http, "Connection preface", "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n", s, preface.Length);
            if (end > s + preface.Length) r.Add(http, "HTTP/2 frames", $"{end - s - preface.Length} bytes", s + preface.Length, end - s - preface.Length);
            return http;
        }
        var p = s;
        var first = true;
        while (p < end)
        {
            var lineEnd = -1;
            for (var i = p; i + 1 < end; i++) if (r.B[i] == '\r' && r.B[i + 1] == '\n') { lineEnd = i; break; }
            if (lineEnd < 0) { r.Add(http, "Incomplete line", r.Ascii(p, end - p), p, end - p); return http; }
            var text = Encoding.UTF8.GetString(r.B, p, lineEnd - p);
            if (text.Length == 0) { r.Add(http, "\\r\\n", null, p, 2); p += 2; break; }
            var line = r.Add(http, text + "\\r\\n", null, p, lineEnd + 2 - p);
            if (first)
            {
                var parts = new List<(int Start, int Length)>();
                var q = p;
                while (q < lineEnd && parts.Count < 3)
                {
                    while (q < lineEnd && r.B[q] == ' ') q++;
                    var t = q;
                    while (q < lineEnd && (r.B[q] != ' ' || parts.Count == 2)) q++;
                    if (q > t) parts.Add((t, q - t));
                }
                var response = text.StartsWith("HTTP/", StringComparison.Ordinal);
                var names = response ? new[] { "Response Version", "Status Code", "Response Phrase" } : new[] { "Request Method", "Request URI", "Request Version" };
                for (var i = 0; i < parts.Count; i++) r.Add(line, names[i], Encoding.UTF8.GetString(r.B, parts[i].Start, parts[i].Length), parts[i].Start, parts[i].Length);
                http.Label = $"Hypertext Transfer Protocol, {(response ? "Response" : "Request")}";
                first = false;
            }
            else
            {
                var colon = text.IndexOf(':');
                if (colon > 0)
                {
                    r.Add(line, "Header Name", text[..colon], p, colon);
                    r.Add(line, "Header Value", text[(colon + 1)..].Trim(), p + colon + 1, lineEnd - p - colon - 1);
                }
            }
            p = lineEnd + 2;
        }
        if (p < end) r.Add(http, "File Data", $"{end - p} bytes", p, end - p);
        return http;
    }

    // TLS

    private static string TlsVersion(int version) => version switch
    {
        0x0300 => "SSL 3.0", 0x0301 => "TLS 1.0", 0x0302 => "TLS 1.1", 0x0303 => "TLS 1.2", 0x0304 => "TLS 1.3",
        _ when (version & 0x0f0f) == 0x0a0a => "Reserved (GREASE)", _ => $"Unknown",
    };
    private static string TlsContent(int type) => type switch
    {
        20 => "Change Cipher Spec", 21 => "Alert", 22 => "Handshake", 23 => "Application Data", 24 => "Heartbeat", _ => $"Unknown ({type})",
    };
    private static string HandshakeName(int type) => type switch
    {
        0 => "Hello Request", 1 => "Client Hello", 2 => "Server Hello", 4 => "New Session Ticket", 8 => "Encrypted Extensions",
        11 => "Certificate", 12 => "Server Key Exchange", 13 => "Certificate Request", 14 => "Server Hello Done", 15 => "Certificate Verify",
        16 => "Client Key Exchange", 20 => "Finished", _ => $"Unknown ({type})",
    };
    private static readonly Dictionary<int, string> TlsExtensions = new()
    {
        [0] = "server_name", [1] = "max_fragment_length", [5] = "status_request", [10] = "supported_groups", [11] = "ec_point_formats",
        [13] = "signature_algorithms", [16] = "application_layer_protocol_negotiation", [18] = "signed_certificate_timestamp",
        [21] = "padding", [22] = "encrypt_then_mac", [23] = "extended_master_secret", [27] = "compress_certificate", [28] = "record_size_limit",
        [35] = "session_ticket", [41] = "pre_shared_key", [42] = "early_data", [43] = "supported_versions", [45] = "psk_key_exchange_modes",
        [49] = "post_handshake_auth", [50] = "signature_algorithms_cert", [51] = "key_share", [57] = "quic_transport_parameters",
        [17513] = "application_settings", [17613] = "application_settings", [65037] = "encrypted_client_hello", [65281] = "renegotiation_info",
    };
    private static string ExtensionName(int type) => (type & 0x0f0f) == 0x0a0a ? "Reserved (GREASE)" : TlsExtensions.TryGetValue(type, out var n) ? n : $"Unknown type {type}";
    private static readonly Dictionary<int, string> CipherSuites = new()
    {
        [0x1301] = "TLS_AES_128_GCM_SHA256", [0x1302] = "TLS_AES_256_GCM_SHA384", [0x1303] = "TLS_CHACHA20_POLY1305_SHA256",
        [0xc02b] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", [0xc02c] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        [0xc02f] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", [0xc030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        [0xcca8] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", [0xcca9] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        [0xc013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", [0xc014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        [0xc009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", [0xc00a] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        [0x009c] = "TLS_RSA_WITH_AES_128_GCM_SHA256", [0x009d] = "TLS_RSA_WITH_AES_256_GCM_SHA384",
        [0x002f] = "TLS_RSA_WITH_AES_128_CBC_SHA", [0x0035] = "TLS_RSA_WITH_AES_256_CBC_SHA", [0x000a] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        [0x00ff] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    };
    private static string CipherName(int value) => (value & 0x0f0f) == 0x0a0a ? "Reserved (GREASE)" : CipherSuites.TryGetValue(value, out var n) ? n : "Unknown";
    private static string GroupName(int value) => value switch
    {
        0x0017 => "secp256r1", 0x0018 => "secp384r1", 0x0019 => "secp521r1", 0x001d => "x25519", 0x001e => "x448",
        0x0100 => "ffdhe2048", 0x0101 => "ffdhe3072", 0x11ec => "X25519MLKEM768", 0x6399 => "X25519Kyber768Draft00",
        _ when (value & 0x0f0f) == 0x0a0a => "Reserved (GREASE)", _ => "Unknown",
    };

    private static void DissectTls(Reader r, int s, int end, LayerFactory layer, ref PacketField? current)
    {
        var p = s;
        while (p < end)
        {
            if (end - p < 5 || r.B[p] < 20 || r.B[p] > 24 || r.B[p + 1] != 3)
            {
                current = DataLayer(r, layer, p, end, "TLS segment data");
                return;
            }
            var type = r.U8(p);
            var version = r.U16(p + 1);
            var length = r.U16(p + 3);
            var recordEnd = p + 5 + length;
            var available = Math.Min(recordEnd, end);
            var record = current = layer("TLS", $"{TlsVersion(version)} Record Layer: {TlsContent(type)} Protocol", p, available - p, LayerKind.Payload);
            r.Add(record, "Content Type", $"{TlsContent(type)} ({type})", p, 1);
            r.Add(record, "Version", $"{TlsVersion(version)} (0x{version:x4})", p + 1, 2);
            r.Add(record, "Length", N(length), p + 3, 2);
            var body = p + 5;
            if (recordEnd > end)
            {
                r.Note(record, $"[Record continues in a later segment: {end - body} of {length} bytes in this packet]");
                if (end > body) r.Add(record, type == 23 ? "Encrypted Application Data (partial)" : "Record data (partial)", r.Hex(body, end - body), body, end - body);
                return;
            }
            switch (type)
            {
                case 22: DissectHandshakes(r, body, recordEnd, record); break;
                case 23: r.Add(record, "Encrypted Application Data", r.Hex(body, length), body, length); break;
                case 20: r.Add(record, "Change Cipher Spec Message", null, body, length); break;
                case 21 when length == 2:
                    r.Add(record, "Alert Message", null, body, 2);
                    r.Add(record, "Level", r.U8(body) == 2 ? "Fatal (2)" : r.U8(body) == 1 ? "Warning (1)" : N(r.U8(body)), body, 1);
                    r.Add(record, "Description", N(r.U8(body + 1)), body + 1, 1);
                    break;
                case 21: r.Add(record, "Encrypted Alert", r.Hex(body, length), body, length); break;
                default: if (length > 0) r.Add(record, "Data", r.Hex(body, length), body, length); break;
            }
            p = recordEnd;
        }
    }

    private static void DissectHandshakes(Reader r, int q, int end, PacketField record)
    {
        var names = new List<string>();
        while (q < end)
        {
            if (end - q < 4 || q + 4 + r.U24(q + 1) > end)
            {
                r.Add(record, "Handshake Protocol: Encrypted Handshake Message", r.Hex(q, end - q), q, end - q);
                names.Add("Encrypted Handshake Message");
                break;
            }
            var type = r.U8(q);
            var length = r.U24(q + 1);
            var name = HandshakeName(type);
            names.Add(name);
            var hs = r.Add(record, $"Handshake Protocol: {name}", null, q, 4 + length);
            r.Add(hs, "Handshake Type", $"{name} ({type})", q, 1);
            r.Add(hs, "Length", N(length), q + 1, 3);
            var body = q + 4;
            var stop = body + length;
            if (type is 1 or 2) Hello(r, body, stop, hs, type == 1);
            else if (length > 0) r.Add(hs, "Handshake data", r.Hex(body, length), body, length);
            q = stop;
        }
        record.Label += ": " + string.Join(", ", names);
    }

    private static void Hello(Reader r, int p, int end, PacketField hs, bool client)
    {
        var version = r.U16(p);
        r.Add(hs, "Version", $"{TlsVersion(version)} (0x{version:x4})", p, 2);
        r.Add(hs, "Random", r.Hex(p + 2, 32), p + 2, 32);
        p += 34;
        var sessionLength = r.U8(p);
        r.Add(hs, "Session ID Length", N(sessionLength), p, 1);
        if (sessionLength > 0) r.Add(hs, "Session ID", r.Hex(p + 1, sessionLength), p + 1, sessionLength);
        p += 1 + sessionLength;
        if (client)
        {
            var cipherLength = r.U16(p);
            r.Add(hs, "Cipher Suites Length", N(cipherLength), p, 2);
            var suites = r.Add(hs, "Cipher Suites", $"({cipherLength / 2} suites)", p + 2, cipherLength);
            for (var i = p + 2; i + 1 < p + 2 + cipherLength; i += 2) r.Add(suites, "Cipher Suite", $"{CipherName(r.U16(i))} (0x{r.U16(i):x4})", i, 2);
            p += 2 + cipherLength;
            var compressionLength = r.U8(p);
            r.Add(hs, "Compression Methods Length", N(compressionLength), p, 1);
            if (compressionLength > 0) r.Add(hs, "Compression Methods", r.Hex(p + 1, compressionLength), p + 1, compressionLength);
            p += 1 + compressionLength;
        }
        else
        {
            r.Add(hs, "Cipher Suite", $"{CipherName(r.U16(p))} (0x{r.U16(p):x4})", p, 2);
            r.Add(hs, "Compression Method", N(r.U8(p + 2)), p + 2, 1);
            p += 3;
        }
        if (p + 2 > end) return;
        var extensionsLength = r.U16(p);
        r.Add(hs, "Extensions Length", N(extensionsLength), p, 2);
        p += 2;
        var extensionsEnd = Math.Min(end, p + extensionsLength);
        while (p + 4 <= extensionsEnd)
        {
            var type = r.U16(p);
            var length = r.U16(p + 2);
            var name = ExtensionName(type);
            var data = p + 4;
            var extension = r.Add(hs, $"Extension: {name}", $"(len={length})", p, Math.Min(4 + length, extensionsEnd - p));
            r.Add(extension, "Type", $"{name} ({type})", p, 2);
            r.Add(extension, "Length", N(length), p + 2, 2);
            ExtensionFields(r, type, data, length, extension, client);
            p = data + length;
        }
    }

    private static void ExtensionFields(Reader r, int type, int d, int length, PacketField extension, bool client)
    {
        if (length == 0) return;
        switch (type)
        {
            case 0 when length >= 5:
            {
                r.Add(extension, "Server Name list length", N(r.U16(d)), d, 2);
                var q = d + 2;
                while (q + 3 <= d + length)
                {
                    var nameLength = r.U16(q + 1);
                    var entry = r.Add(extension, "Server Name Indication", r.Utf8(q + 3, nameLength), q, 3 + nameLength);
                    r.Add(entry, "Server Name Type", r.U8(q) == 0 ? "host_name (0)" : N(r.U8(q)), q, 1);
                    r.Add(entry, "Server Name length", N(nameLength), q + 1, 2);
                    r.Add(entry, "Server Name", r.Utf8(q + 3, nameLength), q + 3, nameLength);
                    q += 3 + nameLength;
                }
                extension.Label += $" ({string.Join(", ", extension.children.Where(c => c.Name == "Server Name Indication").Select(c => c.Label[(c.Label.IndexOf(':') + 2)..]))})";
                return;
            }
            case 16 when length >= 3:
            {
                r.Add(extension, "ALPN Extension Length", N(r.U16(d)), d, 2);
                var protocols = new List<string>();
                for (var q = d + 2; q < d + length;)
                {
                    var n = r.U8(q);
                    var protocol = r.Utf8(q + 1, n);
                    protocols.Add(protocol);
                    var entry = r.Add(extension, "ALPN Protocol", protocol, q, 1 + n);
                    r.Add(entry, "ALPN string length", N(n), q, 1);
                    r.Add(entry, "ALPN Next Protocol", protocol, q + 1, n);
                    q += 1 + n;
                }
                extension.Label += $" ({string.Join(", ", protocols)})";
                return;
            }
            case 43 when client:
            {
                r.Add(extension, "Supported Versions length", N(r.U8(d)), d, 1);
                for (var q = d + 1; q + 1 < d + length; q += 2) r.Add(extension, "Supported Version", $"{TlsVersion(r.U16(q))} (0x{r.U16(q):x4})", q, 2);
                return;
            }
            case 43:
                r.Add(extension, "Supported Version", $"{TlsVersion(r.U16(d))} (0x{r.U16(d):x4})", d, 2);
                return;
            case 10:
            {
                r.Add(extension, "Supported Groups List Length", N(r.U16(d)), d, 2);
                for (var q = d + 2; q + 1 < d + length; q += 2) r.Add(extension, "Supported Group", $"{GroupName(r.U16(q))} (0x{r.U16(q):x4})", q, 2);
                return;
            }
            default:
                r.Add(extension, "Data", r.Hex(d, length), d, length);
                return;
        }
    }

    // QUIC

    private static (long Value, int Size) Varint(Reader r, int at)
    {
        var first = r.U8(at);
        var size = 1 << (first >> 6);
        long value = first & 0x3f;
        for (var i = 1; i < size; i++) value = value << 8 | (long)r.U8(at + i);
        return (value, size);
    }

    private static PacketField DissectQuic(Reader r, int s, int end, LayerFactory layer)
    {
        var first = r.U8(s);
        var version = r.U32(s + 1);
        var kind = (first >> 4) & 3;
        var types = version == 1 ? new[] { "Initial", "0-RTT", "Handshake", "Retry" } : new[] { "Retry", "Initial", "0-RTT", "Handshake" };
        var typeName = types[kind];
        var dcidLength = r.U8(s + 5);
        var scidAt = s + 6 + dcidLength;
        var scidLength = r.U8(scidAt);
        var quic = layer("QUIC", $"QUIC IETF, {typeName}, DCID={r.Hex(s + 6, dcidLength)}, SCID={r.Hex(scidAt + 1, scidLength)}", s, end - s, LayerKind.Payload);
        var flags = r.Add(quic, "Header Form / Flags", $"0x{first:x2}", s, 1);
        r.Bits(flags, s, 1, first, 0x80, "Header Form", "Long Header (1)");
        r.Bits(flags, s, 1, first, 0x40, "Fixed Bit", (first & 0x40) != 0 ? "True" : "False");
        r.Bits(flags, s, 1, first, 0x30, "Packet Type", $"{typeName} ({kind})");
        r.Bits(flags, s, 1, first, 0x0f, "Type-specific bits", "header protected");
        r.Add(quic, "Version", $"{(version == 1 ? "1" : "2")} (0x{version:x8})", s + 1, 4);
        r.Add(quic, "Destination Connection ID Length", N(dcidLength), s + 5, 1);
        if (dcidLength > 0) r.Add(quic, "Destination Connection ID", r.Hex(s + 6, dcidLength), s + 6, dcidLength);
        r.Add(quic, "Source Connection ID Length", N(scidLength), scidAt, 1);
        if (scidLength > 0) r.Add(quic, "Source Connection ID", r.Hex(scidAt + 1, scidLength), scidAt + 1, scidLength);
        var p = scidAt + 1 + scidLength;
        if (typeName == "Retry")
        {
            if (p < end) r.Add(quic, "Retry Token and Integrity Tag", r.Hex(p, end - p), p, end - p);
            return quic;
        }
        if (typeName == "Initial")
        {
            var (tokenLength, tokenSize) = Varint(r, p);
            r.Add(quic, "Token Length", N(tokenLength), p, tokenSize);
            p += tokenSize;
            if (tokenLength > 0) { r.Add(quic, "Token", r.Hex(p, (int)tokenLength), p, (int)tokenLength); p += (int)tokenLength; }
        }
        var (length, lengthSize) = Varint(r, p);
        r.Add(quic, "Length", N(length), p, lengthSize);
        p += lengthSize;
        var protectedEnd = (int)Math.Min(end, p + length);
        if (protectedEnd > p) r.Add(quic, "Protected Packet Number and Payload", $"{protectedEnd - p} bytes (encrypted)", p, protectedEnd - p);
        if (protectedEnd < end) r.Add(quic, "Coalesced packet data", $"{end - protectedEnd} bytes", protectedEnd, end - protectedEnd);
        return quic;
    }
}
