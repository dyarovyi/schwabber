using System.Buffers.Binary;
using System.Text;
using CaptureCore;
using Xunit;

namespace CaptureCore.Tests;

public class DissectorTests
{
    private static byte[] Ipv4(int proto, byte[] payload, byte a = 1, byte b = 2)
    {
        var ip = new byte[20 + payload.Length];
        ip[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(ip.AsSpan(2), (ushort)ip.Length);
        ip[6] = 0x40; ip[8] = 64; ip[9] = (byte)proto;
        new byte[] { 192, 168, 0, a }.CopyTo(ip, 12); new byte[] { 10, 0, 0, b }.CopyTo(ip, 16);
        payload.CopyTo(ip, 20);
        return ip;
    }

    private static byte[] Eth(byte[] ip, int type = 0x0800)
    {
        var frame = new byte[14 + ip.Length];
        frame[0] = 0x02; frame[6] = 0x04; frame[11] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), (ushort)type);
        ip.CopyTo(frame, 14);
        return frame;
    }

    private static byte[] Tcp(int source, int destination, byte flags, byte[] options, byte[] payload)
    {
        var size = 20 + options.Length;
        var tcp = new byte[size + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(0), (ushort)source);
        BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(2), (ushort)destination);
        BinaryPrimitives.WriteUInt32BigEndian(tcp.AsSpan(4), 1000);
        tcp[12] = (byte)(size / 4 << 4); tcp[13] = flags; tcp[14] = 0xff;
        options.CopyTo(tcp, 20); payload.CopyTo(tcp, size);
        return tcp;
    }

    private static byte[] Udp(int source, int destination, byte[] payload)
    {
        var udp = new byte[8 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(0), (ushort)source);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2), (ushort)destination);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4), (ushort)udp.Length);
        payload.CopyTo(udp, 8);
        return udp;
    }

    private static Packet MakePacket(byte[] frame, int wire = -1)
    {
        var d = CaptureReader.Decode(frame, 1);
        return new Packet
        {
            Id = 7, Time = 10.5, Source = d?.Source ?? "", Destination = d?.Destination ?? "", Length = wire < 0 ? frame.Length : wire,
            Flags = d?.Flags ?? "", Dns = d?.Dns ?? Array.Empty<DnsMessage>(), Application = d?.Application, RawBytes = frame,
            Seconds = 10, Microseconds = 500_000,
        };
    }

    private static PacketDissection Dissect(byte[] frame) => PacketDissector.Dissect(MakePacket(frame), 1, 0);

    /// <summary>Every byte maps to a real field, and every child range sits inside its parent and the capture.</summary>
    private static void AssertWellFormed(PacketDissection d, bool fullCoverage = true)
    {
        void Check(PacketField field)
        {
            if (field.HasBytes) Assert.InRange(field.Offset + field.Length, 1, d.CapturedLength);
            foreach (var child in field.Children)
            {
                if (child.HasBytes && field.HasBytes)
                {
                    Assert.True(child.Offset >= field.Offset && child.Offset + child.Length <= field.Offset + field.Length, $"{child.Path} outside {field.Path}");
                }
                Check(child);
            }
        }
        foreach (var layer in d.Layers) Check(layer);
        if (!fullCoverage) return;
        for (var i = 0; i < d.CapturedLength; i++)
        {
            var field = d.FieldAt(i);
            Assert.NotNull(field);
            Assert.NotEqual(LayerKind.Frame, field!.Kind);
        }
    }

    private static byte[] HttpFrame()
    {
        var options = new byte[] { 2, 4, 0x05, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2 }.Concat(new byte[] { 1, 1, 1, 0 }).ToArray();
        var http = Encoding.ASCII.GetBytes("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nbody");
        return Eth(Ipv4(6, Tcp(51000, 80, 0x18, options, http)));
    }

    [Fact]
    public void TcpHttpLayersSizesAndByteLookup()
    {
        var frame = HttpFrame();
        var d = Dissect(frame);
        AssertWellFormed(d);
        Assert.Equal(new[] { "Frame", "Ethernet II", "IPv4", "TCP", "HTTP" }, d.Layers.Select(l => l.Name));
        Assert.Equal(new[] { ("Ethernet", 14), ("IPv4", 20), ("TCP", 40) }, d.HeaderParts);
        Assert.Equal(74, d.HeaderLength);
        Assert.Equal(74, d.PayloadOffset);
        Assert.Equal(frame.Length - 74, d.PayloadLength);
        Assert.Equal(frame.Length - 74, d.PayloadWireLength);
        Assert.Equal("TCP › Source Port", d.FieldAt(34)!.Path);
        Assert.Equal("Flags", d.FieldAt(47)!.Name);
        Assert.Contains("PSH, ACK", d.FieldAt(47)!.Label);
        Assert.Equal("Header Length", d.FieldAt(46)!.Name);
        Assert.Equal("MSS Value", d.FieldAt(56)!.Name);
        Assert.Equal("Request Method", d.FieldAt(74)!.Name);
        Assert.Equal("Header Value", d.FieldAt(74 + 23)!.Name);
        Assert.Equal("File Data", d.FieldAt(frame.Length - 1)!.Name);
        Assert.Equal("Source Address", d.FieldAt(26)!.Name);
        Assert.Equal("Destination", d.FieldAt(0)!.Name);
    }

    [Fact]
    public void EthernetPaddingIsTrailer()
    {
        var frame = Eth(Ipv4(6, Tcp(1, 2, 0x10, Array.Empty<byte>(), Array.Empty<byte>()))).Concat(new byte[6]).ToArray();
        var d = Dissect(frame);
        AssertWellFormed(d);
        Assert.Equal(6, d.TrailerLength);
        Assert.Equal(0, d.PayloadLength);
        Assert.Equal("Trailer", d.Layers[^1].Name);
    }

    [Fact]
    public void DnsResponseFields()
    {
        var name = new byte[] { 7 }.Concat(Encoding.ASCII.GetBytes("example")).Append((byte)3).Concat(Encoding.ASCII.GetBytes("com")).Append((byte)0);
        var dns = new byte[] { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 }.Concat(name).Concat(new byte[] { 0, 1, 0, 1 })
            .Concat(new byte[] { 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4 }).ToArray();
        var frame = Eth(Ipv4(17, Udp(53, 5000, dns)));
        var d = Dissect(frame);
        AssertWellFormed(d);
        Assert.Equal("Domain Name System (response)", d.Layers[^1].Label);
        var address = d.FieldAt(frame.Length - 1)!;
        Assert.Equal("Address: 1.2.3.4", address.Label);
        Assert.Equal("DNS › Answers › example.com: type A, class IN, 1.2.3.4 › Address", address.Path);
    }

    [Fact]
    public void TlsClientHelloSni()
    {
        var host = Encoding.ASCII.GetBytes("example.com");
        var sni = new byte[] { 0, 0, 0, (byte)(host.Length + 5), 0, (byte)(host.Length + 3), 0, 0, (byte)host.Length }.Concat(host);
        var alpn = new byte[] { 0, 16, 0, 5, 0, 3, 2, 104, 50 };
        var extensions = sni.Concat(alpn).ToArray();
        var body = new byte[] { 3, 3 }.Concat(new byte[32]).Concat(new byte[] { 0, 0, 2, 0x13, 1, 1, 0, 0, (byte)extensions.Length }).Concat(extensions).ToArray();
        var handshake = new byte[] { 1, 0, 0, (byte)body.Length }.Concat(body).ToArray();
        var record = new byte[] { 22, 3, 1, 0, (byte)handshake.Length }.Concat(handshake).ToArray();
        var frame = Eth(Ipv4(6, Tcp(50000, 443, 0x18, Array.Empty<byte>(), record)));
        var d = Dissect(frame);
        AssertWellFormed(d);
        Assert.Contains("Client Hello", d.Layers[^1].Label);
        var sniByte = Array.IndexOf(frame, (byte)'x');
        Assert.Equal("Server Name: example.com", d.FieldAt(sniByte)!.Label);
        Assert.Equal("ALPN Next Protocol: h2", d.FieldAt(frame.Length - 1)!.Label);
        Assert.Contains("TLS_AES_128_GCM_SHA256", d.FieldAt(54 + 5 + 4 + 2 + 32 + 1 + 2)!.Label);
    }

    [Fact]
    public void StunAndQuic()
    {
        var port = (ushort)(54321 ^ 0x2112);
        var ip = new byte[] { 203 ^ 0x21, 0 ^ 0x12, 113 ^ 0xa4, 7 ^ 0x42 };
        var attribute = new byte[] { 0, 0x20, 0, 8, 0, 1, (byte)(port >> 8), (byte)port }.Concat(ip).ToArray();
        var stun = new byte[] { 1, 1, 0, (byte)attribute.Length, 0x21, 0x12, 0xa4, 0x42 }.Concat(new byte[12]).Concat(attribute).ToArray();
        var d = Dissect(Eth(Ipv4(17, Udp(3478, 5000, stun))));
        AssertWellFormed(d);
        Assert.Contains(d.Layers[^1].Children.SelectMany(c => c.Children), f => f.Label == "XOR-MAPPED-ADDRESS: 203.0.113.7:54321");

        var quic = new byte[] { 0xc3, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc, 0, 0x41, 0x00 }.Concat(new byte[256]).ToArray();
        d = Dissect(Eth(Ipv4(17, Udp(5000, 443, quic))));
        AssertWellFormed(d);
        Assert.Equal("QUIC IETF, Initial, DCID=aabb, SCID=cc", d.Layers[^1].Label);
        Assert.Contains(d.Layers[^1].Children, f => f.Label == "Length: 256");
    }

    [Fact]
    public void Ipv6VlanAndTruncationNeverThrow()
    {
        var ip6 = new byte[40];
        ip6[0] = 0x60; ip6[4] = 0; ip6[5] = 16; ip6[6] = 17; ip6[7] = 64; ip6[23] = 1; ip6[39] = 2;
        var udp = Udp(5000, 6000, new byte[8]);
        var inner = ip6.Concat(udp).ToArray();
        var vlan = new byte[] { 0, 10, 0x86, 0xdd }.Concat(inner).ToArray();
        var frame = Eth(vlan, 0x8100);
        var d = Dissect(frame);
        AssertWellFormed(d);
        Assert.Equal(new[] { ("Ethernet", 14), ("802.1Q", 4), ("IPv6", 40), ("UDP", 8) }, d.HeaderParts);
        Assert.Equal("::1", d.FieldAt(18 + 8 + 15)!.Label.Split(": ")[1]);

        foreach (var whole in new[] { frame, HttpFrame() })
        {
            for (var count = 0; count < whole.Length; count++)
            {
                var truncated = PacketDissector.Dissect(MakePacket(whole[..count], whole.Length), 1, 0);
                AssertWellFormed(truncated, fullCoverage: false);
            }
        }
    }
}
