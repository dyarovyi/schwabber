using System.Text;
using CaptureCore;
using Xunit;

namespace CaptureCore.Tests;

public class CaptureTests
{
    private static byte[] Packet(bool reverse = false)
    {
        var b = new byte[42];
        b[12] = 8; b[14] = 0x45; b[17] = 28; b[23] = 17;
        new byte[] { 10, 0, 0, (byte)(reverse ? 2 : 1) }.CopyTo(b, 26);
        new byte[] { 10, 0, 0, (byte)(reverse ? 1 : 2) }.CopyTo(b, 30);
        (reverse ? new byte[] { 0, 53, 0x30, 0x39 } : new byte[] { 0x30, 0x39, 0, 53 }).CopyTo(b, 34);
        b[39] = 8;
        return b;
    }

    private static string TempPath(string extension = ".pcap") => Path.Combine(Path.GetTempPath(), Guid.NewGuid() + extension);

    [Fact]
    public void DecodingAndTruncation()
    {
        var b = Packet();
        var result = CaptureReader.Decode(b, 1);
        Assert.Equal("UDP", result?.Transport);
        Assert.Equal("10.0.0.1:12345", result?.Source);
        Assert.Equal("10.0.0.2:53", result?.Destination);
        for (var count = 0; count < b.Length; count++) Assert.Null(CaptureReader.Decode(b[..count], 1));
        var fragment = (byte[])b.Clone(); fragment[21] = 1;
        Assert.Null(CaptureReader.Decode(fragment, 1));
    }

    [Fact]
    public void BidirectionalGroupingAndIdleTimeout()
    {
        var data = new List<byte> { 0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0 };
        void Append(uint number) => data.AddRange(BitConverter.GetBytes(number));
        foreach (var (time, reverse) in new[] { (1u, false), (2u, true), (100u, false) })
        {
            var b = Packet(reverse);
            Append(time); Append(0); Append((uint)b.Length); Append((uint)b.Length); data.AddRange(b);
        }
        var path = TempPath();
        File.WriteAllBytes(path, data.ToArray());
        var exportPath = TempPath();
        try
        {
            var capture = CaptureReader.Read(path);
            Assert.Equal(3, capture.TotalPackets);
            Assert.Equal(0, capture.SkippedPackets);
            Assert.Equal(2, capture.Sessions.Count);
            Assert.Equal(2, capture.Sessions[0].Packets.Count);
            Assert.Equal(99, capture.End - capture.Start);
            capture.Export(new HashSet<int> { capture.Sessions[0].Id }, exportPath);
            var subset = CaptureReader.Read(exportPath);
            Assert.Equal(2, subset.TotalPackets);
            Assert.Equal(capture.Sessions[0].Packets.Select(p => p.RawBytes), subset.Sessions[0].Packets.Select(p => p.RawBytes));
            Assert.Equal(new double[] { 1, 2 }, subset.Sessions[0].Packets.Select(p => p.Time));
            capture.Export(capture.Sessions.Select(s => s.Id).ToHashSet(), exportPath);
            Assert.Equal(3, CaptureReader.Read(exportPath).TotalPackets);
            Assert.Throws<CaptureException>(() => capture.Export(new HashSet<int>(), exportPath));
        }
        finally
        {
            File.Delete(path);
            File.Delete(exportPath);
        }
    }

    [Fact]
    public void InvalidFile()
    {
        var path = TempPath("");
        File.WriteAllText(path, "invalid");
        try { Assert.Throws<CaptureException>(() => CaptureReader.Read(path)); }
        finally { File.Delete(path); }
    }

    private static byte[] DnsQuery() =>
        new byte[] { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7 }.Concat(Encoding.UTF8.GetBytes("example")).Append((byte)3)
            .Concat(Encoding.UTF8.GetBytes("com")).Concat(new byte[] { 0, 0, 1, 0, 1 }).ToArray();

    [Fact]
    public void DnsQueryAndCompressedResponse()
    {
        var query = DnsQuery();
        Assert.Equal(new[] { "example.com A" }, DnsDecoder.Decode(query)?.Questions);
        Assert.Equal(0x1234, DnsDecoder.Decode(query)?.Id);
        var response = (byte[])query.Clone();
        response[2] = 0x81; response[3] = 0x80; response[7] = 1;
        response = response.Concat(new byte[] { 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4 }).ToArray();
        Assert.Equal(new[] { "example.com A 1.2.3.4" }, DnsDecoder.Decode(response)?.Answers);
        Assert.True(DnsDecoder.Decode(response)?.IsResponse);
        response[3] = 0x83;
        Assert.Equal("NXDOMAIN", DnsDecoder.Decode(response)?.Status);
        for (var count = 0; count < response.Length; count++) Assert.Null(DnsDecoder.Decode(response[..count]));
        var loop = (byte[])query.Clone(); loop[12] = 0xc0; loop[13] = 12;
        Assert.Null(DnsDecoder.Decode(loop));
    }

    [Fact]
    public void DnsUdpAndTcpIntegration()
    {
        var query = DnsQuery();
        var udp = Packet().Concat(query).ToArray();
        udp[17] = (byte)(28 + query.Length); udp[39] = (byte)(8 + query.Length);
        Assert.Equal(new[] { "example.com A" }, CaptureReader.Decode(udp, 1)?.Dns.FirstOrDefault()?.Questions);
        udp[37] = 54;
        Assert.Equal(0, CaptureReader.Decode(udp, 1)?.Dns.Count);
        udp[39] = 7;
        Assert.Null(CaptureReader.Decode(udp, 1));
        var tcp = Packet()[..34].Concat(new byte[20]).ToArray();
        tcp[23] = 6; tcp[34] = 0x30; tcp[35] = 0x39; tcp[37] = 53; tcp[46] = 0x50;
        tcp = tcp.Concat(new byte[] { 0, (byte)query.Length }).Concat(query).ToArray();
        tcp[17] = (byte)(tcp.Length - 14);
        Assert.Equal(0x1234, CaptureReader.Decode(tcp, 1)?.Dns.FirstOrDefault()?.Id);
        tcp = tcp[..^1];
        Assert.Equal(0, CaptureReader.Decode(tcp, 1)?.Dns.Count);
    }

    [Fact]
    public void HigherProtocols()
    {
        var http = Encoding.UTF8.GetBytes("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n");
        Assert.Equal("HTTP", ProtocolDecoder.Decode(http, tcp: true)?.Name);
        Assert.Equal("GET /hello HTTP/1.1 · Host: example.com", ProtocolDecoder.Decode(http, tcp: true)?.Summary);
        Assert.Null(ProtocolDecoder.Decode(http, tcp: false));
        var stun = new byte[] { 0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42 }.Concat(new byte[12]).ToArray();
        Assert.Equal("STUN", ProtocolDecoder.Decode(stun, tcp: false)?.Name);
        Assert.StartsWith("Binding request", ProtocolDecoder.Decode(stun, tcp: false)?.Summary);
        var quic = new byte[] { 0xc0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc, 0 };
        Assert.Equal("QUIC", ProtocolDecoder.Decode(quic, tcp: false)?.Name);
        Assert.Contains("DCID aabb · SCID cc", ProtocolDecoder.Decode(quic, tcp: false)?.Summary);
        Assert.Null(ProtocolDecoder.Decode(new byte[] { 0x40, 1, 2, 3 }, tcp: false));
        var tls = new byte[] { 23, 3, 3, 0, 2, 1, 2 };
        Assert.Equal("TLS", ProtocolDecoder.Decode(tls, tcp: true)?.Name);
        foreach (var data in new[] { stun, quic, tls, http })
        {
            for (var count = 0; count < data.Length; count++)
            {
                _ = ProtocolDecoder.Decode(data[..count], tcp: true);
                _ = ProtocolDecoder.Decode(data[..count], tcp: false);
            }
        }
        Assert.Null(ProtocolDecoder.Decode(stun[..19], tcp: false));
        var malformed = (byte[])stun.Clone(); malformed[3] = 4;
        Assert.Null(ProtocolDecoder.Decode(malformed, tcp: false));
        var badId = (byte[])quic.Clone(); badId[5] = 255;
        Assert.Null(ProtocolDecoder.Decode(badId, tcp: false));
    }

    [Fact]
    public void TlsClientHelloMetadata()
    {
        var host = Encoding.UTF8.GetBytes("example.com");
        var sni = new byte[] { 0, 0, 0, (byte)(host.Length + 5), 0, (byte)(host.Length + 3), 0, 0, (byte)host.Length }.Concat(host);
        var alpn = new byte[] { 0, 16, 0, 5, 0, 3, 2, 104, 50 };
        var extensions = sni.Concat(alpn).ToArray();
        var body = new byte[] { 3, 3 }.Concat(new byte[32]).Concat(new byte[] { 0, 0, 2, 0x13, 1, 1, 0, 0, (byte)extensions.Length }).Concat(extensions).ToArray();
        var handshake = new byte[] { 1, 0, 0, (byte)body.Length }.Concat(body).ToArray();
        var record = new byte[] { 22, 3, 1, 0, (byte)handshake.Length }.Concat(handshake).ToArray();
        var result = ProtocolDecoder.Decode(record, tcp: true);
        Assert.Contains("SNI example.com", result?.Summary);
        Assert.Contains("ALPN h2", result?.Summary);
        for (var count = 0; count < record.Length; count++) _ = ProtocolDecoder.Decode(record[..count], tcp: true);
    }

    // Windows-only addition: the managed reader replaces libpcap, so check PCAPNG and nanosecond PCAP too.
    [Theory]
    [InlineData(6)]
    [InlineData(9)]
    [InlineData(19)]
    [InlineData(191)] // Binary resolution: 2^63 ticks per second.
    public void PcapNgScratchBufferPreservesPacketsAndTimestamps(int resolution)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(0x0A0D0D0Au); writer.Write(28u); writer.Write(0x1A2B3C4Du);
        writer.Write((ushort)1); writer.Write((ushort)0); writer.Write(-1L); writer.Write(28u);
        writer.Write(1u); writer.Write(32u); writer.Write((ushort)1); writer.Write((ushort)0); writer.Write(0u);
        writer.Write((ushort)9); writer.Write((ushort)1); writer.Write((byte)resolution);
        writer.Write(new byte[3]); writer.Write(0u); writer.Write(32u);
        ulong ticks = resolution == 191 ? 1UL << 63 : resolution == 19 ? 10_000_000_000_000_000_000UL :
            resolution == 9 ? 1_000_000_000UL : 1_000_000UL;
        var timestamp = ticks - 1;
        var payloads = new[] { new byte[] { 1, 2, 3 }, Enumerable.Repeat((byte)42, 4096).ToArray(), new byte[] { 7 } };
        foreach (var payload in payloads)
        {
            var padded = (payload.Length + 3) & ~3;
            writer.Write(6u); writer.Write((uint)(32 + padded)); writer.Write(0u);
            writer.Write((uint)(timestamp >> 32)); writer.Write((uint)timestamp);
            writer.Write((uint)payload.Length); writer.Write((uint)payload.Length);
            writer.Write(payload); writer.Write(new byte[padded - payload.Length]); writer.Write((uint)(32 + padded));
        }
        var path = TempPath(".pcapng");
        File.WriteAllBytes(path, stream.ToArray());
        try
        {
            using var file = CaptureFile.Open(path);
            var records = payloads.Select(_ => file.Next()!.Value).ToArray();
            Assert.Null(file.Next());
            for (var i = 0; i < records.Length; i++)
            {
                Assert.Equal(payloads[i], records[i].Data);
                Assert.Equal(0L, records[i].Seconds);
                Assert.Equal(999_999L, records[i].Microseconds);
            }
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void PcapNgAndNanosecondPcap()
    {
        var packet = Packet();
        var ng = new List<byte>();
        void U16(ushort v) => ng.AddRange(BitConverter.GetBytes(v));
        void U32(uint v) => ng.AddRange(BitConverter.GetBytes(v));
        U32(0x0A0D0D0A); U32(28); U32(0x1A2B3C4D); U16(1); U16(0); ng.AddRange(BitConverter.GetBytes(-1L)); U32(28);
        // Interface with if_tsresol = 9 (nanoseconds).
        U32(1); U32(32); U16(1); U16(0); U32(0); U16(9); U16(1); ng.AddRange(new byte[] { 9, 0, 0, 0 }); U16(0); U16(0); U32(32);
        var ts = 5_000_000_000UL + 250_000_000;
        var padded = (packet.Length + 3) & ~3;
        U32(6); U32((uint)(32 + padded)); U32(0); U32((uint)(ts >> 32)); U32((uint)ts); U32((uint)packet.Length); U32((uint)packet.Length);
        ng.AddRange(packet); ng.AddRange(new byte[padded - packet.Length]); U32((uint)(32 + padded));
        var path = TempPath(".pcapng");
        File.WriteAllBytes(path, ng.ToArray());
        try
        {
            var capture = CaptureReader.Read(path);
            Assert.Equal(1, capture.TotalPackets);
            Assert.Equal(5.25, capture.Sessions[0].Packets[0].Time, 6);
            Assert.Equal(250_000u, capture.Sessions[0].Packets[0].Microseconds);
        }
        finally { File.Delete(path); }

        var nano = new List<byte> { 0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0 };
        nano.AddRange(BitConverter.GetBytes(7u)); nano.AddRange(BitConverter.GetBytes(123_456_789u));
        nano.AddRange(BitConverter.GetBytes((uint)packet.Length)); nano.AddRange(BitConverter.GetBytes((uint)packet.Length)); nano.AddRange(packet);
        path = TempPath();
        File.WriteAllBytes(path, nano.ToArray());
        try { Assert.Equal(123_456u, CaptureReader.Read(path).Sessions[0].Packets[0].Microseconds); }
        finally { File.Delete(path); }

        path = TempPath();
        File.WriteAllBytes(path, nano.Take(nano.Count - 3).ToArray());
        try { Assert.Throws<CaptureException>(() => CaptureReader.Read(path)); }
        finally { File.Delete(path); }
    }
}
