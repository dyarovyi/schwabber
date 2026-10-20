using System.Text;
using System.Text.Json;
using CaptureCore;
using Xunit;

namespace CaptureCore.Tests;

/// <summary>Ports of the macOS core checks for features added after the first Windows release.</summary>
public class ParityTests
{
    private static byte[] UdpTemplate()
    {
        var b = new byte[42];
        b[12] = 8; b[14] = 0x45; b[17] = 28; b[23] = 17;
        new byte[] { 10, 0, 0, 1 }.CopyTo(b, 26); new byte[] { 10, 0, 0, 2 }.CopyTo(b, 30);
        new byte[] { 0x30, 0x39, 0, 53 }.CopyTo(b, 34); b[39] = 8;
        return b;
    }

    private static byte[] NativeTcp(byte[] payload, byte[]? options = null)
    {
        options ??= Array.Empty<byte>();
        var b = UdpTemplate()[..34].Concat(new byte[20]).Concat(options).Concat(payload).ToArray();
        b[23] = 6; b[34] = 0xc3; b[35] = 0x50; b[37] = 80;
        b[46] = (byte)(((20 + options.Length) / 4) << 4); b[47] = 0x18;
        b[16] = (byte)((b.Length - 14) >> 8); b[17] = (byte)((b.Length - 14) & 255);
        return b;
    }

    private static Packet NativePacket(byte[] bytes, int id = 1)
    {
        var d = CaptureReader.Decode(bytes, 1);
        return new Packet
        {
            Id = id, Time = 1, Source = d?.Source ?? "", Destination = d?.Destination ?? "", Length = bytes.Length, Flags = d?.Flags ?? "",
            Dns = d?.Dns ?? Array.Empty<DnsMessage>(), Application = d?.Application, RawBytes = bytes,
            PayloadStart = d?.PayloadStart ?? bytes.Length, PayloadEnd = d?.PayloadEnd ?? bytes.Length, Seconds = 1, Microseconds = 0,
        };
    }

    private static Session SessionOf(IReadOnlyList<Packet> packets)
    {
        var session = new Session(0, "TCP", packets[0].Source, packets[0].Destination, packets[0]);
        foreach (var packet in packets.Skip(1)) session.Append(packet);
        return session;
    }

    [Fact]
    public void PayloadSessionFiltering()
    {
        var packet = NativePacket(NativeTcp(new byte[] { 0, 1, 255 }.Concat(Encoding.UTF8.GetBytes("Hello payload")).ToArray()));
        var session = SessionOf(new[] { packet });
        Assert.True(new SessionFilter("x00x01xFF").Matches(session));
        Assert.True(new SessionFilter("Hello payload").Matches(session));
        Assert.False(new SessionFilter("hello payload").Matches(session));
        Assert.True(new SessionFilter("10.0.0.1").Matches(session));
        Assert.True(new SessionFilter("x00x01xGG").InvalidHex);
        Assert.False(new SessionFilter("x00x01xGG").Matches(session));
        Assert.False(new SessionFilter("x45x00").Matches(session));
        Assert.True(new SessionFilter("").Matches(session));
    }

    [Fact]
    public void Http2Frames()
    {
        var preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        var settings = new byte[] { 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100 };
        Assert.Equal("HTTP/2", ProtocolDecoder.Decode(preface.Concat(settings).ToArray(), tcp: true)?.Name);
        Assert.Contains(Http2Decoder.Decode(settings)!.Fields, f => f.Name == "Setting Value" && f.Value == "100");
        Assert.Null(Http2Decoder.Decode(new byte[] { 0, 0, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        Assert.Null(Http2Decoder.Decode(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        for (var count = 0; count < settings.Length; count++) _ = Http2Decoder.Decode(settings[..count]);
        var packet = NativePacket(NativeTcp(preface.Concat(settings).ToArray()));
        var dissection = PacketDissector.Dissect(packet, 1, 0);
        Assert.Contains(dissection.Layers[^1].Children, f => f.Name == "Setting Value");
    }

    [Fact]
    public void TcpReassemblyOrdersRetransmitsAndGaps()
    {
        Packet Segment(uint seq, string text, int id)
        {
            var b = NativeTcp(Encoding.ASCII.GetBytes(text));
            b[38] = (byte)(seq >> 24); b[39] = (byte)(seq >> 16); b[40] = (byte)(seq >> 8); b[41] = (byte)seq;
            b[47] = 16;
            return NativePacket(b, id);
        }
        var session = SessionOf(new[] { Segment(103, "def", 1), Segment(100, "abc", 2), Segment(100, "abc", 3), Segment(110, "xyz", 4) });
        var result = TcpReassembly.Reassemble(session, 1);
        Assert.Single(result);
        Assert.Equal(new[] { "abcdef", "xyz" }, result[0].Chunks.Select(c => Encoding.ASCII.GetString(c.Bytes)));
        Assert.Equal(4, result[0].MissingBytes);
        Assert.Equal(3, result[0].OverlapBytes);
        Assert.Equal(0, result[0].ConflictingBytes);
        var wrapped = SessionOf(new[] { Segment(0xfffffffd, "abc", 1), Segment(0, "def", 2) });
        Assert.Equal("abcdef", Encoding.ASCII.GetString(TcpReassembly.Reassemble(wrapped, 1)[0].Chunks[0].Bytes));
    }

    [Fact]
    public void WiresharkSourceRanges()
    {
        var frame = new byte[] { 1, 2, 3, 4 };
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["bytes"] = Convert.ToBase64String(frame),
            ["ds"] = new[]
            {
                new Dictionary<string, object> { ["name"] = "Decrypted QUIC", ["bytes"] = Convert.ToBase64String(new byte[] { 5, 6, 7 }) },
                new Dictionary<string, object> { ["name"] = "Reassembled TLS", ["bytes"] = Convert.ToBase64String(new byte[] { 8, 9 }) },
            },
            ["tree"] = new object[]
            {
                new Dictionary<string, object> { ["l"] = "Captured", ["f"] = "udp", ["h"] = new[] { 0, 2 } },
                new Dictionary<string, object>
                {
                    ["l"] = "QUIC", ["f"] = "quic", ["ds"] = 1, ["h"] = new[] { 0, 3 },
                    ["n"] = new object[]
                    {
                        new Dictionary<string, object> { ["l"] = "Type", ["ds"] = 1, ["h"] = new[] { 0, 1 } },
                        new Dictionary<string, object> { ["l"] = "Generated", ["ds"] = 1, ["h"] = new[] { 0, 1 }, ["g"] = true },
                    },
                },
                new Dictionary<string, object> { ["l"] = "TLS", ["ds"] = 2, ["h"] = new[] { 0, 2 } },
                new Dictionary<string, object> { ["l"] = "Invalid source", ["ds"] = 3, ["h"] = new[] { 0, 1 } },
                new Dictionary<string, object> { ["l"] = "Invalid range", ["ds"] = 2, ["h"] = new[] { 1, int.MaxValue } },
            },
        });
        using var document = JsonDocument.Parse(json);
        var parsed = WiresharkInspection.ParseFrame(document.RootElement, frame);
        Assert.Equal(2, parsed.AdditionalSources.Count);
        Assert.Equal(new byte[] { 5, 6, 7 }, parsed.AdditionalSources[0].Bytes);
        Assert.Equal("1. Decrypted QUIC", parsed.AdditionalSources[0].Name);
        Assert.Equal(0, parsed.Fields[0].SourceIndex);
        Assert.Equal(1, parsed.Fields[1].SourceIndex);
        Assert.Equal((0, 1), (parsed.Fields[1].Children[0].Start, parsed.Fields[1].Children[0].Length));
        Assert.False(parsed.Fields[1].Children[1].HasRange);
        Assert.Equal((2, 0, 2), (parsed.Fields[2].SourceIndex, parsed.Fields[2].Start, parsed.Fields[2].Length));
        Assert.False(parsed.Fields[3].HasRange);
        Assert.False(parsed.Fields[4].HasRange);
        Assert.Same(parsed.Fields[1], parsed.Fields[1].Children[0].Parent);
        Assert.Throws<CaptureException>(() => WiresharkInspection.ParseFrame(document.RootElement, new byte[] { 0 }));
    }

    [Fact]
    public void ErrorsAndMissingResultsFromSharkdAreReported()
    {
        Assert.Throws<CaptureException>(() => WiresharkInspection.ParseResponses("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-2001,\"message\":\"Unable to open the file\"}}\n", 2, new byte[1]));
        Assert.Throws<CaptureException>(() => WiresharkInspection.ParseResponses("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"OK\"}}\n", 2, new byte[1]));
    }

    /// <summary>Runs the real sharkd when Wireshark is installed; skipped silently otherwise.</summary>
    [Fact]
    public async Task SharkdAnalysesFrameWhenInstalled()
    {
        if (WiresharkInspection.FindSharkd() is null) return;
        var frame = NativeTcp(Encoding.ASCII.GetBytes("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"));
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pcap");
        var file = new List<byte> { 0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0 };
        file.AddRange(BitConverter.GetBytes(1u)); file.AddRange(BitConverter.GetBytes(0u));
        file.AddRange(BitConverter.GetBytes((uint)frame.Length)); file.AddRange(BitConverter.GetBytes((uint)frame.Length)); file.AddRange(frame);
        File.WriteAllBytes(path, file.ToArray());
        try
        {
            var capture = CaptureReader.Read(path);
            var packet = capture.Sessions[0].Packets[0];
            var result = await WiresharkInspection.InspectAsync(packet, capture, null, CancellationToken.None);
            Assert.Contains(result.Fields, f => f.Name == "http");
            Assert.Contains(result.Fields, f => f.Name == "tcp" && f.HasRange);
        }
        finally { File.Delete(path); }
    }
}
