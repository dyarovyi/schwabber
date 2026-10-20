using CaptureCore;
using Xunit;

namespace CaptureCore.Tests;

public class RtpTests
{
    [Fact]
    public void RtpValidatesHeadersExtensionsPaddingAndTransport()
    {
        byte[] rtp = { 0xb1,0xe0,0,42,0,0,1,0,1,2,3,4,5,6,7,8,0xbe,0xde,0,1,0x10,42,0,0,0xab,0xcd,0,2 };
        Assert.Equal("RTP", ProtocolDecoder.Decode(rtp, false)?.Name);
        Assert.Contains("sequence 42", ProtocolDecoder.Decode(rtp, false)?.Summary);
        Assert.Contains("2 media bytes", ProtocolDecoder.Decode(rtp, false)?.Summary);
        Assert.Null(ProtocolDecoder.Decode(rtp, true));
        for (var count = 0; count < 24; count++) Assert.Null(ProtocolDecoder.Decode(rtp[..count], false));
        var bad = (byte[])rtp.Clone(); bad[27] = 0; Assert.Null(ProtocolDecoder.Decode(bad, false));
        bad[27] = 5; Assert.Null(ProtocolDecoder.Decode(bad, false));
        bad = (byte[])rtp.Clone(); bad[1] = 200; Assert.Null(ProtocolDecoder.Decode(bad, false));
    }
    [Fact]
    public void StunTurnAndInvalidLength()
    {
        byte[] stun = { 0,3,0,0,0x21,0x12,0xa4,0x42,0,0,0,0,0,0,0,0,0,0,0,0 };
        Assert.Equal("STUN", ProtocolDecoder.Decode(stun, false)?.Name);
        Assert.StartsWith("Allocate request", ProtocolDecoder.Decode(stun, false)?.Summary);
        stun[3] = 4; Assert.Null(ProtocolDecoder.Decode(stun, false));
    }
}
