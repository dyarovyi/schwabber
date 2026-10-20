using System.Text;
using CaptureCore;
using Xunit;
namespace CaptureCore.Tests;
public class RealtimeTests
{
    [Fact]
    public void DecodesRealtimeProtocolsAndRejectsInvalidLengths()
    {
        byte[] rr = { 0x81,201,0,7,0,0,0,1,0,0,0,2,128,255,255,255,0,0,0,10,0,0,0,20,0,0,0,0,0,0,0,0 };
        byte[] dtls = { 22,254,253,0,0,0,0,0,0,0,1,0,12,14,0,0,0,0,1,0,0,0,0,0,0 };
        byte[] turn = { 0x40,1,0,3,1,2,3 };
        var sip = Encoding.UTF8.GetBytes("INVITE sip:b@example.com SIP/2.0\r\nCall-ID: test\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5004 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n");
        foreach (var (bytes,name) in new[] { (rr,"RTCP"),(dtls,"DTLS"),(turn,"TURN"),(sip,"SIP") })
        {
            Assert.Equal(name,ProtocolDecoder.Decode(bytes,false)?.Name);
            Assert.All(RealtimeDecoder.Decode(bytes,false)!.Fields,f => Assert.True(f.Offset>=0 && f.Offset+f.Length<=bytes.Length));
            for (int count=0; count<bytes.Length; count++) _ = RealtimeDecoder.Decode(bytes[..count],false);
        }
        Assert.Contains(RealtimeDecoder.Decode(rr,false)!.Fields,f=>f.Name=="Cumulative Lost" && f.Value=="-1");
        Assert.Contains(RealtimeDecoder.Decode(rr,false)!.Fields,f=>f.Value=="50.00%");
        Assert.Contains("opus/48000/2",ProtocolDecoder.Decode(sip,true)!.Summary);
        Assert.Null(RealtimeDecoder.Decode(turn,true));
        Assert.Equal("TURN",RealtimeDecoder.Decode(turn.Concat(new byte[]{0}).ToArray(),true)?.Name);
        Assert.Null(RealtimeDecoder.Decode(rr,true));
        var bad = (byte[])rr.Clone(); bad[3]=8; Assert.Null(RealtimeDecoder.Decode(bad,false));
        bad=(byte[])dtls.Clone(); bad[24]=1; Assert.Null(RealtimeDecoder.Decode(bad,false));
        Assert.Equal(2,RealtimeDecoder.Decode(rr.Concat(rr).ToArray(),false)!.Fields.Count(f=>f.Name=="Packet Type"));
    }
}
