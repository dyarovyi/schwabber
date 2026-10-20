using CaptureCore;
using Xunit;
namespace CaptureCore.Tests;
public class IcmpTests {
    [Fact] public void EchoAndTruncation() {
        var b = new byte[42]; b[12]=8; b[14]=0x45; b[17]=28; b[23]=1;
        b[26]=10; b[29]=1; b[30]=10; b[33]=2; b[34]=8; b[39]=7; b[41]=2;
        var decoded=CaptureReader.Decode(b,1);
        Assert.Equal("ICMP",decoded?.Transport);
        Assert.Equal("10.0.0.1",decoded?.Source);
        Assert.Contains("id 7 sequence 2",decoded?.Flags);
        for(int count=0;count<b.Length;count++) Assert.Null(CaptureReader.Decode(b[..count],1));
        var v6=new byte[62]; v6[12]=0x86; v6[13]=0xdd; v6[14]=0x60; v6[19]=8; v6[20]=58; v6[54]=2; v6[60]=5;
        Assert.Equal("ICMPv6",CaptureReader.Decode(v6,1)?.Transport);
    }
}
