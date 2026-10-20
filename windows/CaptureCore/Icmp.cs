namespace CaptureCore;
internal static class Icmp
{
    public static string Name(int type, bool v6) => v6
        ? type switch { 1=>"Destination Unreachable",2=>"Packet Too Big",3=>"Time Exceeded",4=>"Parameter Problem",128=>"Echo Request",129=>"Echo Reply",133=>"Router Solicitation",134=>"Router Advertisement",135=>"Neighbor Solicitation",136=>"Neighbor Advertisement",137=>"Redirect",_=>"Message" }
        : type switch { 0=>"Echo Reply",3=>"Destination Unreachable",5=>"Redirect",8=>"Echo Request",11=>"Time Exceeded",12=>"Parameter Problem",13=>"Timestamp Request",14=>"Timestamp Reply",_=>"Message" };
}
