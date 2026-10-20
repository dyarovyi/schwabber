using System.Text;
using System.Globalization;
namespace CaptureCore;
internal record RealtimeField(string Name, string Value, int Offset, int Length);
internal record RealtimeMessage(string Name, string Summary, List<RealtimeField> Fields);
internal static class RealtimeDecoder
{
    public static RealtimeMessage? Decode(byte[] b, bool tcp)
    {
        var fields = new List<RealtimeField>();
        ulong U(int p, int n) { ulong v = 0; for (var i = p; i < p+n; i++) v = (v << 8) | b[i]; return v; }
        void Add(string name, int p, int n, string? value = null) => fields.Add(new(name,value ?? U(p,n).ToString(CultureInfo.InvariantCulture),p,n));
        RealtimeMessage Result(string name, string summary) => new(name,summary,fields);
        if (!tcp && b.Length >= 4 && b[0] >> 6 == 2 && b[1] >= 200 && b[1] <= 207)
        {
            int p = 0; var names = new List<string>();
            while (p < b.Length)
            {
                if (p+4 > b.Length || b[p] >> 6 != 2 || b[p+1] < 200 || b[p+1] > 207) return null;
                int type = b[p+1], count = b[p]&31, size = ((int)U(p+2,2)+1)*4;
                if (size < 4 || p+size > b.Length) return null;
                int pad = (b[p]&32) != 0 ? b[p+size-1] : 0;
                if (pad > size-4 || ((b[p]&32) != 0 && (pad == 0 || p+size != b.Length))) return null;
                int end = p+size-pad;
                var name = new[] { "Sender Report","Receiver Report","Source Description","Goodbye","Application","Transport Feedback","Payload Feedback","Extended Report" }[type-200];
                names.Add(name); Add("Packet Type",p+1,1,name); Add("Count / Format",p,1,count.ToString()); Add("Length (words minus one)",p+2,2);
                int q = p+4;
                if (type == 200 || type == 201)
                {
                    if (p+(type == 200 ? 28 : 8)+count*24 > end) return null;
                    Add("Sender SSRC",q,4); q += 4;
                    if (type == 200) { Add("NTP Timestamp",q,8); Add("RTP Timestamp",q+8,4); Add("Sender Packet Count",q+12,4); Add("Sender Octet Count",q+16,4); q += 20; }
                    for (int i=0; i<count; i++)
                    {
                        Add("Report SSRC",q,4); Add("Fraction Lost",q+4,1,(b[q+4]*100.0/256).ToString("F2",CultureInfo.InvariantCulture)+"%");
                        int lost = (int)U(q+5,3); Add("Cumulative Lost",q+5,3,((lost&0x800000)!=0 ? lost-0x1000000 : lost).ToString());
                        Add("Extended Highest Sequence",q+8,4); Add("Jitter (timestamp units)",q+12,4); Add("Last Sender Report",q+16,4); Add("Delay Since Last SR (1/65536 s)",q+20,4); q += 24;
                    }
                }
                if (q < end) Add("Report Data",q,end-q,$"{end-q} bytes");
                if (pad > 0) Add("Padding",end,pad,$"{pad} bytes"); p += size;
            }
            return Result("RTCP",string.Join(" · ",names));
        }
        if (!tcp && b.Length >= 13 && b[0] >= 20 && b[0] <= 24 && b[1] == 254 && (b[2] == 255 || b[2] == 253))
        {
            int p = 0; var names = new List<string>();
            while (p < b.Length)
            {
                if (p+13 > b.Length || b[p] < 20 || b[p] > 24 || b[p+1] != 254 || (b[p+2] != 255 && b[p+2] != 253)) return null;
                int size = (int)U(p+11,2), end = p+13+size; if (end > b.Length) return null;
                int type = b[p]; var name = new[] { "Change Cipher Spec","Alert","Handshake","Application Data","Heartbeat" }[type-20]; names.Add(name);
                Add("Content Type",p,1,name); Add("Version",p+1,2,b[p+2] == 253 ? "DTLS 1.2" : "DTLS 1.0"); Add("Epoch",p+3,2); Add("Record Sequence",p+5,6); Add("Record Length",p+11,2);
                int q = p+13;
                if (type == 22 && U(p+3,2) == 0)
                {
                    while (q < end)
                    {
                        if (q+12 > end) return null;
                        int total = (int)U(q+1,3), offset = (int)U(q+6,3), length = (int)U(q+9,3);
                        if (offset > total || length > total-offset || q+12+length > end) return null;
                        var hs = b[q] switch { 1=>"ClientHello",2=>"ServerHello",3=>"HelloVerifyRequest",11=>"Certificate",14=>"ServerHelloDone",16=>"ClientKeyExchange",20=>"Finished",_=>b[q].ToString() };
                        Add("Handshake Type",q,1,hs); Add("Handshake Length",q+1,3); Add("Message Sequence",q+4,2); Add("Fragment Offset",q+6,3); Add("Fragment Length",q+9,3);
                        Add("Handshake Fragment",q+12,length,$"{length} bytes"); q += 12+length;
                    }
                }
                if (q < end) Add("Record Data",q,end-q,$"{end-q} bytes (possibly encrypted)"); p = end;
            }
            return Result("DTLS",string.Join(" · ",names));
        }
        if (b.Length >= 4 && b[0] >> 6 == 1)
        {
            int size = (int)U(2,2), padded = (size+3)&~3;
            if (b.Length == 4+padded || (!tcp && b.Length == 4+size))
            {
                Add("Channel Number",0,2); Add("Data Length",2,2); Add("Channel Data",4,size,$"{size} bytes");
                if (b.Length > size+4) Add("Padding",size+4,b.Length-size-4,"padding");
                return Result("TURN",$"Channel {U(0,2)} · {size} bytes · heuristic");
            }
        }
        int LineEnd(int p) { for (int i=p; i+1<b.Length; i++) if (b[i]==13 && b[i+1]==10) return i; return -1; }
        int firstEnd = LineEnd(0); if (firstEnd < 0) return null;
        string first = Encoding.UTF8.GetString(b,0,firstEnd); var parts = first.Split(' ',StringSplitOptions.RemoveEmptyEntries);
        bool response = parts.Length>=2 && parts[0]=="SIP/2.0" && parts[1].Length==3 && int.TryParse(parts[1],out _);
        bool request = parts.Length==3 && parts[2]=="SIP/2.0" && new[] {"INVITE","ACK","BYE","CANCEL","REGISTER","OPTIONS","INFO","PRACK","UPDATE","MESSAGE","SUBSCRIBE","NOTIFY","REFER","PUBLISH"}.Contains(parts[0]);
        if (!response && !request) return null;
        Add("Start Line",0,firstEnd,first);
        int cursor = firstEnd+2; bool sdp = false; int? bodyLength = null; string summary = first;
        while (cursor+1 < b.Length)
        {
            int q = LineEnd(cursor); if (q < 0) break;
            if (q == cursor) { cursor += 2; break; }
            string line = Encoding.UTF8.GetString(b,cursor,q-cursor); Add("SIP Header",cursor,q-cursor,line);
            int colon = line.IndexOf(':');
            if (colon >= 0)
            {
                string key = line[..colon].ToLowerInvariant(), value = line[(colon+1)..].Trim();
                if (key is "content-type" or "c") sdp = value.ToLowerInvariant().Split(';')[0] == "application/sdp";
                if ((key is "content-length" or "l") && int.TryParse(value,out int length)) bodyLength = length;
                if (key is "call-id" or "i") summary += " · Call-ID " + value;
            }
            cursor = q+2;
        }
        int bodyEnd = cursor + Math.Min(b.Length-cursor,Math.Max(0,bodyLength ?? b.Length-cursor));
        if (sdp)
        {
            while (cursor < bodyEnd)
            {
                int q = Array.IndexOf(b,(byte)10,cursor,bodyEnd-cursor); if (q < 0) q = bodyEnd;
                int n = q>cursor && b[q-1]==13 ? q-cursor-1 : q-cursor;
                string line = Encoding.UTF8.GetString(b,cursor,n); Add("SDP",cursor,n,line);
                if (line.StartsWith("m=") || line.StartsWith("a=rtpmap:") || line.StartsWith("c=")) summary += " · " + line;
                cursor = Math.Min(q+1,bodyEnd);
            }
        }
        else if (cursor < bodyEnd) Add("Body",cursor,bodyEnd-cursor,$"{bodyEnd-cursor} bytes");
        return Result("SIP",summary);
    }
}
