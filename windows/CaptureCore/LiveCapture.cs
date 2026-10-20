using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
namespace CaptureCore;

/// <summary>Preferred marks a connected, non-loopback adapter, the best default (like en0 on macOS).</summary>
public sealed record CaptureInterface(string Id, string Label, bool Preferred = false);
public sealed class LiveCapture
{
    private volatile bool stopped;
    public void Stop() => stopped = true;
    static LiveCapture()
    {
        NativeLibrary.SetDllImportResolver(typeof(LiveCapture).Assembly, (name, assembly, path) =>
        {
            if (name != "wpcap.dll") return IntPtr.Zero;
            return NativeLibrary.Load(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap", "wpcap.dll"), assembly, DllImportSearchPath.UseDllDirectoryForDependencies | DllImportSearchPath.SafeDirectories);
        });
    }
    [StructLayout(LayoutKind.Sequential)] private struct Device { public IntPtr Next, Name, Description, Addresses; public uint Flags; }
    // Windows timeval uses two 32-bit longs on both x86 and x64.
    [StructLayout(LayoutKind.Sequential)] private struct Header { public int Seconds, Microseconds; public uint Captured, Wire; }
    [StructLayout(LayoutKind.Sequential)] private struct Stats { public uint Received, Dropped, InterfaceDropped, Captured; }
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern int pcap_findalldevs(out IntPtr list, StringBuilder error);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern void pcap_freealldevs(IntPtr list);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr pcap_open_live(string device,int snap,int promisc,int timeout,StringBuilder error);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern int pcap_setnonblock(IntPtr handle,int enabled,StringBuilder error);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern int pcap_next_ex(IntPtr handle,out IntPtr header,out IntPtr bytes);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern int pcap_datalink(IntPtr handle);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr pcap_geterr(IntPtr handle);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern int pcap_stats(IntPtr handle,out Stats stats);
    [DllImport("wpcap.dll", CallingConvention=CallingConvention.Cdecl)] private static extern void pcap_close(IntPtr handle);
    public static List<CaptureInterface> Interfaces()
    {
        var error=new StringBuilder(256);
        if(pcap_findalldevs(out var list,error)!=0) throw new CaptureException(error.ToString());
        try {
            var result=new List<CaptureInterface>();
            for(var p=list;p!=IntPtr.Zero;) { var d=Marshal.PtrToStructure<Device>(p); var id=Marshal.PtrToStringAnsi(d.Name)!; var description = Marshal.PtrToStringAnsi(d.Description) ?? id;
                // PCAP_IF_LOOPBACK = 1, PCAP_IF_UP = 2, PCAP_IF_RUNNING = 4, connection status bits 0x30 with 0x10 = connected.
                // WAN Miniport pseudo-adapters also report "connected" but have no addresses.
                var preferred = (d.Flags & 1) == 0 && (d.Flags & 6) == 6 && (d.Flags & 0x30) == 0x10 && d.Addresses != IntPtr.Zero;
                // Windows device names are \Device\NPF_{GUID} paths, so the adapter description is the readable label.
                result.Add(new(id, description, preferred)); p=d.Next; }
            return result;
        } finally { pcap_freealldevs(list); }
    }
    public void Run(string device,string path,Action<Capture,uint> update)
    {
        var error=new StringBuilder(256);
        var handle=pcap_open_live(device,262144,0,100,error);
        if(handle==IntPtr.Zero) throw new CaptureException(error+". Install Npcap and ensure your account has capture access.");
        try {
            int link=pcap_datalink(handle);
            if(!new[]{1,0,108,12,101,113,276}.Contains(link)) throw new CaptureException($"Unsupported interface link type {link}.");
            if(pcap_setnonblock(handle,1,error)!=0) throw new CaptureException(error.ToString());
            using var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
            using var writer=new BinaryWriter(file);
            writer.Write(0xa1b2c3d4u); writer.Write((ushort)2); writer.Write((ushort)4); writer.Write(0u); writer.Write(0u); writer.Write(262144u); writer.Write((uint)(link==12?101:link)); writer.Flush();
            var sessions=new List<Session>(); var active=new Dictionary<string,int>(); int total=0,skipped=0; long totalBytes=0;
            var timer=Stopwatch.StartNew(); long next=0; int publishedTotal=-1;
            void Publish() {
                writer.Flush();
                var copies=sessions.Select(s=> { var copy=new Session(s.Id,s.Transport,s.EndpointA,s.EndpointB,s.Packets[0]); foreach(var p in s.Packets.Skip(1)) copy.Append(p); return copy; }).ToList();
                pcap_stats(handle,out var stats);
                update(new Capture { Sessions=copies,LinkType=link,TotalPackets=total,SkippedPackets=skipped,TotalBytes=totalBytes,SourcePath=path },stats.Dropped);
                publishedTotal=total;
            }
            while(!stopped) {
                for(int i=0;i<256;i++) {
                    int status=pcap_next_ex(handle,out var hp,out var bp); if(status==0) break;
                    if(status!=1) throw new CaptureException(Marshal.PtrToStringAnsi(pcap_geterr(handle)) ?? "Capture failed");
                    var h=Marshal.PtrToStructure<Header>(hp); if(h.Captured>262144) throw new CaptureException("Invalid capture length");
                    var bytes=new byte[(int)h.Captured]; Marshal.Copy(bp,bytes,0,bytes.Length);
                    writer.Write((uint)h.Seconds); writer.Write((uint)h.Microseconds); writer.Write(h.Captured); writer.Write(h.Wire); writer.Write(bytes);
                    total++; totalBytes+=h.Wire;
                    if(CaptureReader.Decode(bytes,link) is not {} d) { skipped++; continue; }
                    var packet=new Packet { Id=total,Time=h.Seconds+h.Microseconds/1_000_000.0,Source=d.Source,Destination=d.Destination,Length=(int)Math.Min(h.Wire,int.MaxValue),Flags=d.Flags,Dns=d.Dns,Application=d.Application,RawBytes=bytes,Seconds=(uint)h.Seconds,Microseconds=(uint)h.Microseconds,PayloadStart=d.PayloadStart,PayloadEnd=d.PayloadEnd };
                    var ends=new[]{d.Source,d.Destination}; Array.Sort(ends,StringComparer.Ordinal); var key=d.Transport+"|"+string.Join("|",ends);
                    if(active.TryGetValue(key,out int index) && packet.Time-sessions[index].End<=60) sessions[index].Append(packet);
                    else { active[key]=sessions.Count; sessions.Add(new Session(sessions.Count,d.Transport,d.Source,d.Destination,packet)); }
                }
                // Idle captures do not republish unchanged snapshots.
                if(timer.ElapsedMilliseconds>=next) { if(total!=publishedTotal) Publish(); else writer.Flush(); next=timer.ElapsedMilliseconds+500; }
                Thread.Sleep(10);
            }
            Publish();
        } finally { pcap_close(handle); }
    }
}
