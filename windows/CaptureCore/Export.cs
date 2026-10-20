using System.Buffers.Binary;

namespace CaptureCore;

public static class CaptureExport
{
    /// <summary>Original packet bytes in capture order, including both directions of each selected session.</summary>
    public static void Export(this Capture capture, IReadOnlySet<int> sessionIds, string path)
    {
        var packets = capture.Sessions.Where(s => sessionIds.Contains(s.Id)).SelectMany(s => s.Packets).OrderBy(p => p.Id).ToList();
        if (packets.Count == 0) throw new CaptureException("Select at least one session to export.");
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new BufferedStream(new FileStream(temporary, FileMode.CreateNew, FileAccess.Write), 1 << 20))
            {
                var buffer = new byte[24];
                void U32(uint value, int at) => BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(at), value);
                U32(0xa1b2c3d4, 0);
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(4), 2);
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(6), 4);
                U32(0, 8); U32(0, 12);
                U32((uint)packets.Max(p => p.RawBytes.Length), 16);
                // DLT_RAW is 12 on some platforms, whereas the portable savefile LINKTYPE_RAW is 101.
                U32((uint)(capture.LinkType == 12 ? 101 : capture.LinkType), 20);
                stream.Write(buffer, 0, 24);
                foreach (var packet in packets)
                {
                    U32(packet.Seconds, 0); U32(packet.Microseconds, 4);
                    U32((uint)packet.RawBytes.Length, 8); U32((uint)packet.Length, 12);
                    stream.Write(buffer, 0, 16);
                    stream.Write(packet.RawBytes);
                }
            }
            File.Move(temporary, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(temporary); } catch { /* best effort */ }
            throw;
        }
    }
}
