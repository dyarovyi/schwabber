using System.Buffers.Binary;

namespace CaptureCore;

/// <summary>One record as libpcap's pcap_next_ex would return it, with timestamps at microsecond precision.</summary>
internal readonly record struct RawRecord(long Seconds, long Microseconds, uint OriginalLength, byte[] Data);

/// <summary>
/// Managed reader for classic PCAP (microsecond, nanosecond and modified variants) and PCAPNG files,
/// replacing libpcap's pcap_open_offline so no capture driver needs to be installed.
/// </summary>
internal abstract class CaptureFile : IDisposable
{
    protected const int MaxSnapshotLength = 262144;
    protected readonly Stream Stream;
    protected CaptureFile(Stream stream) { Stream = stream; }
    public int LinkType { get; protected set; }
    public abstract RawRecord? Next();
    public void Dispose() => Stream.Dispose();

    public static CaptureFile Open(string path)
    {
        Stream stream;
        try { stream = new BufferedStream(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete), 1 << 20); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { throw new CaptureException($"{path}: {e.Message}"); }
        try
        {
            var magic = new byte[4];
            var got = ReadFully(stream, magic);
            if (got < 4) throw new CaptureException($"truncated dump file; tried to read 4 file header bytes, only got {got}");
            var value = BinaryPrimitives.ReadUInt32LittleEndian(magic);
            if (value == 0x0A0D0D0A) return new PcapNgFile(stream);
            foreach (var little in new[] { true, false })
            {
                var m = little ? value : BinaryPrimitives.ReverseEndianness(value);
                if (m is 0xa1b2c3d4 or 0xa1b23c4d or 0xa1b2cd34) return new PcapFile(stream, little, m);
            }
            throw new CaptureException("unknown file format");
        }
        catch { stream.Dispose(); throw; }
    }

    protected static int ReadFully(Stream stream, byte[] buffer, int count = -1)
    {
        if (count < 0) count = buffer.Length;
        var total = 0;
        while (total < count)
        {
            var n = stream.Read(buffer, total, count - total);
            if (n == 0) break;
            total += n;
        }
        return total;
    }
}

internal sealed class PcapFile : CaptureFile
{
    private readonly bool little;
    private readonly bool nanoseconds;
    private readonly int recordHeaderLength;
    private readonly byte[] header;

    public PcapFile(Stream stream, bool little, uint magic) : base(stream)
    {
        this.little = little;
        nanoseconds = magic == 0xa1b23c4d;
        recordHeaderLength = magic == 0xa1b2cd34 ? 24 : 16;
        header = new byte[recordHeaderLength];
        var rest = new byte[20];
        var got = ReadFully(stream, rest);
        if (got < 20) throw new CaptureException($"truncated dump file; tried to read 24 file header bytes, only got {got + 4}");
        var major = U16(rest, 0);
        if (major != 2) throw new CaptureException($"archaic pcap savefile format {major}.{U16(rest, 2)}");
        LinkType = (int)(U32(rest, 16) & 0x03FFFFFF);
    }

    private ushort U16(byte[] b, int i) => little ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(i)) : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(i));
    private uint U32(byte[] b, int i) => little ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i)) : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(i));

    public override RawRecord? Next()
    {
        var got = ReadFully(Stream, header);
        if (got == 0) return null;
        if (got < recordHeaderLength) throw new CaptureException($"truncated dump file; tried to read {recordHeaderLength} header bytes, only got {got}");
        var seconds = U32(header, 0);
        var fraction = U32(header, 4);
        var captured = U32(header, 8);
        var original = U32(header, 12);
        if (captured > MaxSnapshotLength) throw new CaptureException($"invalid packet capture length {captured}, bigger than maximum of {MaxSnapshotLength}");
        var data = new byte[captured];
        got = ReadFully(Stream, data);
        if (got < captured) throw new CaptureException($"truncated dump file; tried to read {captured} captured bytes, only got {got}");
        return new RawRecord(seconds, nanoseconds ? fraction / 1000 : fraction, original, data);
    }
}

internal sealed class PcapNgFile : CaptureFile
{
    private sealed record Interface(int LinkType, uint SnapLength, ulong TicksPerSecond, long Offset);
    private readonly List<Interface> interfaces = new();
    private bool little = true;
    private bool haveLinkType;

    public PcapNgFile(Stream stream) : base(stream)
    {
        // The first block must be a Section Header Block, whose type was already consumed.
        ParseSectionHeader(ReadSectionHeaderBody());
        // libpcap reports the link type of the first interface. A packet block before any
        // interface is an error, so reading ahead never consumes a packet.
        while (!haveLinkType && ReadBlock(out _)) { }
        if (!haveLinkType) LinkType = 1;
    }

    public override RawRecord? Next()
    {
        while (ReadBlock(out var record))
            if (record is not null) return record;
        return null;
    }

    private uint U32(ReadOnlySpan<byte> b, int i) => little ? BinaryPrimitives.ReadUInt32LittleEndian(b[i..]) : BinaryPrimitives.ReadUInt32BigEndian(b[i..]);
    private ushort U16(ReadOnlySpan<byte> b, int i) => little ? BinaryPrimitives.ReadUInt16LittleEndian(b[i..]) : BinaryPrimitives.ReadUInt16BigEndian(b[i..]);

    private readonly byte[] word = new byte[4];
    private byte[] blockBuffer = Array.Empty<byte>();

    /// <summary>Reads a Section Header Block whose type field was already consumed.</summary>
    private byte[] ReadSectionHeaderBody()
    {
        // Byte order is only known after the byte-order magic that follows the length field.
        var first = new byte[8];
        var got = ReadFully(Stream, first);
        if (got < 8) throw new CaptureException($"truncated dump file; tried to read {8} header bytes, only got {got}");
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(4));
        if (magic == 0x1A2B3C4D) little = true;
        else if (magic == 0x4D3C2B1A) little = false;
        else throw new CaptureException("unknown file format");
        var total = U32(first, 0);
        if (total < 28 || total % 4 != 0 || total > 16 * 1024 * 1024) throw new CaptureException($"block in pcapng dump file has a length of {total} < 28 or is not a multiple of 4");
        var rest = new byte[total - 16];
        got = ReadFully(Stream, rest);
        if (got < rest.Length) throw new CaptureException($"truncated pcapng dump file; tried to read {rest.Length} bytes, only got {got}");
        var trailer = new byte[4];
        if (ReadFully(Stream, trailer) < 4) throw new CaptureException("truncated pcapng dump file");
        var body = new byte[total - 12];
        Array.Copy(first, 4, body, 0, 4);
        Array.Copy(rest, 0, body, 4, rest.Length);
        return body;
    }

    private void ParseSectionHeader(byte[] body)
    {
        var major = U16(body, 4);
        if (major != 1) throw new CaptureException($"unsupported pcapng savefile version {major}.{U16(body, 6)}");
        interfaces.Clear();
    }

    /// <summary>Reads one block. Returns false at end of file; record is set for packet blocks.</summary>
    private bool ReadBlock(out RawRecord? record)
    {
        record = null;
        var got = ReadFully(Stream, word);
        if (got == 0) return false;
        if (got < 4) throw new CaptureException($"truncated pcapng dump file; tried to read 8 header bytes, only got {got}");
        var type = U32(word, 0);
        if (type == 0x0A0D0D0A)
        {
            ParseSectionHeader(ReadSectionHeaderBody());
            return true;
        }
        got = ReadFully(Stream, word);
        if (got < 4) throw new CaptureException($"truncated pcapng dump file; tried to read 8 header bytes, only got {got + 4}");
        var total = U32(word, 0);
        if (total < 12 || total % 4 != 0 || total > 16 * 1024 * 1024)
            throw new CaptureException($"block in pcapng dump file has a length of {total} < 12 or is not a multiple of 4");
        // Reuse scratch storage; Packet copies payloads before the next block is read.
        var bodyLength = (int)total - 12;
        if (blockBuffer.Length < bodyLength) blockBuffer = new byte[bodyLength];
        var body = blockBuffer.AsSpan(0, bodyLength);
        got = ReadFully(Stream, blockBuffer, bodyLength);
        if (got < body.Length) throw new CaptureException($"truncated pcapng dump file; tried to read {body.Length} bytes, only got {got}");
        if (ReadFully(Stream, word) < 4) throw new CaptureException("truncated pcapng dump file");

        switch (type)
        {
            case 1:
                if (body.Length < 8) throw new CaptureException("Interface Description Block is too short");
                AddInterface(body);
                return true;
            case 6:
            {
                if (body.Length < 20) throw new CaptureException("Enhanced Packet Block is too short");
                var id = (int)U32(body, 0);
                var ts = (ulong)U32(body, 4) << 32 | U32(body, 8);
                var captured = U32(body, 12);
                var original = U32(body, 16);
                if (captured > body.Length - 20) throw new CaptureException("Enhanced Packet Block captured length is larger than the block");
                record = Packet(id, ts, original, body.Slice(20, (int)captured));
                return true;
            }
            case 2:
            {
                if (body.Length < 20) throw new CaptureException("Packet Block is too short");
                var id = U16(body, 0);
                var ts = (ulong)U32(body, 4) << 32 | U32(body, 8);
                var captured = U32(body, 12);
                var original = U32(body, 16);
                if (captured > body.Length - 20) throw new CaptureException("Packet Block captured length is larger than the block");
                record = Packet(id, ts, original, body.Slice(20, (int)captured));
                return true;
            }
            case 3:
            {
                if (body.Length < 4) throw new CaptureException("Simple Packet Block is too short");
                if (interfaces.Count == 0) throw new CaptureException("Simple Packet Block appears before any Interface Description Block");
                var original = U32(body, 0);
                var captured = (int)Math.Min(Math.Min(original, interfaces[0].SnapLength == 0 ? uint.MaxValue : interfaces[0].SnapLength), (uint)(body.Length - 4));
                record = Packet(0, 0, original, body.Slice(4, captured), simple: true);
                return true;
            }
            default:
                return true;
        }
    }

    private void AddInterface(ReadOnlySpan<byte> body)
    {
        var link = U16(body, 0);
        var snap = U32(body, 4);
        ulong ticks = 1_000_000;
        long offset = 0;
        var p = 8;
        while (p + 4 <= body.Length)
        {
            var code = U16(body, p);
            var length = U16(body, p + 2);
            p += 4;
            if (code == 0 || p + length > body.Length) break;
            if (code == 9 && length == 1)
            {
                var r = body[p];
                ticks = (r & 0x80) != 0 ? 1UL << Math.Min(63, r & 0x7f) : Pow10(r);
            }
            else if (code == 14 && length == 8)
            {
                offset = little ? BinaryPrimitives.ReadInt64LittleEndian(body[p..]) : BinaryPrimitives.ReadInt64BigEndian(body[p..]);
            }
            p += (length + 3) & ~3;
        }
        if (!haveLinkType) { LinkType = link; haveLinkType = true; }
        interfaces.Add(new Interface(link, snap, ticks == 0 ? 1_000_000 : ticks, offset));
    }

    private static ulong Pow10(int n)
    {
        ulong v = 1;
        for (var i = 0; i < n && i < 19; i++) v *= 10;
        return v;
    }

    private RawRecord Packet(int interfaceId, ulong ts, uint original, ReadOnlySpan<byte> data, bool simple = false)
    {
        if (interfaceId < 0 || interfaceId >= interfaces.Count)
            throw new CaptureException($"a packet arrived on interface {interfaceId}, but there's no Interface Description Block for that interface");
        var iface = interfaces[interfaceId];
        if (iface.LinkType != LinkType)
            throw new CaptureException($"an interface has a type {iface.LinkType} different from the type of the first interface");
        if (data.Length > MaxSnapshotLength) throw new CaptureException($"invalid packet capture length {data.Length}, bigger than maximum of {MaxSnapshotLength}");
        long seconds = 0, micros = 0;
        if (!simple)
        {
            var whole = ts / iface.TicksPerSecond;
            var fraction = ts % iface.TicksPerSecond;
            seconds = (long)whole + iface.Offset;
            micros = (long)((UInt128)fraction * 1_000_000 / iface.TicksPerSecond);
        }
        return new RawRecord(seconds, micros, original, data.ToArray());
    }
}
