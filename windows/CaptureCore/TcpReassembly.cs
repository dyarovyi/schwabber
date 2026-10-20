namespace CaptureCore;

/// <summary>A contiguous run of stream bytes. Offset is relative to the first captured data byte of its direction.</summary>
public sealed record TcpChunk(int Id, long Offset, byte[] Bytes);

public sealed class TcpDirection
{
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public required IReadOnlyList<TcpChunk> Chunks { get; init; }
    public required int OverlapBytes { get; init; }
    public required int ConflictingBytes { get; init; }
    public long MissingBytes => Chunks.Zip(Chunks.Skip(1)).Sum(pair => Math.Max(0, pair.Second.Offset - pair.First.Offset - pair.First.Bytes.Length));
}

/// <summary>
/// Orders each direction's TCP payload by sequence number. Retransmitted overlap is dropped (the first segment in
/// sequence order wins, capture order breaks ties) and conflicting bytes are counted; gaps start a new chunk.
/// </summary>
public static class TcpReassembly
{
    public static IReadOnlyList<TcpDirection> Reassemble(Session session, int linkType)
    {
        if (session.Transport != "TCP") return Array.Empty<TcpDirection>();
        var result = new List<TcpDirection>();
        foreach (var source in new[] { session.EndpointA, session.EndpointB })
        {
            uint? anchor = null;
            var segments = new List<(long Position, int Id, byte[] Data)>();
            foreach (var packet in session.Packets)
            {
                if (packet.Source != source || packet.PayloadEnd <= packet.PayloadStart) continue;
                var field = FindSequence(PacketDissector.Dissect(packet, linkType, 0).Layers);
                if (field is null || field.Offset + 4 > packet.RawBytes.Length) continue;
                var b = packet.RawBytes;
                var sequence = (uint)(b[field.Offset] << 24 | b[field.Offset + 1] << 16 | b[field.Offset + 2] << 8 | b[field.Offset + 3]);
                if (packet.Flags.Split(' ').Contains("SYN")) sequence = unchecked(sequence + 1);
                anchor ??= sequence;
                var relative = (long)unchecked((int)(sequence - anchor.Value));
                segments.Add((relative, packet.Id, packet.Payload.ToArray()));
            }
            if (segments.Count == 0) continue;
            segments.Sort((x, y) => x.Position == y.Position ? x.Id.CompareTo(y.Id) : x.Position.CompareTo(y.Position));
            var basePosition = segments[0].Position;
            var chunks = new List<TcpChunk>();
            var bytes = new List<byte>();
            long start = 0;
            int overlap = 0, conflicts = 0;
            foreach (var (position, _, data) in segments)
            {
                long offset = position - basePosition, end = start + bytes.Count;
                if (offset > end)
                {
                    if (bytes.Count > 0) chunks.Add(new TcpChunk(chunks.Count, start, bytes.ToArray()));
                    start = offset; bytes = new List<byte>();
                }
                var covered = (int)Math.Min(data.Length, Math.Max(0, start + bytes.Count - offset));
                overlap += covered;
                var index = (int)(offset - start);
                for (var i = 0; i < covered; i++) if (bytes[index + i] != data[i]) conflicts++;
                if (covered < data.Length) bytes.AddRange(data.AsSpan(covered).ToArray());
            }
            if (bytes.Count > 0) chunks.Add(new TcpChunk(chunks.Count, start, bytes.ToArray()));
            result.Add(new TcpDirection
            {
                Source = source,
                Destination = source == session.EndpointA ? session.EndpointB : session.EndpointA,
                Chunks = chunks, OverlapBytes = overlap, ConflictingBytes = conflicts,
            });
        }
        return result;
    }

    private static PacketField? FindSequence(IEnumerable<PacketField> fields)
    {
        foreach (var field in fields)
        {
            if (field.Name == "Sequence Number (raw)") return field;
            if (FindSequence(field.Children) is { } found) return found;
        }
        return null;
    }
}
