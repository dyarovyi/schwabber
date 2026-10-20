import Foundation

public struct TCPChunk: Identifiable, Sendable {
    public let id: Int
    public let offset: Int64
    public let bytes: Data
}
public struct TCPDirection: Sendable {
    public let source: String
    public let destination: String
    public let chunks: [TCPChunk]
    public let overlapBytes: Int
    public let conflictingBytes: Int
    public var missingBytes: Int64 {
        zip(chunks, chunks.dropFirst()).reduce(0) { $0 + max(0, $1.1.offset - $1.0.offset - Int64($1.0.bytes.count)) }
    }
}
public enum TCPReassembly {
    public static func reassemble(_ session: Session, linkType: Int32) -> [TCPDirection] {
        guard session.transport == "TCP" else { return [] }
        return [session.endpointA, session.endpointB].compactMap { source in
            var anchor: UInt32?
            var segments: [(Int64, Int, Data)] = []
            for packet in session.packets where packet.source == source && !packet.payloadRange.isEmpty {
                let fields = NativeDissector.dissect(packet, linkType: linkType).fields
                guard let field = fields.first(where: { $0.name == "Sequence Number (raw)" }), field.offset + 4 <= packet.rawBytes.count else { continue }
                var sequence = packet.rawBytes[field.offset..<(field.offset+4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                if packet.flags.split(separator: " ").contains("SYN") { sequence &+= 1 }
                if anchor == nil { anchor = sequence }
                let relative = Int64(Int32(bitPattern: sequence &- anchor!))
                segments.append((relative, packet.id, packet.payload))
            }
            guard !segments.isEmpty else { return nil }
            segments.sort { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }
            let base = segments[0].0
            var chunks: [TCPChunk] = [], bytes = Data(), start: Int64 = 0
            var overlap = 0, conflicts = 0
            for (position, _, data) in segments {
                let offset = position-base, end = start+Int64(bytes.count)
                if offset > end {
                    if !bytes.isEmpty { chunks.append(TCPChunk(id: chunks.count, offset: start, bytes: bytes)) }
                    start = offset; bytes = Data()
                }
                let covered = min(data.count, max(0, Int(start+Int64(bytes.count)-offset)))
                overlap += covered
                if covered > 0 {
                    let index = Int(offset-start)
                    for i in 0..<covered where bytes[index+i] != data[i] { conflicts += 1 }
                }
                if covered < data.count { bytes.append(data.dropFirst(covered)) }
            }
            if !bytes.isEmpty { chunks.append(TCPChunk(id: chunks.count, offset: start, bytes: bytes)) }
            return TCPDirection(source: source, destination: source == session.endpointA ? session.endpointB : session.endpointA, chunks: chunks, overlapBytes: overlap, conflictingBytes: conflicts)
        }
    }
}
