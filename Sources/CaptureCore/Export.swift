import Foundation

public extension Capture {
    /// Original packet bytes in capture order, including both directions of each selected session.
    func export(sessionIDs: Set<Int>, to url: URL) throws {
        let packets = sessions.filter { sessionIDs.contains($0.id) }.flatMap(\.packets).sorted { $0.id < $1.id }
        guard !packets.isEmpty else { throw CaptureError.read("Select at least one session to export.") }
        var data = Data()
        func append<T: FixedWidthInteger>(_ value: T) {
            var little = value.littleEndian
            withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
        }
        append(UInt32(0xa1b2c3d4)); append(UInt16(2)); append(UInt16(4))
        append(UInt32(0)); append(UInt32(0))
        append(UInt32(packets.map { $0.rawBytes.count }.max() ?? 65535))
        // DLT_RAW is 12 on macOS, whereas the portable savefile LINKTYPE_RAW is 101.
        append(UInt32(linkType == 12 ? 101 : linkType))
        for packet in packets {
            append(packet.seconds); append(packet.microseconds)
            append(UInt32(packet.rawBytes.count)); append(UInt32(packet.length))
            data.append(packet.rawBytes)
        }
        try data.write(to: url, options: .atomic)
    }
}
