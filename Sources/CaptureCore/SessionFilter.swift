import Foundation

/// Compile once per filter change, then search packet payloads without copying them.
public struct SessionFilter: Sendable {
    private let text: String
    private let pattern: Data?
    private let hex: Bool
    public let invalidHex: Bool
    public init(_ query: String) {
        text = query
        let bytes = Array(query.utf8)
        func digit(_ b: UInt8) -> UInt8? {
            switch b { case 48...57: return b-48; case 65...70: return b-55; case 97...102: return b-87; default: return nil }
        }
        hex = bytes.count >= 3 && (bytes[0] == 120 || bytes[0] == 88) && digit(bytes[1]) != nil && digit(bytes[2]) != nil
        if hex {
            var decoded: [UInt8] = []; var valid = bytes.count % 3 == 0
            if valid {
                for i in stride(from: 0, to: bytes.count, by: 3) {
                    guard bytes[i] == 120 || bytes[i] == 88, let a = digit(bytes[i+1]), let b = digit(bytes[i+2]) else { valid = false; break }
                    decoded.append(a*16+b)
                }
            }
            invalidHex = !valid; pattern = valid ? Data(decoded) : nil
        } else { invalidHex = false; pattern = query.isEmpty ? nil : Data(query.utf8) }
    }
    public func matches(_ session: Session) -> Bool {
        if text.isEmpty { return true }
        if invalidHex { return false }
        if !hex && session.matches(text) { return true }
        guard let pattern, !pattern.isEmpty else { return false }
        return session.packets.contains { packet in
            packet.rawBytes.range(of: pattern, in: packet.payloadRange) != nil
        }
    }
}
