import Foundation

public struct ProtocolInfo: Sendable {
    public let name: String
    public let summary: String
}

/// Packet-local decoding: never infers an encrypted application from its port.
enum ProtocolDecoder {
    static func decode(_ b: [UInt8], tcp: Bool) -> ProtocolInfo? {
        if tcp, let message = HTTP2Decoder.decode(b) { return ProtocolInfo(name: message.name, summary: message.summary) }
        if let message = RealtimeDecoder.decode(b, tcp: tcp) { return ProtocolInfo(name: message.name, summary: message.summary) }
        func word(_ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }
        func hex(_ bytes: ArraySlice<UInt8>) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
        if b.count >= 20, b[0] & 0xc0 == 0, Array(b[4..<8]) == [0x21, 0x12, 0xa4, 0x42] {
            let length = word(2)
            guard length % 4 == 0, length + 20 <= b.count else { return nil }
            let type = word(0)
            let method = (type & 15) | ((type & 0xe0) >> 1) | ((type & 0x3e00) >> 2)
            let kind = ((type >> 4) & 1) | ((type >> 7) & 2)
            var fields = ["\([1:"Binding",3:"Allocate",4:"Refresh",6:"Send",7:"Data",8:"CreatePermission",9:"ChannelBind"][method] ?? "Method \(method)") \(["request", "indication", "success", "error"][kind])", "transaction \(hex(b[8..<20]))"]
            var p = 20
            while p < 20 + length {
                guard p + 4 <= 20 + length else { return nil }
                let attribute = word(p), size = word(p + 2)
                p += 4
                guard p + size <= 20 + length else { return nil }
                if attribute == 0x20, size == 8, b[p + 1] == 1 {
                    let cookie: [UInt8] = [0x21, 0x12, 0xa4, 0x42]
                    let ip = (0..<4).map { String(b[p + 4 + $0] ^ cookie[$0]) }.joined(separator: ".")
                    fields.append("mapped \(ip):\(word(p + 2) ^ 0x2112)")
                }
                p += (size + 3) & ~3
                guard p <= 20 + length else { return nil }
            }
            return ProtocolInfo(name: "STUN", summary: fields.joined(separator: " · "))
        }
        // Heuristic UDP RTP v2; exclude the RTP/RTCP multiplexing reserved range.
        if !tcp, b.count >= 12, b[0] >> 6 == 2, !(64...95).contains(Int(b[1] & 127)) {
            var header = 12 + Int(b[0] & 15) * 4
            guard header <= b.count else { return nil }
            if b[0] & 16 != 0 {
                guard header + 4 <= b.count else { return nil }
                header += 4 + word(header + 2) * 4
                guard header <= b.count else { return nil }
            }
            let padding = b[0] & 32 != 0 ? Int(b.last!) : 0
            guard (b[0] & 32 == 0 || padding > 0), padding <= b.count - header else { return nil }
            let stamp = b[4..<8].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            return ProtocolInfo(name: "RTP", summary: "PT \(b[1] & 127) · sequence \(word(2)) · timestamp \(stamp) · SSRC \(hex(b[8..<12])) · \(b.count - header - padding) media bytes · heuristic")
        }
        if tcp {
            let text = String(decoding: b.prefix(16384), as: UTF8.self)
            if text.hasPrefix("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
                return ProtocolInfo(name: "HTTP", summary: "HTTP/2 connection preface")
            }
            if let end = text.range(of: "\r\n") {
                let line = String(text[..<end.lowerBound])
                let parts = line.split(separator: " ")
                let request = parts.count == 3 && ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"].contains(String(parts[0])) && ["HTTP/1.0", "HTTP/1.1"].contains(String(parts[2]))
                let response = parts.count >= 2 && ["HTTP/1.0", "HTTP/1.1"].contains(String(parts[0])) && parts[1].count == 3 && Int(parts[1]) != nil
                if request || response {
                    let headers = text.components(separatedBy: "\r\n\r\n")[0].components(separatedBy: "\r\n")
                    let host = headers.first { $0.lowercased().hasPrefix("host:") }
                    return ProtocolInfo(name: "HTTP", summary: line + (host.map { " · \($0)" } ?? ""))
                }
            }
            if b.count >= 5, (20...24).contains(b[0]), b[1] == 3, b[2] <= 3, word(3) <= 18432 {
                let size = word(3)
                let kind = [20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Encrypted application data", 24: "Heartbeat"][Int(b[0])]!
                var summary = "\(kind) · record version 3.\(b[2]) · \(size) bytes"
                if size + 5 > b.count { summary += " · incomplete record" }
                else if b[0] == 22, size >= 4 {
                    let handshake = [1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange", 20: "Finished"][Int(b[5])] ?? "Handshake \(b[5])"
                    summary = handshake + " · " + summary
                    if b[5] == 1 { summary += clientHello(Array(b[5..<(size + 5)])) }
                }
                return ProtocolInfo(name: "TLS", summary: summary)
            }
        } else if b.count >= 7, b[0] & 0xc0 == 0xc0 {
            let version = b[1..<5].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard version == 1 || version == 0x6b3343cf else { return nil }
            let dcidLength = Int(b[5])
            guard dcidLength <= 20, 6 + dcidLength < b.count else { return nil }
            let p = 6 + dcidLength, scidLength = Int(b[p])
            guard scidLength <= 20, p + 1 + scidLength < b.count else { return nil }
            let kind = Int((b[0] >> 4) & 3)
            let types = version == 1 ? ["Initial", "0-RTT", "Handshake", "Retry"] : ["Retry", "Initial", "0-RTT", "Handshake"]
            return ProtocolInfo(name: "QUIC", summary: "\(version == 1 ? "v1" : "v2") \(types[kind]) long header · DCID \(hex(b[6..<p])) · SCID \(hex(b[(p + 1)..<(p + 1 + scidLength)])) · encrypted payload")
        }
        return nil
    }

    private static func clientHello(_ b: [UInt8]) -> String {
        guard b.count >= 39 else { return "" }
        let length = Int(b[1]) << 16 | Int(b[2]) << 8 | Int(b[3])
        guard length + 4 <= b.count else { return " · incomplete ClientHello" }
        let end = length + 4
        func word(_ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }
        var p = 38
        let sessionLength = Int(b[p]); p += 1 + sessionLength
        guard p + 2 <= end else { return "" }
        let cipherLength = word(p); p += 2 + cipherLength
        guard p < end else { return "" }
        let compressionLength = Int(b[p]); p += 1 + compressionLength
        guard p + 2 <= end else { return "" }
        let extensionsEnd = p + 2 + word(p); p += 2
        guard extensionsEnd <= end else { return "" }
        var fields: [String] = []
        while p + 4 <= extensionsEnd {
            let type = word(p), size = word(p + 2); p += 4
            let next = p + size
            guard next <= extensionsEnd else { return "" }
            if type == 0, size >= 5, word(p) == size - 2, b[p + 2] == 0 {
                let count = word(p + 3)
                if p + 5 + count <= next {
                    fields.append("SNI " + String(decoding: b[(p + 5)..<(p + 5 + count)], as: UTF8.self))
                }
            } else if type == 16, size >= 3, word(p) == size - 2 {
                var q = p + 2
                var names: [String] = []
                while q < next {
                    let count = Int(b[q]); q += 1
                    guard count > 0, q + count <= next else { return "" }
                    names.append(String(decoding: b[q..<(q + count)], as: UTF8.self)); q += count
                }
                fields.append("ALPN " + names.joined(separator: ", "))
            }
            p = next
        }
        return fields.isEmpty ? "" : " · " + fields.joined(separator: " · ")
    }
}
