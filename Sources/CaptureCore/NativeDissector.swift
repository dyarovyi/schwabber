import Foundation
import Darwin

public struct NativeField: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let label: String
    public let offset: Int
    public let length: Int
    public let kind: String
    public let isBits: Bool
    public let children: [NativeField]
    public var hasBytes: Bool { length > 0 }
    public var flattened: [NativeField] { [self] + children.flatMap(\.flattened) }
}
public struct NativeDissection: Sendable {
    public let layers: [NativeField]
    public let headerParts: [(String, Int)]
    public let payloadRange: Range<Int>
    public let payloadWireLength: Int
    public let trailerLength: Int
    public var headerLength: Int { headerParts.reduce(0) { $0 + $1.1 } }
    public var fields: [NativeField] { layers.flatMap(\.flattened) }
    public func field(at byte: Int) -> NativeField? {
        fields.filter { !$0.isBits && $0.length > 0 && byte >= $0.offset && byte < $0.offset + $0.length }
            .enumerated().min { a, b in a.element.length == b.element.length ? a.offset > b.offset : a.element.length < b.element.length }?.element
    }
}

/// Packet-local dissector patterned after windows/CaptureCore/Dissector.cs.
/// Fields always refer to the captured frame, never to reconstructed data.
public enum NativeDissector {
    public static func dissect(_ packet: Packet, linkType: Int32) -> NativeDissection {
        let r = FieldReader(Array(packet.rawBytes))
        let frame = r.layer("Frame", "Frame \(packet.id): \(packet.length) bytes on wire, \(r.b.count) bytes captured", 0, r.b.count, "frame")
        r.note(frame, "Arrival Time", String(format: "%.6f", packet.time))
        r.note(frame, "Summary", packet.details)
        var headers: [(String, Int)] = []
        var start = r.b.count, end = r.b.count, wirePayload = 0, trailer = 0
        do {
            var o = 0
            switch linkType {
            case 1:
                try r.check(0, 14)
                let eth = r.layer("Ethernet II", "Ethernet II", 0, 14)
                r.add(eth, "Destination", r.hex(0, 6, separator: ":"), 0, 6)
                r.add(eth, "Source", r.hex(6, 6, separator: ":"), 6, 6)
                r.number(eth, "Type", 12, 2, hex: true)
                headers.append(("Ethernet", 14)); o = 14
                var type = try r.u(12, 2)
                while [0x8100, 0x88a8, 0x9100].contains(type) {
                    try r.check(o, 4)
                    let vlan = r.layer("802.1Q", "802.1Q Virtual LAN", o, 4)
                    let tci = r.number(vlan, "Tag Control Information", o, 2, hex: true)
                    r.bits(tci, "Priority", o, 2, 0xe000); r.bits(tci, "DEI", o, 2, 0x1000); r.bits(tci, "ID", o, 2, 0xfff)
                    r.number(vlan, "Type", o + 2, 2, hex: true)
                    type = try r.u(o + 2, 2); headers.append(("802.1Q", 4)); o += 4
                }
            case 0, 108:
                try r.check(0, 4)
                let loop = r.layer("Loopback", "Null/Loopback", 0, 4)
                r.add(loop, "Family", r.hex(0, 4), 0, 4); headers.append(("Loopback", 4)); o = 4
            case 113, 276:
                o = linkType == 113 ? 16 : 20; try r.check(0, o)
                let layer = r.layer("Linux cooked", "Linux cooked capture \(linkType == 113 ? "v1" : "v2")", 0, o)
                if linkType == 113 {
                    r.number(layer, "Packet type", 0, 2); r.number(layer, "Address type", 2, 2)
                    r.number(layer, "Address length", 4, 2); r.add(layer, "Address", r.hex(6, 8), 6, 8); r.number(layer, "Protocol", 14, 2, hex: true)
                } else {
                    r.number(layer, "Protocol", 0, 2, hex: true); r.number(layer, "Reserved", 2, 2)
                    r.number(layer, "Interface index", 4, 4); r.number(layer, "Address type", 8, 2)
                    r.number(layer, "Packet type", 10, 1); r.number(layer, "Address length", 11, 1); r.add(layer, "Address", r.hex(12, 8), 12, 8)
                }
                headers.append(("Linux cooked", o))
            default: break
            }
            let version = try r.u(o, 1) >> 4
            var proto: Int, wireEnd: Int
            if version == 4 {
                try r.check(o, 20)
                let size = try (r.u(o, 1) & 15) * 4
                guard size >= 20 else { throw FieldError.invalid }
                let ip = r.layer("IPv4", "Internet Protocol Version 4", o, size)
                let vh = r.number(ip, "Version / Header Length", o, 1, hex: true)
                r.bits(vh, "Version", o, 1, 0xf0); r.bits(vh, "Header Length", o, 1, 15)
                r.number(ip, "Differentiated Services", o + 1, 1, hex: true)
                r.number(ip, "Total Length", o + 2, 2); r.number(ip, "Identification", o + 4, 2, hex: true)
                let flags = r.number(ip, "Flags / Fragment Offset", o + 6, 2, hex: true)
                r.bits(flags, "Don't fragment", o + 6, 2, 0x4000); r.bits(flags, "More fragments", o + 6, 2, 0x2000); r.bits(flags, "Fragment offset", o + 6, 2, 0x1fff)
                r.number(ip, "Time to Live", o + 8, 1); r.number(ip, "Protocol", o + 9, 1)
                r.number(ip, "Header Checksum (not verified)", o + 10, 2, hex: true)
                r.add(ip, "Source Address", r.address(o + 12, 4), o + 12, 4); r.add(ip, "Destination Address", r.address(o + 16, 4), o + 16, 4)
                if size > 20 { r.add(ip, "Options", r.hex(o + 20, size - 20), o + 20, size - 20) }
                proto = try r.u(o + 9, 1); wireEnd = try o + r.u(o + 2, 2)
                headers.append(("IPv4", size)); o += size
            } else if version == 6 {
                try r.check(o, 40)
                let ip = r.layer("IPv6", "Internet Protocol Version 6", o, 40)
                let head = r.number(ip, "Version / Traffic Class / Flow Label", o, 4, hex: true)
                r.bits(head, "Version", o, 4, 0xf0000000); r.bits(head, "Traffic class", o, 4, 0xff00000); r.bits(head, "Flow label", o, 4, 0xfffff)
                r.number(ip, "Payload Length", o + 4, 2); r.number(ip, "Next Header", o + 6, 1); r.number(ip, "Hop Limit", o + 7, 1)
                r.add(ip, "Source Address", r.address(o + 8, 16), o + 8, 16); r.add(ip, "Destination Address", r.address(o + 24, 16), o + 24, 16)
                proto = try r.u(o + 6, 1); wireEnd = try o + 40 + r.u(o + 4, 2)
                let ipStart = o; o += 40
                while [0, 43, 44, 51, 60].contains(proto) {
                    let size = try proto == 44 ? 8 : (r.u(o + 1, 1) + (proto == 51 ? 2 : 1)) * (proto == 51 ? 4 : 8)
                    try r.check(o, size)
                    ip.length += size
                    let ext = r.add(ip, "Extension \(proto)", "\(size) bytes", o, size)
                    r.number(ext, "Next Header", o, 1); r.add(ext, "Data", r.hex(o + 1, size - 1), o + 1, size - 1)
                    proto = try r.u(o, 1); o += size
                }
                headers.append(("IPv6", o - ipStart))
            } else { throw FieldError.invalid }
            end = min(wireEnd, r.b.count)
            guard o <= end else { throw FieldError.invalid }
            if proto == 6 {
                try r.check(o, 20)
                let size = try (r.u(o + 12, 1) >> 4) * 4
                guard size >= 20, o + size <= end else { throw FieldError.invalid }
                let tcp = r.layer("TCP", "Transmission Control Protocol", o, size)
                r.number(tcp, "Source Port", o, 2); r.number(tcp, "Destination Port", o + 2, 2)
                r.number(tcp, "Sequence Number (raw)", o + 4, 4); r.number(tcp, "Acknowledgment Number (raw)", o + 8, 4)
                r.add(tcp, "Header Length", "\(size) bytes", o + 12, 1)
                let flags = r.add(tcp, "Flags", packet.flags, o + 12, 2)
                for (mask, name) in [(1,"FIN"),(2,"SYN"),(4,"RST"),(8,"PSH"),(16,"ACK"),(32,"URG"),(64,"ECE"),(128,"CWR"),(256,"AE")] { r.bits(flags, name, o + 12, 2, mask) }
                r.number(tcp, "Window", o + 14, 2); r.number(tcp, "Checksum (not verified)", o + 16, 2, hex: true); r.number(tcp, "Urgent Pointer", o + 18, 2)
                if size > 20 { try options(r, tcp, o + 20, o + size) }
                headers.append(("TCP", size)); start = o + size; wirePayload = max(0, wireEnd - start)
            } else if proto == 17 {
                try r.check(o, 8)
                let udp = r.layer("UDP", "User Datagram Protocol", o, 8)
                r.number(udp, "Source Port", o, 2); r.number(udp, "Destination Port", o + 2, 2)
                r.number(udp, "Length", o + 4, 2); r.number(udp, "Checksum (not verified)", o + 6, 2, hex: true)
                let size = try r.u(o + 4, 2); guard size >= 8 else { throw FieldError.invalid }
                start = o + 8; end = min(end, o + size); wirePayload = max(0, min(wireEnd - start, size - 8))
                headers.append(("UDP", 8))
            } else if proto == 1 || proto == 58 {
                guard o + 8 <= end else { throw FieldError.invalid }
                let type = try r.u(o, 1), name = proto == 1 ? "ICMP" : "ICMPv6"
                let node = r.layer(name, ICMPDecoder.name(type, v6: proto == 58), o, 8)
                r.number(node, "Type", o, 1); r.number(node, "Code", o+1, 1); r.number(node, "Checksum (not verified)", o+2, 2, hex: true)
                if (proto == 1 && [0,8,13,14].contains(type)) || (proto == 58 && [128,129].contains(type)) {
                    r.number(node, "Identifier", o+4, 2); r.number(node, "Sequence Number", o+6, 2)
                } else if proto == 58 && type == 2 { r.number(node, "MTU", o+4, 4) }
                else if proto == 1 && type == 3 && r.b[o+1] == 4 { r.number(node, "Unused", o+4, 2); r.number(node, "Next-hop MTU", o+6, 2) }
                else { r.number(node, "Message-specific Data", o+4, 4, hex: true) }
                start = o+8; wirePayload = max(0, wireEnd-start); headers.append((name,8))
            } else { start = o; wirePayload = max(0, wireEnd - o) }
            if end > start { try application(r, packet, start, end, proto == 6) }
            trailer = max(0, r.b.count - min(wireEnd, r.b.count))
            if trailer > 0 { let node = r.layer("Trailer", "Trailer / padding (\(trailer) bytes)", r.b.count - trailer, trailer); r.add(node, "Data", r.hex(r.b.count - trailer, trailer), r.b.count - trailer, trailer) }
        } catch { r.note(r.roots.last ?? frame, "Truncated / malformed", "Some fields extend beyond the available packet") }
        start = min(max(start, 0), r.b.count); end = min(max(end, start), r.b.count)
        return NativeDissection(layers: r.freeze(), headerParts: headers, payloadRange: start..<end, payloadWireLength: wirePayload, trailerLength: trailer)
    }
    private static func options(_ r: FieldReader, _ tcp: FieldNode, _ start: Int, _ end: Int) throws {
        let options = r.add(tcp, "Options", "\(end - start) bytes", start, end - start)
        var p = start
        while p < end {
            let kind = try r.u(p, 1)
            if kind <= 1 { r.add(options, kind == 0 ? "End of Option List" : "No-Operation", "", p, 1); p += 1; if kind == 0 { if p < end { r.add(options, "Padding", "", p, end - p) }; break }; continue }
            let size = try r.u(p + 1, 1); guard size >= 2, p + size <= end else { throw FieldError.invalid }
            let node = r.add(options, [2:"Maximum segment size",3:"Window scale",4:"SACK permitted",5:"SACK",8:"Timestamps",30:"Multipath TCP",34:"TCP Fast Open Cookie"][kind] ?? "Option \(kind)", "", p, size)
            r.number(node, "Kind", p, 1); r.number(node, "Length", p + 1, 1)
            if kind == 2 && size == 4 { r.number(node, "MSS Value", p + 2, 2) }
            else if kind == 3 && size == 3 { r.number(node, "Shift count", p + 2, 1) }
            else if kind == 8 && size == 10 { r.number(node, "Timestamp value", p + 2, 4); r.number(node, "Timestamp echo reply", p + 6, 4) }
            else if kind == 5 { for q in stride(from: p + 2, to: p + size - 7, by: 8) { r.number(node, "Left edge", q, 4); r.number(node, "Right edge", q + 4, 4) } }
            else if size > 2 { r.add(node, "Data", r.hex(p + 2, size - 2), p + 2, size - 2) }
            p += size
        }
    }
    private static func application(_ r: FieldReader, _ packet: Packet, _ s: Int, _ end: Int, _ tcp: Bool) throws {
        let name = !packet.dns.isEmpty ? "DNS" : packet.application?.name ?? "Data"
        let node = r.layer(name, packet.application?.summary ?? (packet.dns.first?.summary ?? "Data (\(end - s) bytes)"), s, end - s, "payload")
        switch name {
        case "RTCP", "SIP", "DTLS", "TURN":
            if let message = RealtimeDecoder.decode(Array(r.b[s..<end]), tcp: tcp) {
                for field in message.fields { r.add(node, field.name, field.value, s + field.offset, field.length) }
            }
        case "HTTP/2":
            if let message = HTTP2Decoder.decode(Array(r.b[s..<end])) {
                for field in message.fields { r.add(node, field.name, field.value, s+field.offset, field.length) }
            }
        case "HTTP":
            var p = s, first = true
            while p < end {
                guard let q = (p..<max(p, end - 1)).first(where: { r.b[$0] == 13 && r.b[$0 + 1] == 10 }) else { r.add(node, "File Data", r.text(p, end - p), p, end - p); break }
                if q == p { r.add(node, "End of headers", "", p, 2); p += 2; if p < end { r.add(node, "File Data", "\(end - p) bytes", p, end - p) }; break }
                let line = r.add(node, first ? "Start line" : "Header", r.text(p, q - p), p, q + 2 - p)
                if first {
                    let response = r.text(p, q - p).hasPrefix("HTTP/")
                    let names = response ? ["Response Version","Status Code","Response Phrase"] : ["Request Method","Request URI","Request Version"]
                    var cursor = p
                    for i in 0..<3 where cursor < q {
                        let stop = i == 2 ? q : (cursor..<q).first(where: { r.b[$0] == 32 }) ?? q
                        r.add(line, names[i], r.text(cursor, stop - cursor), cursor, stop - cursor); cursor = stop + 1
                    }
                } else if let colon = (p..<q).first(where: { r.b[$0] == 58 }) {
                    r.add(line, "Header Name", r.text(p, colon - p), p, colon - p)
                    r.add(line, "Header Value", r.text(colon + 1, q - colon - 1), colon + 1, q - colon - 1)
                }
                first = false; p = q + 2
            }
        case "DNS": try dns(r, node, s + (tcp ? 2 : 0), end)
        case "RTP":
            let flags = r.number(node, "Flags", s, 1, hex: true)
            for (mask, label) in [(192,"Version"),(32,"Padding"),(16,"Extension"),(15,"CSRC count")] { r.bits(flags, label, s, 1, mask) }
            let type = r.number(node, "Marker / Payload Type", s + 1, 1, hex: true)
            r.bits(type, "Marker", s + 1, 1, 128); r.bits(type, "Payload Type", s + 1, 1, 127)
            r.number(node, "Sequence Number", s + 2, 2); r.number(node, "Timestamp", s + 4, 4); r.number(node, "SSRC", s + 8, 4, hex: true)
            var p = s + 12
            for _ in 0..<(try r.u(s, 1) & 15) { r.number(node, "CSRC", p, 4, hex: true); p += 4 }
            if try r.u(s, 1) & 16 != 0 {
                let size = try r.u(p + 2, 2) * 4
                guard p + 4 + size <= end else { throw FieldError.invalid }
                r.number(node, "Extension Profile", p, 2, hex: true); r.number(node, "Extension Length (words)", p + 2, 2)
                r.add(node, "Extension Data", r.hex(p + 4, size), p + 4, size); p += 4 + size
            }
            let padding = try r.u(s, 1) & 32 != 0 ? r.u(end - 1, 1) : 0
            guard padding <= end - p else { throw FieldError.invalid }
            r.add(node, "Media Payload", r.hex(p, end - p - padding), p, end - p - padding)
            if padding > 0 { r.add(node, "Padding", "\(padding) bytes", end - padding, padding) }
        case "STUN":
            guard s + 20 <= end else { throw FieldError.invalid }
            r.number(node, "Message Type", s, 2, hex: true); r.number(node, "Message Length", s + 2, 2)
            r.number(node, "Magic Cookie", s + 4, 4, hex: true); r.add(node, "Transaction ID", r.hex(s + 8, 12), s + 8, 12)
            let end = min(end, s + 20 + (try r.u(s + 2, 2)))
            var p = s + 20
            while p + 4 <= end {
                let type = try r.u(p, 2), size = try r.u(p + 2, 2)
                guard p + 4 + size <= end else { throw FieldError.invalid }
                let a = r.add(node, [1:"MAPPED-ADDRESS",0x20:"XOR-MAPPED-ADDRESS",0x12:"XOR-PEER-ADDRESS",0x16:"XOR-RELAYED-ADDRESS",6:"USERNAME",9:"ERROR-CODE",0x14:"REALM",0x15:"NONCE",0x8022:"SOFTWARE"][type] ?? "Attribute \(type)", "\(size) bytes", p, 4 + size)
                r.number(a, "Type", p, 2, hex: true); r.number(a, "Length", p + 2, 2)
                let v = p + 4
                if [1,0x8023,0x20,0x12,0x16].contains(type) && size >= 8 {
                    let xor = [0x20,0x12,0x16].contains(type), family = try r.u(v + 1, 1)
                    let port = try r.u(v + 2, 2) ^ (xor ? 0x2112 : 0)
                    r.number(a, "Reserved", v, 1); r.number(a, "Family", v + 1, 1)
                    r.add(a, xor ? "X-Port" : "Port", String(port), v + 2, 2)
                    let count = family == 2 ? 16 : 4
                    if size >= count + 4 {
                        let decoded = (0..<count).map { r.b[v + 4 + $0] ^ (xor ? r.b[s + 4 + $0] : 0) }
                        let address = count == 4 ? decoded.map(String.init).joined(separator: ".") : stride(from: 0, to: 16, by: 2).map { String(Int(decoded[$0]) << 8 | Int(decoded[$0 + 1]), radix: 16) }.joined(separator: ":")
                        r.add(a, xor ? "X-Address" : "Address", address, v + 4, count)
                        a.label += ": \(address):\(port)"
                    }
                } else if [6,0x14,0x15,0x8022].contains(type) {
                    r.add(a, [6:"Username",0x14:"Realm",0x15:"Nonce",0x8022:"Software"][type]!, r.text(v, size), v, size)
                } else if type == 9 && size >= 4 {
                    r.number(a, "Reserved", v, 2); r.add(a, "Error Class", String(try r.u(v + 2, 1) & 7), v + 2, 1)
                    r.number(a, "Error Number", v + 3, 1); r.add(a, "Error Reason Phrase", r.text(v + 4, size - 4), v + 4, size - 4)
                } else if [0x24,0x0d].contains(type) && size == 4 {
                    r.number(a, type == 0x24 ? "Priority" : "Lifetime (seconds)", v, 4)
                } else { r.add(a, [8:"HMAC-SHA1",0x8028:"CRC-32",0x8029:"Tie breaker",0x802a:"Tie breaker"][type] ?? "Value", r.hex(v, size), v, size) }
                let next = p + 4 + ((size + 3) & ~3)
                if next <= end && next > p + 4 + size { r.add(node, "Padding", "", p + 4 + size, next - p - 4 - size) }
                p = next
            }
        case "TLS": try tls(r, node, s, end)
        case "QUIC":
            r.number(node, "Header Form / Flags", s, 1, hex: true); r.number(node, "Version", s + 1, 4, hex: true)
            let dcid = try r.u(s + 5, 1); guard s + 6 + dcid < end else { throw FieldError.invalid }
            r.number(node, "Destination Connection ID Length", s + 5, 1); r.add(node, "Destination Connection ID", r.hex(s + 6, dcid), s + 6, dcid)
            var p = s + 6 + dcid; let scid = try r.u(p, 1); guard p + 1 + scid <= end else { throw FieldError.invalid }
            r.number(node, "Source Connection ID Length", p, 1); r.add(node, "Source Connection ID", r.hex(p + 1, scid), p + 1, scid); p += 1 + scid
            let version = try r.u(s + 1, 4), kind = try (r.u(s, 1) >> 4) & 3
            let initial = (version == 1 && kind == 0) || (version != 1 && kind == 1)
            let retry = (version == 1 && kind == 3) || (version != 1 && kind == 0)
            func varint(_ label: String) throws -> Int {
                let size = 1 << (try r.u(p, 1) >> 6); guard p + size <= end else { throw FieldError.invalid }
                var value = try r.u(p, 1) & 63
                if size > 1 { for q in (p + 1)..<(p + size) { value = (value << 8) | Int(r.b[q]) } }
                r.add(node, label, String(value), p, size); p += size; return value
            }
            if !retry {
                if initial { let size = try varint("Token Length"); guard size <= end - p else { throw FieldError.invalid }; if size > 0 { r.add(node, "Token", r.hex(p, size), p, size); p += size } }
                _ = try varint("Length")
            }
            if p < end { r.add(node, retry ? "Retry Token / Integrity Tag" : "Protected Packet Number and Payload", "encrypted", p, end - p) }
        default: r.add(node, "Data", r.hex(s, end - s), s, end - s)
        }
    }
    private static func dns(_ r: FieldReader, _ node: FieldNode, _ s: Int, _ end: Int) throws {
        guard s + 12 <= end else { throw FieldError.invalid }
        r.number(node, "Transaction ID", s, 2, hex: true)
        let flags = r.number(node, "Flags", s + 2, 2, hex: true)
        for (mask, name) in [(0x8000,"Response"),(0x7800,"Opcode"),(0x400,"Authoritative"),(0x200,"Truncated"),(0x100,"Recursion desired"),(0x80,"Recursion available"),(15,"Response code")] { r.bits(flags, name, s + 2, 2, mask) }
        let counts = try [r.u(s + 4, 2),r.u(s + 6, 2),r.u(s + 8, 2),r.u(s + 10, 2)]
        for i in 0..<4 { r.number(node, ["Questions","Answer RRs","Authority RRs","Additional RRs"][i], s + 4 + i * 2, 2) }
        func domain(_ cursor: inout Int) throws -> String {
            var p = cursor, jumped = false, seen = Set<Int>(), labels: [String] = []
            while p < end && seen.insert(p).inserted {
                let size = Int(r.b[p]); if size & 0xc0 == 0xc0 {
                    guard p + 1 < end else { throw FieldError.invalid }
                    let target = s + ((size & 63) << 8) + Int(r.b[p + 1]); guard target < p else { throw FieldError.invalid }
                    if !jumped { cursor = p + 2 }; jumped = true; p = target
                } else {
                    guard size <= 63, p + size + 1 <= end else { throw FieldError.invalid }; p += 1
                    if size == 0 { if !jumped { cursor = p }; return labels.joined(separator: ".") }
                    labels.append(r.text(p, size)); p += size
                }
            }; throw FieldError.invalid
        }
        var p = s + 12
        for section in 0..<4 where counts[section] > 0 {
            let group = r.add(node, ["Queries","Answers","Authoritative nameservers","Additional records"][section], "", p, 0)
            for _ in 0..<counts[section] {
                let begin = p, name = try domain(&p), nameEnd = p
                guard p + (section == 0 ? 4 : 10) <= end else { throw FieldError.invalid }
                let type = try r.u(p, 2)
                let record = r.add(group, name, "type \(type)", begin, 0)
                r.add(record, "Name", name, begin, nameEnd - begin); r.number(record, "Type", p, 2); r.number(record, "Class", p + 2, 2); p += 4
                if section > 0 {
                    r.number(record, "Time to live", p, 4); r.number(record, "Data length", p + 4, 2)
                    let size = try r.u(p + 4, 2); p += 6; guard p + size <= end else { throw FieldError.invalid }
                    if type == 1 && size == 4 || type == 28 && size == 16 { r.add(record, "Address", r.address(p, size), p, size) }
                    else if [2,5,12].contains(type) { var q = p; let text = try domain(&q); guard q <= p + size else { throw FieldError.invalid }; r.add(record, "Domain name", text, p, size) }
                    else if type == 15 && size >= 3 {
                        r.number(record, "Preference", p, 2)
                        var q = p + 2; let name = try domain(&q); guard q <= p + size else { throw FieldError.invalid }
                        r.add(record, "Mail Exchange", name, p + 2, size - 2)
                    } else if type == 16 {
                        var q = p
                        while q < p + size {
                            let count = try r.u(q, 1); guard q + 1 + count <= p + size else { throw FieldError.invalid }
                            r.number(record, "TXT Length", q, 1); r.add(record, "TXT", r.text(q + 1, count), q + 1, count); q += count + 1
                        }
                    } else { r.add(record, "Data", r.hex(p, size), p, size) }; p += size
                }
                record.length = p - begin
            }; group.length = p - group.offset
        }
    }
    private static func tls(_ r: FieldReader, _ root: FieldNode, _ s: Int, _ end: Int) throws {
        var p = s
        while p + 5 <= end {
            let size = try r.u(p + 3, 2), stop = min(end, p + 5 + size), type = try r.u(p, 1)
            let record = r.add(root, "Record", [20:"Change Cipher Spec",21:"Alert",22:"Handshake",23:"Encrypted Application Data"][type] ?? "TLS", p, stop - p)
            r.number(record, "Content Type", p, 1); r.number(record, "Legacy record version", p + 1, 2, hex: true); r.number(record, "Length", p + 3, 2)
            if stop < p + 5 + size { r.note(record, "Partial record", "continues in another segment") }
            var q = p + 5
            if type == 22 {
                while q + 4 <= stop {
                    let hsType = try r.u(q, 1), hsSize = try r.u(q + 1, 3)
                    guard hsSize <= stop - q - 4 else { break }
                    let hs = r.add(record, "Handshake", hsType == 1 ? "Client Hello" : hsType == 2 ? "Server Hello" : String(hsType), q, 4 + hsSize)
                    r.number(hs, "Handshake Type", q, 1); r.number(hs, "Length", q + 1, 3)
                    if hsType == 1 || hsType == 2 { try hello(r, hs, q + 4, q + 4 + hsSize, hsType == 1) }
                    else { r.add(hs, "Handshake data", r.hex(q + 4, hsSize), q + 4, hsSize) }; q += 4 + hsSize
                }
            }
            if type == 21 && size == 2 && q + 2 <= stop {
                r.number(record, "Alert Level", q, 1); r.number(record, "Alert Description", q + 1, 1); q += 2
            }
            if q < stop { r.add(record, type == 23 ? "Encrypted Application Data" : "Record data", r.hex(q, stop - q), q, stop - q) }
            p = stop
        }
        if p < end { r.add(root, "TLS segment data", r.hex(p, end - p), p, end - p) }
    }
    private static func hello(_ r: FieldReader, _ hs: FieldNode, _ s: Int, _ end: Int, _ client: Bool) throws {
        guard s + 35 <= end else { throw FieldError.invalid }
        r.number(hs, "Version", s, 2, hex: true); r.add(hs, "Random", r.hex(s + 2, 32), s + 2, 32)
        var p = s + 34
        let sid = try r.u(p, 1); r.number(hs, "Session ID Length", p, 1); p += 1
        guard p + sid <= end else { throw FieldError.invalid }; r.add(hs, "Session ID", r.hex(p, sid), p, sid); p += sid
        func cipher(_ parent: FieldNode, _ at: Int) throws {
            let value = try r.u(at, 2)
            r.add(parent, "Cipher Suite", ([0x1301:"TLS_AES_128_GCM_SHA256",0x1302:"TLS_AES_256_GCM_SHA384",0x1303:"TLS_CHACHA20_POLY1305_SHA256",0xc02b:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",0xc02c:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",0xc02f:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",0xc030:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",0xcca8:"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",0xcca9:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",0xc013:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",0xc014:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",0xc009:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",0xc00a:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",0x009c:"TLS_RSA_WITH_AES_128_GCM_SHA256",0x009d:"TLS_RSA_WITH_AES_256_GCM_SHA384",0x002f:"TLS_RSA_WITH_AES_128_CBC_SHA",0x0035:"TLS_RSA_WITH_AES_256_CBC_SHA",0x000a:"TLS_RSA_WITH_3DES_EDE_CBC_SHA",0x00ff:"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"][value] ?? "Unknown") + String(format: " (0x%04x)", value), at, 2)
        }
        if client {
            guard p + 2 <= end else { throw FieldError.invalid }; let size = try r.u(p, 2); r.number(hs, "Cipher Suites Length", p, 2); p += 2
            guard p + size <= end else { throw FieldError.invalid }; let suites = r.add(hs, "Cipher Suites", "", p, size)
            for q in stride(from: p, to: p + size - 1, by: 2) { try cipher(suites, q) }; p += size
            guard p < end else { throw FieldError.invalid }; let size2 = try r.u(p, 1); r.number(hs, "Compression Methods Length", p, 1); p += 1
            guard p + size2 <= end else { throw FieldError.invalid }; r.add(hs, "Compression Methods", r.hex(p, size2), p, size2); p += size2
        } else {
            guard p + 3 <= end else { throw FieldError.invalid }; try cipher(hs, p); r.number(hs, "Compression Method", p + 2, 1); p += 3
        }
        guard p + 2 <= end else { return }; let length = try r.u(p, 2); r.number(hs, "Extensions Length", p, 2); p += 2
        let limit = min(end, p + length)
        while p + 4 <= limit {
            let type = try r.u(p, 2), size = try r.u(p + 2, 2), d = p + 4
            guard d + size <= limit else { throw FieldError.invalid }
            let ext = r.add(hs, "Extension \(type)", [0:"server_name",1:"max_fragment_length",5:"status_request",10:"supported_groups",11:"ec_point_formats",13:"signature_algorithms",16:"application_layer_protocol_negotiation",18:"signed_certificate_timestamp",21:"padding",22:"encrypt_then_mac",23:"extended_master_secret",27:"compress_certificate",28:"record_size_limit",35:"session_ticket",41:"pre_shared_key",42:"early_data",43:"supported_versions",45:"psk_key_exchange_modes",49:"post_handshake_auth",50:"signature_algorithms_cert",51:"key_share",57:"quic_transport_parameters",17513:"application_settings",17613:"application_settings",65037:"encrypted_client_hello",65281:"renegotiation_info"][type] ?? "\(size) bytes", p, 4 + size)
            r.number(ext, "Type", p, 2); r.number(ext, "Length", p + 2, 2)
            if type == 0 && size >= 5 {
                r.number(ext, "Server Name list length", d, 2); var q = d + 2
                while q + 3 <= d + size { let count = try r.u(q + 1, 2); guard q + 3 + count <= d + size else { throw FieldError.invalid }; r.number(ext, "Server Name Type", q, 1); r.number(ext, "Server Name length", q + 1, 2); r.add(ext, "Server Name", r.text(q + 3, count), q + 3, count); q += 3 + count }
            } else if type == 16 && size >= 3 {
                r.number(ext, "ALPN Extension Length", d, 2); var q = d + 2
                while q < d + size { let count = try r.u(q, 1); guard count > 0, q + 1 + count <= d + size else { throw FieldError.invalid }; r.number(ext, "ALPN string length", q, 1); r.add(ext, "ALPN Next Protocol", r.text(q + 1, count), q + 1, count); q += 1 + count }
            } else if type == 43 {
                let start = client ? d + 1 : d
                if client && size > 0 { r.number(ext, "Supported Versions length", d, 1) }
                for q in stride(from: start, to: d + size - 1, by: 2) {
                    let version = try r.u(q, 2)
                    let name = [0x0300:"SSL 3.0",0x0301:"TLS 1.0",0x0302:"TLS 1.1",0x0303:"TLS 1.2",0x0304:"TLS 1.3"][version] ?? "Unknown"
                    r.add(ext, "Supported Version", name + String(format: " (0x%04x)", version), q, 2)
                }
            } else if type == 10 && size >= 2 {
                r.number(ext, "Supported Groups List Length", d, 2)
                for q in stride(from: d + 2, to: d + size - 1, by: 2) {
                    let group = try r.u(q, 2)
                    let name = [0x17:"secp256r1",0x18:"secp384r1",0x19:"secp521r1",0x1d:"x25519",0x1e:"x448",0x100:"ffdhe2048",0x101:"ffdhe3072",0x11ec:"X25519MLKEM768",0x6399:"X25519Kyber768Draft00"][group] ?? "Unknown"
                    r.add(ext, "Supported Group", name + String(format: " (0x%04x)", group), q, 2)
                }
            } else if size > 0 { r.add(ext, "Data", r.hex(d, size), d, size) }
            p = d + size
        }
    }
}

private enum FieldError: Error { case invalid }
private final class FieldNode {
    var name: String, label: String, kind: String
    let offset: Int
    var length: Int
    var bits = false
    var children: [FieldNode] = []
    init(_ name: String, _ label: String, _ offset: Int, _ length: Int, _ kind: String) { self.name = name; self.label = label; self.offset = offset; self.length = length; self.kind = kind }
}
private final class FieldReader {
    let b: [UInt8]
    var roots: [FieldNode] = []
    init(_ bytes: [UInt8]) { b = bytes }
    func check(_ at: Int, _ size: Int) throws { guard at >= 0, size >= 0, at <= b.count, size <= b.count - at else { throw FieldError.invalid } }
    func u(_ at: Int, _ size: Int) throws -> Int { try check(at, size); return b[at..<(at + size)].reduce(0) { ($0 << 8) | Int($1) } }
    func hex(_ at: Int, _ size: Int, separator: String = "") -> String { guard (try? check(at, size)) != nil else { return "[truncated]" }; return b[at..<min(at + size, at + 64)].map { String(format: "%02x", $0) }.joined(separator: separator) + (size > 64 ? "…" : "") }
    func text(_ at: Int, _ size: Int) -> String { guard (try? check(at, size)) != nil else { return "[truncated]" }; return String(decoding: b[at..<(at + size)], as: UTF8.self) }
    func address(_ at: Int, _ size: Int) -> String {
        guard (try? check(at, size)) != nil else { return "[truncated]" }
        if size == 4 { return b[at..<(at + 4)].map(String.init).joined(separator: ".") }
        var bytes = Array(b[at..<(at + 16)]), output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = bytes.withUnsafeBytes { inet_ntop(AF_INET6, $0.baseAddress, &output, socklen_t(output.count)) }
        return String(decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    @discardableResult func layer(_ name: String, _ label: String, _ at: Int, _ size: Int, _ kind: String = "header") -> FieldNode { let n = FieldNode(name, label, at, size, kind); roots.append(n); return n }
    @discardableResult func add(_ parent: FieldNode, _ name: String, _ value: String, _ at: Int, _ size: Int) -> FieldNode { let n = FieldNode(name, value.isEmpty ? name : "\(name): \(value)", at, size, parent.kind); parent.children.append(n); return n }
    @discardableResult func number(_ parent: FieldNode, _ name: String, _ at: Int, _ size: Int, hex: Bool = false) -> FieldNode { let value = try? u(at, size); return add(parent, name, value.map { hex ? String(format: "0x%0*lx", size * 2, $0) : String($0) } ?? "[truncated]", at, size) }
    func note(_ parent: FieldNode, _ name: String, _ value: String) { add(parent, name, value, 0, 0) }
    func bits(_ parent: FieldNode, _ name: String, _ at: Int, _ size: Int, _ mask: Int) {
        let value = (try? u(at, size)) ?? 0
        let pattern = (0..<(size * 8)).reversed().map { bit -> String in mask & (1 << bit) == 0 ? "." : value & (1 << bit) == 0 ? "0" : "1" }.joined()
        let n = add(parent, name, pattern + " = \((value & mask) >> mask.trailingZeroBitCount)", at, size); n.bits = true
    }
    func freeze() -> [NativeField] {
        func convert(_ nodes: [FieldNode], _ path: String, _ parentRange: Range<Int>) -> [NativeField] {
            var counts: [String: Int] = [:]
            return nodes.map { n in
                let number = counts[n.name, default: 0]; counts[n.name] = number + 1
                let id = path + (path.isEmpty ? "" : " › ") + n.name + (number == 0 ? "" : " [\(number + 1)]")
                let lo = max(parentRange.lowerBound, min(n.offset, parentRange.upperBound))
                let hi = max(lo, min(parentRange.upperBound, n.offset + max(0, n.length)))
                let range = lo..<hi
                return NativeField(id: id, name: n.name, label: n.label, offset: lo, length: range.count, kind: n.kind, isBits: n.bits, children: convert(n.children, id, n.length == 0 ? parentRange : range))
            }
        }
        return convert(roots, "", 0..<b.count)
    }
}
