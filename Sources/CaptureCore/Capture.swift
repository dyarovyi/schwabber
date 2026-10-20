import Foundation
import CPcap

public struct Packet: Identifiable, Sendable {
    public let id: Int
    public let time: Double
    public let source: String
    public let destination: String
    public let length: Int
    public let flags: String
    public let dns: [DNSMessage]
    public let application: ProtocolInfo?
    public let rawBytes: Data
    public let payloadRange: Range<Int>
    public var payload: Data { rawBytes.subdata(in: payloadRange) }
    public let seconds: UInt32
    public let microseconds: UInt32
    public var details: String { [flags, application.map { "\($0.name): \($0.summary)" } ?? "", dns.map(\.summary).joined(separator: " | ")].filter { !$0.isEmpty }.joined(separator: " · ") }
}
public struct Session: Identifiable, Sendable {
    public let id: Int
    public let transport: String
    public let endpointA: String
    public let endpointB: String
    public private(set) var packets: [Packet]
    public private(set) var bytes: Int = 0
    public private(set) var hasDNS = false
    public private(set) var applicationProtocols: [String] = []
    public private(set) var summary = ""
    public init(id: Int, transport: String, endpointA: String, endpointB: String, packets: [Packet]) {
        self.id = id; self.transport = transport; self.endpointA = endpointA; self.endpointB = endpointB
        self.packets = packets
        for packet in packets { includeMetadata(packet) }
    }
    private mutating func includeMetadata(_ packet: Packet) {
        bytes += packet.length
        hasDNS = hasDNS || !packet.dns.isEmpty
        if let name = packet.application?.name, !applicationProtocols.contains(name) { applicationProtocols.append(name); applicationProtocols.sort() }
        if !packet.dns.isEmpty && !applicationProtocols.contains("DNS") { applicationProtocols.append("DNS"); applicationProtocols.sort() }
        if summary.isEmpty && (packet.application != nil || !packet.dns.isEmpty || transport.hasPrefix("ICMP")) { summary = packet.details }
    }
    mutating func append(_ packet: Packet) { packets.append(packet); includeMetadata(packet) }
    public var start: Double { packets.first!.time }
    public var end: Double { packets.last!.time }
    public var protocolLabel: String { (applicationProtocols + [transport]).joined(separator: " / ") }
    public var searchText: String { "\(endpointA) \(endpointB) " + packets.map(\.details).joined(separator: " ") }
    public func matches(_ query: String) -> Bool {
        endpointA.localizedCaseInsensitiveContains(query) || endpointB.localizedCaseInsensitiveContains(query) ||
        packets.contains { $0.details.localizedCaseInsensitiveContains(query) }
    }
    public var dnsSummary: String { packets.lazy.flatMap(\.dns).first?.questions.joined(separator: ", ") ?? "" }

}
public struct Capture: Sendable {
    public var sessions: [Session]
    public let sourceURL: URL
    public let linkType: Int32
    public let totalBytes: Int
    public let totalPackets: Int
    public let skippedPackets: Int
    public var start: Double { sessions.map(\.start).min() ?? 0 }
    public var end: Double { sessions.map(\.end).max() ?? start }
}
public enum CaptureError: Error, LocalizedError {
    case read(String)
    public var errorDescription: String? { if case .read(let message) = self { return message }; return nil }
}

public enum CaptureReader {
    public static func read(url: URL) throws -> Capture {
        var error = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let handle = pcap_open_offline(url.path, &error) else {
            throw CaptureError.read(String(decoding: error.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
        }
        defer { pcap_close(handle) }
        let link = pcap_datalink(handle)
        guard [1, 0, 108, 12, 101, 113, 276].contains(link) else {
            throw CaptureError.read("Unsupported capture link type: \(link). Try an Ethernet, loopback, raw IP or Linux cooked capture.")
        }
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var data: UnsafePointer<UInt8>?
        var decoded: [(String, String, String, Packet)] = []
        var total = 0
        var totalBytes = 0
        while true {
            let result = pcap_next_ex(handle, &header, &data)
            if result == -2 { break }
            if result == -1 { throw CaptureError.read(String(cString: pcap_geterr(handle))) }
            guard result == 1, let header, let data else { continue }
            total += 1
            let h = header.pointee
            totalBytes += Int(h.len)
            let bytes = Array(UnsafeBufferPointer(start: data, count: Int(h.caplen)))
            if let p = decode(bytes, link: Int(link)) {
                let time = Double(h.ts.tv_sec) + Double(h.ts.tv_usec) / 1_000_000
                decoded.append((p.0, p.1, p.2, Packet(id: total, time: time, source: p.1, destination: p.2, length: Int(h.len), flags: p.3, dns: p.4, application: p.5, rawBytes: Data(bytes), payloadRange: p.6, seconds: UInt32(clamping: h.ts.tv_sec), microseconds: UInt32(clamping: h.ts.tv_usec))))
            }
        }
        decoded.sort { $0.3.time == $1.3.time ? $0.3.id < $1.3.id : $0.3.time < $1.3.time }
        var sessions: [Session] = []
        var active: [String: Int] = [:]
        for (transport, source, destination, packet) in decoded {
            let endpoints = [source, destination].sorted()
            let key = "\(transport)|\(endpoints[0])|\(endpoints[1])"
            if let index = active[key], packet.time - sessions[index].end <= 60 {
                sessions[index].append(packet)
            } else {
                active[key] = sessions.count
                sessions.append(Session(id: sessions.count, transport: transport, endpointA: source, endpointB: destination, packets: [packet]))
            }
        }
        return Capture(sessions: sessions, sourceURL: url, linkType: link, totalBytes: totalBytes, totalPackets: total, skippedPackets: total - decoded.count)
    }

    // Bounds checks also reject truncated headers and non-initial fragments.
    static func decode(_ b: [UInt8], link: Int) -> (String, String, String, String, [DNSMessage], ProtocolInfo?, Range<Int>)? {
        func u16(_ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }
        var offset: Int
        switch link {
        case 1:
            guard b.count >= 14 else { return nil }
            offset = 14
            var type = u16(12)
            while [0x8100, 0x88a8, 0x9100].contains(type) {
                guard b.count >= offset + 4 else { return nil }
                type = u16(offset + 2); offset += 4
            }
            guard [0x0800, 0x86dd].contains(type) else { return nil }
        case 0, 108: offset = 4
        case 113:
            guard b.count >= 16, [0x0800, 0x86dd].contains(u16(14)) else { return nil }
            offset = 16
        case 276:
            guard b.count >= 20, [0x0800, 0x86dd].contains(u16(0)) else { return nil }
            offset = 20
        default: offset = 0
        }
        guard b.count > offset else { return nil }
        var proto: Int
        var source: String
        var destination: String
        let limit: Int
        if b[offset] >> 4 == 4 {
            guard b.count >= offset + 20 else { return nil }
            let size = Int(b[offset] & 15) * 4
            guard size >= 20, b.count >= offset + size, u16(offset + 2) >= size, u16(offset + 6) & 0x1fff == 0 else { return nil }
            limit = min(b.count, offset + u16(offset + 2))
            source = b[(offset + 12)..<(offset + 16)].map(String.init).joined(separator: ".")
            destination = b[(offset + 16)..<(offset + 20)].map(String.init).joined(separator: ".")
            proto = Int(b[offset + 9]); offset += size
        } else if b[offset] >> 4 == 6 {
            guard b.count >= offset + 40 else { return nil }
            limit = min(b.count, offset + 40 + u16(offset + 4))
            func ipv6(_ start: Int) -> String {
                "[" + stride(from: start, to: start + 16, by: 2).map { String(u16($0), radix: 16) }.joined(separator: ":") + "]"
            }
            source = ipv6(offset + 8); destination = ipv6(offset + 24)
            proto = Int(b[offset + 6]); offset += 40
            while [0, 43, 44, 51, 60].contains(proto) {
                guard limit >= offset + 8 else { return nil }
                let next = Int(b[offset])
                let size: Int
                if proto == 44 {
                    guard u16(offset + 2) & 0xfff8 == 0 else { return nil }
                    size = 8
                } else if proto == 51 { size = (Int(b[offset + 1]) + 2) * 4 }
                else { size = (Int(b[offset + 1]) + 1) * 8 }
                guard limit >= offset + size else { return nil }
                offset += size; proto = next
            }
        } else { return nil }
        if proto == 1 || proto == 58 {
            guard limit >= offset + 8 else { return nil }
            let name = proto == 1 ? "ICMP" : "ICMPv6"
            let type = Int(b[offset]), code = Int(b[offset+1])
            let label = ICMPDecoder.name(type, v6: proto == 58)
            var summary = "\(label) · type \(type) code \(code)"
            if (proto == 1 && [0,8].contains(type)) || (proto == 58 && [128,129].contains(type)) {
                summary += " · id \(u16(offset+4)) sequence \(u16(offset+6))"
            }
            return (name, source, destination, summary, [], nil, (offset+8)..<limit)
        }
        guard proto == 6 || proto == 17, limit >= offset + (proto == 6 ? 20 : 8) else { return nil }
        let isDNS = u16(offset) == 53 || u16(offset + 2) == 53
        source += ":\(u16(offset))"; destination += ":\(u16(offset + 2))"
        var flags = ""
        var dns: [DNSMessage] = []
        var application: ProtocolInfo?
        var payloadRange = offset..<offset
        if proto == 6 {
            let size = Int(b[offset + 12] >> 4) * 4
            guard size >= 20, limit >= offset + size else { return nil }
            payloadRange = (offset + size)..<limit
            application = ProtocolDecoder.decode(Array(b[payloadRange]), tcp: true)
            let f = b[offset + 13]
            flags = [(UInt8(2), "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH"), (32, "URG")].compactMap { f & $0.0 != 0 ? $0.1 : nil }.joined(separator: " ")
            if isDNS {
                var p = offset + size
                while p + 2 <= limit {
                    let length = u16(p); p += 2
                    guard length > 0, p + length <= limit else { break }
                    if let message = DNSDecoder.decode(Array(b[p..<(p + length)])) { dns.append(message) }
                    p += length
                }
            }
        } else {
            let length = u16(offset + 4)
            guard length >= 8 else { return nil }
            payloadRange = (offset + 8)..<min(limit, offset + length)
            if offset + length <= limit { application = ProtocolDecoder.decode(Array(b[(offset + 8)..<(offset + length)]), tcp: false) }
            if isDNS, offset + length <= limit,
               let message = DNSDecoder.decode(Array(b[(offset + 8)..<(offset + length)])) {
                dns.append(message)
            }
        }
        return (proto == 6 ? "TCP" : "UDP", source, destination, flags, dns, application, payloadRange)
    }
}
