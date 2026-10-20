import XCTest
@testable import CaptureCore

final class CaptureTests: XCTestCase {
    func testHexDumpFormattingParity() {
        // Compare the complete display against the original formatter, including
        // partial rows, nonzero Data indices, and printable ASCII boundaries.
        func reference(_ data: Data, base: Int) -> String {
            let bytes = Array(data)
            return stride(from: 0, to: bytes.count, by: 16).map { offset in
                let row = bytes[offset..<min(offset + 16, bytes.count)]
                let hex = row.map { String(format: "%02x", $0) }.joined(separator: " ")
                let ascii = row.map { (32...126).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
                return String(format: "%06x  ", base + offset) + hex.padding(toLength: 47, withPad: " ", startingAt: 0) + "  |" + ascii + "|"
            }.joined(separator: "\n")
        }
        let allBytes = Data((0...255).map(UInt8.init))
        for length in [0, 1, 15, 16, 17, 255, 256] {
            for base in [0, 42, 0xfffff8, -1] {
                let data = Data(allBytes.prefix(length))
                XCTAssertEqual(WiresharkInspection.hexDump(data, baseOffset: base), reference(data, base: base))
            }
        }
        let slice = allBytes.dropFirst(31)
        XCTAssertEqual(WiresharkInspection.hexDump(slice), reference(slice, base: 0))
    }

    func testTimelineChunks() {
        let chunks = TimelineChunks.split(times: [0, 3, 6, 10, 10], captureStart: 0, duration: 100, width: 100)
        XCTAssertEqual(chunks.map(\.start), [0, 3])
        XCTAssertEqual(chunks.map(\.count), [3, 2])
        XCTAssertEqual(chunks.map(\.left), [0, 10])
        XCTAssertEqual(chunks.map(\.right), [8, 12])
        let zoomed = TimelineChunks.split(times: [0, 3, 6, 10, 10], captureStart: 0, duration: 100, width: 200)
        XCTAssertEqual(zoomed.map(\.count), [1, 1, 1, 2])
        XCTAssertEqual(TimelineChunks.split(times: [], captureStart: 0, duration: 1, width: 100), [])
        XCTAssertEqual(TimelineChunks.split(times: [0], captureStart: 0, duration: 0, width: 100), [])
        let edge = TimelineChunks.split(times: [1099, 1100], captureStart: 1000, duration: 100, width: 100)
        XCTAssertEqual(edge.count, 1)
        XCTAssertEqual(edge.first?.left, 98)
        XCTAssertEqual(edge.first?.right, 100)
    }

    func testWiresharkSourceRanges() throws {
        let frame = Data([1, 2, 3, 4])
        let result: [String: Any] = [
            "bytes": frame.base64EncodedString(),
            "ds": [["name": "Decrypted QUIC", "bytes": Data([5, 6, 7]).base64EncodedString()],
                   ["name": "Reassembled TLS", "bytes": Data([8, 9]).base64EncodedString()]],
            "tree": [
                ["l": "Captured", "f": "udp", "h": [0, 2]],
                ["l": "QUIC", "f": "quic", "ds": 1, "h": [0, 3], "n": [
                    ["l": "Type", "ds": 1, "h": [0, 1]],
                    ["l": "Generated", "ds": 1, "h": [0, 1], "g": true]]],
                ["l": "TLS", "ds": 2, "h": [0, 2]],
                ["l": "Invalid source", "ds": 3, "h": [0, 1]],
                ["l": "Invalid range", "ds": 2, "h": [1, Int.max]]
            ]
        ]
        let parsed = try WiresharkInspection.parseSharkFrame(result, expectedFrame: frame)
        XCTAssertEqual(parsed.additionalSources.count, 2)
        XCTAssertEqual(parsed.additionalSources[0].bytes, Data([5, 6, 7]))
        XCTAssertEqual(parsed.fields[0].sourceIndex, 0)
        XCTAssertEqual(parsed.fields[1].sourceIndex, 1)
        XCTAssertEqual(parsed.fields[1].children?[0].byteRange, 0..<1)
        XCTAssertNil(parsed.fields[1].children?[1].byteRange)
        XCTAssertEqual(parsed.fields[2].sourceIndex, 2)
        XCTAssertEqual(parsed.fields[2].byteRange, 0..<2)
        XCTAssertNil(parsed.fields[3].byteRange)
        XCTAssertNil(parsed.fields[4].byteRange)
        XCTAssertThrowsError(try WiresharkInspection.parseSharkFrame(result, expectedFrame: Data([0])))
    }

    func packet(reverse: Bool = false) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: 42)
        b[12] = 8; b[14] = 0x45; b[17] = 28; b[23] = 17
        b[26...29] = [10, 0, 0, reverse ? 2 : 1]
        b[30...33] = [10, 0, 0, reverse ? 1 : 2]
        b[34...37] = reverse ? [0, 53, 0x30, 0x39] : [0x30, 0x39, 0, 53]
        b[39] = 8
        return b
    }
    func testDecodingAndTruncation() {
        let b = packet()
        let result = CaptureReader.decode(b, link: 1)
        XCTAssertEqual(result?.0, "UDP")
        XCTAssertEqual(result?.1, "10.0.0.1:12345")
        XCTAssertEqual(result?.2, "10.0.0.2:53")
        for count in 0..<b.count { XCTAssertNil(CaptureReader.decode(Array(b.prefix(count)), link: 1)) }
        var fragment = b; fragment[21] = 1
        XCTAssertNil(CaptureReader.decode(fragment, link: 1))
    }
    func testBidirectionalGroupingAndIdleTimeout() throws {
        var data = Data([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0])
        func append(_ number: UInt32) {
            var n = number.littleEndian
            withUnsafeBytes(of: &n) { data.append(contentsOf: $0) }
        }
        for (time, reverse) in [(1, false), (2, true), (100, false)] {
            let b = packet(reverse: reverse)
            append(UInt32(time)); append(0); append(UInt32(b.count)); append(UInt32(b.count)); data.append(contentsOf: b)
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".pcap")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let capture = try CaptureReader.read(url: url)
        XCTAssertEqual(capture.totalPackets, 3)
        XCTAssertEqual(capture.skippedPackets, 0)
        XCTAssertEqual(capture.sessions.count, 2)
        XCTAssertEqual(capture.sessions[0].packets.count, 2)
        XCTAssertEqual(capture.end - capture.start, 99)
        let exportURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".pcap")
        defer { try? FileManager.default.removeItem(at: exportURL) }
        try capture.export(sessionIDs: [capture.sessions[0].id], to: exportURL)
        let subset = try CaptureReader.read(url: exportURL)
        XCTAssertEqual(subset.totalPackets, 2)
        XCTAssertEqual(subset.sessions[0].packets.map(\.rawBytes), capture.sessions[0].packets.map(\.rawBytes))
        XCTAssertEqual(subset.sessions[0].packets.map(\.time), [1, 2])
        try capture.export(sessionIDs: Set(capture.sessions.map(\.id)), to: exportURL)
        XCTAssertEqual(try CaptureReader.read(url: exportURL).totalPackets, 3)
        XCTAssertThrowsError(try capture.export(sessionIDs: [], to: exportURL))
    }
    func testTimelineAxisAndCaptureByteTotals() throws {
        XCTAssertEqual(TimeAxis(duration: 10, width: 550).step, 2)
        XCTAssertEqual(TimeAxis(duration: 10, width: 5500).step, 0.2)
        XCTAssertEqual(TimeAxis(duration: 0.001, width: 550).decimals, 4)
        XCTAssertEqual(TimeAxis(duration: 10, width: 550).ticks, [0, 2, 4, 6, 8, 10])
        var data = Data([0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,1,0,0,0])
        var skipped = packet(); skipped[23] = 99
        for (bytes, wire) in [(packet(), 100), (skipped, 200)] {
            for n in [1, 0, bytes.count, wire] {
                var value = UInt32(n).littleEndian
                withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
            }
            data.append(contentsOf: bytes)
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".pcap")
        try data.write(to: url); defer { try? FileManager.default.removeItem(at: url) }
        let capture = try CaptureReader.read(url: url)
        XCTAssertEqual(capture.totalBytes, 300)
        XCTAssertEqual(capture.sessions[0].bytes, 100)
        XCTAssertEqual(capture.skippedPackets, 1)
    }
    func testRTPAndSTUN() {
        let rtp: [UInt8] = [0xb1,0xe0,0,42,0,0,1,0,1,2,3,4,5,6,7,8,0xbe,0xde,0,1,0x10,42,0,0,0xab,0xcd,0,2]
        XCTAssertEqual(ProtocolDecoder.decode(rtp, tcp: false)?.name, "RTP")
        XCTAssertNil(ProtocolDecoder.decode(rtp, tcp: true))
        var udp = packet() + rtp; udp[17] = UInt8(28 + rtp.count); udp[39] = UInt8(8 + rtp.count)
        let fields = NativeDissector.dissect(nativePacket(udp), linkType: 1).fields
        XCTAssertEqual(fields.contains { $0.label == "Sequence Number: 42" }, true)
        XCTAssertEqual(fields.contains { $0.name == "Media Payload" && $0.length == 2 }, true)
        XCTAssertEqual(fields.contains { $0.name == "Extension Data" && $0.length == 4 }, true)
        for count in 0..<24 { XCTAssertNil(ProtocolDecoder.decode(Array(rtp.prefix(count)), tcp: false)) }
        var bad = rtp; bad[27] = 0; XCTAssertNil(ProtocolDecoder.decode(bad, tcp: false))
        bad = rtp; bad[27] = 5; XCTAssertNil(ProtocolDecoder.decode(bad, tcp: false))
        bad = rtp; bad[1] = 200; XCTAssertNil(ProtocolDecoder.decode(bad, tcp: false))
        let stun: [UInt8] = [0,3,0,0,0x21,0x12,0xa4,0x42] + Array(repeating: 0, count: 12)
        XCTAssertEqual(ProtocolDecoder.decode(stun, tcp: false)?.name, "STUN")
        XCTAssertEqual(ProtocolDecoder.decode(stun, tcp: false)?.summary.hasPrefix("Allocate request"), true)
        bad = stun; bad[3] = 4; XCTAssertNil(ProtocolDecoder.decode(bad, tcp: false))
    }
    func testRealtimeProtocols() {
        let rr: [UInt8] = [0x81,201,0,7,0,0,0,1,0,0,0,2,128,255,255,255,0,0,0,10,0,0,0,20,0,0,0,0,0,0,0,0]
        let dtls: [UInt8] = [22,254,253,0,0,0,0,0,0,0,1,0,12,14,0,0,0,0,1,0,0,0,0,0,0]
        let turn: [UInt8] = [0x40,1,0,3,1,2,3]
        let sip = Array("INVITE sip:b@example.com SIP/2.0\r\nCall-ID: test\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5004 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\n".utf8)
        for (bytes, name) in [(rr,"RTCP"),(dtls,"DTLS"),(turn,"TURN"),(sip,"SIP")] {
            XCTAssertEqual(ProtocolDecoder.decode(bytes, tcp: false)?.name, name)
            let detail = RealtimeDecoder.decode(bytes, tcp: false)!
            XCTAssertEqual(detail.fields.allSatisfy { $0.offset >= 0 && $0.offset + $0.length <= bytes.count }, true)
            for count in 0..<bytes.count { _ = RealtimeDecoder.decode(Array(bytes.prefix(count)), tcp: false) }
        }
        XCTAssertEqual(RealtimeDecoder.decode(rr, tcp: false)?.fields.contains { $0.name == "Cumulative Lost" && $0.value == "-1" }, true)
        XCTAssertEqual(RealtimeDecoder.decode(rr, tcp: false)?.fields.contains { $0.value == "50.00%" }, true)
        XCTAssertEqual(ProtocolDecoder.decode(sip, tcp: true)?.summary.contains("opus/48000/2"), true)
        XCTAssertNil(RealtimeDecoder.decode(turn, tcp: true))
        XCTAssertEqual(RealtimeDecoder.decode(turn + [0], tcp: true)?.name, "TURN")
        XCTAssertNil(RealtimeDecoder.decode(rr, tcp: true))
        var bad = rr; bad[3] = 8; XCTAssertNil(RealtimeDecoder.decode(bad, tcp: false))
        bad = dtls; bad[24] = 1; XCTAssertNil(RealtimeDecoder.decode(bad, tcp: false))
        XCTAssertEqual(RealtimeDecoder.decode(rr + rr, tcp: false)?.fields.filter { $0.name == "Packet Type" }.count, 2)
    }
    func testICMP() {
        var echo = packet(); echo[23] = 1; echo[34...41] = [8,0,0,0,0,7,0,2]
        let decoded = CaptureReader.decode(echo, link: 1)
        XCTAssertEqual(decoded?.0, "ICMP")
        XCTAssertEqual(decoded?.1, "10.0.0.1")
        XCTAssertEqual(decoded?.3, "Echo Request · type 8 code 0 · id 7 sequence 2")
        XCTAssertEqual(NativeDissector.dissect(nativePacket(echo), linkType: 1).fields.contains { $0.label == "Identifier: 7" }, true)
        for count in 0..<echo.count { XCTAssertNil(CaptureReader.decode(Array(echo.prefix(count)), link: 1)) }
        var v6 = Array(echo.prefix(14)) + Array(repeating: UInt8(0), count: 48)
        v6[12] = 0x86; v6[13] = 0xdd; v6[14] = 0x60; v6[19] = 8; v6[20] = 58
        v6[54...61] = [2,0,0,0,0,0,5,0]
        XCTAssertEqual(CaptureReader.decode(v6, link: 1)?.0, "ICMPv6")
        XCTAssertEqual(NativeDissector.dissect(nativePacket(v6), linkType: 1).fields.contains { $0.label == "MTU: 1280" }, true)
    }
    func testLiveCaptureAccumulation() {
        var builder = LiveCaptureBuilder(url: URL(fileURLWithPath: "/tmp/live-test.pcap"), link: 1)
        builder.append(Data(packet()), wire: 42, seconds: 1, microseconds: 0)
        let first = builder.capture
        builder.append(Data(packet(reverse: true)), wire: 42, seconds: 2, microseconds: 0)
        builder.append(Data(packet()), wire: 42, seconds: 100, microseconds: 0)
        builder.append(Data([0]), wire: 100, seconds: 101, microseconds: 0)
        XCTAssertEqual(first.totalPackets, 1)
        XCTAssertEqual(first.sessions[0].packets.count, 1)
        XCTAssertEqual(builder.capture.sessions.count, 2)
        XCTAssertEqual(builder.capture.sessions[0].packets.count, 2)
        XCTAssertEqual(builder.capture.skippedPackets, 1)
        XCTAssertEqual(builder.capture.totalBytes, 226)
        XCTAssertEqual(builder.capture.sessions[1].packets[0].id, 3)
        XCTAssertEqual(builder.capture.sessions[0].bytes, 84)
        XCTAssertEqual(first.sessions[0].bytes, 42)
        XCTAssertEqual(builder.capture.sessions[0].matches("10.0.0.1"), true)
        XCTAssertEqual(builder.capture.sessions[0].matches("nonexistent.example"), false)
        let http = nativePacket(nativeTCP(Array("GET / HTTP/1.1\r\nHost: test.example\r\n\r\n".utf8)))
        var session = Session(id: 0, transport: "TCP", endpointA: http.source, endpointB: http.destination, packets: [http])
        let snapshot = session
        session.append(http)
        XCTAssertEqual(session.bytes, http.length * 2)
        XCTAssertEqual(session.applicationProtocols, ["HTTP"])
        XCTAssertEqual(session.summary, snapshot.summary)
        XCTAssertEqual(session.matches("test.example"), true)
    }
    func testPayloadSessionFiltering() {
        let bytes: [UInt8] = [0,1,255] + Array("Hello payload".utf8)
        let packet = nativePacket(nativeTCP(bytes))
        let session = Session(id: 0, transport: "TCP", endpointA: packet.source, endpointB: packet.destination, packets: [packet])
        XCTAssertEqual(SessionFilter("x00x01xFF").matches(session), true)
        XCTAssertEqual(SessionFilter("Hello payload").matches(session), true)
        XCTAssertEqual(SessionFilter("hello payload").matches(session), false)
        XCTAssertEqual(SessionFilter("10.0.0.1").matches(session), true)
        XCTAssertEqual(SessionFilter("x00x01xGG").invalidHex, true)
        XCTAssertEqual(SessionFilter("x00x01xGG").matches(session), false)
        XCTAssertEqual(SessionFilter("x45x00").matches(session), false)
        XCTAssertEqual(SessionFilter("").matches(session), true)
    }
    func testHTTP2Frames() {
        let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        let settings: [UInt8] = [0,0,6,4,0,0,0,0,0,0,3,0,0,0,100]
        XCTAssertEqual(ProtocolDecoder.decode(preface + settings, tcp: true)?.name, "HTTP/2")
        XCTAssertEqual(HTTP2Decoder.decode(settings)?.fields.contains { $0.name == "Setting Value" && $0.value == "100" }, true)
        XCTAssertNil(HTTP2Decoder.decode([0,0,7,6,0,0,0,0,0,0,0,0,0,0,0,0]))
        XCTAssertNil(HTTP2Decoder.decode([0,0,0,0,0,0,0,0,0]))
        for count in 0..<settings.count { _ = HTTP2Decoder.decode(Array(settings.prefix(count))) }
        let packet = nativePacket(nativeTCP(preface + settings))
        XCTAssertEqual(NativeDissector.dissect(packet, linkType: 1).fields.contains { $0.name == "Setting Value" }, true)
    }
    func testTCPReassembly() {
        func segment(_ seq: UInt32, _ text: String) -> Packet {
            var b = nativeTCP(Array(text.utf8))
            b[38...41] = [UInt8(seq >> 24),UInt8((seq >> 16)&255),UInt8((seq >> 8)&255),UInt8(seq&255)]
            b[47] = 16
            return nativePacket(b)
        }
        let packets = [segment(103,"def"),segment(100,"abc"),segment(100,"abc"),segment(110,"xyz")]
        let session = Session(id:0,transport:"TCP",endpointA:packets[0].source,endpointB:packets[0].destination,packets:packets)
        let result = TCPReassembly.reassemble(session,linkType:1)
        XCTAssertEqual(result.count,1)
        XCTAssertEqual(result[0].chunks.map { String(decoding:$0.bytes,as:UTF8.self) },["abcdef","xyz"])
        XCTAssertEqual(result[0].missingBytes,4)
        XCTAssertEqual(result[0].overlapBytes,3)
        XCTAssertEqual(result[0].conflictingBytes,0)
        let wrap = [segment(0xfffffffd,"abc"),segment(0,"def")]
        let wrapped = Session(id:0,transport:"TCP",endpointA:wrap[0].source,endpointB:wrap[0].destination,packets:wrap)
        XCTAssertEqual(String(decoding:TCPReassembly.reassemble(wrapped,linkType:1)[0].chunks[0].bytes,as:UTF8.self),"abcdef")
    }
    func testInvalidFile() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("invalid".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertThrowsError(try CaptureReader.read(url: url))
    }
    func dnsQuery() -> [UInt8] {
        [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7] + Array("example".utf8) + [3] + Array("com".utf8) + [0, 0, 1, 0, 1]
    }
    func testDNSQueryAndCompressedResponse() {
        let query = dnsQuery()
        XCTAssertEqual(DNSDecoder.decode(query)?.questions, ["example.com A"])
        XCTAssertEqual(DNSDecoder.decode(query)?.id, 0x1234)
        var response = query
        response[2] = 0x81; response[3] = 0x80; response[7] = 1
        response += [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]
        XCTAssertEqual(DNSDecoder.decode(response)?.answers, ["example.com A 1.2.3.4"])
        XCTAssertEqual(DNSDecoder.decode(response)?.isResponse, true)
        response[3] = 0x83
        XCTAssertEqual(DNSDecoder.decode(response)?.status, "NXDOMAIN")
        for count in 0..<response.count { XCTAssertNil(DNSDecoder.decode(Array(response.prefix(count)))) }
        var loop = query; loop[12] = 0xc0; loop[13] = 12
        XCTAssertNil(DNSDecoder.decode(loop))
    }
    func testDNSUDPAndTCPIntegration() {
        let query = dnsQuery()
        var udp = packet() + query
        udp[17] = UInt8(28 + query.count); udp[39] = UInt8(8 + query.count)
        XCTAssertEqual(CaptureReader.decode(udp, link: 1)?.4.first?.questions, ["example.com A"])
        udp[37] = 54
        XCTAssertEqual(CaptureReader.decode(udp, link: 1)?.4.count, 0)
        udp[39] = 7
        XCTAssertNil(CaptureReader.decode(udp, link: 1))
        var tcp = Array(packet().prefix(34)) + [UInt8](repeating: 0, count: 20)
        tcp[23] = 6; tcp[34] = 0x30; tcp[35] = 0x39; tcp[37] = 53; tcp[46] = 0x50
        tcp += [0, UInt8(query.count)] + query
        tcp[17] = UInt8(tcp.count - 14)
        XCTAssertEqual(CaptureReader.decode(tcp, link: 1)?.4.first?.id, 0x1234)
        tcp.removeLast()
        XCTAssertEqual(CaptureReader.decode(tcp, link: 1)?.4.count, 0)
    }
    func testHigherProtocols() {
        let http = Array("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)
        XCTAssertEqual(ProtocolDecoder.decode(http, tcp: true)?.name, "HTTP")
        XCTAssertEqual(ProtocolDecoder.decode(http, tcp: true)?.summary, "GET /hello HTTP/1.1 · Host: example.com")
        XCTAssertNil(ProtocolDecoder.decode(http, tcp: false))
        let stun: [UInt8] = [0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42] + Array(repeating: 0, count: 12)
        XCTAssertEqual(ProtocolDecoder.decode(stun, tcp: false)?.name, "STUN")
        XCTAssertEqual(ProtocolDecoder.decode(stun, tcp: false)?.summary.hasPrefix("Binding request"), true)
        let quic: [UInt8] = [0xc0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc, 0]
        XCTAssertEqual(ProtocolDecoder.decode(quic, tcp: false)?.name, "QUIC")
        XCTAssertEqual(ProtocolDecoder.decode(quic, tcp: false)?.summary.contains("DCID aabb · SCID cc"), true)
        XCTAssertNil(ProtocolDecoder.decode([0x40, 1, 2, 3], tcp: false))
        let tls: [UInt8] = [23, 3, 3, 0, 2, 1, 2]
        XCTAssertEqual(ProtocolDecoder.decode(tls, tcp: true)?.name, "TLS")
        for data in [stun, quic, tls, http] {
            for count in 0..<data.count {
                _ = ProtocolDecoder.decode(Array(data.prefix(count)), tcp: true)
                _ = ProtocolDecoder.decode(Array(data.prefix(count)), tcp: false)
            }
        }
        XCTAssertNil(ProtocolDecoder.decode(Array(stun.prefix(19)), tcp: false))
        var malformed = stun; malformed[3] = 4
        XCTAssertNil(ProtocolDecoder.decode(malformed, tcp: false))
        var badID = quic; badID[5] = 255
        XCTAssertNil(ProtocolDecoder.decode(badID, tcp: false))
    }
    func testTLSClientHelloMetadata() {
        let host = Array("example.com".utf8)
        let sni: [UInt8] = [0, 0, 0, UInt8(host.count + 5), 0, UInt8(host.count + 3), 0, 0, UInt8(host.count)] + host
        let alpn: [UInt8] = [0, 16, 0, 5, 0, 3, 2, 104, 50]
        let extensions = sni + alpn
        let body: [UInt8] = [3, 3] + Array(repeating: 0, count: 32) + [0, 0, 2, 0x13, 1, 1, 0, 0, UInt8(extensions.count)] + extensions
        let handshake: [UInt8] = [1, 0, 0, UInt8(body.count)] + body
        let record: [UInt8] = [22, 3, 1, 0, UInt8(handshake.count)] + handshake
        let result = ProtocolDecoder.decode(record, tcp: true)
        XCTAssertEqual(result?.summary.contains("SNI example.com"), true)
        XCTAssertEqual(result?.summary.contains("ALPN h2"), true)
        for count in 0..<record.count { _ = ProtocolDecoder.decode(Array(record.prefix(count)), tcp: true) }
    }
    func testPacketInspectionBytesAndFields() throws {
        var udp = packet() + [65, 0, 66, 0, 0, 0]
        udp[17] = 31; udp[39] = 11
        XCTAssertEqual(CaptureReader.decode(udp, link: 1)?.6, 42..<45)
        XCTAssertEqual(CaptureReader.decode(Array(udp.prefix(44)), link: 1)?.6, 42..<44)
        XCTAssertEqual(CaptureReader.decode(packet(), link: 1)?.6, 42..<42)
        let text = "Packet (2 bytes):\n0000  41 42                                             AB\nDecrypted TLS (3 bytes):\n0000  41 00 42                                          A.B\n"
        let sources = WiresharkInspection.parseHexSources(text)
        XCTAssertEqual(sources.count, 2)
        XCTAssertEqual(sources[0].bytes, Data([65, 66]))
        XCTAssertEqual(sources[1].bytes, Data([65, 0, 66]))
        XCTAssertEqual(WiresharkInspection.hexDump(sources[1].bytes).hasSuffix("|A.B|"), true)
        let xml = "<pdml><packet><proto name='http' showname='HTTP'><field name='http.host' showname='Host: example.com' show='example.com'/></proto></packet></pdml>"
        let fields = try WiresharkInspection.parsePDML(Data(xml.utf8))
        XCTAssertEqual(fields.first?.label, "HTTP")
        XCTAssertEqual(fields.first?.children?.first?.value, "example.com")
        XCTAssertThrowsError(try WiresharkInspection.parsePDML(Data("<broken>".utf8)))
    }
    func nativePacket(_ bytes: [UInt8], wire: Int? = nil) -> Packet {
        let d = CaptureReader.decode(bytes, link: 1)
        return Packet(id: 1, time: 1, source: d?.1 ?? "", destination: d?.2 ?? "", length: wire ?? bytes.count,
                      flags: d?.3 ?? "", dns: d?.4 ?? [], application: d?.5, rawBytes: Data(bytes),
                      payloadRange: d?.6 ?? bytes.count..<bytes.count, seconds: 1, microseconds: 0)
    }
    func nativeTCP(_ payload: [UInt8], options: [UInt8] = []) -> [UInt8] {
        var b = Array(packet().prefix(34)) + [UInt8](repeating: 0, count: 20) + options + payload
        b[23] = 6; b[34] = 0xc3; b[35] = 0x50; b[37] = 80
        b[46] = UInt8(((20 + options.count) / 4) << 4); b[47] = 0x18
        b[16] = UInt8((b.count - 14) >> 8); b[17] = UInt8((b.count - 14) & 255)
        return b
    }
    func testNativeDissectorWindowsParity() {
        let http = Array("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nbody".utf8)
        let b = nativeTCP(http, options: [2, 4, 5, 180])
        let d = NativeDissector.dissect(nativePacket(b), linkType: 1)
        XCTAssertEqual(d.layers.map(\.name), ["Frame", "Ethernet II", "IPv4", "TCP", "HTTP"])
        XCTAssertEqual(d.headerLength, 58)
        XCTAssertEqual(d.payloadWireLength, http.count)
        XCTAssertEqual(d.field(at: 34)?.id, "TCP › Source Port")
        XCTAssertEqual(d.field(at: 47)?.name, "Flags")
        XCTAssertEqual(d.field(at: 46)?.name, "Header Length")
        XCTAssertEqual(d.field(at: 56)?.name, "MSS Value")
        XCTAssertEqual(d.field(at: 58)?.name, "Request Method")
        XCTAssertEqual(d.field(at: b.count - 1)?.name, "File Data")
        XCTAssertEqual(d.field(at: 26)?.name, "Source Address")
        for offset in b.indices { XCTAssertEqual(d.field(at: offset)?.kind == "frame", false) }
        let padded = NativeDissector.dissect(nativePacket(nativeTCP([]) + [0,0,0,0,0,0]), linkType: 1)
        XCTAssertEqual(padded.trailerLength, 6)
        XCTAssertEqual(padded.payloadRange.count, 0)
        for count in 0..<b.count {
            let truncated = NativeDissector.dissect(nativePacket(Array(b.prefix(count)), wire: b.count), linkType: 1)
            for field in truncated.fields {
                XCTAssertEqual(field.offset >= 0 && field.offset + field.length <= count, true)
            }
        }
    }
    func testNativeApplicationByteLookup() {
        var dns = dnsQuery(); dns[2] = 0x81; dns[3] = 0x80; dns[7] = 1
        dns += [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]
        var udp = packet() + dns; udp[17] = UInt8(28 + dns.count); udp[39] = UInt8(8 + dns.count)
        let d = NativeDissector.dissect(nativePacket(udp), linkType: 1)
        XCTAssertEqual(d.field(at: udp.count - 1)?.label, "Address: 1.2.3.4")
        let host = Array("example.com".utf8)
        let ext: [UInt8] = [0,0,0,UInt8(host.count + 5),0,UInt8(host.count + 3),0,0,UInt8(host.count)] + host + [0,43,0,3,2,3,4,0,10,0,4,0,2,0,29] + [0,16,0,5,0,3,2,104,50]
        let body: [UInt8] = [3,3] + Array(repeating: 0, count: 32) + [0,0,2,0x13,1,1,0,0,UInt8(ext.count)] + ext
        let hs: [UInt8] = [1,0,0,UInt8(body.count)] + body
        let b = nativeTCP([22,3,1,0,UInt8(hs.count)] + hs)
        let tls = NativeDissector.dissect(nativePacket(b), linkType: 1)
        XCTAssertEqual(tls.field(at: b.count - 1)?.label, "ALPN Next Protocol: h2")
        XCTAssertEqual(tls.fields.contains { $0.label == "Server Name: example.com" }, true)
        XCTAssertEqual(tls.fields.contains { $0.label == "Supported Version: TLS 1.3 (0x0304)" }, true)
        XCTAssertEqual(tls.fields.contains { $0.label == "Supported Group: x25519 (0x001d)" }, true)
        for count in 0..<b.count { _ = NativeDissector.dissect(nativePacket(Array(b.prefix(count)), wire: b.count), linkType: 1) }
    }
}
