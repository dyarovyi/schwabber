import Foundation

public struct PacketField: Identifiable, Sendable {
    public let id = UUID()
    public let name: String
    public let label: String
    public let value: String
    public var children: [PacketField]?
    public var sourceIndex: Int = 0
    public var byteRange: Range<Int>? = nil
}
public struct PacketDataSource: Identifiable, Sendable {
    public var id: String { name }
    public let name: String
    public let bytes: Data
}
public struct PacketDissection: Sendable {
    public let fields: [PacketField]
    public let additionalSources: [PacketDataSource]
    public var applicationFields: [PacketField] {
        fields.filter { !["geninfo", "frame", "eth", "ethertype", "vlan", "sll", "sll2", "null", "raw", "ip", "ipv6", "ipv6.hopopts", "ipv6.routing", "ipv6.fraghdr", "ipv6.dstopts", "tcp", "udp"].contains($0.name) }
    }
}

public enum WiresharkInspection {
    public static func inspect(packet: Packet, capture: Capture, keyLog: URL?) async throws -> PacketDissection {
        let worker = Task.detached(priority: .userInitiated) {
            try inspectSync(packet: packet, capture: capture, keyLog: keyLog)
        }
        return try await withTaskCancellationHandler(operation: { try await worker.value }, onCancel: { worker.cancel() })
    }
    private static func inspectSync(packet: Packet, capture: Capture, keyLog: URL?) throws -> PacketDissection {
        let candidates = ["/Applications/Wireshark.app/Contents/MacOS/sharkd", NSHomeDirectory() + "/Applications/Wireshark.app/Contents/MacOS/sharkd", "/opt/homebrew/bin/sharkd", "/usr/local/bin/sharkd"]
        guard let executable = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw CaptureError.read("Install Wireshark with sharkd for reassembled/decrypted sources and linked fields. Captured bytes remain available.")
        }
        let access = capture.sourceURL.startAccessingSecurityScopedResource()
        let keyAccess = keyLog?.startAccessingSecurityScopedResource() ?? false
        defer {
            if access { capture.sourceURL.stopAccessingSecurityScopedResource() }
            if keyAccess { keyLog?.stopAccessingSecurityScopedResource() }
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("Schwabber-inspect-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        var requests: [[String: Any]] = []
        func request(_ method: String, _ params: [String: Any]) {
            requests.append(["jsonrpc": "2.0", "id": requests.count + 1, "method": method, "params": params])
        }
        for preference in ["tcp.desegment_tcp_streams", "tls.desegment_ssl_records", "tls.desegment_ssl_application_data", "http.desegment_headers", "http.desegment_body"] {
            request("setconf", ["name": preference, "value": "true"])
        }
        request("setconf", ["name": "tls.keylog_file", "value": keyLog?.path ?? ""])
        request("load", ["file": capture.sourceURL.path])
        request("analyse", [:])
        request("frame", ["frame": packet.id, "proto": true, "bytes": true])
        var input = Data()
        for request in requests {
            input.append(try JSONSerialization.data(withJSONObject: request)); input.append(10)
        }
        let output = try run(executable, ["-"], in: directory, input: input)
        var result: [String: Any]?
        for line in output.split(separator: 10) {
            guard let response = try JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else { continue }
            if let error = response["error"] as? [String: Any] {
                throw CaptureError.read("Wireshark: " + (error["message"] as? String ?? "Analysis failed"))
            }
            if response["id"] as? Int == requests.count { result = response["result"] as? [String: Any] }
        }
        guard let result else { throw CaptureError.read("Wireshark returned no packet details.") }
        return try parseSharkFrame(result, expectedFrame: packet.rawBytes)
    }

    public static func parseSharkFrame(_ result: [String: Any], expectedFrame: Data) throws -> PacketDissection {
        guard let encoded = result["bytes"] as? String, Data(base64Encoded: encoded) == expectedFrame else {
            throw CaptureError.read("The source capture changed since import. Reopen it before inspecting packets.")
        }
        var sources: [PacketDataSource] = []
        for (index, source) in (result["ds"] as? [[String: Any]] ?? []).enumerated() {
            guard let encoded = source["bytes"] as? String, let bytes = Data(base64Encoded: encoded) else {
                throw CaptureError.read("Wireshark returned an invalid data source.")
            }
            sources.append(PacketDataSource(name: "\(index + 1). " + (source["name"] as? String ?? "Data"), bytes: bytes))
        }
        let sizes = [expectedFrame.count] + sources.map { $0.bytes.count }
        func field(_ node: [String: Any]) -> PacketField {
            let source = node["ds"] as? Int ?? 0
            let span = node["h"] as? [Int] ?? []
            var range: Range<Int>?
            if node["g"] as? Bool != true, span.count == 2, sizes.indices.contains(source),
               span[0] >= 0, span[1] > 0, span[0] <= sizes[source], span[1] <= sizes[source] - span[0] {
                range = span[0]..<(span[0] + span[1])
            }
            let filter = node["f"] as? String ?? ""
            let children = (node["n"] as? [[String: Any]] ?? []).map(field)
            return PacketField(name: filter.components(separatedBy: " ").first ?? filter,
                               label: node["l"] as? String ?? filter, value: filter,
                               children: children.isEmpty ? nil : children, sourceIndex: source, byteRange: range)
        }
        return PacketDissection(fields: (result["tree"] as? [[String: Any]] ?? []).map(field), additionalSources: sources)
    }
    private static func run(_ executable: String, _ arguments: [String], in directory: URL, input: Data) throws -> Data {
        try Task.checkCancellation()
        let output = directory.appendingPathComponent("out"), errors = directory.appendingPathComponent("err")
        FileManager.default.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: errors.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let out = try FileHandle(forWritingTo: output), err = try FileHandle(forWritingTo: errors)
        defer { try? out.close(); try? err.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = out; process.standardError = err
        let inputURL = directory.appendingPathComponent("requests")
        FileManager.default.createFile(atPath: inputURL.path, contents: input, attributes: [.posixPermissions: 0o600])
        let stdin = try FileHandle(forReadingFrom: inputURL)
        defer { try? stdin.close() }
        process.standardInput = stdin
        try process.run()
        let deadline = Date().addingTimeInterval(120)
        while process.isRunning {
            if Task.isCancelled || Date() > deadline {
                process.terminate()
                if Task.isCancelled { throw CancellationError() }
                throw CaptureError.read("Wireshark analysis timed out. Try a smaller capture.")
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw CaptureError.read("Wireshark: " + (try String(contentsOf: errors, encoding: .utf8)))
        }
        return try Data(contentsOf: output)
    }
    public static func parsePDML(_ data: Data) throws -> [PacketField] {
        let delegate = PDMLReader()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse() else { throw CaptureError.read("Could not read Wireshark packet details.") }
        return delegate.roots
    }
    public static func parseHexSources(_ text: String) -> [PacketDataSource] {
        var results: [PacketDataSource] = [], bytes = Data()
        var title = "Frame"
        func flush() {
            if !bytes.isEmpty { results.append(PacketDataSource(name: "\(results.count + 1). \(title)", bytes: bytes)); bytes = Data() }
        }
        for line in text.components(separatedBy: .newlines) {
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            if let first = parts.first, first.count >= 4, let offset = Int(first, radix: 16), parts.count > 1 {
                if offset == 0 && !bytes.isEmpty { flush() }
                guard offset == bytes.count else { continue }
                // Each dump row contains at most sixteen two-digit hexadecimal bytes.
                let byteColumn = line.dropFirst(first.count + 2).prefix(47)
                for part in byteColumn.split(separator: " ") {
                    guard part.count == 2, let byte = UInt8(part, radix: 16) else { break }
                    bytes.append(byte)
                }
            } else if !line.trimmingCharacters(in: .whitespaces).isEmpty {
                flush(); title = line.trimmingCharacters(in: .whitespaces)
            }
        }
        flush(); return results
    }
    public static func hexDump(_ data: Data, baseOffset: Int = 0) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var output: [UInt8] = []
        output.reserveCapacity((data.count / 16 + 1) * 77)
        data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            for offset in stride(from: 0, to: bytes.count, by: 16) {
                if offset > 0 { output.append(10) }
                output.append(contentsOf: String(format: "%06x  ", baseOffset + offset).utf8)
                let count = min(16, bytes.count - offset)
                for i in 0..<count {
                    if i > 0 { output.append(32) }
                    let byte = bytes[offset + i]
                    output.append(digits[Int(byte >> 4)])
                    output.append(digits[Int(byte & 15)])
                }
                output.append(contentsOf: repeatElement(UInt8(32), count: 47 - (count * 3 - 1)))
                output.append(contentsOf: [32, 32, 124])
                for i in 0..<count {
                    let byte = bytes[offset + i]
                    output.append((32...126).contains(byte) ? byte : 46)
                }
                output.append(124)
            }
        }
        return String(decoding: output, as: UTF8.self)
    }
}
private final class PDMLReader: NSObject, XMLParserDelegate {
    var roots: [PacketField] = []
    var stack: [PacketField] = []
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes a: [String: String]) {
        guard name == "proto" || name == "field" else { return }
        let label = a["showname"] ?? a["show"].map { "\(a["name"] ?? "Field"): \($0)" } ?? a["name"] ?? "Data"
        stack.append(PacketField(name: a["name"] ?? "", label: label, value: a["show"] ?? a["value"] ?? "", children: nil))
    }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        guard name == "proto" || name == "field", let node = stack.popLast() else { return }
        if stack.isEmpty { roots.append(node) }
        else { if stack[stack.count - 1].children == nil { stack[stack.count - 1].children = [] }; stack[stack.count - 1].children?.append(node) }
    }
}
