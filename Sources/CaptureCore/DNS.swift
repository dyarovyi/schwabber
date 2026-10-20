import Foundation

public struct DNSMessage: Sendable {
    public let id: Int
    public let isResponse: Bool
    public let status: String
    public let questions: [String]
    public let answers: [String]
    public let truncated: Bool
    public var summary: String {
        "\(isResponse ? "Response" : "Query") #\(id) " + questions.joined(separator: ", ") +
        (isResponse ? " · \(status)" : "") +
        (answers.isEmpty ? "" : " → " + answers.joined(separator: "; ")) +
        (truncated ? " · truncated" : "")
    }
}

enum DNSDecoder {
    static func decode(_ b: [UInt8]) -> DNSMessage? {
        guard b.count >= 12 else { return nil }
        func u16(_ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }
        func typeName(_ type: Int) -> String {
            [1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"][type] ?? "TYPE\(type)"
        }
        func name(_ cursor: inout Int) -> String? {
            var pos = cursor
            var jumped = false
            var seen = Set<Int>()
            var labels: [String] = []
            var length = 1
            while pos < b.count, seen.insert(pos).inserted {
                let size = Int(b[pos])
                if size & 0xc0 == 0xc0 {
                    guard pos + 1 < b.count else { return nil }
                    let target = (size & 63) << 8 | Int(b[pos + 1])
                    guard target < pos else { return nil }
                    if !jumped { cursor = pos + 2 }
                    jumped = true; pos = target
                } else {
                    guard size <= 63, pos + 1 + size <= b.count else { return nil }
                    pos += 1
                    if size == 0 {
                        if !jumped { cursor = pos }
                        return labels.isEmpty ? "." : labels.joined(separator: ".")
                    }
                    length += size + 1
                    guard length <= 255 else { return nil }
                    labels.append(b[pos..<(pos + size)].map { byte in
                        (byte >= 33 && byte <= 126 && byte != 46 && byte != 92) ? String(UnicodeScalar(byte)) : String(format: "\\%03d", Int(byte))
                    }.joined())
                    pos += size
                }
            }
            return nil
        }
        var cursor = 12
        var questions: [String] = []
        var answers: [String] = []
        for _ in 0..<u16(4) {
            guard let domain = name(&cursor), cursor + 4 <= b.count else { return nil }
            questions.append("\(domain) \(typeName(u16(cursor)))")
            cursor += 4
        }
        let answerCount = u16(6)
        let recordCount = answerCount + u16(8) + u16(10)
        for index in 0..<recordCount {
            guard let domain = name(&cursor), cursor + 10 <= b.count else { return nil }
            let type = u16(cursor)
            let size = u16(cursor + 8)
            cursor += 10
            let end = cursor + size
            guard end <= b.count else { return nil }
            var value = "\(size) bytes"
            if type == 1 {
                guard size == 4 else { return nil }
                value = b[cursor..<end].map(String.init).joined(separator: ".")
            } else if type == 28 {
                guard size == 16 else { return nil }
                value = stride(from: cursor, to: end, by: 2).map { String(u16($0), radix: 16) }.joined(separator: ":")
            } else if [2, 5, 12, 15].contains(type) {
                var p = cursor
                var prefix = ""
                if type == 15 {
                    guard size >= 3 else { return nil }
                    prefix = "\(u16(p)) "; p += 2
                }
                guard let target = name(&p), p == end else { return nil }
                value = prefix + target
            }
            if index < answerCount { answers.append("\(domain) \(typeName(type)) \(value)") }
            cursor = end
        }
        let flags = u16(2)
        return DNSMessage(id: u16(0), isResponse: flags & 0x8000 != 0,
                          status: [0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"][flags & 15] ?? "RCODE \(flags & 15)",
                          questions: questions, answers: answers, truncated: flags & 0x0200 != 0)
    }
}
