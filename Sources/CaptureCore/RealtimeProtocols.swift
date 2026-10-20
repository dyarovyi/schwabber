import Foundation

struct RealtimeField { let name: String; let value: String; let offset: Int; let length: Int }
struct RealtimeMessage { let name: String; let summary: String; let fields: [RealtimeField] }
enum RealtimeDecoder {
    static func decode(_ b: [UInt8], tcp: Bool) -> RealtimeMessage? {
        var fields: [RealtimeField] = []
        func u(_ p: Int, _ n: Int) -> UInt64 { b[p..<(p+n)].reduce(0) { ($0 << 8) | UInt64($1) } }
        func add(_ name: String, _ p: Int, _ n: Int, _ value: String? = nil) { fields.append(RealtimeField(name: name, value: value ?? String(u(p,n)), offset: p, length: n)) }
        func result(_ name: String, _ summary: String) -> RealtimeMessage { RealtimeMessage(name: name, summary: summary, fields: fields) }
        if !tcp, b.count >= 4, b[0] >> 6 == 2, (200...207).contains(b[1]) {
            var p = 0; var names: [String] = []
            while p < b.count {
                guard p + 4 <= b.count, b[p] >> 6 == 2, (200...207).contains(b[p+1]) else { return nil }
                let type = Int(b[p+1]), count = Int(b[p] & 31), size = (Int(u(p+2,2))+1)*4
                guard size >= 4, p + size <= b.count else { return nil }
                let pad = b[p] & 32 != 0 ? Int(b[p+size-1]) : 0
                guard pad <= size-4, b[p] & 32 == 0 || (pad > 0 && p+size == b.count) else { return nil }
                let end = p+size-pad
                let name = [200:"Sender Report",201:"Receiver Report",202:"Source Description",203:"Goodbye",204:"Application",205:"Transport Feedback",206:"Payload Feedback",207:"Extended Report"][type]!
                names.append(name); add("Packet Type",p+1,1,name); add("Count / Format",p,1,String(count)); add("Length (words minus one)",p+2,2)
                var q = p+4
                if type == 200 || type == 201 {
                    let base = type == 200 ? 28 : 8
                    guard p+base+count*24 <= end else { return nil }
                    add("Sender SSRC",q,4); q += 4
                    if type == 200 {
                        add("NTP Timestamp",q,8); add("RTP Timestamp",q+8,4); add("Sender Packet Count",q+12,4); add("Sender Octet Count",q+16,4); q += 20
                    }
                    for _ in 0..<count {
                        add("Report SSRC",q,4); add("Fraction Lost",q+4,1,String(format:"%.2f%%", Double(b[q+4])*100/256))
                        let lost = Int(u(q+5,3)); add("Cumulative Lost",q+5,3,String(lost & 0x800000 != 0 ? lost-0x1000000 : lost))
                        add("Extended Highest Sequence",q+8,4); add("Jitter (timestamp units)",q+12,4); add("Last Sender Report",q+16,4); add("Delay Since Last SR (1/65536 s)",q+20,4); q += 24
                    }
                }
                if q < end { add("Report Data",q,end-q,"\(end-q) bytes") }
                if pad > 0 { add("Padding",end,pad,"\(pad) bytes") }; p += size
            }
            return result("RTCP",names.joined(separator:" · "))
        }
        if !tcp, b.count >= 13, (20...24).contains(b[0]), b[1] == 254, [255,253].contains(b[2]) {
            var p = 0; var names: [String] = []
            while p < b.count {
                guard p+13 <= b.count, (20...24).contains(b[p]), b[p+1] == 254, [255,253].contains(b[p+2]) else { return nil }
                let size = Int(u(p+11,2)), end = p+13+size
                guard end <= b.count else { return nil }
                let type = Int(b[p]); let name = [20:"Change Cipher Spec",21:"Alert",22:"Handshake",23:"Application Data",24:"Heartbeat"][type]!
                names.append(name); add("Content Type",p,1,name); add("Version",p+1,2,b[p+2] == 253 ? "DTLS 1.2" : "DTLS 1.0")
                add("Epoch",p+3,2); add("Record Sequence",p+5,6); add("Record Length",p+11,2)
                var q = p+13
                if type == 22 && u(p+3,2) == 0 {
                    while q < end {
                        guard q+12 <= end else { return nil }
                        let total = Int(u(q+1,3)), offset = Int(u(q+6,3)), length = Int(u(q+9,3))
                        guard offset <= total, length <= total-offset, q+12+length <= end else { return nil }
                        add("Handshake Type",q,1,[1:"ClientHello",2:"ServerHello",3:"HelloVerifyRequest",11:"Certificate",14:"ServerHelloDone",16:"ClientKeyExchange",20:"Finished"][Int(b[q])] ?? String(b[q]))
                        add("Handshake Length",q+1,3); add("Message Sequence",q+4,2); add("Fragment Offset",q+6,3); add("Fragment Length",q+9,3)
                        add("Handshake Fragment",q+12,length,"\(length) bytes"); q += 12+length
                    }
                }
                if q < end { add("Record Data",q,end-q,"\(end-q) bytes (possibly encrypted)") }; p = end
            }
            return result("DTLS",names.joined(separator:" · "))
        }
        if b.count >= 4, b[0] >> 6 == 1 {
            let size = Int(u(2,2)), padded = (size+3) & ~3
            if b.count == 4+padded || (!tcp && b.count == 4+size) {
                add("Channel Number",0,2); add("Data Length",2,2); add("Channel Data",4,size,"\(size) bytes")
                if b.count > size+4 { add("Padding",size+4,b.count-size-4,"padding") }
                return result("TURN","Channel \(u(0,2)) · \(size) bytes · heuristic")
            }
        }
        // Parse text by byte offsets to preserve field/byte selection with UTF-8.
        guard let firstEnd = b.indices.dropLast().first(where: { b[$0] == 13 && b[$0+1] == 10 }) else { return nil }
        let first = String(decoding:b[..<firstEnd],as:UTF8.self), parts = first.split(separator:" ")
        let response = parts.count >= 2 && parts[0] == "SIP/2.0" && parts[1].count == 3 && Int(parts[1]) != nil
        let request = parts.count == 3 && parts[2] == "SIP/2.0" && ["INVITE","ACK","BYE","CANCEL","REGISTER","OPTIONS","INFO","PRACK","UPDATE","MESSAGE","SUBSCRIBE","NOTIFY","REFER","PUBLISH"].contains(String(parts[0]))
        guard response || request else { return nil }
        add("Start Line",0,firstEnd,first)
        var p = firstEnd+2; var sdp = false; var bodyLength: Int?; var summary = first
        while p+1 < b.count {
            guard let q = (p..<(b.count-1)).first(where:{ b[$0] == 13 && b[$0+1] == 10 }) else { break }
            if q == p { p += 2; break }
            let line = String(decoding:b[p..<q],as:UTF8.self)
            add("SIP Header",p,q-p,line)
            if let colon = line.firstIndex(of:":") {
                let key = line[..<colon].lowercased(), value = line[line.index(after:colon)...].trimmingCharacters(in:.whitespaces)
                if ["content-type","c"].contains(key) { sdp = value.lowercased().split(separator:";").first == "application/sdp" }
                if ["content-length","l"].contains(key) { bodyLength = Int(value) }
                if ["call-id","i"].contains(key) { summary += " · Call-ID \(value)" }
            }; p = q+2
        }
        let end = p + min(b.count-p,max(0,bodyLength ?? (b.count-p)))
        if sdp {
            while p < end {
                let q = (p..<end).first(where:{ b[$0] == 10 }) ?? end
                let n = q > p && b[q-1] == 13 ? q-p-1 : q-p
                let line = String(decoding:b[p..<(p+n)],as:UTF8.self)
                add("SDP",p,n,line)
                if line.hasPrefix("m=") || line.hasPrefix("a=rtpmap:") || line.hasPrefix("c=") { summary += " · " + line }
                p = min(q+1,end)
            }
        } else if p < end { add("Body",p,end-p,"\(end-p) bytes") }
        return result("SIP",summary)
    }
}
