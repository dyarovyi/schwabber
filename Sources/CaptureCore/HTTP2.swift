import Foundation

enum HTTP2Decoder {
    static func decode(_ b: [UInt8]) -> RealtimeMessage? {
        let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        let hasPreface = b.starts(with: preface)
        var p = hasPreface ? preface.count : 0
        var fields: [RealtimeField] = [], names: [String] = []
        func u(_ p: Int, _ n: Int) -> Int { b[p..<(p+n)].reduce(0) { ($0 << 8) | Int($1) } }
        func add(_ name: String, _ at: Int, _ size: Int, _ value: String? = nil) { fields.append(RealtimeField(name: name, value: value ?? String(u(at,size)), offset: at, length: size)) }
        if hasPreface { add("Connection Preface",0,p,"HTTP/2") }
        while p < b.count {
            guard p+9 <= b.count else { return hasPreface ? RealtimeMessage(name:"HTTP/2",summary:"Connection preface · partial frame header",fields:fields) : nil }
            let length = u(p,3), type = Int(b[p+3]), flags = Int(b[p+4]), stream = u(p+5,4)&0x7fffffff
            guard type <= 9 else { return nil }
            if [0,1,2,3,5,9].contains(type) && stream == 0 { return nil }
            if [4,6,7].contains(type) && stream != 0 { return nil }
            if type == 2 && length != 5 || type == 3 && length != 4 || type == 6 && length != 8 || type == 8 && length != 4 || type == 7 && length < 8 || type == 4 && (length % 6 != 0 || flags & 1 != 0 && length != 0) { return nil }
            let name = ["DATA","HEADERS","PRIORITY","RST_STREAM","SETTINGS","PUSH_PROMISE","PING","GOAWAY","WINDOW_UPDATE","CONTINUATION"][type]
            names.append("\(name) stream \(stream)")
            add("Frame Length",p,3); add("Frame Type",p+3,1,name); add("Flags",p+4,1,String(format:"0x%02x",flags)); add("Stream ID",p+5,4,String(stream))
            let end = p+9+length, body = p+9
            guard end <= b.count else {
                guard hasPreface else { return nil }
                if body < b.count { add("Partial Frame Payload",body,b.count-body,"\(length) bytes expected") }
                break
            }
            if type == 4 {
                for q in stride(from:body,to:end,by:6) { add("Setting ID",q,2); add("Setting Value",q+2,4) }
            } else if type == 8 { add("Window Increment",body,4,String(u(body,4)&0x7fffffff)) }
            else if type == 3 { add("Error Code",body,4) }
            else if type == 7 {
                add("Last Stream ID",body,4,String(u(body,4)&0x7fffffff)); add("Error Code",body+4,4)
                if length > 8 { add("Debug Data",body+8,length-8,"\(length-8) bytes") }
            } else if length > 0 { add([1,5,9].contains(type) ? "Header Block / Frame Payload (HPACK not decoded)" : "Frame Payload",body,length,"\(length) bytes") }
            p = end
        }
        guard hasPreface || !names.isEmpty else { return nil }
        return RealtimeMessage(name:"HTTP/2",summary:names.isEmpty ? "Connection preface" : names.joined(separator:" · "),fields:fields)
    }
}
