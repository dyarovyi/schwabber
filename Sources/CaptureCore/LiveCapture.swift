import Foundation
import CPcap

public struct CaptureInterface: Identifiable, Sendable {
    public let id: String
    public let label: String
    public var preferred: Bool = false
}

/// Only the stop flag crosses threads; libpcap handles belong to the capture worker.
public final class LiveCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    public init() {}
    public func stop() { lock.lock(); stopped = true; lock.unlock() }
    private var shouldStop: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
    public static func interfaces() throws -> [CaptureInterface] {
        var error = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        var list: UnsafeMutablePointer<pcap_if_t>?
        guard pcap_findalldevs(&list, &error) == 0 else { throw CaptureError.read(String(decoding: error.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)) }
        defer { pcap_freealldevs(list) }
        var result: [CaptureInterface] = []; var cursor = list
        while let item = cursor {
            let name = String(cString: item.pointee.name)
            let description = item.pointee.description.map { String(cString: $0) } ?? name
            let flags = item.pointee.flags
            let preferred = flags & UInt32(PCAP_IF_LOOPBACK) == 0 && flags & UInt32(PCAP_IF_UP) != 0 && flags & UInt32(PCAP_IF_RUNNING) != 0 && item.pointee.addresses != nil
            result.append(CaptureInterface(id: name, label: description == name ? name : "\(name) — \(description)", preferred: preferred))
            cursor = item.pointee.next
        }
        return result
    }
    public func run(interface: String, url: URL, update: @escaping @Sendable (Capture, UInt32) async -> Void) async throws {
        var error = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
        guard let handle = pcap_open_live(interface, 262144, 0, 100, &error) else {
            throw CaptureError.read("Cannot capture on \(interface): \(String(decoding: error.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)). macOS requires access to /dev/bpf devices. Install Wireshark’s ChmodBPF helper if access is denied, then restart Schwabber.")
        }
        defer { pcap_close(handle) }
        let link = pcap_datalink(handle)
        guard [1,0,108,12,101,113,276].contains(link) else { throw CaptureError.read("This interface uses unsupported link type \(link). Choose another interface.") }
        guard pcap_setnonblock(handle, 1, &error) == 0 else { throw CaptureError.read(String(decoding: error.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)) }
        guard let dump = pcap_dump_open(handle, url.path) else { throw CaptureError.read(String(cString: pcap_geterr(handle))) }
        defer { pcap_dump_close(dump) }
        var builder = LiveCaptureBuilder(url: url, link: link)
        var next = Date.distantPast
        var publishedTotal = -1
        var header: UnsafeMutablePointer<pcap_pkthdr>?
        var bytes: UnsafePointer<UInt8>?
        while !shouldStop && !Task.isCancelled {
            for _ in 0..<256 {
                let status = pcap_next_ex(handle, &header, &bytes)
                if status == 0 { break }
                guard status == 1, let header, let bytes else { throw CaptureError.read(String(cString: pcap_geterr(handle))) }
                pcap_dump(UnsafeMutableRawPointer(dump).assumingMemoryBound(to: UInt8.self), header, bytes)
                let h = header.pointee
                builder.append(Data(bytes: bytes, count: Int(h.caplen)), wire: Int(h.len), seconds: UInt32(clamping: h.ts.tv_sec), microseconds: UInt32(clamping: h.ts.tv_usec))
            }
            if Date() >= next {
                guard pcap_dump_flush(dump) == 0 else { throw CaptureError.read("Unable to write recording. Check free disk space. The partial recording remains at \(url.path).") }
                var stats = pcap_stat(); _ = pcap_stats(handle, &stats)
                if builder.total != publishedTotal {
                    await update(builder.capture, stats.ps_drop)
                    publishedTotal = builder.total
                }
                next = Date().addingTimeInterval(0.5)
            }
            try? await Task.sleep(for: .milliseconds(10))
        }
        guard pcap_dump_flush(dump) == 0 else { throw CaptureError.read("Unable to flush recording to disk.") }
        var stats = pcap_stat(); _ = pcap_stats(handle, &stats)
        await update(builder.capture, stats.ps_drop)
    }
}

struct LiveCaptureBuilder {
    let url: URL
    let link: Int32
    var sessions: [Session] = []
    var active: [String: Int] = [:]
    var total = 0, bytes = 0, skipped = 0
    var capture: Capture { Capture(sessions: sessions, sourceURL: url, linkType: link, totalBytes: bytes, totalPackets: total, skippedPackets: skipped) }
    mutating func append(_ data: Data, wire: Int, seconds: UInt32, microseconds: UInt32) {
        total += 1; bytes += wire
        guard let d = CaptureReader.decode(Array(data), link: Int(link)) else { skipped += 1; return }
        let time = Double(seconds) + Double(microseconds)/1_000_000
        let packet = Packet(id: total, time: time, source: d.1, destination: d.2, length: wire, flags: d.3, dns: d.4, application: d.5, rawBytes: data, payloadRange: d.6, seconds: seconds, microseconds: microseconds)
        let key = d.0 + "|" + [d.1,d.2].sorted().joined(separator: "|")
        if let index = active[key], time - sessions[index].end <= 60 {
            sessions[index].append(packet)
        } else {
            active[key] = sessions.count
            sessions.append(Session(id: sessions.count, transport: d.0, endpointA: d.1, endpointB: d.2, packets: [packet]))
        }
    }
}
