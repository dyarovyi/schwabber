import SwiftUI
import AppKit
import CaptureCore

@MainActor enum TCPStreamWindow {
    private static var controller: NSWindowController?
    static func open(session: Session, linkType: Int32) {
        let window = controller?.window ?? NSWindow(contentRect: NSRect(x:0,y:0,width:900,height:650), styleMask:[.titled,.closable,.resizable,.miniaturizable], backing:.buffered, defer:false)
        window.title = "Reassembled TCP — Schwabber"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: TCPStreamView(session:session,linkType:linkType).id(UUID()))
        if controller == nil { controller = NSWindowController(window:window); window.center() }
        window.makeKeyAndOrderFront(nil)
    }
}
private typealias StreamState<Value> = SwiftUI.State<Value>
private struct TCPStreamView: View {
    let session: Session
    let linkType: Int32
    @StreamState<[TCPDirection]> private var directions: [TCPDirection] = []
    @StreamState<Int> private var direction = 0
    @StreamState<Int> private var chunk = 0
    @StreamState<Bool> private var loading = true
    @StreamState<Bool> private var text = false
    @StreamState<String?> private var error: String?
    private var current: TCPDirection? { directions.indices.contains(direction) ? directions[direction] : nil }
    private var data: Data { current?.chunks.first(where: { $0.id == chunk })?.bytes ?? Data() }
    var body: some View {
        VStack(alignment:.leading,spacing:10) {
            Text("TCP wire bytes · TLS content remains encrypted").font(.headline)
            Text("Directions are separate. Gaps stay separate; overlapping bytes are kept from the first segment in sequence order. Offsets start at the first captured data byte. Connections spanning more than 2 GiB of sequence space are not supported.").font(.caption).foregroundStyle(.secondary)
            if loading { ProgressView("Reassembling…") }
            else if directions.isEmpty { Text("No captured TCP payload in this session.") }
            else {
                Picker("Direction",selection:$direction) {
                    ForEach(directions.indices,id:\.self) { i in Text("\(directions[i].source) → \(directions[i].destination)").tag(i) }
                }.onChange(of:direction) { _,_ in chunk = 0 }
                if let current {
                    Text("\(current.missingBytes) missing bytes between chunks · \(current.overlapBytes) overlapping bytes · \(current.conflictingBytes) conflicting bytes")
                        .font(.caption).foregroundStyle(current.missingBytes > 0 || current.conflictingBytes > 0 ? .orange : .secondary)
                    Picker("Contiguous chunk",selection:$chunk) {
                        ForEach(current.chunks) { c in Text("Offset \(c.offset) · \(c.bytes.count) bytes").tag(c.id) }
                    }
                }
                HStack {
                    Toggle("Text preview",isOn:$text).toggleStyle(.checkbox)
                    Spacer()
                    Button("Save chunk…") { save() }.disabled(data.isEmpty)
                }
                if text {
                    ScrollView { Text(String(decoding:data.prefix(65536),as:UTF8.self)).font(.system(size:12,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading) }
                    if data.count > 65536 { Text("Preview limited to 64 KiB; Save chunk exports all bytes.").font(.caption) }
                } else {
                    PacketHexView(bytes:data,range:0..<data.count,payloadRange:0..<data.count,selection:nil,describe:{ "Stream chunk byte \($0)" },clicked:{ _ in })
                }
            }
            if let error { Text(error).foregroundStyle(.red) }
        }.padding(14).frame(minWidth:750,minHeight:450)
        .task {
            directions = await Task.detached(priority:.userInitiated) { TCPReassembly.reassemble(session,linkType:linkType) }.value
            loading = false
        }
    }
    private func save() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "TCP-direction-\(direction)-chunk-\(chunk).bin"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try data.write(to:url,options:.atomic) } catch { self.error = error.localizedDescription }
    }
}
