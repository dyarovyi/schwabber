import SwiftUI
import AppKit
import UniformTypeIdentifiers
import CaptureCore

private typealias PacketState<Value> = SwiftUI.State<Value>

@MainActor enum PacketWindow {
    private static var controller: NSWindowController?
    private static let closeDelegate = InspectorCloseDelegate()
    static func close() { controller?.close(); controller = nil }
    static func open(session: Session, capture: Capture, packetID: Int, timeline: TimelineInspection, onClosed: @escaping () -> Void, onPacketShown: @escaping (Int) -> Void) {
        closeDelegate.closed = onClosed
        let view = PacketWindowView(timeline: timeline, session: session, capture: capture, initialPacketID: packetID, onPacketShown: onPacketShown)
        if let window = controller?.window {
            window.contentView = NSHostingView(rootView: view.id(UUID()))
            window.makeKeyAndOrderFront(nil)
            return
        }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1080, height: 820),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.delegate = closeDelegate
        window.title = "Schwabber — Packet Inspector"
        window.minSize = NSSize(width: 900, height: 650)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: view)
        controller = NSWindowController(window: window)
        window.center(); controller?.showWindow(nil)
    }
}

@MainActor private final class InspectorCloseDelegate: NSObject, NSWindowDelegate {
    var closed: () -> Void = {}
    func windowWillClose(_ notification: Notification) { closed() }
}

private struct PacketWindowView: View {
    let timeline: TimelineInspection
    let session: Session
    let capture: Capture
    let onPacketShown: (Int) -> Void
    @PacketState<NativeDissection> private var native: NativeDissection
    @PacketState<Int?> private var packetID: Int?
    @PacketState<Bool> private var includeHeaders = true
    @PacketState<String> private var sourceID = "frame"
    @PacketState<URL?> private var keyLog: URL?
    @PacketState<Bool> private var choosingKeys = false
    @PacketState<PacketDissection?> private var dissection: PacketDissection?
    @PacketState<String?> private var error: String?
    @PacketState<Bool> private var loading = false
    @PacketState<Bool> private var asText = false
    @PacketState<Set<String>> private var expanded: Set<String> = []
    @PacketState<String?> private var selectedPath: String?
    @PacketState<Bool> private var useWireshark = true
    @PacketState<UUID?> private var selectedWiresharkField: UUID?
    @PacketState<Set<UUID>> private var expandedWireshark: Set<UUID> = []
    init(timeline: TimelineInspection, session: Session, capture: Capture, initialPacketID: Int, onPacketShown: @escaping (Int) -> Void) {
        self.timeline = timeline
        self.onPacketShown = onPacketShown
        _native = PacketState(initialValue: NativeDissector.dissect(session.packets.first { $0.id == initialPacketID } ?? session.packets[0], linkType: capture.linkType))
        self.session = session; self.capture = capture
        _packetID = PacketState(initialValue: initialPacketID)
    }
    private var index: Int { session.packets.firstIndex { $0.id == packetID } ?? 0 }
    private var packet: Packet { session.packets[index] }
    private var source: PacketDataSource? { dissection?.additionalSources.first { $0.id == sourceID } }
    private var bytes: Data { source?.bytes ?? (includeHeaders ? packet.rawBytes : packet.payload) }
    private var selectedField: NativeField? { native.fields.first { $0.id == selectedPath && (includeHeaders || $0.kind == "payload") } }
    private var taskID: String { "\(packet.id)|\(keyLog?.path ?? "")|\(useWireshark)" }
    private var positionText: String {
        var text = "Packet #\(packet.id) · \(index + 1) of \(session.packets.count) in session"
        if let chunk = timeline.chunks(session: session, capture: capture).first(where: { index >= $0.start && index < $0.start + $0.count }), chunk.count > 1 {
            text += " · \(index - chunk.start + 1) of \(chunk.count) in chunk"
        }
        return text + String(format: " · +%.6f s", packet.time - capture.start)
    }
    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Button { navigate(-1) } label: { Label("Previous", systemImage: "chevron.left") }.disabled(index == 0)
                    .keyboardShortcut(.leftArrow, modifiers: [.command])
                Button { navigate(1) } label: { Label("Next", systemImage: "chevron.right") }.disabled(index + 1 == session.packets.count)
                    .keyboardShortcut(.rightArrow, modifiers: [.command])
                Text(positionText).monospacedDigit()
                Spacer()
                Toggle("Include headers", isOn: $includeHeaders).toggleStyle(.checkbox)
                    .help("Show link, IP and TCP/UDP headers for captured frames. Application headers stay in payload. Reassembled/decrypted sources are shown exactly as Wireshark provides them.")
            }
            HStack {
                Text("\(packet.source) → \(packet.destination)").font(.headline).textSelection(.enabled)
                Spacer()
                Text(session.protocolLabel).foregroundStyle(.secondary)
            }
            HStack(spacing: 8) {
                sizeCard("WITH HEADERS", packet.length, "\(packet.rawBytes.count) bytes captured")
                sizeCard("WITHOUT HEADERS", native.payloadWireLength, "\(native.payloadRange.count) payload bytes captured")
                sizeCard("HEADERS", native.headerLength + native.trailerLength,
                         native.headerParts.map { "\($0.0) \($0.1)" }.joined(separator: " + ") + (native.trailerLength > 0 ? " + trailer \(native.trailerLength)" : ""))
            }
            HStack {
                Toggle("Wireshark analysis", isOn: $useWireshark).toggleStyle(.checkbox)
                    .help("Optional full-capture analysis for reassembly/decryption. Built-in fields and byte selection work without Wireshark.")
                Button("Choose TLS key log…") { choosingKeys = true }
                if let keyLog {
                    Text(keyLog.lastPathComponent).font(.caption)
                    Button("Clear keys") { self.keyLog = nil }
                }
                Spacer()
                if loading { ProgressView().controlSize(.small); Text("Analyzing capture…").font(.caption) }
            }
            if let error { Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            if packet.rawBytes.count < packet.length { Text("Capture truncated: some on-wire bytes are unavailable.").font(.caption).foregroundStyle(.orange) }
            VSplitView {
                VStack(alignment: .leading) {
                    Text(useWireshark ? "Packet details · Wireshark" : "Packet details · Built-in analyzer").font(.caption.bold())
                    if useWireshark, let dissection {
                        ScrollViewReader { reader in
                            List {
                                ForEach(wiresharkRows(dissection.fields), id: \.field.id) { row in
                                    HStack(spacing: 4) {
                                        if row.field.children != nil {
                                            Button {
                                                if !expandedWireshark.insert(row.field.id).inserted { expandedWireshark.remove(row.field.id) }
                                            } label: { Image(systemName: expandedWireshark.contains(row.field.id) ? "chevron.down" : "chevron.right").frame(width: 14) }
                                                .buttonStyle(.plain)
                                        } else { Color.clear.frame(width: 14, height: 1) }
                                        Text(row.field.label).font(.system(size: 12, design: .monospaced))
                                        Spacer(minLength: 0)
                                    }.padding(.leading, CGFloat(row.depth) * 15)
                                        .contentShape(Rectangle())
                                        .background(selectedWiresharkField == row.field.id ? Color.accentColor.opacity(0.2) : .clear)
                                        .onTapGesture { selectWiresharkField(row.field) }
                                        .contextMenu { FieldCopyMenu(label: row.field.label, bytes: fieldBytes(row.field)) }
                                        .id(row.field.id)
                                }
                            }.onChange(of: selectedWiresharkField) { _, id in if let id { reader.scrollTo(id) } }
                        }
                    } else {
                        ScrollViewReader { reader in
                            List {
                                ForEach(visibleFields(), id: \.field.id) { row in
                                    HStack(spacing: 4) {
                                        if !row.field.children.isEmpty {
                                            Button { if !expanded.insert(row.field.id).inserted { expanded.remove(row.field.id) } } label: {
                                                Image(systemName: expanded.contains(row.field.id) ? "chevron.down" : "chevron.right").frame(width: 14)
                                            }.buttonStyle(.plain)
                                        } else { Color.clear.frame(width: 14, height: 1) }
                                        Text(row.field.label).font(.system(size: 12, design: .monospaced))
                                            .foregroundStyle(row.field.hasBytes ? .primary : .secondary)
                                        Spacer(minLength: 0)
                                    }.padding(.leading, CGFloat(row.depth) * 15)
                                        .padding(.vertical, 2).contentShape(Rectangle())
                                        .background(selectedPath == row.field.id ? Color.accentColor.opacity(0.2) : .clear)
                                        .onTapGesture { selectedPath = row.field.id }
                                        .contextMenu { FieldCopyMenu(label: row.field.label, bytes: nativeFieldBytes(row.field)) }
                                        .id(row.field.id)
                                }
                            }.onChange(of: selectedPath) { _, path in if let path { reader.scrollTo(path) } }
                        }
                    }
                }.frame(minHeight: 180, idealHeight: 330)
                    .onCopyCommand {
                        let label = useWireshark ? wiresharkSelection?.label : selectedField?.label
                        return label.map { [NSItemProvider(object: $0 as NSString)] } ?? []
                    }
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Picker("Data source", selection: $sourceID) {
                            Text(includeHeaders ? "Captured frame" : "Captured transport payload").tag("frame")
                            ForEach(dissection?.additionalSources ?? []) { source in Text(source.name).tag(source.id) }
                        }.frame(maxWidth: 600)
                            .onChange(of: sourceID) { _, _ in
                                if wiresharkSelection?.sourceIndex != activeSourceIndex { selectedWiresharkField = nil }
                                for field in allWiresharkFields where field.sourceIndex == activeSourceIndex && field.children != nil {
                                    expandedWireshark.insert(field.id)
                                }
                            }
                        Spacer()
                        Toggle("ASCII only", isOn: $asText).toggleStyle(.checkbox)
                    }
                    if source != nil {
                        Text("Wireshark data source · \(bytes.count) bytes · already reassembled/decrypted where applicable; header toggle applies to the captured frame.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Reassembled/decrypted sources appear here when Wireshark produces them for this frame. Some segments reference a later reassembly frame in Packet details.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    PacketHexView(bytes: source?.bytes ?? packet.rawBytes,
                                  range: source.map { 0..<$0.bytes.count } ?? (includeHeaders ? 0..<packet.rawBytes.count : native.payloadRange),
                                  payloadRange: source.map { 0..<$0.bytes.count } ?? native.payloadRange,
                                  selection: useWireshark && dissection != nil ? selectedWiresharkRange : selectedField.map { $0.offset..<($0.offset + $0.length) },
                                  describe: { offset in
                                      if useWireshark, dissection != nil { return wiresharkField(at: offset)?.label ?? "Source byte \(offset)" }
                                      return native.field(at: offset)?.label ?? "Frame byte \(offset)"
                                  },
                                  clicked: { offset in
                                      if useWireshark, dissection != nil {
                                          if let field = wiresharkField(at: offset) { selectWiresharkField(field) }
                                      } else if let field = native.field(at: offset) {
                                          for ancestor in native.fields where field.id.hasPrefix(ancestor.id + " › ") { expanded.insert(ancestor.id) }
                                          selectedPath = field.id
                                      }
                                  }, textOnly: asText)
                        .overlay {
                            if source == nil && !includeHeaders && native.payloadRange.isEmpty {
                                Text("This packet has no payload. Turn on Include headers to see its bytes.").foregroundStyle(.secondary).padding()
                            }
                        }
                }.frame(minHeight: 150, idealHeight: 220)
            }
            Divider()
            VStack(alignment: .leading, spacing: 3) {
                Text(useWireshark ? (wiresharkSelection?.label ?? "Click a byte or a field to see what it is.") : (selectedField?.id ?? "Click a byte or a field to see what it is.")).font(.caption.bold())
                Text(useWireshark ? (selectedWiresharkRange.map { "Source bytes \($0.lowerBound)–\($0.upperBound - 1) · \($0.count) bytes" } ?? "Generated fields have no selectable bytes.") : (selectedField.map { "\($0.label) · \(rangeText($0))" } ?? "Hover over bytes for a description. Header bytes are shaded gray."))
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
        }.padding(12)
        .background(PacketNavigationKeys(navigate: navigate).frame(width: 0, height: 0))
        .fileImporter(isPresented: $choosingKeys, allowedContentTypes: [.data, .plainText]) { result in
            switch result { case .success(let url): keyLog = url; useWireshark = true; case .failure(let failure): error = failure.localizedDescription }
        }
        .task(id: taskID) {
            guard useWireshark else { loading = false; error = nil; dissection = nil; sourceID = "frame"; return }
            loading = true; error = nil; dissection = nil; sourceID = "frame"
            selectedWiresharkField = nil; expandedWireshark = []; selectedPath = nil
            do {
                let result = try await WiresharkInspection.inspect(packet: packet, capture: capture, keyLog: keyLog)
                guard !Task.isCancelled else { return }
                dissection = result
                expandedWireshark = Set(result.fields.map(\.id))
            } catch {
                guard !Task.isCancelled else { return }
                self.error = error.localizedDescription
            }
            loading = false
        }
    }
    private var activeSourceIndex: Int {
        guard let index = dissection?.additionalSources.firstIndex(where: { $0.id == sourceID }) else { return 0 }
        return index + 1
    }
    private var allWiresharkFields: [PacketField] {
        func flatten(_ fields: [PacketField]) -> [PacketField] { fields.flatMap { [$0] + flatten($0.children ?? []) } }
        return flatten(dissection?.fields ?? [])
    }
    private var wiresharkSelection: PacketField? { allWiresharkFields.first { $0.id == selectedWiresharkField } }
    private var selectedWiresharkRange: Range<Int>? {
        guard let field = wiresharkSelection, field.sourceIndex == activeSourceIndex else { return nil }
        return field.byteRange
    }
    private func wiresharkField(at offset: Int) -> PacketField? {
        // Prefer the most specific field, with later/deeper nodes winning ties.
        allWiresharkFields.filter { $0.sourceIndex == activeSourceIndex && ($0.byteRange?.contains(offset) ?? false) }
            .reversed().min { ($0.byteRange?.count ?? Int.max) < ($1.byteRange?.count ?? Int.max) }
    }
    private func selectWiresharkField(_ field: PacketField) {
        selectedWiresharkField = field.id
        if field.byteRange != nil {
            if field.sourceIndex == 0 {
                sourceID = "frame"
                if let range = field.byteRange, !native.payloadRange.contains(range.lowerBound) || range.upperBound > native.payloadRange.upperBound { includeHeaders = true }
            } else if let sources = dissection?.additionalSources, sources.indices.contains(field.sourceIndex - 1) {
                sourceID = sources[field.sourceIndex - 1].id
            }
        }
        func expand(_ nodes: [PacketField]) -> Bool {
            for node in nodes {
                if node.id == field.id { return true }
                if expand(node.children ?? []) { expandedWireshark.insert(node.id); return true }
            }
            return false
        }
        _ = expand(dissection?.fields ?? [])
    }
    private func wiresharkRows(_ nodes: [PacketField], depth: Int = 0) -> [(field: PacketField, depth: Int)] {
        nodes.flatMap { field in
            [(field: field, depth: depth)] + (expandedWireshark.contains(field.id) ? wiresharkRows(field.children ?? [], depth: depth + 1) : [])
        }
    }
    private func fieldBytes(_ field: PacketField) -> Data {
        let data: Data
        if field.sourceIndex == 0 { data = packet.rawBytes }
        else if let sources = dissection?.additionalSources, sources.indices.contains(field.sourceIndex - 1) { data = sources[field.sourceIndex - 1].bytes }
        else { return Data() }
        guard let range = field.byteRange, range.lowerBound >= 0, range.upperBound <= data.count else { return Data() }
        return data.subdata(in: range)
    }
    private func nativeFieldBytes(_ field: NativeField) -> Data {
        guard field.hasBytes, field.offset >= 0, field.offset <= packet.rawBytes.count,
              field.length <= packet.rawBytes.count - field.offset else { return Data() }
        return packet.rawBytes.subdata(in: field.offset..<(field.offset + field.length))
    }
    private func sizeCard(_ title: String, _ value: Int, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption2).foregroundStyle(.secondary)
            Text("\(value.formatted()) bytes").font(.title3.bold()).monospacedDigit()
            Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).help(detail)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(10).background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 6))
    }
    private func rangeText(_ field: NativeField) -> String {
        guard field.hasBytes else { return "Generated information; no frame bytes" }
        var text = "Frame bytes \(field.offset)–\(field.offset + field.length - 1) (0x\(String(field.offset, radix: 16))) · \(field.length) bytes"
        if field.offset >= native.payloadRange.lowerBound && field.offset < native.payloadRange.upperBound {
            text += " · payload bytes \(field.offset - native.payloadRange.lowerBound)–\(field.offset + field.length - 1 - native.payloadRange.lowerBound)"
        } else if field.kind == "header" { text += " · header" }
        return text
    }
    private func visibleFields() -> [(field: NativeField, depth: Int)] {
        func visit(_ nodes: [NativeField], _ depth: Int) -> [(field: NativeField, depth: Int)] {
            nodes.flatMap { field in [(field: field, depth: depth)] + (expanded.contains(field.id) ? visit(field.children, depth + 1) : []) }
        }
        return visit(native.layers.filter { includeHeaders || $0.kind == "payload" }, 0)
    }
    private func navigate(_ delta: Int) {
        let next = index + delta
        if session.packets.indices.contains(next) {
            native = NativeDissector.dissect(session.packets[next], linkType: capture.linkType)
            packetID = session.packets[next].id
            onPacketShown(session.packets[next].id)
        }
    }
}
