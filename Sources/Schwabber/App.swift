import SwiftUI
import AppKit
import UniformTypeIdentifiers
import CaptureCore

private typealias ViewState<Value> = SwiftUI.State<Value>

@main
struct SchwabberApp: App {
    @NSApplicationDelegateAdaptor(AppLifecycle.self) private var lifecycle
    var body: some Scene {
        WindowGroup("Schwabber") { ContentView() }
        .defaultSize(width: 600, height: 420)
        .commands { AppMenus() }
    }
}

struct ContentView: View {
    @ViewState<Capture?> private var capture: Capture?
    @ViewState<String> private var filename = ""
    @ViewState<Int?> private var selected: Int?
    @ViewState<Int?> private var inspectedPacketID: Int?
    @ViewState<Set<Int>> private var selectedIDs: Set<Int> = []
    @ViewState<Bool> private var exporting = false
    @ViewState<String?> private var exportStatus: String?
    @ViewState<String> private var query = ""
    private let protocols = ["TCP", "UDP", "ICMP", "ICMPv6", "DNS", "RTP", "RTCP", "SIP", "DTLS", "TURN", "STUN", "HTTP", "HTTP/2", "TLS", "QUIC"]
    @ViewState<Bool> private var showingProtocols = false
    @ViewState<Set<String>> private var enabledProtocols: Set<String> = ["All"]
    @ViewState<Double> private var zoom = 1.0
    @ViewState<Bool> private var importing = false
    @ViewState<Bool> private var loading = false
    @ViewState<String?> private var failure: String?
    @ViewState<Int> private var firstVisibleRow = 0
    @ViewState private var timelineHeaderPosition = TimelineHeaderPosition()
    @ViewState<CGFloat?> private var resizeOrigin: CGFloat?
    @ViewState<Bool> private var openedArgument = false
    @ViewState<Recording> private var recording = Recording()
    @ViewState<CGFloat> private var labelWidth: CGFloat = 370
    @ViewState<String> private var sessionSort = "Chronological"
    @AppStorage("showEndpoints") private var showEndpoints = true
    @ViewState private var pins: [TimelinePin] = []
    @ViewState private var hoveredPin: TimelinePin?
    @ViewState private var dropTargeted = false
    @ViewState private var timelineScroll = TimelineScrollController()
    @ViewState private var timelineInspection = TimelineInspection()
    private var rowHeight: CGFloat { showEndpoints ? 36 : 23 }
    private var rowStride: CGFloat { rowHeight + 1 }
    private var timelineDuration: Double { max(2, (capture?.end ?? 0) - (capture?.start ?? 0)) }
    private var maximumZoom: Double { timelineDuration / 2 }
    private var expandedWindow: Bool { capture != nil || recording.running }
    private var sessions: [Session] {
        let filter = SessionFilter(query)
        let filtered = capture?.sessions.filter {
            (enabledProtocols.contains("All") || enabledProtocols.contains($0.transport) || !enabledProtocols.isDisjoint(with: $0.applicationProtocols)) && filter.matches($0)
        } ?? []
        return filtered.sorted {
            if sessionSort == "Largest first", $0.bytes != $1.bytes { return $0.bytes > $1.bytes }
            if $0.start != $1.start { return $0.start < $1.start }
            return $0.id < $1.id
        }
    }
    private var selection: Session? { capture?.sessions.first { $0.id == selected } }
    private var selectedBytes: Int {
        capture?.sessions.filter { selectedIDs.contains($0.id) }.reduce(0) { $0 + $1.bytes } ?? 0
    }
    private func sizeDescription(_ bytes: Int) -> String {
        "\(bytes.formatted()) bytes (\(String(format: "%.2f", Double(bytes) / 1000)) kB)"
    }
    var body: some View {
        let shownSessions = sessions
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                if !filename.isEmpty {
                    Text(filename).font(.headline).lineLimit(1).truncationMode(.middle)
                }
                if let capture { Text("\(capture.totalPackets) packets · \(capture.sessions.count) sessions").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                if loading || exporting { ProgressView().controlSize(.small) }
                if recording.running {
                    Text("Recording · \(recording.dropped) dropped").font(.caption).foregroundStyle(.red)
                    Button("Stop", systemImage: "stop.fill") { recording.stop() }.disabled(recording.stopping)
                }
            }.frame(minHeight: filename.isEmpty ? 65 : 0)
                .overlay {
                    if filename.isEmpty {
                        Text("𝔖𝔠𝔥𝔴𝔞𝔟𝔟𝔢𝔯")
                            .font(.system(size: 51, design: .serif))
                            .accessibilityLabel("Schwabber")
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 7)
            Divider()
            if let capture {
                HStack {
                    TextField("Filter IP, port, details, payload text or x00x01…", text: $query).textFieldStyle(.roundedBorder).frame(maxWidth: 420)
                        .help("Text searches metadata and exact UTF-8 payload bytes. Hex uses x00x01xFF notation. Matches stay within individual packet payloads.")
                    Button {
                        showingProtocols.toggle()
                    } label: {
                        Label(enabledProtocols.contains("All") ? "Protocols: All" : "Protocols: \(enabledProtocols.count)", systemImage: "line.3.horizontal.decrease")
                    }.frame(width: 150)
                    .popover(isPresented: $showingProtocols, arrowEdge: .bottom) {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Display protocols").font(.headline)
                            Toggle("All", isOn: Binding(get: { enabledProtocols.contains("All") }, set: { enabledProtocols = $0 ? ["All"] : [] })).toggleStyle(.checkbox)
                            Divider()
                            LazyVGrid(columns: [GridItem(.fixed(110), alignment: .leading), GridItem(.fixed(110), alignment: .leading)], alignment: .leading, spacing: 10) {
                                ForEach(protocols, id: \.self) { name in
                                    Toggle(name, isOn: Binding(get: { enabledProtocols.contains("All") || enabledProtocols.contains(name) }, set: { on in
                                        if enabledProtocols.contains("All") { enabledProtocols = Set(protocols) }
                                        if on { enabledProtocols.insert(name) } else { enabledProtocols.remove(name) }
                                        if enabledProtocols == Set(protocols) { enabledProtocols = ["All"] }
                                    })).toggleStyle(.checkbox)
                                }
                            }
                            HStack {
                                Button("Clear") { enabledProtocols.removeAll() }
                                Spacer()
                                Button("Done") { showingProtocols = false }.keyboardShortcut(.defaultAction)
                            }
                        }.padding(16).frame(width: 260)
                    }
                    if SessionFilter(query).invalidHex { Text("Invalid hex").font(.caption).foregroundStyle(.red) }
                    Spacer()
                    Picker("Sort", selection: $sessionSort) {
                        Text("Chronological").tag("Chronological")
                        Text("Largest first").tag("Largest first")
                    }.frame(width: 175)
                    Text("Zoom").foregroundStyle(.secondary)
                    TimelineZoom(value: $zoom, maximum: maximumZoom).frame(width: 140)
                    Text("\(sessions.count) shown · \(selectedIDs.count) selected").font(.caption).monospacedDigit().help("Selected: \(sizeDescription(selectedBytes))")
                }.padding(.horizontal, 12).padding(.vertical, 6)
                if let exportStatus {
                    Text(exportStatus).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).help(exportStatus)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 12).padding(.bottom, 8)
                }
                VSplitView {
                    GeometryReader { geometry in
                        let columnWidth = min(labelWidth, max(220, geometry.size.width - 260))
                        let width = max(1, geometry.size.width - columnWidth - 12) * min(zoom, maximumZoom)
                        let duration = timelineDuration
                        let axis = TimeAxis(duration: duration, width: width)
                        let lower = max(0, min(max(0, shownSessions.count - Int(geometry.size.height / rowStride) - 20), firstVisibleRow - 8))
                        let upper = min(shownSessions.count, lower + Int(geometry.size.height / rowStride) + 20)
                        let visibleSessions = Array(shownSessions[lower..<upper])
                        ScrollView(.vertical) {
                            HStack(alignment: .top, spacing: 0) {
                                VStack(spacing: 0) {
                                    PinnedTimelineHeader(position: timelineHeaderPosition) {
                                        Text("SESSION / ENDPOINTS").font(.caption.bold()).frame(maxWidth: .infinity, alignment: .leading).frame(height: 38)
                                    }.zIndex(1)
                                    Color.clear.frame(height: CGFloat(lower) * rowStride)
                                    ForEach(visibleSessions) { session in
                                        let share = capture.totalBytes > 0 ? Double(session.bytes) / Double(capture.totalBytes) : 0
                                        VStack(alignment: .leading, spacing: 2) {
                                            HStack {
                                                Button { toggle(session.id) } label: {
                                                    Image(systemName: selectedIDs.contains(session.id) ? "checkmark.square.fill" : "square")
                                                }.buttonStyle(.plain).accessibilityLabel("Select session \(session.id + 1)")
                                                Text("#\(session.id + 1)").font(.caption).foregroundStyle(.secondary)
                                                Text(session.protocolLabel).font(.caption.bold()).foregroundStyle(color(session))
                                                Text("\(session.packets.count) packets").font(.caption).foregroundStyle(.secondary)
                                                Spacer()
                                                Text(share > 0 && share < 0.001 ? "<0.1%" : String(format: share < 0.1 ? "%.1f%%" : "%.0f%%", share * 100)).font(.caption.monospacedDigit())
                                            }
                                            if showEndpoints { Text("\(session.endpointA) ↔ \(session.endpointB)")
                                                .font(.system(size: 11, design: .monospaced)).lineLimit(1).truncationMode(.middle) }
                                        }.padding(.horizontal, 8).frame(width: columnWidth, height: rowHeight, alignment: .leading)
                                        .background(alignment: .leading) { color(session).opacity(0.45).frame(width: share > 0 ? max(2, columnWidth * share) : 0) }
                                        .background(selectedIDs.contains(session.id) ? Color.accentColor.opacity(0.12) : Color.clear)
                                        .background(Color(nsColor: .windowBackgroundColor))
                                        .help(String(format: "%.2f%% of all capture bytes (%@ bytes)", share * 100, session.bytes.formatted()))
                                        .contentShape(Rectangle()).onTapGesture { select(session.id) }
                                        .contextMenu { sessionMenu(session) }
                                        Divider().frame(height: 1)
                                    }
                                    Color.clear.frame(height: CGFloat(shownSessions.count - upper) * rowStride)
                                }.frame(width: columnWidth).clipped()
                                ZStack(alignment: .top) {
                                    Color(nsColor: .separatorColor).opacity(0.35)
                                    Image(systemName: "arrow.left.and.right").font(.system(size: 9)).padding(.top, 12)
                                }.frame(width: 12, height: max(geometry.size.height, CGFloat(shownSessions.count) * rowStride + 38))
                                    .contentShape(Rectangle())
                                    .gesture(DragGesture(minimumDistance: 0, coordinateSpace: .global).onChanged { value in
                                        if resizeOrigin == nil { resizeOrigin = columnWidth }
                                        labelWidth = min(max(220, (resizeOrigin ?? columnWidth) + value.translation.width), max(220, geometry.size.width - 260))
                                    }.onEnded { _ in resizeOrigin = nil })
                                    .onHover { inside in
                                        if inside { NSCursor.resizeLeftRight.push() } else { NSCursor.pop() }
                                    }
                                    .accessibilityLabel("Session column width")
                                    .accessibilityAdjustableAction { direction in
                                        switch direction {
                                        case .increment: labelWidth = min(columnWidth + 20, max(220, geometry.size.width - 260))
                                        case .decrement: labelWidth = max(220, columnWidth - 20)
                                        @unknown default: break
                                        }
                                    }
                                    .help("Drag left or right to resize the session column")
                                ScrollView(.horizontal) {
                                    VStack(spacing: 0) {
                                        PinnedTimelineHeader(position: timelineHeaderPosition) {
                                          ZStack(alignment: .topLeading) {
                                            ForEach(axis.ticks.filter { $0 == 0 || width * $0 / duration <= width - 85 }, id: \.self) { tick in
                                                Text(String(format: "+%.*f s", axis.decimals, tick))
                                                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                                    .offset(x: max(0, min(width - 85, width * tick / duration)), y: 10)
                                            }
                                            ForEach($pins) { $pin in
                                                TimelinePinMarker(pin: $pin, width: width, duration: duration,
                                                                  remove: { pins.removeAll { $0.id == pin.id } },
                                                                  clear: { pins.removeAll() })
                                            }
                                          }.frame(width: width, height: 38, alignment: .topLeading)
                                            .coordinateSpace(name: "timelineRuler")
                                            .contentShape(Rectangle())
                                            .onTapGesture { point in
                                                addTimelinePin(x: point.x, width: width, duration: duration)
                                            }
                                            .contextMenu { Button("Clear all pins") { pins.removeAll() }.disabled(pins.isEmpty) }
                                            .accessibilityHint("Click to pin a time across all sessions. Drag a pin to move it; right-click to add a note or remove it.")
                                        }.zIndex(1)
                                        Color.clear.frame(height: CGFloat(lower) * rowStride)
                                        ForEach(visibleSessions) { session in
                                        Canvas { context, size in
                                            for tick in axis.ticks {
                                                let x = size.width * tick / duration
                                                var path = Path(); path.move(to: CGPoint(x: x, y: 0)); path.addLine(to: CGPoint(x: x, y: size.height))
                                                context.stroke(path, with: .color(.secondary.opacity(0.15)), lineWidth: 1)
                                            }
                                            let x = (session.start - capture.start) / duration * size.width
                                            let end = (session.end - capture.start) / duration * size.width
                                            context.fill(Path(roundedRect: CGRect(x: x, y: (size.height - 18) / 2, width: max(4, end - x), height: 18), cornerRadius: 4), with: .color(color(session).opacity(0.3)))
                                            for pin in pins {
                                                let x = pin.time / duration * size.width
                                                var line = Path(); line.move(to: CGPoint(x: x, y: 0)); line.addLine(to: CGPoint(x: x, y: size.height))
                                                context.stroke(line, with: .color(.orange), style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                                            }
                                            let height = min(24, size.height - 4)
                                            for chunk in TimelineChunks.split(times: session.packets.map(\.time), captureStart: capture.start, duration: duration, width: size.width) {
                                                context.fill(Path(CGRect(x: chunk.left, y: (size.height - height) / 2, width: chunk.right - chunk.left, height: height)), with: .color(color(session)))
                                            }
                                            if let packet = session.packets.first(where: { $0.id == inspectedPacketID }) {
                                                let x = min(size.width - 2, (packet.time - capture.start) / duration * size.width) + 1
                                                context.fill(Path(CGRect(x: x - 4, y: 0, width: 8, height: size.height)), with: .color(.primary.opacity(0.22)))
                                                context.fill(Path(CGRect(x: x - 1.5, y: 1, width: 3, height: size.height - 2)), with: .color(.primary))
                                                var triangle = Path(); triangle.move(to: CGPoint(x: x - 5, y: 0)); triangle.addLine(to: CGPoint(x: x + 5, y: 0)); triangle.addLine(to: CGPoint(x: x, y: 6)); triangle.closeSubpath()
                                                context.fill(triangle, with: .color(.primary))
                                            }
                                        }.frame(width: width, height: rowHeight)
                                            .background(selectedIDs.contains(session.id) ? Color.accentColor.opacity(0.12) : Color.clear)
                                            .contentShape(Rectangle())
                                            .onContinuousHover { phase in
                                                if case .active(let point) = phase { hoveredPin = pins.min(by: { abs($0.time / duration * width - point.x) < abs($1.time / duration * width - point.x) }).flatMap { abs($0.time / duration * width - point.x) <= 5 ? $0 : nil } }
                                                else { hoveredPin = nil }
                                            }
                                            .help(hoveredPin.map(\.tooltip) ?? "Click a packet chunk to inspect it, or empty space to pin a time.")
                                            .onTapGesture { location in
                                                inspectTimelinePacket(at: location, session: session, capture: capture, width: width, duration: duration)
                                            }
                                        .contextMenu { sessionMenu(session) }
                                            Divider().frame(height: 1)
                                        }
                                        Color.clear.frame(height: CGFloat(shownSessions.count - upper) * rowStride)
                                        Color.clear.frame(height: max(0, geometry.size.height - CGFloat(shownSessions.count) * rowStride - 38))
                                            .contentShape(Rectangle())
                                            .onTapGesture { point in addTimelinePin(x: point.x, width: width, duration: duration) }
                                            .overlay {
                                                Canvas { context, size in
                                                    for pin in pins {
                                                        let x = pin.time / duration * size.width
                                                        var line = Path(); line.move(to: CGPoint(x: x, y: 0)); line.addLine(to: CGPoint(x: x, y: size.height))
                                                        context.stroke(line, with: .color(.orange), style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
                                                    }
                                                }.allowsHitTesting(false)
                                            }
                                    }.frame(width: width)
                                        .background(TimelineScrollObserver(changed: { _ in }, horizontal: true, controller: timelineScroll))
                                }.frame(height: max(geometry.size.height, CGFloat(shownSessions.count) * rowStride + 38))
                            }.frame(height: max(geometry.size.height, CGFloat(shownSessions.count) * rowStride + 38), alignment: .topLeading)
                            .background(TimelineScrollObserver(changed: { firstVisibleRow = $0 }, rowStride: rowStride, controller: timelineScroll,
                                offsetChanged: { timelineHeaderPosition.offset = $0 }))
                        }.id(query + "|" + enabledProtocols.sorted().joined(separator: ",") + "|" + sessionSort)
                        .scrollBounceBehavior(.basedOnSize, axes: .vertical)
                        .frame(width: geometry.size.width, height: geometry.size.height)
                        .onAppear { timelineInspection.width = width }
                        .onChange(of: width) { _, value in timelineInspection.width = value }
                        .overlay { if sessions.isEmpty { ContentUnavailableView("No matching sessions", systemImage: "line.3.horizontal.decrease.circle") } }
                    }.frame(maxWidth: .infinity, minHeight: 120, maxHeight: .infinity)
                    if let selection {
                        let deltas = Dictionary(uniqueKeysWithValues: zip(selection.packets, selection.packets.dropFirst()).map { previous, current in
                            (current.id, current.time - previous.time)
                        })
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("\(selection.protocolLabel) · \(selection.endpointA) ↔ \(selection.endpointB)").font(.headline)
                                Spacer()
                                Text("\(String(format: "%.6f", selection.end - selection.start)) s").foregroundStyle(.secondary)
                            }
                            Text("Session size: \(sizeDescription(selection.bytes)) · \(selection.packets.count.formatted()) packets")
                                .font(.subheadline).monospacedDigit()
                                .help("Sum of original packet lengths in both directions, including headers; not application payload or exported file size. 1 kB = 1,000 bytes.")
                            if !selection.summary.isEmpty {
                                Text(selection.summary).font(.caption).foregroundStyle(.secondary).lineLimit(1).help(selection.summary)
                            }
                            Table(selection.packets, selection: Binding<Int?>(get: { inspectedPacketID }, set: { id in
                                if let id { inspectedPacketID = id; openPacket(session: selection, capture: capture, packetID: id) }
                            })) {
                                TableColumn("Packet") { Text(String($0.id)) }.width(60)
                                TableColumn("Relative time") { Text(String(format: "%.6f s", $0.time - capture.start)) }.width(110)
                                TableColumn("Delta time") { packet in
                                    Text(deltas[packet.id].map { String(format: "%.6f s", $0) } ?? "—")
                                        .help("Time since the previous packet in this session, in either direction. The first packet has no delta.")
                                }.width(110)
                                TableColumn("Source", value: \.source)
                                TableColumn("Destination", value: \.destination)
                                TableColumn("Bytes") { Text(String($0.length)) }.width(65)
                                TableColumn("Protocol details") { Text($0.details).help($0.details) }
                            }.font(.system(size: 11, design: .monospaced))
                            HStack {
                                Text("Click a packet to open its inspector window.").font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                Text("[schwabber] : vibecoded by dyarovyi").font(.caption2).foregroundStyle(.secondary)
                            }
                        }.padding(14).frame(minHeight: 190, idealHeight: 230, maxHeight: .infinity)
                    } else {
                        HStack {
                            Text("Click to inspect · ⌘-click or checkboxes to select multiple · Shift-click for a range · ticks show packet arrivals")
                                .font(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Text("[schwabber] : vibecoded by dyarovyi").font(.caption2).foregroundStyle(.secondary)
                        }.padding(8).frame(maxWidth: .infinity)
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity).id(capture.sourceURL)
            } else {
                ContentUnavailableView {
                    Label("Open a packet capture", systemImage: "waveform.path.ecg.rectangle")
                } description: {
                    Text("Choose a .pcap or .pcapng file to see TCP and UDP sessions on a shared timeline.")
                } actions: {
                    VStack(spacing: 12) {
                        Button("Open PCAP…", systemImage: "folder") { importing = true }.disabled(loading || recording.running)
                        Picker("Capture interface", selection: $recording.interface) {
                            ForEach(recording.interfaces) { Text($0.label).tag($0.id) }
                        }.frame(maxWidth: 320).disabled(recording.running)
                        Button("Record PCAP", systemImage: "record.circle") { recording.start() }
                            .disabled(loading || recording.running || recording.interface.isEmpty)
                    }
                }
            }
        }
        .frame(minWidth: expandedWindow ? 1000 : 560, minHeight: expandedWindow ? 650 : 420)
        .background(CaptureWindowSizing(expanded: expandedWindow))
        .background(SessionNavigationKeys(move: moveSession).frame(width: 0, height: 0))
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: 18).strokeBorder(.tint, style: StrokeStyle(lineWidth: 3, dash: [8])).padding(12)
                    .overlay { Text(recording.running ? "Stop recording before opening a capture" : "Drop to open capture").font(.title2).padding(20).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12)) }
                    .allowsHitTesting(false)
            }
        }
        .focusedSceneValue(\.appActions, AppActions(
            open: { importing = true }, export: { exportSelected() }, wireshark: { openInWireshark() },
            selectAll: { selectedIDs = Set(sessions.map(\.id)); selected = sessions.first?.id },
            clear: { selectedIDs.removeAll(); selected = nil },
            start: { PacketWindow.close(); selected = nil; selectedIDs.removeAll(); zoom = 1; recording.start() },
            stop: { recording.stop() }, save: { recording.save() }, refresh: { recording.refresh() },
            chooseInterface: { recording.interface = $0 }, interfaces: recording.interfaces, interface: recording.interface,
            busy: loading, running: recording.running, canExport: !selectedIDs.isEmpty && !exporting,
            canSave: recording.url != nil && !recording.running,
            showEndpoints: showEndpoints, toggleEndpoints: { showEndpoints.toggle() },
            clearPins: { pins.removeAll() }, hasPins: !pins.isEmpty))
        .onChange(of: recording.revision) { _, _ in
            if filename != "Live capture — " + recording.interface {
                PacketWindow.close(); selected = nil; selectedIDs.removeAll(); zoom = 1
            }
            capture = recording.capture; filename = "Live capture — " + recording.interface
        }
        .onChange(of: recording.error) { _, value in if let value { failure = value } }
        .onDisappear { if recording.running { recording.stop() }; PacketWindow.close() }
        .onOpenURL { open($0) }
        .onAppear {
            recording.refresh()
            guard !openedArgument else { return }
            openedArgument = true
            if let path = CommandLine.arguments.dropFirst().first, !path.hasPrefix("-") {
                open(URL(fileURLWithPath: path))
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first, url.isFileURL, !loading, !recording.running else { return false }
            open(url); return true
        } isTargeted: { dropTargeted = $0 }
        .onChange(of: capture?.sourceURL) { _, _ in pins.removeAll() }
        .onChange(of: showEndpoints) { _, _ in
            if let index = sessions.firstIndex(where: { $0.id == selected }) {
                DispatchQueue.main.async { timelineScroll.reveal(row: index, stride: rowStride) }
            }
        }
        .onChange(of: sessionSort) { _, _ in firstVisibleRow = 0 }
        .onChange(of: query) { _, _ in firstVisibleRow = 0 }
        .onChange(of: enabledProtocols) { _, _ in firstVisibleRow = 0 }
        .onChange(of: inspectedPacketID) { _, _ in revealInspectedPacket() }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls): if let url = urls.first { open(url) }
            case .failure(let error): failure = error.localizedDescription
            }
        }
        .alert("Unable to complete action", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
            Button("OK") { failure = nil }
        } message: { Text(failure ?? "") }
    }
    private func color(_ session: Session) -> Color {
        if !session.applicationProtocols.filter({ ["RTCP", "SIP", "DTLS", "TURN"].contains($0) }).isEmpty { return .mint }
        if session.applicationProtocols.contains("RTP") { return .cyan }
        if session.hasDNS { return .purple }
        if session.applicationProtocols.contains("QUIC") { return .pink }
        if session.applicationProtocols.contains("TLS") { return .teal }
        if session.applicationProtocols.contains("HTTP") { return .green }
        if session.applicationProtocols.contains("STUN") { return .indigo }
        return session.transport == "TCP" ? .blue : .orange
    }
    private func toggle(_ id: Int) {
        if let window = NSApp.keyWindow { window.makeFirstResponder(window) }
        if selectedIDs.contains(id) { selectedIDs.remove(id) } else { selectedIDs.insert(id) }
        selected = selectedIDs.contains(id) ? id : selectedIDs.sorted().first
    }
    private func moveSession(_ key: UInt16, _ extend: Bool) -> Bool {
        let shown = sessions
        guard !shown.isEmpty else { return false }
        let current = shown.firstIndex { $0.id == selected }
        let next: Int
        switch key {
        case 115: next = 0
        case 119: next = shown.count - 1
        case 126: next = max(0, (current ?? shown.count) - 1)
        default: next = min(shown.count - 1, (current ?? -1) + 1)
        }
        if extend, let current { selectedIDs.formUnion(shown[min(current, next)...max(current, next)].map(\.id)) }
        else { selectedIDs = [shown[next].id] }
        selected = shown[next].id
        DispatchQueue.main.async { timelineScroll.reveal(row: next, stride: rowStride) }
        return true
    }

    private func openPacket(session: Session, capture: Capture, packetID: Int) {
        PacketWindow.open(session: session, capture: capture, packetID: packetID, timeline: timelineInspection,
                          onClosed: { inspectedPacketID = nil }) { id in
            inspectedPacketID = id
        }
        revealInspectedPacket()
    }
    private func revealInspectedPacket() {
        guard let id = inspectedPacketID, let capture,
              let index = sessions.firstIndex(where: { $0.packets.contains(where: { $0.id == id }) }),
              let packet = sessions[index].packets.first(where: { $0.id == id }) else { return }
        let x = min(timelineInspection.width - 2, (packet.time - capture.start) / timelineDuration * timelineInspection.width) + 1
        DispatchQueue.main.async {
            timelineScroll.reveal(row: index, stride: rowStride)
            timelineScroll.reveal(x: x)
        }
    }

    private func addTimelinePin(x: CGFloat, width: CGFloat, duration: Double) {
        let time = min(duration, max(0, x / width * duration))
        guard !pins.contains(where: { abs($0.time - time) / duration * width < 5 }) else { return }
        pins.append(TimelinePin(time: time))
    }

    private func inspectTimelinePacket(at location: CGPoint, session: Session, capture: Capture, width: CGFloat, duration: Double) {
        // Use the same chunks for drawing and hit testing. A click opens the
        // first packet of the chunk; individual packets remain navigable.
        let modifiers = NSEvent.modifierFlags.intersection([.command, .shift])
        guard modifiers.isEmpty else { select(session.id); return }
        let markHeight = min(24, rowHeight - 4)
        let hitsMarkHeight = ((rowHeight - markHeight) / 2 - 3...(rowHeight + markHeight) / 2 + 3).contains(location.y)
        let chunks = TimelineChunks.split(times: session.packets.map(\.time), captureStart: capture.start, duration: duration, width: width)
        let closest = chunks.min {
            max(0, max($0.left - location.x, location.x - $0.right)) < max(0, max($1.left - location.x, location.x - $1.right))
        }
        guard hitsMarkHeight, let chunk = closest,
              max(0, max(chunk.left - location.x, location.x - chunk.right)) <= 3 else {
            addTimelinePin(x: location.x, width: width, duration: duration)
            return
        }
        let packet = session.packets[chunk.start]
        selected = session.id
        selectedIDs = [session.id]
        inspectedPacketID = packet.id
        openPacket(session: session, capture: capture, packetID: packet.id)
    }

    private func select(_ id: Int) {
        if let window = NSApp.keyWindow { window.makeFirstResponder(window) }
        if NSEvent.modifierFlags.contains(.command) { toggle(id); return }
        if NSEvent.modifierFlags.contains(.shift), let anchor = selected,
           let a = sessions.firstIndex(where: { $0.id == anchor }),
           let b = sessions.firstIndex(where: { $0.id == id }) {
            selectedIDs.formUnion(sessions[min(a, b)...max(a, b)].map(\.id))
        } else { selectedIDs = [id] }
        selected = id
    }
    @ViewBuilder private func sessionMenu(_ session: Session) -> some View {
        if session.transport == "TCP" { Button("Reassemble TCP stream…") { TCPStreamWindow.open(session: session, linkType: capture?.linkType ?? 1) } }
        Button("Inspect session") { selected = session.id }
        Button("Copy 5-tuple") {
            func endpoint(_ value: String) -> (String, String) {
                guard session.transport == "TCP" || session.transport == "UDP",
                      let separator = value.lastIndex(of: ":") else {
                    return (value.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), "N/A")
                }
                let address = String(value[..<separator]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                return (address, String(value[value.index(after: separator)...]))
            }
            let source = endpoint(session.endpointA), destination = endpoint(session.endpointB)
            let tuple = "(\(source.0), \(source.1), \(destination.0), \(destination.1), \(session.transport))"
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(tuple, forType: .string)
        }.help("Source IP, source port, destination IP, destination port, transport protocol; direction follows the first packet. ICMP ports are N/A.")
        Button("Open session in Wireshark") { openInWireshark(ids: [session.id]) }.disabled(exporting)
        Button("Export session…") { exportSelected(ids: [session.id]) }.disabled(exporting)
        Divider()
        Button(selectedIDs.contains(session.id) ? "Remove from selection" : "Add to selection") { toggle(session.id) }
        if selectedIDs.count > 1 && selectedIDs.contains(session.id) {
            Button("Open selected sessions in Wireshark") { openInWireshark() }.disabled(exporting)
            Button("Export selected sessions…") { exportSelected() }.disabled(exporting)
        }
    }
    private func exportSelected(ids requestedIDs: Set<Int>? = nil) {
        let ids = requestedIDs ?? selectedIDs
        guard let capture, !ids.isEmpty, !exporting else { return }
        let panel = NSSavePanel()
        panel.title = "Export selected sessions"
        panel.message = "Save \(ids.count) selected sessions, including both traffic directions."
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? UTType(importedAs: "org.tcpdump.pcap", conformingTo: .data)]
        panel.nameFieldStringValue = (filename as NSString).deletingPathExtension + "-selected.pcap"
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            exporting = true
            exportStatus = nil
            Task {
                do {
                    try await Task.detached(priority: .userInitiated) {
                        let access = url.startAccessingSecurityScopedResource()
                        defer { if access { url.stopAccessingSecurityScopedResource() } }
                        try capture.export(sessionIDs: ids, to: url)
                    }.value
                    exportStatus = "Exported \(ids.count) sessions to \(url.path)"
                } catch { failure = error.localizedDescription }
                exporting = false
            }
        }
    }
    private func openInWireshark(ids requestedIDs: Set<Int>? = nil) {
        let ids = requestedIDs ?? selectedIDs
        guard let capture, !ids.isEmpty, !exporting else { return }
        let standardURL = URL(fileURLWithPath: "/Applications/Wireshark.app")
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "org.wireshark.Wireshark") ??
                (FileManager.default.fileExists(atPath: standardURL.path) ? standardURL : nil) else {
            failure = "Wireshark was not found. Install Wireshark in Applications, then try again."
            return
        }
        exporting = true
        Task {
            do {
                let url = try await Task.detached(priority: .userInitiated) {
                    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("Schwabber-Exports", isDirectory: true)
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                    let url = directory.appendingPathComponent("Sessions-\(UUID().uuidString).pcap")
                    try capture.export(sessionIDs: ids, to: url)
                    return url
                }.value
                let configuration = NSWorkspace.OpenConfiguration()
                configuration.activates = true
                _ = try await NSWorkspace.shared.open([url], withApplicationAt: appURL, configuration: configuration)
            } catch { failure = error.localizedDescription }
            exporting = false
        }
    }
    private func open(_ url: URL) {
        guard !loading, !recording.running else { return }
        loading = true
        Task {
            do {
                let value = try await Task.detached(priority: .userInitiated) {
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    return try CaptureReader.read(url: url)
                }.value
                PacketWindow.close()
                recording.releaseSnapshot()
                firstVisibleRow = 0
                capture = value; filename = url.lastPathComponent; selected = nil; selectedIDs.removeAll(); exportStatus = nil; zoom = 1
            } catch { failure = error.localizedDescription }
            loading = false
        }
    }
}

private struct TimelineZoom: View {
    @Binding var value: Double
    var maximum: Double
    private var fraction: Double { maximum > 1 ? log(max(1, min(value, maximum))) / log(maximum) : 0 }
    private func setFraction(_ fraction: Double) { value = pow(max(1, maximum), min(1, max(0, fraction))) }
    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.25)).frame(height: 4)
                Capsule().fill(Color.accentColor).frame(width: max(0, (proxy.size.width - 14) * fraction + 7), height: 4)
                Circle().fill(Color(nsColor: .controlBackgroundColor)).shadow(radius: 1)
                    .frame(width: 14, height: 14).offset(x: (proxy.size.width - 14) * fraction)
            }.frame(height: proxy.size.height).contentShape(Rectangle())
                .gesture(DragGesture(minimumDistance: 0).onChanged { event in
                    setFraction((event.location.x - 7) / max(1, proxy.size.width - 14))
                })
        }.frame(height: 22)
        .help("Left: fit capture. Right: two seconds across the visible timeline (one second per half).")
        .accessibilityElement().accessibilityLabel("Timeline zoom").accessibilityValue(String(format: "%.1f times", value))
        .accessibilityAdjustableAction { direction in
            switch direction { case .increment: setFraction(fraction + 0.05); case .decrement: setFraction(fraction - 0.05); @unknown default: break }
        }
    }
}
