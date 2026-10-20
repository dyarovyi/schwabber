import AppKit
import SwiftUI

@MainActor enum HelpWindow {
    private static var controller: NSWindowController?
    static func open(shortcuts: Bool = false) {
        let window = controller?.window ?? NSWindow(contentRect: NSRect(x: 0, y: 0, width: 850, height: 650), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Schwabber Help"
        window.minSize = NSSize(width: 650, height: 400)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: HelpGuide(initial: shortcuts ? "Keyboard shortcuts" : "Getting started"))
        if controller == nil { controller = NSWindowController(window: window); window.center() }
        controller?.showWindow(nil)
        window.makeKeyAndOrderFront(nil)
    }
}
private typealias HelpState<Value> = SwiftUI.State<Value>
private struct HelpGuide: View {
    let initial: String
    @HelpState<String?> private var selected = "Getting started"
    private let sections: [(String, String)] = [
        ("Getting started", "Open a PCAP or PCAPNG file, or select an interface and Record PCAP. Each session appears on a shared timeline. Click a session to show its packet list; click a packet mark or a packet in the list to open its inspector."),
        ("Opening captures", "Use File → Open capture (⌘O), drag a capture onto the window, or open a capture with Schwabber from Finder. Opening another capture replaces the current view. Stop recording before opening a file."),
        ("Timeline and pins", "The colored session bar spans its activity; ticks indicate packet arrivals. The ruler stays visible when scrolling. Zoom separates nearby packets; at maximum zoom, two seconds fill the visible timeline. Click the ruler or empty timeline space to pin a time across all rows. Drag a pin on the ruler to move it across the timeline. Right-click a pin to add, edit, or remove a note, or to remove the pin. Hover a pin to read its note and exact time relative to capture start. View → Clear timeline pins removes all pins. Pins and notes belong to the current capture and are not saved into the PCAP. Packets whose marks start less than four pixels apart merge into a chunk at the current zoom. Clicking a chunk opens its first packet; zooming in can split it. The inspected packet has a contrasting marker and is scrolled into view. Closing the inspector clears the marker."),
        ("Filtering and sorting", "The search box matches IPs, ports and session details, or exact UTF-8 payload text. Search binary bytes with x00x01xFF notation. Payload matching is within individual captured packets, not decrypted or reassembled streams. Protocol checkboxes allow multiple choices and stay open until Done. All checks every protocol; unchecking All clears them. Sort chronologically or by largest session first."),
        ("Selecting sessions", "Click a row to select it. ⌘-click or use checkboxes for multiple selections; Shift-click extends a range. Up/Down move between shown sessions, Shift extends the selection, and Home/End jump to the first/last session. These keys leave text fields and packet tables to handle their own navigation. Sessions → Select shown and Clear selection operate on the list."),
        ("Export and Wireshark", "Right-click a session to copy its 5-tuple, export packets, open in Wireshark, or reassemble its TCP stream. Multi-selection actions export all selected sessions. File → Save PCAP saves the full recording, including traffic not represented as sessions; exporting sessions saves their packets only."),
        ("Packet inspector", "Previous/Next moves within the session. The header shows arrival time, position in the session, and position within a multi-packet chunk; chunk counts update with zoom. Include headers changes captured-frame bytes and the displayed payload range. Size cards distinguish original length, captured bytes, and payload. Click a field to highlight bytes, or click hex/ASCII bytes to select a field. Generated fields have no bytes. ASCII only hides the hex column."),
        ("Decryption and reassembly", "Wireshark analysis uses the locally installed sharkd executable. Its Data source picker lists available reassembled/decrypted sources for that frame. Choose a TLS key log for encrypted application traffic. A field can switch to its own data source automatically. Reassembly may only appear on the final contributing packet. Missing keys, missing packets or unsupported encryption can prevent reconstruction."),
        ("Copying fields and bytes", "Right-click a field to copy the full label, its value, or its bytes. Drag across the hex or ASCII pane to select a byte range. Right-click to copy spaced hex, a continuous hex stream, UTF-8 text, or a hex dump. ⌘C in the byte pane copies hex. The same byte tools work in the TCP stream window."),
        ("TCP streams", "Reassemble TCP stream combines captured TCP payload separately in each direction. Retransmitted overlaps are removed; gaps remain separate chunks. Select a direction and contiguous chunk to inspect or save. TLS wire bytes remain encrypted in this view. Very large sequence spans and missing capture data limit reconstruction."),
        ("Live recording", "Choose an interface in Capture or on the welcome screen, then start recording. Sessions update while packets are written to a temporary capture. Stop recording and use File → Save PCAP (⌘S). Capture permissions may be required by macOS. Dropped-packet counts are shown during recording."),
        ("View options", "Drag the divider beside the session column to resize it. Drag the divider above the packet list to change its height. View → Show endpoints hides or restores the second session line; hidden endpoints make rows shorter. The selected session still shows full endpoints in its details. macOS appearance and accessibility settings control native materials."),
        ("Keyboard shortcuts", "⌘O — open capture\n⌘S — save recording\nUp/Down — previous/next session\nShift + Up/Down — extend selection\nHome/End — first/last session\nShift + Home/End — extend to first/last\n⌘Left/Right or Option + Left/Right — previous/next packet\nPage Up/Page Down — previous/next packet\n⌘C — copy selected bytes in the byte pane\nF1 or Help → Schwabber Help — this guide\n⌘Q — quit"),
        ("Protocols and limits", "Sessions support TCP, UDP, ICMP and ICMPv6, with decoding for DNS, HTTP, HTTP/2, TLS, QUIC, STUN, TURN, RTP, RTCP, SIP/SDP and DTLS where recognizable. Wireshark provides deeper decoding when installed. Other traffic and truncated/fragmented packets may not appear as sessions. Session sizes include packet headers. Captures and key logs are processed locally; no upload is needed.")
    ]
    var body: some View {
        HSplitView {
            List(sections.map(\.0), id: \.self, selection: $selected) { title in Text(title).tag(title) }.frame(minWidth: 180, idealWidth: 210, maxWidth: 260)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text(selected ?? initial).font(.title.bold())
                    Text(sections.first { $0.0 == selected }?.1 ?? "").textSelection(.enabled).lineSpacing(6)
                }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minWidth: 380)
        }.onAppear { selected = initial }
    }
}
