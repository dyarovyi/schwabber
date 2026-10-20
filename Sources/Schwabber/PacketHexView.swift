import AppKit
import SwiftUI
import CaptureCore

struct PacketHexView: NSViewRepresentable {
    let bytes: Data
    let range: Range<Int>
    let payloadRange: Range<Int>
    let selection: Range<Int>?
    let describe: (Int) -> String
    let clicked: (Int) -> Void
    var textOnly = false
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true
        scroll.documentView = HexCanvas(frame: .zero)
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? HexCanvas else { return }
        let changed = view.bytes != Array(bytes) || view.range != range
        let changedSelection = view.selection != selection
        view.textOnly = textOnly
        view.bytes = Array(bytes); view.range = range; view.payload = payloadRange
        if changed || changedSelection { view.dragSelection = nil }
        view.selection = selection; view.describe = describe; view.clicked = clicked
        view.setFrameSize(NSSize(width: 760, height: max(40, 16 + CGFloat((range.count + 15) / 16) * 19)))
        if changed { view.scroll(.zero) }
        if changedSelection, let selection, range.contains(selection.lowerBound) {
            view.scrollToVisible(NSRect(x: 0, y: 8 + CGFloat((selection.lowerBound - range.lowerBound) / 16) * 19, width: 1, height: 19))
        }
        view.needsDisplay = true
    }
}
private final class HexCanvas: NSView {
    var bytes: [UInt8] = [], range = 0..<0, payload = 0..<0
    var textOnly = false
    var dragSelection: Range<Int>?
    private var dragAnchor: Int?
    var selection: Range<Int>?
    var describe: (Int) -> String = { _ in "" }
    var clicked: (Int) -> Void = { _ in }
    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { true }
    let font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    let cw: CGFloat = 7.3
    func hexX(_ col: Int) -> CGFloat { 70 + CGFloat(col * 3 + (col >= 8 ? 1 : 0)) * cw }
    func asciiX(_ col: Int) -> CGFloat { (textOnly ? 70 : 450) + CGFloat(col) * cw }
    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: .zero, options: [.activeInKeyWindow, .mouseMoved, .inVisibleRect], owner: self))
    }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.textBackgroundColor.setFill(); dirtyRect.fill()
        let first = max(0, Int((dirtyRect.minY - 8) / 19)), last = min((range.count + 15) / 16, Int(dirtyRect.maxY / 19) + 1)
        guard first < last else { return }
        func text(_ s: String, _ x: CGFloat, _ y: CGFloat, _ color: NSColor = .textColor) {
            (s as NSString).draw(at: NSPoint(x: x, y: y), withAttributes: [.font: font, .foregroundColor: color])
        }
        for row in first..<last {
            let y = 8 + CGFloat(row) * 19
            text(String(format: "%06x", row * 16), 8, y, .secondaryLabelColor)
            for col in 0..<16 {
                let offset = range.lowerBound + row * 16 + col
                guard range.contains(offset), bytes.indices.contains(offset) else { break }
                let selected = (dragSelection ?? selection)?.contains(offset) ?? false
                if selected || !payload.contains(offset) {
                    (selected ? NSColor.selectedTextBackgroundColor : NSColor.quaternaryLabelColor).setFill()
                    if !textOnly { NSRect(x: hexX(col) - 1, y: y, width: cw * 2 + 2, height: 18).fill() }
                    NSRect(x: asciiX(col), y: y, width: cw, height: 18).fill()
                }
                let color: NSColor = selected ? .selectedTextColor : !payload.contains(offset) ? .secondaryLabelColor : .textColor
                if !textOnly { text(String(format: "%02x", bytes[offset]), hexX(col), y, color) }
                text((32...126).contains(bytes[offset]) ? String(UnicodeScalar(bytes[offset])) : ".", asciiX(col), y, color)
            }
        }
    }
    private func offset(_ event: NSEvent) -> Int? {
        let p = convert(event.locationInWindow, from: nil), row = Int(floor((p.y - 8) / 19))
        guard row >= 0 else { return nil }
        let column = (0..<16).first { (!textOnly && p.x >= hexX($0) - 1 && p.x < hexX($0) + 2 * cw + 1) || p.x >= asciiX($0) && p.x < asciiX($0) + cw }
        guard let column else { return nil }
        let offset = range.lowerBound + row * 16 + column
        return range.contains(offset) ? offset : nil
    }
    override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        if let offset = offset(event) { dragAnchor = offset; dragSelection = nil; clicked(offset) }
    }
    override func mouseDragged(with event: NSEvent) {
        autoscroll(with: event)
        guard let anchor = dragAnchor, let end = offset(event) else { return }
        dragSelection = min(anchor, end)..<(max(anchor, end) + 1)
        needsDisplay = true
    }
    override func mouseUp(with event: NSEvent) { dragAnchor = nil }
    private var selectedBytes: Data {
        guard let selected = dragSelection ?? selection else { return Data() }
        let lower = max(range.lowerBound, selected.lowerBound, 0)
        let upper = min(range.upperBound, selected.upperBound, bytes.count)
        return lower < upper ? Data(bytes[lower..<upper]) : Data()
    }
    @objc private func copyBytes(_ sender: NSMenuItem) {
        guard ByteCopyFormat.allCases.indices.contains(sender.tag) else { return }
        copyToClipboard(ByteCopyFormat.allCases[sender.tag].string(selectedBytes))
    }
    @objc func copy(_ sender: Any?) { copyToClipboard(ByteCopyFormat.hex.string(selectedBytes)) }
    override func menu(for event: NSEvent) -> NSMenu? {
        if let offset = offset(event), !((dragSelection ?? selection)?.contains(offset) ?? false) {
            dragSelection = offset..<(offset + 1); needsDisplay = true
        }
        let menu = NSMenu()
        for (index, format) in ByteCopyFormat.allCases.enumerated() {
            let item = NSMenuItem(title: "Copy as " + format.rawValue.lowercased(), action: #selector(copyBytes(_:)), keyEquivalent: "")
            item.target = self; item.tag = index; item.isEnabled = !selectedBytes.isEmpty
            menu.addItem(item)
        }
        menu.autoenablesItems = false
        return menu
    }
    override func mouseMoved(with event: NSEvent) { toolTip = offset(event).map(describe) }
}

struct PacketNavigationKeys: NSViewRepresentable {
    let navigate: (Int) -> Void
    final class Coordinator {
        var monitor: Any?
        var navigate: (Int) -> Void = { _ in }
    }
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        let coordinator = context.coordinator
        coordinator.navigate = navigate
        coordinator.monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak view] event in
            guard let window = view?.window, event.window === window else { return event }
            let modifiers = event.modifierFlags.intersection([.command, .control, .option, .shift])
            if (event.keyCode == 116 && modifiers.isEmpty) || (event.keyCode == 123 && modifiers == .option) { coordinator.navigate(-1); return nil }
            if (event.keyCode == 121 && modifiers.isEmpty) || (event.keyCode == 124 && modifiers == .option) { coordinator.navigate(1); return nil }
            return event
        }
        return view
    }
    func updateNSView(_ view: NSView, context: Context) { context.coordinator.navigate = navigate }
    static func dismantleNSView(_ view: NSView, coordinator: Coordinator) { if let monitor = coordinator.monitor { NSEvent.removeMonitor(monitor) }; coordinator.monitor = nil }
}
