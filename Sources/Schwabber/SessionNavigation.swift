import AppKit
import SwiftUI

@MainActor final class TimelineScrollController {
    weak var clip: NSClipView?
    weak var horizontalClip: NSClipView?
    func reveal(x: CGFloat) {
        guard let clip = horizontalClip, let document = clip.documentView else { return }
        if x < clip.bounds.minX + 20 || x > clip.bounds.maxX - 20 {
            let left = max(0, min(x - clip.bounds.width / 2, document.bounds.width - clip.bounds.width))
            clip.scroll(to: NSPoint(x: left, y: clip.bounds.minY))
            clip.enclosingScrollView?.reflectScrolledClipView(clip)
        }
    }
    func reveal(row: Int, stride: CGFloat) {
        guard let clip, let document = clip.documentView else { return }
        let top = CGFloat(row) * stride + 38
        let bottom = top + stride
        var y = clip.bounds.minY
        if top < y + 38 { y = top - 38 }
        else if bottom > y + clip.bounds.height { y = bottom - clip.bounds.height }
        y = max(0, min(y, document.bounds.height - clip.bounds.height))
        clip.scroll(to: NSPoint(x: clip.bounds.minX, y: y))
        clip.enclosingScrollView?.reflectScrolledClipView(clip)
    }
}
struct SessionNavigationKeys: NSViewRepresentable {
    var move: (UInt16, Bool) -> Bool
    final class Coordinator { var monitor: Any?; var move: (UInt16, Bool) -> Bool = { _, _ in false } }
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        let coordinator = context.coordinator
        coordinator.move = move
        coordinator.monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak view] event in
            guard let window = view?.window, event.window === window else { return event }
            let modifiers = event.modifierFlags.intersection([.command, .control, .option, .shift])
            guard modifiers.isEmpty || modifiers == .shift else { return event }
            var responder = window.firstResponder
            while let current = responder {
                if current is NSTextView || current is NSControl || current is NSTableView { return event }
                responder = current.nextResponder
            }
            guard [UInt16(125), 126, 115, 119].contains(event.keyCode) else { return event }
            return coordinator.move(event.keyCode, modifiers == .shift) ? nil : event
        }
        return view
    }
    func updateNSView(_ view: NSView, context: Context) { context.coordinator.move = move }
    static func dismantleNSView(_ view: NSView, coordinator: Coordinator) {
        if let monitor = coordinator.monitor { NSEvent.removeMonitor(monitor) }
    }
}
