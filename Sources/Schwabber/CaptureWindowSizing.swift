import AppKit
import SwiftUI

struct CaptureWindowSizing: NSViewRepresentable {
    let expanded: Bool
    func makeNSView(context: Context) -> SizingView { SizingView() }
    func updateNSView(_ view: SizingView, context: Context) {
        view.expanded = expanded
        DispatchQueue.main.async { [weak view] in view?.applySize() }
    }
    final class SizingView: NSView {
        var expanded = false
        private var applied: Bool?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            DispatchQueue.main.async { [weak self] in self?.applySize() }
        }
        func applySize() {
            guard let window, applied != expanded else { return }
            applied = expanded
            let desired = expanded ? NSSize(width: 1300, height: 850) : NSSize(width: 600, height: 420)
            window.setContentSize(desired)
            if let screen = window.screen {
                var frame = window.frame
                frame.size.width = min(frame.width, screen.visibleFrame.width)
                frame.size.height = min(frame.height, screen.visibleFrame.height)
                frame.origin.x = min(max(frame.minX, screen.visibleFrame.minX), screen.visibleFrame.maxX-frame.width)
                frame.origin.y = min(max(frame.minY, screen.visibleFrame.minY), screen.visibleFrame.maxY-frame.height)
                window.setFrame(frame, display: true)
            }
        }
    }
}
