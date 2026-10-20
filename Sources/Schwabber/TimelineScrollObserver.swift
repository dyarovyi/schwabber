import AppKit
import SwiftUI

@Observable final class TimelineHeaderPosition {
    var offset: CGFloat = 0
}

/// Only the header observes pixel-level scrolling; session rows keep their
/// existing row-based virtualization updates.
struct PinnedTimelineHeader<Content: View>: View {
    let position: TimelineHeaderPosition
    @ViewBuilder var content: () -> Content

    var body: some View {
        content()
            .background(Color(nsColor: .windowBackgroundColor))
            .overlay(alignment: .bottom) { Divider() }
            .offset(y: position.offset)
    }
}

/// Observe the native clip view: SwiftUI geometry preferences can stay unchanged
/// when AppKit scrolls a fixed-size document without laying it out again.
struct TimelineScrollObserver: NSViewRepresentable {
    var changed: (Int) -> Void
    var horizontal = false
    var rowStride: CGFloat = 37
    var controller: TimelineScrollController? = nil
    var offsetChanged: (CGFloat) -> Void = { _ in }
    func makeNSView(context: Context) -> ObserverView {
        let view = ObserverView(); view.horizontal = horizontal; view.rowStride = rowStride; view.controller = controller; view.changed = changed; view.offsetChanged = offsetChanged; return view
    }
    func updateNSView(_ view: ObserverView, context: Context) {
        view.changed = changed; view.offsetChanged = offsetChanged
        let strideChanged = view.rowStride != rowStride
        view.rowStride = rowStride; view.controller = controller
        if strideChanged { DispatchQueue.main.async { [weak view] in view?.refresh() } }
    }
    static func dismantleNSView(_ view: ObserverView, coordinator: ()) { view.detach() }

    final class ObserverView: NSView {
        var horizontal = false
        var rowStride: CGFloat = 37
        var controller: TimelineScrollController?
        var changed: (Int) -> Void = { _ in }
        var offsetChanged: (CGFloat) -> Void = { _ in }
        private var token: NSObjectProtocol?
        private weak var clip: NSClipView?
        private var lastRow = -1
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            detach()
            guard window != nil else { return }
            DispatchQueue.main.async { [weak self] in self?.attach() }
        }
        private func attach() {
            guard window != nil, let scroll = enclosingScrollView else { return }
            clip = scroll.contentView
            if horizontal { controller?.horizontalClip = scroll.contentView }
            else { controller?.clip = scroll.contentView }
            scroll.contentView.postsBoundsChangedNotifications = true
            token = NotificationCenter.default.addObserver(forName: NSView.boundsDidChangeNotification, object: scroll.contentView, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.publish() }
            }
            publish()
        }
        func refresh() { lastRow = -1; publish() }
        private func publish() {
            guard !horizontal, let clip else { return }
            offsetChanged(max(0, clip.bounds.minY))
            let row = max(0, Int((clip.bounds.minY - 38) / rowStride))
            guard row != lastRow else { return }
            lastRow = row
            changed(row)
        }
        func detach() {
            if let token { NotificationCenter.default.removeObserver(token) }
            token = nil; clip = nil; lastRow = -1
        }
    }
}
