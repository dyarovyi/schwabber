import AppKit

@MainActor final class AppLifecycle: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let window = sender.windows.first(where: { $0.canBecomeMain && !$0.title.contains("Packet Inspector") }) {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
        }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !Recording.active.isEmpty else { return .terminateNow }
        // Let the capture worker flush and close its PCAP before the process exits.
        for recording in Recording.active { recording.stop() }
        Task { @MainActor in
            while !Recording.active.isEmpty { try? await Task.sleep(for: .milliseconds(50)) }
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
