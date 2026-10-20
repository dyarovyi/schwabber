import SwiftUI
import AppKit
import UniformTypeIdentifiers
import CaptureCore

@MainActor @Observable final class Recording {
    static var active: [Recording] = []
    var interfaces: [CaptureInterface] = []
    var interface = ""
    var running = false
    var stopping = false
    var capture: Capture?
    var revision = 0
    var dropped: UInt32 = 0
    var error: String?
    var url: URL?
    var saved = false
    private var worker: LiveCapture?
    func refresh() {
        do { interfaces = try LiveCapture.interfaces(); if !interfaces.contains(where: { $0.id == interface }) { interface = interfaces.first(where: { $0.preferred })?.id ?? interfaces.first(where: { $0.id == "en0" })?.id ?? interfaces.first?.id ?? "" } }
        catch { self.error = error.localizedDescription }
    }
    func start() {
        guard !running, !interface.isEmpty else { return }
        do {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent("Schwabber-Recordings", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let path = directory.appendingPathComponent("Recording-\(UUID().uuidString).pcap")
            // Set private permissions before libpcap opens the file.
            guard FileManager.default.createFile(atPath: path.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw CaptureError.read("Cannot create recording file.") }
            let worker = LiveCapture(); self.worker = worker
            Self.active.append(self)
            running = true; stopping = false; saved = false; url = path; error = nil; capture = nil; dropped = 0
            let device = interface
            Task {
                do {
                    try await Task.detached(priority: .userInitiated) {
                        try await worker.run(interface: device, url: path) { snapshot, dropped in
                            await self.receive(snapshot, dropped: dropped)
                        }
                    }.value
                } catch { self.error = error.localizedDescription }
                running = false; stopping = false; self.worker = nil
                Self.active.removeAll { $0 === self }
            }
        } catch { self.error = error.localizedDescription }
    }
    private func receive(_ capture: Capture, dropped: UInt32) { self.capture = capture; self.dropped = dropped; revision += 1 }
    func releaseSnapshot() { if !running { capture = nil } }
    func stop() { stopping = true; worker?.stop() }
    func save() {
        guard !running, let url else { return }
        let panel = NSSavePanel(); panel.title = "Save recorded capture"
        panel.nameFieldStringValue = "Recording.pcap"
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do {
            // Atomic replacement also handles the overwrite confirmation from NSSavePanel.
            try Data(contentsOf: url, options: .mappedIfSafe).write(to: destination, options: .atomic)
            saved = true
        } catch { self.error = error.localizedDescription }
    }
}
