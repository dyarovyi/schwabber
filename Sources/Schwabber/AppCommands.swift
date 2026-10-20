import SwiftUI
import CaptureCore

struct AppActions {
    var open: () -> Void
    var export: () -> Void
    var wireshark: () -> Void
    var selectAll: () -> Void
    var clear: () -> Void
    var start: () -> Void
    var stop: () -> Void
    var save: () -> Void
    var refresh: () -> Void
    var chooseInterface: (String) -> Void
    var interfaces: [CaptureInterface]
    var interface: String
    var busy: Bool
    var running: Bool
    var canExport: Bool
    var canSave: Bool
    var showEndpoints: Bool
    var toggleEndpoints: () -> Void
    var clearPins: () -> Void
    var hasPins: Bool
}
private struct AppActionsKey: FocusedValueKey { typealias Value = AppActions }
extension FocusedValues {
    var appActions: AppActions? {
        get { self[AppActionsKey.self] }
        set { self[AppActionsKey.self] = newValue }
    }
}
struct AppMenus: Commands {
    @FocusedValue(\.appActions) private var actions
    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Open capture…") { actions?.open() }.keyboardShortcut("o").disabled(actions == nil || actions?.busy == true || actions?.running == true)
            Button("Save PCAP…") { actions?.save() }.keyboardShortcut("s").disabled(actions?.canSave != true)
            Button("Export selected sessions…") { actions?.export() }.disabled(actions?.canExport != true)
            Button("Open selected in Wireshark") { actions?.wireshark() }.disabled(actions?.canExport != true)
        }
        CommandMenu("Sessions") {
            Button("Select shown") { actions?.selectAll() }
            Button("Clear selection") { actions?.clear() }
        }
        CommandGroup(after: .toolbar) {
            Toggle("Show endpoints", isOn: Binding(get: { actions?.showEndpoints ?? true }, set: { _ in actions?.toggleEndpoints() }))
                .disabled(actions == nil)
            Button("Clear timeline pins") { actions?.clearPins() }.disabled(actions?.hasPins != true)
        }
        CommandGroup(replacing: .help) {
            Button("Schwabber Help") { HelpWindow.open() }.keyboardShortcut(KeyEquivalent("\u{F704}"), modifiers: [])
            Button("Keyboard shortcuts") { HelpWindow.open(shortcuts: true) }
        }
        CommandMenu("Capture") {
            Menu("Interface") {
                ForEach(actions?.interfaces ?? []) { device in
                    Button((actions?.interface == device.id ? "✓ " : "") + device.label) { actions?.chooseInterface(device.id) }
                }
            }.disabled(actions?.running == true)
            Button("Refresh interfaces") { actions?.refresh() }.disabled(actions?.running == true)
            Divider()
            Button("Start recording") { actions?.start() }.disabled(actions == nil || actions?.running == true || actions?.busy == true || actions?.interface.isEmpty != false)
            Button("Stop recording") { actions?.stop() }.disabled(actions?.running != true)
        }
    }
}
