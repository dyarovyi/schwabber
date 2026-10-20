import AppKit
import SwiftUI
import CaptureCore

enum ByteCopyFormat: String, CaseIterable {
    case hex = "Hex", stream = "Hex stream", text = "Text", dump = "Hex dump"
    func string(_ data: Data) -> String {
        switch self {
        case .hex: return data.map { String(format: "%02x", $0) }.joined(separator: " ")
        case .stream: return data.map { String(format: "%02x", $0) }.joined()
        case .text: return String(decoding: data, as: UTF8.self)
        case .dump: return WiresharkInspection.hexDump(data)
        }
    }
}
func copyToClipboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}
struct FieldCopyMenu: View {
    let label: String
    let bytes: Data
    var body: some View {
        Button("Copy field") { copyToClipboard(label) }
        Button("Copy value") {
            copyToClipboard(label.range(of: ": ").map { String(label[$0.upperBound...]) } ?? label)
        }
        Divider()
        ForEach(ByteCopyFormat.allCases, id: \.self) { format in
            Button("Copy bytes as \(format.rawValue.lowercased())") { copyToClipboard(format.string(bytes)) }
                .disabled(bytes.isEmpty)
        }
    }
}
