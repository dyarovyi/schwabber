import SwiftUI

private typealias PinState<Value> = SwiftUI.State<Value>

struct TimelinePin: Identifiable {
    let id = UUID()
    var time: Double
    var note = ""

    var tooltip: String {
        let timeText = String(format: "Pin +%.6f s from capture start", time)
        return note.isEmpty ? timeText : timeText + "\n" + note
    }
}

struct TimelinePinMarker: View {
    @Binding var pin: TimelinePin
    let width: CGFloat
    let duration: Double
    let remove: () -> Void
    let clear: () -> Void
    @PinState private var editing = false
    @PinState private var draft = ""
    @PinState private var dragOrigin: Double?
    @PinState private var hovering = false
    @GestureState private var dragging = false

    var body: some View {
        Image(systemName: "pin.fill")
            .foregroundStyle(.orange)
            .frame(width: 16, height: 18)
            .contentShape(Rectangle())
            .accessibilityLabel(pin.tooltip)
            .onHover { hovering = $0 }
            .onTapGesture {} // A click on a marker must not add a ruler pin.
            .gesture(
                DragGesture(minimumDistance: 2, coordinateSpace: .named("timelineRuler"))
                    .updating($dragging) { _, state, _ in state = true }
                    .onChanged { value in
                        if dragOrigin == nil { dragOrigin = pin.time }
                        pin.time = min(duration, max(0, (dragOrigin ?? pin.time) + value.translation.width / max(1, width) * duration))
                    }
                    .onEnded { _ in dragOrigin = nil }
            )
            .onChange(of: dragging) { _, active in
                if !active { dragOrigin = nil }
            }
            .contextMenu {
                Button(pin.note.isEmpty ? "Add note…" : "Edit note…") {
                    draft = pin.note
                    editing = true
                }
                if !pin.note.isEmpty {
                    Button("Remove note") { pin.note = "" }
                }
                Divider()
                Button("Remove pin", action: remove)
                Button("Clear all pins", action: clear)
            }
            .sheet(isPresented: $editing) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Pin note").font(.headline)
                    Text(String(format: "+%.6f s", pin.time))
                        .foregroundStyle(.secondary)
                    TextEditor(text: $draft)
                        .font(.body)
                        .frame(width: 360, height: 140)
                        .border(.secondary.opacity(0.3))
                        .accessibilityLabel("Note")
                    HStack {
                        Spacer()
                        Button("Cancel") { editing = false }
                            .keyboardShortcut(.cancelAction)
                        Button("Save") {
                            pin.note = draft
                            editing = false
                        }.keyboardShortcut(.defaultAction)
                    }
                }.padding(20)
            }
            .overlay(alignment: .topLeading) {
                if hovering && !dragging && !editing {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(String(format: "+%.6f s", pin.time))
                            .font(.caption.monospacedDigit())
                        if !pin.note.isEmpty {
                            Text(pin.note)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(10)
                    .frame(width: 280, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(.secondary.opacity(0.3), lineWidth: 1)
                    }
                    .shadow(radius: 4, y: 2)
                    // Keep the card inside the timeline at either endpoint.
                    .offset(x: max(8 - width * pin.time / duration, min(0, width - width * pin.time / duration - 272)), y: 20)
                    .allowsHitTesting(false)
                }
            }
            .zIndex(hovering ? 1 : 0)
            .offset(x: width * pin.time / duration - 8, y: 20)
    }
}
