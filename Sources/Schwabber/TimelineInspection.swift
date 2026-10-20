import SwiftUI
import CaptureCore

@Observable final class TimelineInspection {
    var width: Double = 1
    func chunks(session: Session, capture: Capture) -> [TimelineChunk] {
        TimelineChunks.split(times: session.packets.map(\.time), captureStart: capture.start,
                             duration: max(2, capture.end - capture.start), width: width)
    }
}
