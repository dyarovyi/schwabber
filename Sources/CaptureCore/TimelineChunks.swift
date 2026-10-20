import Foundation

public struct TimelineChunk: Equatable, Sendable {
    public let start: Int
    public let count: Int
    public let left: Double
    public let right: Double
}

public enum TimelineChunks {
    public static func split(times: [Double], captureStart: Double, duration: Double, width: Double) -> [TimelineChunk] {
        guard !times.isEmpty, width > 0, duration > 0 else { return [] }
        func x(_ time: Double) -> Double { min(width - 2, (time - captureStart) / duration * width) }
        var start = 0, left = x(times[0]), last = left
        var chunks: [TimelineChunk] = []
        for index in times.indices.dropFirst() {
            let position = x(times[index])
            if position - last < 4 { last = max(last, position); continue }
            chunks.append(TimelineChunk(start: start, count: index - start, left: left, right: last + 2))
            start = index; left = position; last = position
        }
        chunks.append(TimelineChunk(start: start, count: times.count - start, left: left, right: last + 2))
        return chunks
    }
}
