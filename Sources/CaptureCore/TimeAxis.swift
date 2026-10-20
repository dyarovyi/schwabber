import Foundation

/// Round tick spacing shared by the ruler and timeline grid.
public struct TimeAxis: Sendable {
    public let step: Double
    public let decimals: Int
    public let ticks: [Double]
    public init(duration: Double, width: Double) {
        let duration = max(duration, 0.000001)
        let raw = duration * 110 / max(width, 1)
        let magnitude = pow(10, floor(log10(raw)))
        step = [1.0, 2, 5, 10].map { $0 * magnitude }.first { $0 >= raw * (1 - 1e-9) }!
        decimals = min(6, max(0, Int(-floor(log10(step) + 1e-9))))
        let tickStep = step
        ticks = (0...min(100_000, Int(floor(duration / step + 1e-9)))).map { Double($0) * tickStep }
    }
}
