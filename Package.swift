// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "Schwabber",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "Schwabber", targets: ["Schwabber"])],
    targets: [
        .systemLibrary(name: "CPcap"),
        .target(name: "CaptureCore", dependencies: ["CPcap"]),
        .executableTarget(name: "Schwabber", dependencies: ["CaptureCore"]),
        .testTarget(name: "CaptureCoreTests", dependencies: ["CaptureCore"])
    ]
)
