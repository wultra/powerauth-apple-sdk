// swift-tools-version:5.4

import PackageDescription

let package = Package(
    name: "PowerAuth",
    platforms: [
        .iOS(.v9),
        .tvOS(.v9),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "PowerAuth",
            targets: ["PowerAuth"]),
    ],
    dependencies: [
        .package(name: "PowerAuthShared", url: "https://github.com/wultra/powerauth-apple-shared.git", .branch("develop")),
        .package(name: "PowerAuthCore", url: "https://github.com/wultra/powerauth-client-core.git", .branch("beta-releases"))
    ],
    targets: [
        .target(
            name: "PowerAuth",
            dependencies: ["PowerAuthShared", "PowerAuthCore"]),
        .testTarget(
            name: "PowerAuthTests",
            dependencies: ["PowerAuth"]),
    ]
)
