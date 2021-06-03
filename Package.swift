// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "PowerAuth",
    products: [
        .library(
            name: "PowerAuth",
            targets: ["PowerAuth"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "PowerAuth",
            dependencies: []),
        .testTarget(
            name: "PowerAuthTests",
            dependencies: ["PowerAuth"]),
    ]
)
