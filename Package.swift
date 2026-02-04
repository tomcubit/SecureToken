// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecureToken",
    platforms: [
        .macOS(.v10_13)
    ],
    products: [
        .executable(name: "securetoken", targets: ["SecureToken"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0")
    ],
    targets: [
        .executableTarget(
            name: "SecureToken",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            path: "Sources/SecureToken"
        ),
        .testTarget(
            name: "SecureTokenTests",
            dependencies: ["SecureToken"],
            path: "Tests/SecureTokenTests"
        )
    ]
)
