// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PQCStandards",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "PQCStandards", targets: ["PQCStandards"]),
        .executable(name: "interop-verify", targets: ["InteropVerify"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "PQCStandards"),
        .executableTarget(name: "InteropVerify", dependencies: ["PQCStandards"]),
        .testTarget(name: "PQCStandardsTests", dependencies: ["PQCStandards"]),
    ]
)
