// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Argon2",
    platforms: [.macOS(.v12)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .executable(name: "Argon2", targets: ["Argon2"])
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/tesseract-one/Blake2.swift.git", from: "0.1.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .executableTarget(name: "Argon2", dependencies: [
            .product(name: "Blake2", package: "Blake2.swift"),
            .product(name: "BigInt", package: "BigInt")
        ]),
        .testTarget(
            name: "Argon2Tests",
            dependencies: ["Argon2"]),
    ]
)
