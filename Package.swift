// swift-tools-version: 6.0
// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import PackageDescription

let package = Package(
    name: "IdCardLib",
    platforms: [.iOS(.v18)],
    products: [
        .library(name: "IdCardLib", targets: ["nfclib"])
    ],
    dependencies: [
        .package(url: "https://github.com/leif-ibsen/BigInt.git", from: "1.15.0"),
        .package(url: "https://github.com/leif-ibsen/SwiftECC", from: "5.1.0")
    ],
    targets: [
        .target(
            name: "nfclib",
            dependencies: [
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "SwiftECC", package: "SwiftECC")
            ]
        )
    ],
    swiftLanguageModes: [.v5]
)
