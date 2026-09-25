// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Darwin // for memset_s

/// Holds sensitive bytes and reliably zeroes them on deinit.
public final class SecureData: Sendable {
    private var storage: Data

    public init(_ bytes: [UInt8]) {
        self.storage = Data(bytes)
    }

    public init(_ data: Data) {
        self.storage = data
    }

    deinit { secureZero() }

    /// Mutating read-only access to the underlying bytes.
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeBytes(body)
    }

    /// Mutating access when you need to write into the buffer.
    func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withUnsafeMutableBytes(body)
    }

    public var count: Int { storage.count }

    /// Explicitly wipe now (also runs on deinit).
    public func secureZero() {
        guard storage.count > 0 else { return }
        storage.withUnsafeMutableBytes { buf in
            _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
        }
        storage.removeAll(keepingCapacity: false)
    }

    /// If you need a temporary `Data` view (try to avoid).
    func asData() -> Data { storage }
}
