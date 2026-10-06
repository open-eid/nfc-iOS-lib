// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Synchronization
import Darwin // for memset_s

/// Holds sensitive bytes and reliably zeroes them on deinit.
public final class SecureData: Sendable {
    private let storage: Mutex<Data>

    public init(_ bytes: [UInt8]) {
        self.storage = Mutex(Data(bytes))
    }

    public init(_ data: Data) {
        self.storage = Mutex(data)
    }

    deinit { secureZero() }

    /// Read-only access to the underlying bytes. The lock is held for the duration of `body`,
    /// which must not call back into this instance.
    func withUnsafeBytes<R: Sendable>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withLock { try $0.withUnsafeBytes(body) }
    }

    /// Mutating access when you need to write into the buffer. Same re-entrancy rule as above.
    func withUnsafeMutableBytes<R: Sendable>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try storage.withLock { try $0.withUnsafeMutableBytes(body) }
    }

    public var count: Int { storage.withLock { $0.count } }

    /// Explicitly wipe now (also runs on deinit).
    public func secureZero() {
        storage.withLock { data in
            guard !data.isEmpty else { return }
            data.withUnsafeMutableBytes { buf in
                _ = memset_s(buf.baseAddress, buf.count, 0, buf.count)
            }
            data.removeAll(keepingCapacity: false)
        }
    }
}
