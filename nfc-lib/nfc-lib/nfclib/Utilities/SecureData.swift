/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

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
