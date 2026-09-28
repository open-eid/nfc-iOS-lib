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
