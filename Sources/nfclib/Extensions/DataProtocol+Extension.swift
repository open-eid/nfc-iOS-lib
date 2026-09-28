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
internal import SwiftECC

extension DataProtocol where Self.Index == Int {
    var toHex: String {
        return map { String(format: "%02x", $0) }.joined()
    }

    func chunked(into size: Int) -> [SubSequence] {
        stride(from: 0, to: count, by: size).map {
            self[index(startIndex, offsetBy: $0) ..< index(startIndex, offsetBy: Swift.min($0 + size, count))]
        }
    }

    func removePadding() throws -> SubSequence {
        var index = endIndex
        while index != startIndex {
            formIndex(before: &index)
            if self[index] == 0x80 {
                return self[startIndex..<index]
            } else if self[index] != 0x00 {
                throw IdCardInternalError.dataPaddingError
            }
        }
        throw IdCardInternalError.dataPaddingError
    }
}

extension DataProtocol where Self.Index == Int, Self: MutableDataProtocol {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        let chars = hex.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }
        guard hex.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }

    func addPadding() -> Self {
        var padding = Self(repeating: 0x00, count: AES.BlockSize - count % AES.BlockSize)
        padding[0] = 0x80
        return self + padding
    }

    public static func ^ (xVal: Self, yVal: Self) -> Self {
        var result = xVal
        for index in 0..<result.count {
            result[index] ^= yVal[index]
        }
        return result
    }

    static func ^ <D: Collection>(lhs: Self, rhs: D) -> Self where D.Element == Self.Element {
        precondition(lhs.count == rhs.count, "XOR operands must have equal length")
        var result = lhs
        for index in 0..<result.count {
            result[result.index(result.startIndex, offsetBy: index)] ^= rhs[rhs.index(rhs.startIndex, offsetBy: index)]
        }
        return result
    }

    mutating func increment() -> Self {
        var index = endIndex
        while index != startIndex {
            formIndex(before: &index)
            self[index] += 1
            if self[index] != 0 {
                break
            }
        }
        return self
    }

    func leftShiftOneBit() -> Self {
        var shifted = Self(repeating: 0x00, count: count)
        let last = index(before: endIndex)
        var iVal = startIndex
        while iVal < last {
            shifted[iVal] = self[iVal] << 1
            let next = index(after: iVal)
            if (self[next] & 0x80) != 0 {
                shifted[iVal] += 0x01
            }
            iVal = next
        }
        shifted[last] = self[last] << 1
        return shifted
    }
}
