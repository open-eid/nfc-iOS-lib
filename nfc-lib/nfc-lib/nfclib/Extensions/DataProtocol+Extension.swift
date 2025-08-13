//
//  DataProtocol+Extension.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

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
        var i = endIndex
        while i != startIndex {
            formIndex(before: &i)
            if self[i] == 0x80 {
                return self[startIndex..<i]
            } else if self[i] != 0x00 {
                throw IdCardInternalError.dataPaddingError
            }
        }
        throw IdCardInternalError.dataPaddingError
    }
}

extension DataProtocol where Self.Index == Int, Self : MutableDataProtocol {
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

    public static func ^ (x: Self, y: Self) -> Self {
        var result = x
        for i in 0..<result.count {
            result[i] ^= y[i]
        }
        return result
    }

    static func ^ <D: Collection>(lhs: Self, rhs: D) -> Self where D.Element == Self.Element {
        precondition(lhs.count == rhs.count, "XOR operands must have equal length")
        var result = lhs
        for i in 0..<result.count {
            result[result.index(result.startIndex, offsetBy: i)] ^= rhs[rhs.index(rhs.startIndex, offsetBy: i)]
        }
        return result
    }

    mutating func increment() -> Self {
        var i = endIndex
        while i != startIndex {
            formIndex(before: &i)
            self[i] += 1
            if self[i] != 0 {
                break
            }
        }
        return self
    }

    func leftShiftOneBit() -> Self {
        var shifted = Self(repeating: 0x00, count: count)
        let last = index(before: endIndex)
        var i = startIndex
        while i < last {
            shifted[i] = self[i] << 1
            let next = index(after: i)
            if (self[next] & 0x80) != 0 {
                shifted[i] += 0x01
            }
            i = next
        }
        shifted[last] = self[last] << 1
        return shifted
    }
}
