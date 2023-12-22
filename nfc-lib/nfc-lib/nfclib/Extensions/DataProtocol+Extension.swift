//
//  DataProtocol+Extension.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import SwiftECC

extension DataProtocol where Self.Index == Int {
    var toHex: String {
        return map { String(format: "%02x", $0) }.joined()
    }

    func chunked(into size: Int) -> [Bytes] {
        return stride(from: 0, to: count, by: size).map {
            Bytes(self[$0 ..< Swift.min($0 + size, count)])
        }
    }

    func removePadding() throws -> SubSequence {
        for i in (0..<count).reversed() {
            if self[i] == 0x80 {
                return self[0..<i]
            }
        }
        throw IdCardError.dataPaddingError
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

    mutating func increment() -> Self {
        for i in (0..<count).reversed() {
            self[i] += 1
            if self[i] != 0 {
                break
            }
        }
        return self
    }

    func leftShiftOneBit() -> Self {
        var shifted = Self(repeating: 0x00, count: count)
        let last = count - 1
        for index in 0..<last {
            shifted[index] = self[index] << 1
            if (self[index + 1] & 0x80) != 0 {
                shifted[index] += 0x01
            }
        }
        shifted[last] = self[last] << 1
        return shifted
    }
}
