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

import CommonCrypto
import Foundation
internal import SwiftECC

class AES {
    typealias DataType = DataProtocol & ContiguousBytes
    static let BlockSize: Int = kCCBlockSizeAES128
    static let Zero = Bytes(repeating: 0x00, count: BlockSize)

    public class CBC {
        private let key: any DataType
        private let ivVal: any DataType

        init<K: DataType, I: DataType>(key: K, ivVal: I = Zero) {
            self.key = key
            self.ivVal = ivVal
        }

        func encrypt<T: DataType>(_ data: T) throws -> Bytes {
            return try crypt(data: data, operation: kCCEncrypt)
        }

        func decrypt<T: DataType>(_ data: T) throws -> Bytes {
            return try crypt(data: data, operation: kCCDecrypt)
        }

        private func crypt<T: DataType>(data: T, operation: Int) throws -> Bytes {
            try Bytes(unsafeUninitializedCapacity: data.count + BlockSize) { buffer, initializedCount in
                let status = data.withUnsafeBytes { dataBytes in
                    ivVal.withUnsafeBytes { ivBytes in
                        key.withUnsafeBytes { keyBytes in
                            CCCrypt(
                                CCOperation(operation),
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(0),
                                keyBytes.baseAddress, key.count,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress, data.count,
                                buffer.baseAddress, buffer.count,
                                &initializedCount
                            )
                        }
                    }
                }
                guard status == kCCSuccess else {
                    throw IdCardInternalError.AESCBCError
                }
            }
        }
    }

    public class CMAC {
        static let RBytes: Bytes = [
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x87
        ]
        let cipher: AES.CBC
        let k1Bytes: Bytes
        let k2Bytes: Bytes

        init<T: DataType>(key: T) throws {
            cipher = AES.CBC(key: key)
            let LBytes = try cipher.encrypt(Zero)
            k1Bytes = (LBytes[0] & 0x80) == 0 ? LBytes.leftShiftOneBit() : LBytes.leftShiftOneBit() ^ CMAC.RBytes
            k2Bytes = (k1Bytes[0] & 0x80) == 0 ? k1Bytes.leftShiftOneBit() : k1Bytes.leftShiftOneBit() ^ CMAC.RBytes
        }

        func authenticate<T: DataType>(bytes: T, count: Int = 8) throws -> Bytes.SubSequence where T.Index == Int {
            var blocks = bytes.chunked(into: BlockSize)
            let mLast: Bytes
            if let last = blocks.popLast() {
                if bytes.count % BlockSize == 0 {
                    mLast = Bytes(last) ^ k1Bytes
                } else {
                    mLast = Bytes(last).addPadding() ^ k2Bytes
                }
            } else {
                mLast = Bytes().addPadding() ^ k1Bytes
            }

            var xVal = Bytes(repeating: 0x00, count: BlockSize)
            for mIndex in blocks {
                let yVal = xVal ^ mIndex
                xVal = try cipher.encrypt(yVal)
            }
            let yVal = xVal ^ mLast
            let tBytes = try cipher.encrypt(yVal)
            return tBytes[0..<count]
        }
    }
}
