/*
 * Copyright 2017 - 2023 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import CommonCrypto
import SwiftECC

class AES {
    static let BlockSize: Int = kCCBlockSizeAES128
    static let Zero = Bytes(repeating: 0x00, count: BlockSize)

    public class CBC {
        private let key: Bytes
        private let iv: Bytes

        init(key: Bytes, iv: Bytes) {
            self.key = key
            self.iv = iv
        }

        func encrypt<T : DataProtocol & ContiguousBytes>(_ data: T) throws -> Bytes {
            return try crypt(data: data, operation: kCCEncrypt)
        }

        func decrypt<T : DataProtocol & ContiguousBytes>(_ data: T) throws -> Bytes {
            return try crypt(data: data, operation: kCCDecrypt)
        }

        private func crypt<T : DataProtocol & ContiguousBytes>(data: T, operation: Int) throws -> Bytes {
            var bytesWritten = 0
            var outputBuffer = Bytes(repeating: 0, count: data.count + BlockSize)
            let status = data.withUnsafeBytes { dataBytes in
                iv.withUnsafeBytes { ivBytes in
                    key.withUnsafeBytes { keyBytes in
                        CCCrypt(
                            CCOperation(operation),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), //kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            key.count,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress,
                            data.count,
                            &outputBuffer,
                            outputBuffer.count,
                            &bytesWritten
                        )
                    }
                }
            }
            if status != kCCSuccess {
                throw IdCardInternalError.AESCBCError
            }
            return Bytes(outputBuffer.prefix(bytesWritten))
        }
    }

    public class CMAC {
        static let Rb: Bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87]
        let cipher: AES.CBC
        let K1: Bytes
        let K2: Bytes

        public init(key: Bytes) throws {
            cipher = AES.CBC(key: key, iv: Zero)
            let L = try cipher.encrypt(Zero)
            K1 = (L[0] & 0x80) == 0 ? L.leftShiftOneBit() : L.leftShiftOneBit() ^ CMAC.Rb
            K2 = (K1[0] & 0x80) == 0 ? K1.leftShiftOneBit() : K1.leftShiftOneBit() ^ CMAC.Rb
        }

        public func authenticate<T>(bytes: T, count: Int) throws -> Bytes where T : DataProtocol, T.Index == Int {
            let n = ceil(Double(bytes.count) / Double(BlockSize))
            let lastBlockComplete: Bool
            if n == 0 {
                lastBlockComplete = false
            } else {
                lastBlockComplete = bytes.count % BlockSize == 0
            }

            var blocks = bytes.chunked(into: BlockSize)
            var M_last = blocks.popLast() ?? Bytes()
            if lastBlockComplete {
                M_last = M_last ^ K1
            } else {
                M_last = M_last.addPadding() ^ K2
            }

            var x = Bytes(repeating: 0x00, count: BlockSize)
            var y: Bytes
            for M_i in blocks {
                y = x ^ M_i
                x = try cipher.encrypt(y)
            }
            y = M_last ^ x
            let T = try cipher.encrypt(y)
            return Bytes(T[0..<count])
        }
    }
}
