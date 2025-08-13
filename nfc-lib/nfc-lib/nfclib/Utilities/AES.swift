//
//  AES.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import CommonCrypto
internal import SwiftECC

class AES {
    typealias DataType = DataProtocol & ContiguousBytes
    static let BlockSize: Int = kCCBlockSizeAES128
    static let Zero = Bytes(repeating: 0x00, count: BlockSize)

    public class CBC {
        private let key: any DataType
        private let iv: any DataType

        init<K: DataType, I: DataType>(key: K, iv: I = Zero) {
            self.key = key
            self.iv = iv
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
                    iv.withUnsafeBytes { ivBytes in
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
        static let Rb: Bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87]
        let cipher: AES.CBC
        let K1: Bytes
        let K2: Bytes

        init<T: DataType>(key: T) throws {
            cipher = AES.CBC(key: key)
            let L = try cipher.encrypt(Zero)
            K1 = (L[0] & 0x80) == 0 ? L.leftShiftOneBit() : L.leftShiftOneBit() ^ CMAC.Rb
            K2 = (K1[0] & 0x80) == 0 ? K1.leftShiftOneBit() : K1.leftShiftOneBit() ^ CMAC.Rb
        }

        func authenticate<T: DataType>(bytes: T, count: Int = 8) throws -> Bytes.SubSequence where T.Index == Int {
            var blocks = bytes.chunked(into: BlockSize)
            let M_last: Bytes
            if let last = blocks.popLast() {
                if bytes.count % BlockSize == 0 {
                    M_last = Bytes(last) ^ K1
                } else {
                    M_last = Bytes(last).addPadding() ^ K2
                }
            } else {
                M_last = Bytes().addPadding() ^ K1
            }

            var x = Bytes(repeating: 0x00, count: BlockSize)
            for M_i in blocks {
                let y = x ^ M_i
                x = try cipher.encrypt(y)
            }
            let y = x ^ M_last
            let T = try cipher.encrypt(y)
            return T[0..<count]
        }
    }
}
