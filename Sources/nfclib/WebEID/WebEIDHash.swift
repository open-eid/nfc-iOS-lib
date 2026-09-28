// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CommonCrypto

enum HashLength: Int {
    case bits256 = 256
    case bits384 = 384
    case bits512 = 512
}

func hashLengthFromInt(_ intValue: Int) -> HashLength? {
    return HashLength(rawValue: intValue)
}

func sha(hashLength: HashLength, data: Data) -> Data? {
    let digestLength: Int
    let hashFunction: (UnsafeRawPointer?, CC_LONG, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?

    switch hashLength {
    case .bits256:
        digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        hashFunction = CC_SHA256
    case .bits384:
        digestLength = Int(CC_SHA384_DIGEST_LENGTH)
        hashFunction = CC_SHA384
    case .bits512:
        digestLength = Int(CC_SHA512_DIGEST_LENGTH)
        hashFunction = CC_SHA512
    }

    let hashBytes = Bytes(unsafeUninitializedCapacity: digestLength) { buffer, initializedCount in
        data.withUnsafeBytes { dataBytes in
            _ = hashFunction(dataBytes.baseAddress, CC_LONG(data.count), buffer.baseAddress)
        }
        initializedCount = digestLength
    }

    return Data(hashBytes)
}
