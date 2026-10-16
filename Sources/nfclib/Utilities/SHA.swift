// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CommonCrypto

enum HashLength {
    case bits256
    case bits384
    case bits512
}

func sha(hashLength: HashLength, data: some DataType) -> Bytes {
    let (digestLength, hashFunction) = switch hashLength {
    case .bits256:
        (Int(CC_SHA256_DIGEST_LENGTH), CC_SHA256)
    case .bits384:
        (Int(CC_SHA384_DIGEST_LENGTH), CC_SHA384)
    case .bits512:
        (Int(CC_SHA512_DIGEST_LENGTH), CC_SHA512)
    }

    return Bytes(unsafeUninitializedCapacity: digestLength) { buffer, initializedCount in
        data.withUnsafeBytes { dataBytes in
            _ = hashFunction(dataBytes.baseAddress, CC_LONG(dataBytes.count), buffer.baseAddress)
        }
        initializedCount = digestLength
    }
}
