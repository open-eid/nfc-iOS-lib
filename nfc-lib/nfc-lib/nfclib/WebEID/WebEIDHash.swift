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
    var hash: [UInt8]
    
    switch hashLength {
    case .bits256:
        hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { dataBytes in
            _ = CC_SHA256(dataBytes.baseAddress, CC_LONG(data.count), &hash)
        }
    case .bits384:
        hash = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        data.withUnsafeBytes { dataBytes in
            _ = CC_SHA384(dataBytes.baseAddress, CC_LONG(data.count), &hash)
        }
    case .bits512:
        hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes { dataBytes in
            _ = CC_SHA512(dataBytes.baseAddress, CC_LONG(data.count), &hash)
        }
    }
    
    return Data(hash)
}
