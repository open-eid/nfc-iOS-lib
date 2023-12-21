//
//  WebEIDHash.swift
//  nfc-lib
//
//  Created by Riivo Ehrlich on 12.12.2023.
//

import Foundation
import CommonCrypto

public enum HashLength: Int {
    case bits256 = 256
    case bits384 = 384
    case bits512 = 512
}

func hashLengthFromInt(_ intValue: Int) -> HashLength? {
    return HashLength(rawValue: intValue)
}

public func sha(hashLength: HashLength, data: Data) -> Data? {
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
