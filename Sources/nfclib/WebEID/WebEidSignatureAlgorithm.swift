// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Security

public enum WebEidSignatureAlgorithm: String, Sendable {
    case es256 = "ES256"
    case es384 = "ES384"

    var hashLength: HashLength {
        switch self {
        case .es256: .bits256
        case .es384: .bits384
        }
    }

    static func forAuthenticationKey(
        _ key: SecKey
    ) throws(AuthenticateWithWebEidError) -> WebEidSignatureAlgorithm {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let keyType = attributes[kSecAttrKeyType as String] as? String,
              let keySizeInBits = attributes[kSecAttrKeySizeInBits as String] as? Int else {
            throw .failedToDetermineAlgorithm
        }

        guard keyType == String(kSecAttrKeyTypeECSECPrimeRandom) else {
            throw .failedToMapAlgorithm
        }

        switch keySizeInBits {
        case 256: return .es256
        case 384: return .es384
        default: throw .failedToMapAlgorithm
        }
    }
}
