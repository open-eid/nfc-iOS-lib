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
import SwiftECC
import CommonCrypto
import CoreNFC
import BigInt

public let rsaAlgorithmName = "RSA"
public let ecAlgorithmName = "EC"
public let unknownAlgorithmName = "Unknown"

func decryptNonce(encryptedNonce: Data, CAN: String) throws -> Bytes {
    let decryptionKey = KDF(key: Array(CAN.utf8), counter: 3)
    let cipher = AES.CBC(key: decryptionKey, iv: AES.Zero)
    return try cipher.decrypt(Bytes(encryptedNonce))
}

func KDF(key: Bytes, counter: UInt8) -> Bytes  {
    var keydata = key + Bytes(repeating: 0x00, count: 4)
    keydata[keydata.count - 1] = counter
    return SHA256(data: keydata)
}

func SHA256(data: Bytes) -> Bytes {
    var hash = Bytes(repeating: 0x00, count: Int(CC_SHA256_DIGEST_LENGTH))
    _ = data.withUnsafeBytes { bufferPointer in
        CC_SHA256(bufferPointer.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash
}

func convertBytesToX509Certificate(_ data: Data) throws -> SecCertificate {
    guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
        throw CertificateConversionError.creationFailed
    }
    
    return certificate
}

enum CertificateConversionError: Error {
    case creationFailed
}
