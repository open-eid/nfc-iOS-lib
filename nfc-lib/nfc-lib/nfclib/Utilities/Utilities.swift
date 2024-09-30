//
//  Utilities.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import Foundation
@_implementationOnly import SwiftECC
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
