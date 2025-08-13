//
//  Utilities.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import Foundation
internal import SwiftECC
import CommonCrypto
import CoreNFC
import BigInt

public let rsaAlgorithmName = "RSA"
public let ecAlgorithmName = "EC"
public let unknownAlgorithmName = "Unknown"

func convertBytesToX509Certificate(_ data: Data) throws -> SecCertificate {
    guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
        throw CertificateConversionError.creationFailed
    }
    
    return certificate
}

enum CertificateConversionError: Error {
    case creationFailed
}
