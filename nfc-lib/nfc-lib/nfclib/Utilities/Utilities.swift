// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Security

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
    case malformed(field: String)
}

func validateCertificateStructure(_ certificate: SecCertificate) throws -> (notBefore: Date, notAfter: Date) {
    guard SecCertificateCopySerialNumberData(certificate, nil) != nil else {
        throw CertificateConversionError.malformed(field: "serial number")
    }
    guard SecCertificateCopyNormalizedSubjectSequence(certificate) != nil else {
        throw CertificateConversionError.malformed(field: "subject")
    }
    guard SecCertificateCopyNormalizedIssuerSequence(certificate) != nil else {
        throw CertificateConversionError.malformed(field: "issuer")
    }
    guard let notBefore = SecCertificateCopyNotValidBeforeDate(certificate) as Date?,
          let notAfter = SecCertificateCopyNotValidAfterDate(certificate) as Date? else {
        throw CertificateConversionError.malformed(field: "validity period")
    }
    return (notBefore, notAfter)
}
