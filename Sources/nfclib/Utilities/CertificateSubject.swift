// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CryptoTokenKit

/**
 * Subject fields of an X.509 certificate, read from the DER directly because iOS publishes no
 * per-RDN accessor and `SecCertificateCopyNormalizedSubjectSequence` returns a DER-encoded name
 * rather than decoded strings.
 */
struct CertificateSubject {
    let surname: String
    let givenName: String
    let country: String
    let serialNumber: String

    private enum AttributeOID {
        static let surname = "550404"      // 2.5.4.4
        static let givenName = "55042a"    // 2.5.4.42
        static let serialNumber = "550405" // 2.5.4.5
        static let country = "550406"      // 2.5.4.6
    }

    init(derEncodedCertificate certificate: Data) throws {
        let attributes = try CertificateSubject.subjectAttributes(of: certificate)
        guard let surname = attributes[AttributeOID.surname],
              let givenName = attributes[AttributeOID.givenName] else {
            throw CertificateConversionError.malformed(field: "subject name")
        }
        self.surname = surname
        self.givenName = givenName
        country = attributes[AttributeOID.country] ?? ""
        serialNumber = attributes[AttributeOID.serialNumber] ?? ""
    }

    /**
     * Extract the subject's RDN values by attribute-type OID, keyed by lower-case hex as
     * `toHex` renders it. Where an OID appears more than once the first occurrence wins.
     */
    private static func subjectAttributes(of certificate: Data) throws -> [String: String] {
        guard let outer = TKBERTLVRecord(from: certificate),
              let tbsCertificate = TKBERTLVRecord.sequenceOfRecords(from: outer.value)?.first,
              var fields = TKBERTLVRecord.sequenceOfRecords(from: tbsCertificate.value) else {
            throw CertificateConversionError.malformed(field: "certificate")
        }

        if fields.first?.tag == 0xA0 {
            fields.removeFirst()
        }
        guard fields.count > 4, fields[4].tag == 0x30 else {
            throw CertificateConversionError.malformed(field: "subject")
        }

        guard let relativeNames = TKBERTLVRecord.sequenceOfRecords(from: fields[4].value) else {
            throw CertificateConversionError.malformed(field: "subject")
        }
        var attributes: [String: String] = [:]
        for relativeName in relativeNames {
            for attribute in TKBERTLVRecord.sequenceOfRecords(from: relativeName.value) ?? [] {
                guard let pair = TKBERTLVRecord.sequenceOfRecords(from: attribute.value),
                      pair.count >= 2, pair[0].tag == 0x06,
                      let value = directoryString(pair[1]) else { continue }
                let objectIdentifier = pair[0].value.toHex
                if attributes[objectIdentifier] == nil {
                    attributes[objectIdentifier] = value
                }
            }
        }
        return attributes
    }

    private static func directoryString(_ record: TKTLVRecord) -> String? {
        switch record.tag {
        case 0x1E: return String(data: record.value, encoding: .utf16BigEndian)
        case 0x14: return String(data: record.value, encoding: .isoLatin1)
        case 0x0C, 0x13, 0x16: return String(data: record.value, encoding: .utf8)
        default: return nil
        }
    }
}
