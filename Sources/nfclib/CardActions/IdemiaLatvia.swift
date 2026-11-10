// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Synchronization

/**
 * Latvian eID card NFC token.
 *
 * Built on the same IDEMIA chip as the Estonian card, so PACE, secure messaging, and PIN
 * operations come from ``Idemia``. Overrides the personal-data read and uses different key
 * references for authentication and signing.
 */
final class IdemiaLatvia: Idemia {
    private static let personalCodeEF: Bytes = [0x50, 0x01]
    private static let objectDirectoryEF: Bytes = [0x50, 0x31]
    private static let certificateDirectoryTag: UInt32 = 0xA4
    private static let privateKeyDirectoryTag: UInt32 = 0xA0
    private static let privateECKeyTag: UInt32 = 0xA0

    private enum CertificateUsage: Hashable {
        case authentication, signing

        var aid: Bytes {
            switch self {
            case .authentication: IdemiaAID.oberthur
            case .signing: IdemiaAID.qscd
            }
        }

        var df: Bytes {
            switch self {
            case .authentication: [0xAD, 0xF1]
            case .signing: [0xAD, 0xF2]
            }
        }

        var defaultKeyReference: UInt8 {
            switch self {
            case .authentication: 0x82
            case .signing: 0x9E
            }
        }
    }

    private struct KeyDescriptor {
        let certificateFile: Bytes
        let keyReference: UInt8
    }

    private let descriptors = Mutex<[CertificateUsage: KeyDescriptor]>([:])

    let canChangePUK: Bool = true
    let reader: CardReader
    let fillChar: UInt8 = 0xFF
    let cardType: CardType = .idemiaLatvia

    var authKeyRef: UInt8 { get async throws { try await descriptor(for: .authentication).keyReference } }

    var signKeyRef: UInt8 { get async throws { try await descriptor(for: .signing).keyReference } }

    var authCertFile: Bytes { get async throws { try await descriptor(for: .authentication).certificateFile } }

    var signCertFile: Bytes { get async throws { try await descriptor(for: .signing).certificateFile } }

    init?(reader: CardReader, aid: Bytes) {
        guard aid == IdemiaAID.main else {
            return nil
        }
        self.reader = reader
    }

    init?(reader: CardReader, selectAID: Bool) async {
        self.reader = reader
        if (selectAID) {
            do {
                _ = try await select(file: IdemiaAID.main)
            } catch {
                return nil
            }
        }
    }

    // MARK: - Public Data

    /**
     * Read personal data from the auth certificate subject and EF 0x5001 (personal code).
     * Latvian eID cards store only the personal code in EF files (DF 0x5000 / EF 0x5001).
     * Name, issuing country, and document number are extracted from the auth certificate subject:
     *   - OID 2.5.4.4  (surname)
     *   - OID 2.5.4.42 (givenName)
     *   - OID 2.5.4.5  (serialNumber) — format "PNOLV-{personalCode}", used as the document
     *     number because the card carries no separate document-number field
     *   - C (2.5.4.6)  — issuing country of the certificate authority. Mapped to
     *     ``CardInfo/issuingCountry``, NOT to citizenship: the value is the CA's country
     *     (always "LV" here), and a foreign resident could in principle hold an LV-issued card.
     *     Citizenship is left empty because the LV card does not expose it over NFC.
     * Cert expiry comes from the certificate's notAfter; document expiry is not exposed by
     * Latvian IDEMIA cards over NFC, so it is left nil.
     */
    func readPublicData() async throws -> CardInfo {
        let personalCode = try await readPersonalCode()

        let certificateBytes = try await readAuthenticationCertificate()
        let certificate = try convertBytesToX509Certificate(certificateBytes)
        let (_, notAfter) = try validateCertificateStructure(certificate)
        let subject = try CertificateSubject(derEncodedCertificate: certificateBytes)

        return CardInfo(
            givenName: subject.givenName,
            surname: subject.surname,
            personalCode: personalCode,
            documentNumber: subject.serialNumber,
            issuingCountry: subject.country,
            certificateExpiryDate: notAfter,
            cardType: cardType
        )
    }

    // MARK: - Reads

    private func readPersonalCode() async throws -> String {
        // Read personal code from EF 0x5001
        _ = try await select(file: IdemiaAID.main)
        _ = try await select(p1Byte: 0x01, file: personalDataDF)
        _ = try await select(p1Byte: 0x02, file: IdemiaLatvia.personalCodeEF)
        let record = try await reader.sendAPDU(ins: 0xB0, leByte: 0x00)

        // Strip trailing 0xFF (CardOS unused-space marker on fixed-size EFs) before UTF-8
        // decoding — 0xFF is not valid UTF-8, so leaving it in fails the decode outright.
        let trimmed = record.prefix(while: { $0 != fillChar })
        guard let personalCode = String(data: Data(trimmed), encoding: .utf8) else {
            throw IdCardInternalError.failedReadingField(.personalCode)
        }
        let trimmedCode = personalCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedCode.isEmpty else {
            throw IdCardInternalError.failedReadingField(.personalCode)
        }
        return trimmedCode
    }

    // MARK: - PKCS#15 descriptors

    private func descriptor(for usage: CertificateUsage) async throws -> KeyDescriptor {
        if let cached = descriptors.withLock({ $0[usage] }) {
            return cached
        }

        _ = try await select(file: usage.aid)
        let objects = try await readFile(p1Byte: 0x02, file: IdemiaLatvia.objectDirectoryEF)

        let certificateDirectory = try await readDirectory(
            objects, tag: IdemiaLatvia.certificateDirectoryTag, file: "EF.CD")
        let certificateFile = try descriptorValue(
            certificateDirectory, path: [0x30, 0xA1, 0x30, 0x30, 0x04], file: "EF.CD")
        guard certificateFile.count == 2 else {
            throw IdCardInternalError.invalidResponse(
                message: "EF.CD: certificate reference is \(certificateFile.count) bytes, expected 2")
        }

        let privateKeyDirectory = try await readDirectory(
            objects, tag: IdemiaLatvia.privateKeyDirectoryTag, file: "EF.PrKD")
        guard let key = TLV.sequenceOfRecords(from: privateKeyDirectory)?.first else {
            throw IdCardInternalError.invalidResponse(message: "EF.PrKD: no private key record")
        }
        guard key.tag == IdemiaLatvia.privateECKeyTag else {
            throw IdCardInternalError.cardNotSupported
        }

        let descriptor = KeyDescriptor(
            certificateFile: usage.df + Bytes(certificateFile),
            keyReference: keyReference(in: key.value) ?? usage.defaultKeyReference
        )
        descriptors.withLock { $0[usage] = descriptor }
        return descriptor
    }

    private func readDirectory(_ objectDirectory: Data, tag: UInt32, file: String) async throws -> Data {
        let reference = try descriptorValue(objectDirectory, path: [tag, 0x30, 0x04], file: "EF.OD")
        guard reference.count == 2 else {
            throw IdCardInternalError.invalidResponse(
                message: "EF.OD: \(file) reference is \(reference.count) bytes, expected 2")
        }
        return try await readFile(p1Byte: 0x02, file: Bytes(reference))
    }

    private func keyReference(in privateKey: Data) -> UInt8? {
        guard let attributes = TLV.sequenceOfRecords(from: privateKey)?.dropFirst().first,
              let identifier = TLV.sequenceOfRecords(from: attributes.value)?
                  .first(where: { $0.tag == 0x02 }),
              identifier.value.count == 2 else {
            return nil
        }
        return identifier.value.last
    }

    private func descriptorValue(_ data: Data, path: [UInt32], file: String) throws -> Data {
        var value = data
        for tag in path {
            guard let records = TLV.sequenceOfRecords(from: value),
                  let record = records.first(where: { $0.tag == tag }) else {
                throw IdCardInternalError.invalidResponse(
                    message: "\(file): missing PKCS#15 tag 0x\(String(tag, radix: 16, uppercase: true))")
            }
            value = record.value
        }
        return value
    }
}
