// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

/**
 * Latvian eID card NFC token.
 *
 * Built on the same IDEMIA chip as the Estonian card, so PACE, secure messaging, and PIN
 * operations come from ``Idemia``. Overrides the personal-data read and uses different key
 * references for authentication and signing.
 */
final class IdemiaLatvia: Idemia {
    private static let personalCodeDF: Bytes = [0x50, 0x00]
    private static let personalCodeEF: Bytes = [0x50, 0x01]

    let canChangePUK: Bool = true
    let reader: CardReader
    let fillChar: UInt8 = 0xFF
    let cardType: CardType = .idemiaLatvia

    let authKeyRef: UInt8 = 0x82
    let signKeyRef: UInt8 = 0x9E

    /**
     * Algorithm references for the MSE algorithm-reference DO, sent as a single byte here where
     * the Estonian profile is sent the 4-byte `FF xx xx xx` form. That is what each profile is
     * known to accept, not a documented country rule:
     * - `0x04` — ECC auth / decrypt
     * - `0x54` — ECC sign
     */
    let authAlgorithm: Bytes = [0x04]
    let signAlgorithm: Bytes = [0x54]
    let decryptAlgorithm: Bytes = [0x04]
    let authCertFile: Bytes = [0xAD, 0xF1, 0x34, 0x01]
    let signCertFile: Bytes = [0xAD, 0xF2, 0x34, 0x1F]

    init(reader: CardReader) {
        self.reader = reader
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
        _ = try await select(p1Byte: 0x01, file: IdemiaLatvia.personalCodeDF)
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
}
