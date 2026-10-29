// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

private let ATR = Bytes(hex: "3B DB 96 00 80 B1 FE 45 1F 83 00 12 23 3F 53 65 49 44 0F 90 00 F1")
private let ATRv2 = Bytes(hex: "3B DC 96 00 80 B1 FE 45 1F 83 00 12 23 3F 54 65 49 44 32 0F 90 00 C3")

final class Idemia: IdemiaCard {
    let canChangePUK: Bool = true
    let reader: CardReader
    let fillChar: UInt8 = 0xFF
    let cardType: CardType = .id1

    let authKeyRef: UInt8 = 0x81
    let signKeyRef: UInt8 = 0x9F
    let authAlgorithm: Bytes = [0xFF, 0x20, 0x08, 0x00]
    let signAlgorithm: Bytes = [0xFF, 0x15, 0x08, 0x00]
    let decryptAlgorithm: Bytes = [0xFF, 0x30, 0x04, 0x00]

    init?(reader: CardReader, atr: Bytes) {
        guard atr == ATR || atr == ATRv2 else {
            return nil
        }
        self.reader = reader
    }

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

    func readPublicData() async throws -> CardInfo {
        _ = try await select(file: IdemiaAID.main)
        _ = try await select(p1Byte: 0x01, file: [0x50, 0x00])
        var personalData = CardInfo(cardType: cardType)
        for recordNr: UInt8 in 1...8 {
            let data = try await readFile(p1Byte: 0x02, file: [0x50, recordNr])
            let record = String(data: data, encoding: .utf8) ?? "-"
            switch recordNr {
            case 1: personalData.surname = record
            case 2: personalData.givenName = record
            case 4: personalData.citizenship = !record.isEmpty ? record : "-"
            case 5: personalData.dateAndPlaceOfBirth = record
            case 6: personalData.personalCode = record
            case 7: personalData.documentNumber = record
            case 8: personalData.dateOfExpiry = record.replacing(" ", with: ".")
            default: break
            }
        }
        return personalData
    }

    func readAuthenticationCertificate() async throws -> Data {
        _ = try await select(file: IdemiaAID.main)
        return try await readFile(p1Byte: 0x09, file: [0xAD, 0xF1, 0x34, 0x01])
    }

    func readSignatureCertificate() async throws -> Data {
        _ = try await select(file: IdemiaAID.main)
        return try await readFile(p1Byte: 0x09, file: [0xAD, 0xF2, 0x34, 0x1F])
    }
}
