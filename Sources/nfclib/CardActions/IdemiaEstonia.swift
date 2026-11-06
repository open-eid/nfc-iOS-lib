// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

final class IdemiaEstonia: Idemia {
    let canChangePUK: Bool = true
    let reader: CardReader
    let fillChar: UInt8 = 0xFF
    let cardType: CardType = .idemiaEstonia

    let authKeyRef: UInt8 = 0x81
    let signKeyRef: UInt8 = 0x9F
    let authAlgorithm: Bytes = [0xFF, 0x20, 0x08, 0x00]
    let signAlgorithm: Bytes = [0xFF, 0x15, 0x08, 0x00]
    let decryptAlgorithm: Bytes = [0xFF, 0x30, 0x04, 0x00]
    let authCertFile: Bytes = [0xAD, 0xF1, 0x34, 0x01]
    let signCertFile: Bytes = [0xAD, 0xF2, 0x34, 0x1F]

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
}
