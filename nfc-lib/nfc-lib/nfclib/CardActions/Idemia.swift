/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import Foundation

private let ATR = Bytes(hex: "3B DB 96 00 80 B1 FE 45 1F 83 00 12 23 3F 53 65 49 44 0F 90 00 F1")
private let ATRv2 = Bytes(hex: "3B DC 96 00 80 B1 FE 45 1F 83 00 12 23 3F 54 65 49 44 32 0F 90 00 C3")
private let kAID = Bytes(hex: "A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 01 00")
private let kAIDQSCD = Bytes(hex: "51 53 43 44 20 41 70 70 6C 69 63 61 74 69 6F 6E")
private let kAIDOberthur = Bytes(hex: "E8 28 BD 08 0F F2 50 4F 54 20 41 57 50")
private let AUTHKEY: UInt8 = 0x81
private let SIGNKEY: UInt8 = 0x9F

extension CodeType {
    fileprivate var aid: Bytes {
        switch self {
        case .pin1: return kAID
        case .pin2: return kAIDQSCD
        case .puk: return kAID
        }
    }
    fileprivate var pinRef: UInt8 {
        switch self {
        case .pin1: return 0x01
        case .pin2: return 0x85
        case .puk: return 0x02
        }
    }
}

class Idemia: CardCommandsInternal {
    let canChangePUK: Bool = true
    let reader: CardReader
    let fillChar: UInt8 = 0xFF

    required init?(reader: CardReader, atr: Bytes) {
        guard atr == ATR || atr == ATRv2 else {
            return nil
        }
        self.reader = reader
    }

    required init?(reader: CardReader, aid: Bytes) {
        guard aid == kAID else {
            return nil
        }
        self.reader = reader
    }

    required init?(reader: CardReader, selectAID: Bool) async {
        self.reader = reader
        if (selectAID) {
            do {
                _ = try await select(file: kAID)
            } catch {
                return nil
            }
        }
    }

    // MARK: - Public Data

    func readPublicData() async throws -> CardInfo {
        _ = try await select(file: kAID)
        _ = try await select(p1Byte: 0x01, file: [0x50, 0x00])
        var personalData = CardInfo()
        for recordNr: UInt8 in 1...8 {
            let data = try await readFile(p1Byte: 0x02, file: [0x50, recordNr])
            let record = String(data: data, encoding: .utf8) ?? "-"
            switch recordNr {
            case 1: personalData.surname = record
            case 2: personalData.givenName = record
            case 4: personalData.citizenship = !record.isEmpty ? record : "-"
            case 6: personalData.personalCode = record
            case 8: personalData.dateOfExpiry = record.replacingOccurrences(of: " ", with: ".")
            default: break
            }
        }
        return personalData
    }

    func readAuthenticationCertificate() async throws -> Data {
        _ = try await select(file: kAID)
        return try await readFile(p1Byte: 0x09, file: [0xAD, 0xF1, 0x34, 0x01])
    }

    func readSignatureCertificate() async throws -> Data {
        _ = try await select(file: kAID)
        return try await readFile(p1Byte: 0x09, file: [0xAD, 0xF2, 0x34, 0x1F])
    }

    // MARK: - PIN & PUK Management

    func readCodeTryCounterRecord(_ type: CodeType) async throws -> UInt8 {
        _ = try await select(file: type.aid)
        let ref = type.pinRef & ~0x80
        let data = try await reader.sendAPDU(ins: 0xCB, p1Byte: 0x3F, p2Byte: 0xFF, data:
            [0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, ref, 0x02, 0xA0, 0x80], leByte: 0x00)
        if let info = TLV(from: data), info.tag == 0x70,
           let tag = TLV(from: info.value), tag.tag == 0xBF8100 | UInt32(ref),
           let a0value = TLV(from: tag.value), a0value.tag == 0xA0 {
            for record in TLV.sequenceOfRecords(from: a0value.value) ?? [] where record.tag == 0x9B {
                return record.value[0]
            }
        }
        return 0
    }

    func changeCode(_ type: CodeType, to code: SecureData, verifyCode: SecureData) async throws {
        _ = try await select(file: type.aid)
        try await changeCode(type.pinRef, to: code, verifyCode: verifyCode)
    }

    func verifyCode(_ type: CodeType, code: SecureData) async throws {
        try await verifyCode(type.pinRef, code: code)
    }

    func unblockCode(_ type: CodeType, puk: SecureData, newCode: SecureData) async throws {
        guard type != .puk else {
            throw IdCardInternalError.notSupportedCodeType
        }
        try await verifyCode(.puk, code: puk)
        if type == .pin2 {
            _ = try await select(file: type.aid)
        }
        try await unblockCode(type.pinRef, puk: nil, newCode: newCode)
    }

    // MARK: - Authentication & Signing

    func authenticate(for hash: Data, withPin1 pin1: SecureData) async throws -> Data {
        _ = try await select(file: kAIDOberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xA4, algo: [0xFF, 0x20, 0x08, 0x00], keyRef: AUTHKEY)
        var paddedHash = Data(repeating: 0x00, count: max(48, hash.count) - hash.count)
        paddedHash.append(hash)
        return try await reader.sendAPDU(ins: 0x88, data: paddedHash, leByte: 0x00)
    }

    func calculateSignature(for hash: Data, withPin2 pin2: SecureData) async throws -> Data {
        _ = try await select(file: kAIDQSCD)
        try await verifyCode(.pin2, code: pin2)
        try await setSecEnv(mode: 0xB6, algo: [0xFF, 0x15, 0x08, 0x00], keyRef: SIGNKEY)
        var paddedHash = Data(repeating: 0x00, count: max(48, hash.count) - hash.count)
        paddedHash.append(hash)
        return try await reader.sendAPDU(ins: 0x2A, p1Byte: 0x9E, p2Byte: 0x9A, data: paddedHash, leByte: 0x00)
    }

    func decryptData(_ hash: Data, withPin1 pin1: SecureData) async throws -> Data {
        _ = try await select(file: kAIDOberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xB8, algo: [0xFF, 0x30, 0x04, 0x00], keyRef: AUTHKEY)
        return try await reader.sendAPDU(ins: 0x2A, p1Byte: 0x80, p2Byte: 0x86, data: [0x00] + hash, leByte: 0x00)
    }
}
