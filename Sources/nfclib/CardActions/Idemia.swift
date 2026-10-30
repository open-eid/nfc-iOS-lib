// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

private let kAID: Bytes = [
    0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
    0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00
]
private let kAIDQSCD: Bytes = [
    0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70,
    0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E
]
private let kAIDOberthur: Bytes = [
    0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xF2, 0x50, 0x4F,
    0x54, 0x20, 0x41, 0x57, 0x50
]
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

final class Idemia: CardCommandsInternal {
    let canChangePUK: Bool = true
    let reader: CardReader
    let fillChar: UInt8 = 0xFF

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
        _ = try await select(file: kAID)
        return try await readFile(p1Byte: 0x09, file: [0xAD, 0xF1, 0x34, 0x01])
    }

    func readSignatureCertificate() async throws -> Data {
        _ = try await select(file: kAID)
        return try await readFile(p1Byte: 0x09, file: [0xAD, 0xF2, 0x34, 0x1F])
    }

    // MARK: - PIN & PUK Management

    func readCodeTryCounterRecord(_ type: CodeType) async throws -> (retryCount: UInt8, pinActive: Bool) {
        _ = try await select(file: type.aid)
        let ref = type.pinRef & ~0x80
        let data = try await reader.sendAPDU(ins: 0xCB, p1Byte: 0x3F, p2Byte: 0xFF, data:
            [0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, ref, 0x02, 0xA0, 0x80], leByte: 0x00)
        if let info = TLV(from: data), info.tag == 0x70,
           let tag = TLV(from: info.value), tag.tag == 0xBF8100 | UInt32(ref),
           let a0Value = TLV(from: tag.value), a0Value.tag == 0xA0,
           let records = TLV.sequenceOfRecords(from: a0Value.value) {
            for record in records where record.tag == 0x9B {
                guard let counter = record.value.first else { continue }
                return (counter, true)
            }
        }
        throw IdCardInternalError.invalidResponse(message: "Missing PIN counter record")
    }

    func changeCode(_ type: CodeType, to code: SecureData, verifyCode: SecureData) async throws {
        _ = try await select(file: type.aid)
        try await changeCode(type.pinRef, codeType: type, to: code, verifyCode: verifyCode)
    }

    func verifyCode(_ type: CodeType, code: SecureData) async throws {
        try await verifyCode(type.pinRef, codeType: type, code: code)
    }

    func unblockCode(_ type: CodeType, puk: SecureData, newCode: SecureData) async throws {
        guard type != .puk else {
            throw IdCardInternalError.notSupportedCodeType
        }
        try await verifyCode(.puk, code: puk)
        if type == .pin2 {
            _ = try await select(file: type.aid)
        }
        try await unblockCode(type.pinRef, codeType: type, puk: nil, newCode: newCode)
    }

    // MARK: - Authentication & Signing

    func authenticate(for hash: any DataType, withPin1 pin1: SecureData) async throws -> Data {
        _ = try await select(file: kAIDOberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xA4, algo: [0xFF, 0x20, 0x08, 0x00], keyRef: AUTHKEY)
        var paddedHash = Data(repeating: 0x00, count: max(48, hash.count) - hash.count)
        paddedHash.append(contentsOf: hash)
        return try await reader.sendAPDU(ins: 0x88, data: paddedHash, leByte: 0x00)
    }

    func calculateSignature(for hash: any DataType, withPin2 pin2: SecureData) async throws -> Data {
        _ = try await select(file: kAIDQSCD)
        try await verifyCode(.pin2, code: pin2)
        try await setSecEnv(mode: 0xB6, algo: [0xFF, 0x15, 0x08, 0x00], keyRef: SIGNKEY)
        var paddedHash = Data(repeating: 0x00, count: max(48, hash.count) - hash.count)
        paddedHash.append(contentsOf: hash)
        return try await reader.sendAPDU(ins: 0x2A, p1Byte: 0x9E, p2Byte: 0x9A, data: paddedHash, leByte: 0x00)
    }

    func decryptData(_ hash: any DataType, withPin1 pin1: SecureData) async throws -> Data {
        _ = try await select(file: kAIDOberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xB8, algo: [0xFF, 0x30, 0x04, 0x00], keyRef: AUTHKEY)
        return try await reader.sendAPDU(ins: 0x2A, p1Byte: 0x80, p2Byte: 0x86, data: [0x00] + hash, leByte: 0x00)
    }
}
