// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

enum IdemiaAID {
    static let main: Bytes = [
        0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
        0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00
    ]
    static let qscd: Bytes = [
        0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70,
        0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E
    ]
    static let oberthur: Bytes = [
        0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xF2, 0x50, 0x4F,
        0x54, 0x20, 0x41, 0x57, 0x50
    ]
}

extension CodeType {
    fileprivate var aid: Bytes {
        switch self {
        case .pin1: return IdemiaAID.main
        case .pin2: return IdemiaAID.qscd
        case .puk: return IdemiaAID.main
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

protocol Idemia: CardCommandsInternal {
    var authKeyRef: UInt8 { get async throws }
    var signKeyRef: UInt8 { get async throws }
    var authCertFile: Bytes { get async throws }
    var signCertFile: Bytes { get async throws }
}

extension Idemia {
    var personalDataDF: Bytes { [0x50, 0x00] }
    var authAlgorithm: Bytes { [0x04] }
    var signAlgorithm: Bytes { [0x54] }
    var decryptAlgorithm: Bytes { [0x04] }

    // MARK: - Certificates

    func readAuthenticationCertificate() async throws -> Data {
        try await readCertificate(file: authCertFile)
    }

    func readSignatureCertificate() async throws -> Data {
        try await readCertificate(file: signCertFile)
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
        throw IdCardInternalError.invalidResponse(
            message: "Missing PIN counter record for \(cardType.rawValue)")
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
        let keyRef = try await authKeyRef
        _ = try await select(file: IdemiaAID.oberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xA4, algo: authAlgorithm, keyRef: keyRef)
        return try await reader.sendAPDU(ins: 0x88, data: padWithZeroes(hash), leByte: 0x00)
    }

    func calculateSignature(for hash: any DataType, withPin2 pin2: SecureData) async throws -> Data {
        let keyRef = try await signKeyRef
        _ = try await select(file: IdemiaAID.qscd)
        try await verifyCode(.pin2, code: pin2)
        try await setSecEnv(mode: 0xB6, algo: signAlgorithm, keyRef: keyRef)
        return try await reader.sendAPDU(
            ins: 0x2A, p1Byte: 0x9E, p2Byte: 0x9A, data: padWithZeroes(hash), leByte: 0x00)
    }

    func decryptData(_ hash: any DataType, withPin1 pin1: SecureData) async throws -> Data {
        let keyRef = try await authKeyRef
        _ = try await select(file: IdemiaAID.oberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xB8, algo: decryptAlgorithm, keyRef: keyRef)
        return try await reader.sendAPDU(ins: 0x2A, p1Byte: 0x80, p2Byte: 0x86, data: [0x00] + hash, leByte: 0x00)
    }

    // MARK: - Helpers

    private func readCertificate(file: Bytes) async throws -> Data {
        _ = try await select(file: IdemiaAID.main)
        return try await readFile(p1Byte: 0x09, file: file)
    }

    /**
     * @return zero padded hash with 48 byte length or same hash if it's longer than 48 bytes.
     */
    private func padWithZeroes(_ hash: any DataType) -> Data {
        var padded = Data(repeating: 0x00, count: max(0, 48 - hash.count))
        padded.append(contentsOf: hash)
        return padded
    }
}
