// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

enum IdemiaAID {
    static let main = Bytes(hex: "A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 01 00")
    static let qscd = Bytes(hex: "51 53 43 44 20 41 70 70 6C 69 63 61 74 69 6F 6E")
    static let oberthur = Bytes(hex: "E8 28 BD 08 0F F2 50 4F 54 20 41 57 50")
}

/**
 * Commands shared by the IDEMIA cards. PIN management, authentication, signing and decryption
 * are identical across them; only the key references and MSE algorithm references vary, so
 * conformers supply those as values. Personal data and certificate layout differ, so those stay
 * requirements of ``CardCommands``.
 */
protocol IdemiaCard: CardCommandsInternal {
    var authKeyRef: UInt8 { get }
    var signKeyRef: UInt8 { get }
    var authAlgorithm: Bytes { get }
    var signAlgorithm: Bytes { get }
    var decryptAlgorithm: Bytes { get }
}

extension IdemiaCard {

    // MARK: - PIN & PUK Management

    func readCodeTryCounterRecord(_ type: CodeType) async throws -> (retryCount: UInt8, pinActive: Bool) {
        _ = try await select(file: aid(for: type))
        let ref = pinRef(for: type) & ~0x80
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
        _ = try await select(file: aid(for: type))
        try await changeCode(pinRef(for: type), codeType: type, to: code, verifyCode: verifyCode)
    }

    func verifyCode(_ type: CodeType, code: SecureData) async throws {
        try await verifyCode(pinRef(for: type), codeType: type, code: code)
    }

    func unblockCode(_ type: CodeType, puk: SecureData, newCode: SecureData) async throws {
        guard type != .puk else {
            throw IdCardInternalError.notSupportedCodeType
        }
        // PUK is associated with the MAIN AID context, so VERIFY PUK must run there. Make this
        // self-contained instead of relying on the caller leaving MAIN active — otherwise calls
        // composed after readCodeTryCounterRecord(.pin2)/calculateSignature would silently fail
        // with a "wrong PUK" error.
        _ = try await select(file: IdemiaAID.main)
        try await verifyCode(.puk, code: puk)
        if type == .pin2 {
            _ = try await select(file: IdemiaAID.qscd)
        }
        try await unblockCode(pinRef(for: type), codeType: type, puk: nil, newCode: newCode)
    }

    // MARK: - Authentication & Signing

    func authenticate(for hash: Data, withPin1 pin1: SecureData) async throws -> Data {
        _ = try await select(file: IdemiaAID.oberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xA4, algo: authAlgorithm, keyRef: authKeyRef)
        return try await reader.sendAPDU(ins: 0x88, data: padWithZeroes(hash), leByte: 0x00)
    }

    func calculateSignature(for hash: Data, withPin2 pin2: SecureData) async throws -> Data {
        _ = try await select(file: IdemiaAID.qscd)
        try await verifyCode(.pin2, code: pin2)
        try await setSecEnv(mode: 0xB6, algo: signAlgorithm, keyRef: signKeyRef)
        return try await reader.sendAPDU(
            ins: 0x2A, p1Byte: 0x9E, p2Byte: 0x9A, data: padWithZeroes(hash), leByte: 0x00)
    }

    func decryptData(_ hash: Data, withPin1 pin1: SecureData) async throws -> Data {
        _ = try await select(file: IdemiaAID.oberthur)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xB8, algo: decryptAlgorithm, keyRef: authKeyRef)
        return try await reader.sendAPDU(ins: 0x2A, p1Byte: 0x80, p2Byte: 0x86, data: [0x00] + hash, leByte: 0x00)
    }

    // MARK: - Helpers

    private func aid(for type: CodeType) -> Bytes {
        switch type {
        case .pin1, .puk: return IdemiaAID.main
        case .pin2: return IdemiaAID.qscd
        }
    }

    private func pinRef(for type: CodeType) -> UInt8 {
        switch type {
        case .pin1: return 0x01
        case .pin2: return 0x85
        case .puk: return 0x02
        }
    }

    /**
     * @return zero padded hash with 48 byte length or same hash if it's longer than 48 bytes.
     * Zeros go in front: the card reads the input as a big-endian integer, which leading zero
     * bytes leave unchanged, while padding on the right would change the value.
     */
    private func padWithZeroes(_ hash: Data) -> Data {
        Data(repeating: 0x00, count: max(0, 48 - hash.count)) + hash
    }
}
