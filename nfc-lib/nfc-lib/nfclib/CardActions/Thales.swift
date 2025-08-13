import CryptoTokenKit

extension CodeType {
    fileprivate var pinRef: UInt8 {
        switch self {
        case .pin1: return 0x81
        case .pin2: return 0x82
        case .puk: return 0x83
        }
    }
}

class Thales: CardCommandsInternal {
    static private let ATR = Bytes(hex: "3B FF 96 00 00 80 31 FE 43 80 31 B8 53 65 49 44 64 B0 85 05 10 12 23 3F 1D")
    static private let kAID = Bytes(hex: "A0 00 00 00 63 50 4B 43 53 2D 31 35")
    static private let kAIDGlobal = Bytes(hex: "A0 00 00 00 18 10 02 03 00 00 00 00 00 00 00 01")
    static private let AUTH_KEY: UInt8 = 0x01
    static private let SIGN_KEY: UInt8 = 0x05

    let canChangePUK: Bool = false
    let reader: CardReader
    let fillChar: UInt8 = 0x00

    required init?(reader: CardReader, aid: Bytes) {
        guard aid == Thales.kAIDGlobal else {
            return nil
        }
        self.reader = reader
    }

    // MARK: - Public Data

    func readPublicData() async throws -> CardInfo {
        _ = try await select(file: Thales.kAID)
        _ = try await select(p1: 0x08, file: [0xDF, 0xDD])
        var personalData = CardInfo()
        for recordNr: UInt8 in 1...8 {
            let data = try await readFile(p1: 0x02, file: [0x50, recordNr])
            let record = String(data: Data(data), encoding: .utf8) ?? "-"
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
        _ = try await select(file: Thales.kAID)
        return try await readFile(p1: 0x08, file: [0xAD, 0xF1, 0x34, 0x11])
    }

    func readSignatureCertificate() async throws -> Data {
        _ = try await select(file: Thales.kAID)
        return try await readFile(p1: 0x08, file: [0xAD, 0xF2, 0x34, 0x21])
    }

    // MARK: - PIN & PUK Management
    func readCodeTryCounterRecord(_ type: CodeType) async throws -> UInt8 {
        _ = try await select(file: Thales.kAID)
        let data = try await reader.sendAPDU(ins: 0xCB, p1: 0x00, p2: 0xFF, data:
            [0xA0, 0x03, 0x83, 0x01, type.pinRef], le: 0)
        if let info = TLV(from: data), info.tag == 0xA0 {
            for record in TLV.sequenceOfRecords(from: info.value) ?? [] where record.tag == 0xdf21 {
                return record.value[0]
            }
        }
        return 0
    }

    func changeCode(_ type: CodeType, to code: String, verifyCode: String) async throws {
        guard type != .puk else {
            throw IdCardInternalError.notSupportedCodeType
        }
        _ = try await select(file: Thales.kAID)
        try await changeCode(type.pinRef, to: code, verifyCode: verifyCode)
    }

    func verifyCode(_ type: CodeType, code: String) async throws {
        try await verifyCode(type.pinRef, code: code)
    }

    func unblockCode(_ type: CodeType, puk: String, newCode: String) async throws {
        guard type != .puk else {
            throw IdCardInternalError.notSupportedCodeType
        }
        try await unblockCode(type.pinRef, puk: puk, newCode: newCode)
    }

    // MARK: - Authentication & Signing

    private func sign(type: CodeType, pin: String, keyRef: UInt8, hash: Data) async throws -> Data {
        try await verifyCode(type, code: pin)
        try await setSecEnv(mode: 0xB6, algo: [0x24 + UInt8(hash.count)], keyRef: keyRef)
        _ = try await reader.sendAPDU(ins: 0x2A, p1: 0x90, p2: 0xA0, data: TLV(tag: 0x90, value: Data(hash)).data)
        return try await reader.sendAPDU(ins: 0x2A, p1: 0x9E, p2: 0x9A, le: 0x00)
    }

    func authenticate(for hash: Data, withPin1 pin1: String) async throws -> Data {
        _ = try await select(file: Thales.kAID)
        return try await sign(type: .pin1, pin: pin1, keyRef: Thales.AUTH_KEY, hash: hash)
    }

    func calculateSignature(for hash: Data, withPin2 pin2: String) async throws -> Data {
        _ = try await select(file: Thales.kAID)
        return try await sign(type: .pin2, pin: pin2, keyRef: Thales.SIGN_KEY, hash: hash)
    }

    func decryptData(_ hash: Data, withPin1 pin1: String) async throws -> Data {
        _ = try await select(file: Thales.kAID)
        try await verifyCode(.pin1, code: pin1)
        try await setSecEnv(mode: 0xB8, keyRef: Thales.AUTH_KEY)
        return try await reader.sendAPDU(ins: 0x2A, p1: 0x80, p2: 0x86, data: [0x00] + hash, le: 0x00)
    }
}

extension Bytes {
    init(hex: String) {
        self = hex.split(separator: " ").compactMap { UInt8($0, radix: 16) }
    }
}
