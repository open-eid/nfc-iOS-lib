import CryptoTokenKit

protocol CardCommandsInternal: CardCommands {
    /**
     * The smart card reader used to communicate with the card.
     *
     * Implementations may use this to send APDU commands and manage card sessions.
     */
    var reader: CardReader { get }

    var fillChar: UInt8 { get }
}

extension CardCommandsInternal {
    typealias TLV = TKBERTLVRecord

    func select(p1: UInt8 = 0x04, p2: UInt8 = 0x0C, file: Bytes) async throws -> Data {
        return try await reader.sendAPDU(ins: 0xA4, p1: p1, p2: p2, data: file, le: p2 == 0x0C ? nil : 0x00)
    }

    func readFile(p1: UInt8, file: Bytes) async throws -> Data {
        var size = 0xE5
        if let fci = TLV(from: try await select(p1: p1, p2: 0x04, file: file)) {
            for record in TLV.sequenceOfRecords(from: fci.value) ?? [] where record.tag == 0x80 || record.tag == 0x81 {
                size = Int(record.value[0]) << 8 | Int(record.value[1])
            }
        }
        var data = Data()
        while data.count < size {
            data.append(contentsOf: try await reader.sendAPDU(
                ins: 0xB0, p1: UInt8(data.count >> 8), p2: UInt8(truncatingIfNeeded: data.count), le: UInt8(min(0xE5, size - data.count))))
        }
        return data
    }

    private func errorForPinActionResponse(execute: () async throws -> Void) async throws {
        do {
            try await execute()
        } catch let error {
            if case let IdCardInternalError.swError(uInt16) = error {
                switch uInt16 {
                    case 0x9000: // Success
                        return
                    case 0x6A80:  // New pin is invalid
                        throw IdCardInternalError.invalidNewPin
                    case 0x63C0, 0x6983: // Authentication method blocked
                        throw IdCardInternalError.pinVerificationFailed
                    // For pin codes this means verification failed due to wrong pin
                    case let uInt16 where (uInt16 & 0xFFF0) == 0x63C0:
                        // Last char in trailer holds retry count
                        throw IdCardInternalError.remainingPinRetryCount(Int(uInt16 & 0x000F))
                    default:
                        throw error
                }
            } else {
                throw error
            }
        }
    }

    private func pinTemplate(_ pin: String?) -> Data {
        guard let pin else { return .init() }
        var data = pin.data(using: .utf8)!
        if data.count < 12 {
            data.append(Data(repeating: fillChar, count: 12 - data.count))
            return data
        } else {
            return data
        }
    }

    func changeCode(_ pinRef: UInt8, to code: String, verifyCode: String) async throws {
        try await errorForPinActionResponse {
            _ = try await reader.sendAPDU(ins: 0x24, p2: pinRef, data: pinTemplate(verifyCode) + pinTemplate(code))
        }
    }

    func unblockCode(_ pinRef: UInt8, puk: String?, newCode: String) async throws {
        try await errorForPinActionResponse {
            _ = try await reader.sendAPDU(ins: 0x2C, p1: puk == nil ? 0x02 : 0x00, p2: pinRef, data: pinTemplate(puk) + pinTemplate(newCode))
        }
    }

    func verifyCode(_ pinRef: UInt8, code: String) async throws {
        try await errorForPinActionResponse {
            _ = try await reader.sendAPDU(ins: 0x20, p2: pinRef, data: pinTemplate(code))
        }
    }

    func setSecEnv(mode: UInt8, algo: Bytes? = nil, keyRef: UInt8) async throws {
        let algo: Data = algo != nil ? TLV(tag: 0x80, value: Data(algo!)).data : Data()
        _ = try await reader.sendAPDU(ins: 0x22, p1: 0x41, p2: mode,
                                data: algo + TLV(tag: 0x84, value: Data([keyRef])).data)
    }
}
