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

import CryptoTokenKit
@MainActor
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

    func select(p1Byte: UInt8 = 0x04, p2Byte: UInt8 = 0x0C, file: Bytes) async throws -> Data {
        return try await reader.sendAPDU(
                ins: 0xA4,
                p1Byte: p1Byte,
                p2Byte: p2Byte,
                data: file,
                leByte: p2Byte == 0x0C ? nil : 0x00
            )
    }

    func readFile(p1Byte: UInt8, file: Bytes) async throws -> Data {
        var size = 0xE5
        if let fci = TLV(from: try await select(p1Byte: p1Byte, p2Byte: 0x04, file: file)) {
            for record in TLV.sequenceOfRecords(from: fci.value) ?? [] where record.tag == 0x80 || record.tag == 0x81 {
                size = Int(record.value[0]) << 8 | Int(record.value[1])
            }
        }
        var data = Data()
        while data.count < size {
            data.append(
                    contentsOf: try await reader.sendAPDU(
                        ins: 0xB0,
                        p1Byte: UInt8(data.count >> 8),
                        p2Byte: UInt8(truncatingIfNeeded: data.count),
                        leByte: UInt8(min(0xE5, size - data.count))
                    )
                )
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

    private func pinTemplate(_ pin: SecureData?) -> Data {
        guard let pin = pin else { return Data() }

        var out = Data()
        out.reserveCapacity(12)

        pin.withUnsafeBytes { raw in
            // Copy up to 12 bytes from the secure buffer
            let nVal = min(raw.count, 12)
            let src = raw.bindMemory(to: UInt8.self)
            out.append(contentsOf: src.prefix(nVal))
        }

        // Pad with fillChar if needed
        if out.count < 12 {
            out.append(Data(repeating: fillChar, count: 12 - out.count))
        }

        return out
    }

    func changeCode(_ pinRef: UInt8, to code: SecureData, verifyCode: SecureData) async throws {
        try await errorForPinActionResponse {
            _ = try await reader.sendAPDU(ins: 0x24, p2Byte: pinRef, data: pinTemplate(verifyCode) + pinTemplate(code))
        }
    }

    func unblockCode(_ pinRef: UInt8, puk: SecureData?, newCode: SecureData) async throws {
        try await errorForPinActionResponse {
            _ = try await reader
                .sendAPDU(
                    ins: 0x2C,
                    p1Byte: puk == nil ? 0x02 : 0x00,
                    p2Byte: pinRef,
                    data: pinTemplate(puk) + pinTemplate(newCode)
                )
        }
    }

    func verifyCode(_ pinRef: UInt8, code: SecureData) async throws {
        try await errorForPinActionResponse {
            _ = try await reader.sendAPDU(ins: 0x20, p2Byte: pinRef, data: pinTemplate(code))
        }
    }

    func setSecEnv(mode: UInt8, algo: Bytes? = nil, keyRef: UInt8) async throws {
        var algoData: Data = Data()
        if let algoValue = algo {
            algoData =  TLV(tag: 0x80, value: Data(algoValue)).data
        }

        _ = try await reader.sendAPDU(ins: 0x22, p1Byte: 0x41, p2Byte: mode,
                                data: algoData + TLV(tag: 0x84, value: Data([keyRef])).data)
    }
}
