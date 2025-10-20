//
//  NFCISO7816Tag+Extension.swift
//  IdCardLib
//
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

import CoreNFC
import CryptoTokenKit
import OSLog

extension NFCISO7816Tag {

    func sendCommand(
        cls: UInt8,
        ins: UInt8,
        p1Byte: UInt8,
        p2Byte: UInt8,
        data: Data = Data(),
        leByte: Int = -1
    ) async throws -> Data {
        let apdu = NFCISO7816APDU(
            instructionClass: cls,
            instructionCode: ins,
            p1Parameter: p1Byte,
            p2Parameter: p2Byte,
            data: data,
            expectedResponseLength: leByte
        )
        let result = try await _sendCommandNonisolated(apdu: apdu)
        switch result {
        case (_, 0x63, 0x00):
            throw IdCardInternalError.canAuthenticationFailed
        case (let data, 0x61, let len):
            return data + (try await sendCommand(cls: 0x00, ins: 0xC0, p1Byte: 0x00, p2Byte: 0x00, leByte: Int(len)))
        case (_, 0x6C, let len):
            return try await sendCommand(
                cls: cls,
                ins: ins,
                p1Byte: p1Byte,
                p2Byte: p2Byte,
                data: data,
                leByte: Int(len)
            )
        case (let data, _, _):
            return data
        }
    }

    func sendCommand(
        cls: UInt8,
        ins: UInt8,
        p1Byte: UInt8,
        p2Byte: UInt8,
        records: [TKTLVRecord],
        leByte: Int = -1
    ) async throws -> Data {
        let data = records.reduce(Data()) { partialResult, record in
            partialResult + record.data
        }
        return try await sendCommand(cls: cls, ins: ins, p1Byte: p1Byte, p2Byte: p2Byte, data: data, leByte: leByte)
    }

    func sendPaceCommand(records: [TKTLVRecord], tagExpected: TKTLVTag) async throws -> TKBERTLVRecord {
        let request = TKBERTLVRecord(tag: 0x7c, records: records)
        do {
            let data = try await sendCommand(
                cls: tagExpected == 0x86 ? 0x00 : 0x10,
                ins: 0x86,
                p1Byte: 0x00,
                p2Byte: 0x00,
                data: request.data,
                leByte: 256
            )
            if let response = TKBERTLVRecord(from: data), response.tag == 0x7c,
               let result = TKBERTLVRecord(from: response.value), result.tag == tagExpected {
                return result
            } else {
                throw IdCardInternalError.invalidResponse(message: "response conversion failed")
            }
        } catch let error as IdCardInternalError {
            let logger = Logger(subsystem: "ee.ria.digidoc.RIADigiDoc", category: "NFCISO7816Tag")
            logger.error("sendPaceCommand \(error.localizedDescription)")
            switch error {
            case .sendCommandFailed(message: let message):
                throw IdCardInternalError.invalidResponse(message: message)
            default:
                throw error
            }
        }
    }

    private func _sendCommandNonisolated(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(Data, UInt8, UInt8), Error>) in
            self.sendCommand(apdu: apdu) { data, sw1, sw2, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: (data, sw1, sw2))
                }
            }
        }
    }
}
