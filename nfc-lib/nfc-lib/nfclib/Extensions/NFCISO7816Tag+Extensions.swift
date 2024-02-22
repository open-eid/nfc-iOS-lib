/*
 * Copyright 2017 - 2023 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import CoreNFC
import CryptoTokenKit

extension NFCISO7816Tag {
    func sendCommand(cls: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data, le: Int?) async throws -> Data {
        let responseLength = le ?? -1
        do {
            let apdu = NFCISO7816APDU(instructionClass: cls, instructionCode: ins, p1Parameter: p1, p2Parameter: p2, data: data, expectedResponseLength: responseLength)
            switch try await sendCommand(apdu: apdu) {
            case (let data, 0x90, 0x00):
                return data
            case (let data, 0x61, let len):
                return data + (try await sendCommand(cls: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00, data: Data(), le: Int(len)))
            case (_, 0x6C, let len):
                return try await sendCommand(cls: cls, ins: ins, p1: p1, p2: p2, data: data, le: Int(len))
            case (_, let sw1, let sw2):
                throw IdCardInternalError.sendCommandFailed(message: String(format: "%02X%02X", sw1, sw2))
            }
        } catch {
            throw error
        }
    }

    func sendPaceCommand(records: [TKTLVRecord], tagExpected: TKTLVTag) async throws -> TKBERTLVRecord {
        let request = TKBERTLVRecord(tag: 0x7c, records: records)
        do {
            let data = try await sendCommand(cls: tagExpected == 0x86 ? 0x00 : 0x10, ins: 0x86, p1: 0x00, p2: 0x00, data: request.data, le: 256)
            if let response = TKBERTLVRecord(from: data), response.tag == 0x7c,
               let result = TKBERTLVRecord(from: response.value), result.tag == tagExpected {
                return result
            } else {
                throw IdCardInternalError.invalidResponse(message: "response conversion failed")
            }
        } catch let error as IdCardInternalError {
            print("sendPaceCommand \(error.localizedDescription)")
            switch error {
            case .sendCommandFailed(message: let message):
                throw IdCardInternalError.invalidResponse(message: message)
            default:
                throw error
            }
        }
    }
}

