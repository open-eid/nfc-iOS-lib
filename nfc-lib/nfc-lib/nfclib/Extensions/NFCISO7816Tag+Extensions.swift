//
//  NFCISO7816Tag+Extensions.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import CoreNFC
import CryptoTokenKit

extension NFCISO7816Tag {
    func sendCommand(cls: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data = Data(), le: Int = -1) async throws -> Data {
        let apdu = NFCISO7816APDU(instructionClass: cls, instructionCode: ins, p1Parameter: p1, p2Parameter: p2, data: data, expectedResponseLength: le)
        let result = try await sendCommand(apdu: apdu)
        switch result {
        case (_, 0x63, 0x00):
            throw IdCardInternalError.canAuthenticationFailed
        case (let data, 0x61, let len):
            return data + (try await sendCommand(cls: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00, le: Int(len)))
        case (_, 0x6C, let len):
            return try await sendCommand(cls: cls, ins: ins, p1: p1, p2: p2, data: data, le: Int(len))
        case (let data, _, _):
            return data
        }
    }

    func sendCommand(cls: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, records: [TKTLVRecord], le: Int = -1) async throws -> Data {
        let data = records.reduce(Data()) { partialResult, record in
            partialResult + record.data
        }
        return try await sendCommand(cls: cls, ins: ins, p1: p1, p2: p2, data: data, le: le)
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

