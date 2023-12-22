//
//  NFCIdCard.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 28.11.2023.
//

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
import SwiftECC
import BigInt

enum IdCardError: Error {
    case missingRESTag,
         missingMACTag,
         invalidMACValue,
         failedReadingField(CardField),
         hexConversionFailed,
         AESCBCError,
         sendCommandFailed(message: String),
         invalidResponse(message: String),
         pinVerificationFailed,
         remainingPinRetryCount(Int),
         dataPaddingError
}

struct PinError: Error {
    let msg: String
    let remainingCount: Int
}

public struct CardInfo {
    public var givenName: String
    public var surname: String
    public var personalCode: String
    public var citizenship: String
    public var dateOfExpiry: String

    public init(givenName: String, surname: String, personalCode: String, citizenship: String, dateOfExpiry: String) {
        self.givenName = givenName
        self.surname = surname
        self.personalCode = personalCode
        self.citizenship = citizenship
        self.dateOfExpiry = dateOfExpiry
    }

    public var formattedDescription: String {
        """
        Name: \(givenName) \(surname)
        Personal Code: \(personalCode)
        Citizenship: \(citizenship)
        Date of Expiry: \(dateOfExpiry)
        """
    }
}

enum CertificateUsage {
    case auth
    case sign

    var applicationData: Data {
        switch self {
        case .auth:
            return Data([0xAD, 0xF1])
        case .sign:
            return Data([0xAD, 0xF2])
        }
    }

    var fileData: Data {
        switch self {
        case .auth:
            return Data([0x34, 0x01])
        case .sign:
            return Data([0x34, 0x1F])
        }
    }
}

enum PinType {
    case pin1
    case pin2
    case puk

    var data: UInt8 {
        switch self {
        case .pin1:
            return 0x01
        case .pin2:
            return 0x85
        case .puk:
            return 0x02
        }
    }
}

enum CardField: Int {
    case surname = 1,
         firstName,
         sex,
         citizenship,
         dateAndPlaceOfBirth,
         personalCode,
         documentNr,
         dateOfExpiry
}

public class NFCIdCard : NSObject {

    private let ksEnc: Bytes?
    private let ksMac: Bytes?
    private var SSC: Bytes?
    
    init(ksEnc: Bytes? = nil, ksMac: Bytes? = nil, SSC: Bytes? = nil) {
        self.ksEnc = ksEnc
        self.ksMac = ksMac
        self.SSC = SSC
        super.init()
    }

    func sendWrapped(tag: NFCISO7816Tag, cls: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: Data, le: Int) async throws -> Data {
        guard SSC != nil else {
            return try await tag.sendCommand(cls: cls, ins: ins, p1: p1, p2: p2, data: Data(), le: 256)
        }
        _ = SSC!.increment()
        let DO87: Data
        if !data.isEmpty {
            let iv = try AES.CBC(key: ksEnc!, iv: AES.Zero).encrypt(SSC!)
            let enc_data = try AES.CBC(key: ksEnc!, iv: iv).encrypt(data.addPadding())
            DO87 = TKBERTLVRecord(tag: 0x87, bytes: [0x01] + enc_data).data
        } else {
            DO87 = Data()
        }
        let DO97: Data
        if le > 0 {
            DO97 = TKBERTLVRecord(tag: 0x97, bytes: [UInt8(le == 256 ? 0 : le)]).data
        } else {
            DO97 = Data()
        }
        let cmd_header: Bytes = [cls | 0x0C, ins, p1, p2]
        let M = cmd_header.addPadding() + DO87 + DO97
        let N = SSC! + M
        let mac = try AES.CMAC(key: ksMac!).authenticate(bytes: N.addPadding(), count: 8)
        let DO8E = TKBERTLVRecord(tag: 0x8E, bytes: mac).data
        let send = DO87 + DO97 + DO8E
        print(">: \(send.toHex)")
        do {
            let response = try await tag.sendCommand(cls: cmd_header[0], ins: ins, p1: p1, p2: p2, data: send, le: 256)
            print("<: \(response.toHex)")
            var tlvEnc: TKTLVRecord?
            var tlvRes: TKTLVRecord?
            var tlvMac: TKTLVRecord?
            for tlv in TKBERTLVRecord.sequenceOfRecords(from: response)! {
                switch tlv.tag {
                case 0x87: tlvEnc = tlv
                case 0x99: tlvRes = tlv
                case 0x8E: tlvMac = tlv
                default: print("Unknown tag")
                }
            }
            guard tlvRes != nil else {
                throw IdCardError.missingRESTag
            }
            guard tlvMac != nil else {
                throw IdCardError.missingMACTag
            }
            let K = SSC!.increment() + (tlvEnc?.data ?? Data()) + tlvRes!.data
            if try Data(AES.CMAC(key: ksMac!).authenticate(bytes: K.addPadding(), count: 8)) != tlvMac!.value {
                throw IdCardError.invalidMACValue
            }
            if tlvRes!.value != Data([0x90, 0x00]) {
                throw IdCardError.hexConversionFailed
            }
            guard tlvEnc != nil else {
                return Data()
            }
            let iv = try AES.CBC(key: ksEnc!, iv: AES.Zero).encrypt(SSC!)
            let responseData = try AES.CBC(key: ksEnc!, iv: iv).decrypt(tlvEnc!.value[1...])
            return Data(try responseData.removePadding())
        } catch {
            throw error
        }
    }
    
    func selectFile(tag: NFCISO7816Tag, file: Data) async throws {
        _ = try await sendWrapped(tag: tag, cls: 0x00, ins: 0xA4, p1: 0x01, p2: 0x0C, data: file, le: 256)
    }

    func selectDF(tag: NFCISO7816Tag, file: Data) async throws {
        _ = try await sendWrapped(tag: tag, cls: 0x00, ins: 0xA4, p1: file.isEmpty ? 0x00 : 0x01, p2: 0x0C, data: file, le: 256)
    }
    
    func selectMF(tag: NFCISO7816Tag) async throws {
        _ = try await selectDF(tag: tag, file: Data())
    }

    func selectEF(tag: NFCISO7816Tag, file: Data) async throws -> Int {
        let data = try await sendWrapped(tag: tag, cls: 0x00, ins: 0xA4, p1: 0x02, p2: 0x04, data: file, le: 256)
        print("FCI: \(data.toHex)")
        guard let fci = TKBERTLVRecord(from: data) else {
            return 0
        }
        for tlv in TKBERTLVRecord.sequenceOfRecords(from: fci.value)! where tlv.tag == 0x80 {
            return Int(tlv.value[0]) << 8 | Int(tlv.value[1])
        }
        return 0
    }

    func read(field: CardField, tag: NFCISO7816Tag) async throws -> String {
        print("reading field: \(field)")
        try await selectDF(tag: tag, file: Data([0x50, UInt8(field.rawValue)]))
        print("Selected field: \(field)")
        let output = try await readBinaryMod(tag: tag)
        guard let textValue = String(data: output, encoding: .utf8) else {
            throw IdCardError.failedReadingField(field)
        }
        print("selected value: \(textValue)")
        return textValue
    }

    func readBinaryMod(tag: NFCISO7816Tag) async throws -> Data {
        return try await sendWrapped(tag: tag, cls: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, data: Data(), le: 256)
    }

    func readBinary(tag: NFCISO7816Tag, len: Int, pos: Int) async throws -> Data {
        return try await sendWrapped(tag: tag, cls: 0x00, ins: 0xB0, p1: UInt8(pos >> 8), p2: UInt8(truncatingIfNeeded: pos), data: Data(), le: len)
    }

    func readBinary(tag: NFCISO7816Tag, len: Int) async throws -> Data {
        var data = Data()
        for i in stride(from: 0, to: len, by: 0xD8) {
            data += try await readBinary(tag: tag, len: Swift.min(len - i, 0xD8), pos: i)
        }
        return data
    }


    func readEF(tag: NFCISO7816Tag, file: Data) async throws -> Data {
        let len = try await selectEF(tag: tag, file: file)
        return try await readBinary(tag: tag, len: len)
    }
    
    func readCert(tag: NFCISO7816Tag, usage: CertificateUsage) async throws -> Data {
        try await selectMF(tag: tag)
        try await selectFile(tag: tag, file: usage.applicationData)
        return try await readEF(tag: tag, file: usage.fileData)
    }
    
    func authenticate(tag: NFCISO7816Tag, pin1: Data, token: Data) async throws -> Data {
        try await selectMF(tag: tag)
        try await selectFile(tag: tag, file: CertificateUsage.auth.applicationData)
        try await verifyPin(tag: tag, pinType: PinType.pin1, pin1: pin1)
        try await selectAuthSecurityEnv(tag: tag)
        return try await internalAuthenticate(tag: tag, data: token)
    }
    
    private func internalAuthenticate(tag: NFCISO7816Tag, data: Data) async throws -> Data {
        return try await sendWrapped(tag: tag, cls: 0x00, ins: 0x88, p1: 0x00, p2: 0x00, data: data, le: 256)
    }
    
    private func selectAuthSecurityEnv(tag: NFCISO7816Tag) async throws {
        let envData = Data([0x80, 0x04, 0xFF, 0x20, 0x08, 0x00, 0x84, 0x01, 0x81])
        _ = try await sendWrapped(tag: tag, cls: 0x00, ins: 0x22, p1: 0x41, p2: 0xA4, data: envData, le: 256)
    }
    
    private func verifyPin(tag: NFCISO7816Tag, pinType: PinType, pin1: Data) async throws {
        let paddedPin = padPin(inputData: pin1)
        do {
            _ = try await sendWrapped(tag: tag, cls: 0x00, ins: 0x20, p1: 0x00, p2: pinType.data, data: paddedPin, le: 256)
        } catch let error as IdCardError {
            if case .sendCommandFailed(message: let message) = error {
                if let pinCount = try getCountFromError(message) {
                    throw PinError(msg: message, remainingCount: pinCount)
                }
            }
            throw error
        } catch {
            throw error
        }
    }
    
    private func padPin(inputData: Data) -> Data {
        var paddedData = inputData

        // Pad with 0xFF until the length is 0x0C (12 bytes)
        while paddedData.count < 0x0C {
            paddedData.append(0xFF)
        }

        return paddedData
    }
    
    func getCountFromError(_ errorMessage: String) throws -> Int? {
        guard let data = hexStringToData(errorMessage) else {
            throw IdCardError.pinVerificationFailed
        }
        
        // Check if the data has at least two bytes
        guard data.count >= 2 else {
            throw IdCardError.pinVerificationFailed
        }

        // Check if the first byte is 0x63
        if data[0] == 0x63 {
            // Extract the second byte
            let secondByte = data[1]

            // Check if the second byte is in the form of 0xCX
            if (0xC0...0xCF).contains(secondByte) {
                // Extract the count from the lower 4 bits
                let count = Int(secondByte & 0x0F)
                throw IdCardError.remainingPinRetryCount(count)
            } else {
                throw IdCardError.pinVerificationFailed
            }
        } else {
            throw IdCardError.pinVerificationFailed
        }
    }
    
    func hexStringToData(_ hexString: String) -> Data? {
        var hex = hexString
        // Ensure the hex string has an even number of characters
        if hex.count % 2 != 0 {
            hex = "0" + hex
        }

        var data = Data()
        var index = hex.startIndex

        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                // Invalid hex digit
                return nil
            }
            index = nextIndex
        }

        return data
    }
}
