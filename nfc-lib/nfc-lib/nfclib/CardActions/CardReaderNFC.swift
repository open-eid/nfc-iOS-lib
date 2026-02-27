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

import OSLog
import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt

class CardReaderNFC: CardReader, @unchecked Sendable {
    private static let logger = Logger(subsystem: "ee.ria.digidoc.RIADigiDoc", category: "CardReaderNFC")
    // swiftlint:disable identifier_name
    enum PasswordType: UInt8 {
        case id_PasswordType_MRZ = 1 // 0.4.0.127.0.7.2.2.12.1
        case id_PasswordType_CAN = 2 // 0.4.0.127.0.7.2.2.12.2
        var data: String {
            return switch self {
            case .id_PasswordType_MRZ: "04007F000702020C01"
            case .id_PasswordType_CAN: "04007F000702020C02"
            }
        }
    }
    enum MappingType: String {
        case id_PACE_ECDH_GM_AES_CBC_CMAC_256 = "04007f00070202040204" // 0.4.0.127.0.7.2.2.4.2.4
        case id_PACE_ECDH_IM_AES_CBC_CMAC_256 = "04007f00070202040404" // 0.4.0.127.0.7.2.2.4.4.4
        var data: Data {
            guard let value = Data(hex: rawValue) else { return Data() }
            return value
        }
    }
    // swiftlint:enable identifier_name
    enum ParameterId: UInt8 {
        case EC256r1 = 12
        case BP256r1 = 13
        case EC384r1 = 15
        case BP384r1 = 16
        case BP512r1 = 17
        case EC521r1 = 18
        var domain: Domain {
            return switch self {
            case .EC256r1: .instance(curve: .EC256r1)
            case .EC384r1: .instance(curve: .EC384r1)
            case .EC521r1: .instance(curve: .EC521r1)
            case .BP256r1: .instance(curve: .BP256r1)
            case .BP384r1: .instance(curve: .BP384r1)
            case .BP512r1: .instance(curve: .BP512r1)
            }
        }
    }
    typealias TLV = TKBERTLVRecord

    let tag: SendableISO7816Tag
    var ksEnc: Bytes
    var ksMac: Bytes
    var SSC: Bytes = AES.Zero

    init(_ tag: NFCISO7816Tag, CAN: String) async throws {
        self.tag = SendableISO7816Tag(tag: tag)

        CardReaderNFC.logger.debug("Select CardAccess")
        _ = try await self.tag.sendCommand(cls: 0x00, ins: 0xA4, p1Byte: 0x02, p2Byte: 0x0C, data: Data([0x01, 0x1C]))
        CardReaderNFC.logger.debug("Read CardAccess")
        let data = try await self.tag.sendCommand(cls: 0x00, ins: 0xB0, p1Byte: 0x00, p2Byte: 0x00, leByte: 256)

        guard let (mappingType, parameterId) = TLV.sequenceOfRecords(from: data)?
            .flatMap({ cardAccess in TLV.sequenceOfRecords(from: cardAccess.value) ?? [] })
            .compactMap({ tlv in
                if let records = TLV.sequenceOfRecords(from: tlv.value),
                   records.count == 3,
                   let mapping = MappingType(rawValue: records[0].value.toHex),
                   let parameterId = ParameterId(rawValue: records[2].value[0]) {
                    return (mapping, parameterId)
                }
                return nil
            })
            .first
        else {
            throw IdCardInternalError.authenticationFailed
        }
        let domain = parameterId.domain

        _ = try await self.tag.sendCommand(cls: 0x00, ins: 0x22, p1Byte: 0xc1, p2Byte: 0xa4, records: [
            TLV(tag: 0x80, value: mappingType.data),
            TLV(tag: 0x83, bytes: [PasswordType.id_PasswordType_CAN.rawValue]),
            TLV(tag: 0x84, bytes: [parameterId.rawValue])
        ])

        // Step1 - General Authentication
        let nonceEnc = try await self.tag.sendPaceCommand(records: [], tagExpected: 0x80)
        CardReaderNFC.logger.debug("Challenge \(nonceEnc.value.toHex)")
        let nonce = try CardReaderNFC.decryptNonce(CAN: CAN, encryptedNonce: nonceEnc.value)
        CardReaderNFC.logger.debug("Nonce \(nonce.toHex)")

        // Step2
        let mappedPoint: Point
        switch mappingType {
        case .id_PACE_ECDH_IM_AES_CBC_CMAC_256:
            let pcdNonce = try CardReaderNFC.random(count: nonce.count)
            _ = try await self.tag.sendPaceCommand(records: [TLV(tag: 0x81, value: pcdNonce)], tagExpected: 0x82)
            let psrn = try CardReaderNFC.pseudoRandomNumberMappingAES(sVal: nonce, tVal: pcdNonce, domain: domain)
            mappedPoint = CardReaderNFC.pointEncodeIM(tVal: psrn, domain: domain)

        case .id_PACE_ECDH_GM_AES_CBC_CMAC_256:
            let (terminalPubKey, terminalPrivKey) = domain.makeKeyPair()
            let mappingKey = try await self.tag.sendPaceCommand(
                records: [try TLV(tag: 0x81, publicKey: terminalPubKey)],
                tagExpected: 0x82)
            CardReaderNFC.logger.debug("Mapping key \(mappingKey.value.hex)")
            let cardPubKey = try ECPublicKey(domain: domain, point: mappingKey.value)!

            // Mapping
            let nonceS = BInt(magnitude: nonce)
            let mappingBasePoint = ECPublicKey(privateKey: try ECPrivateKey(domain: domain, s: nonceS)) // S*G
            // swiftlint:disable line_length
            CardReaderNFC.logger.debug("Card Key x: \(mappingBasePoint.w.x.asMagnitudeBytes().hex), y: \(mappingBasePoint.w.y.asMagnitudeBytes().hex)")
            // swiftlint:enable line_length
            let sharedSecretH = try domain.multiplyPoint(cardPubKey.w, terminalPrivKey.s)
            // swiftlint:disable line_length
            CardReaderNFC.logger.debug("Shared Secret x: \(sharedSecretH.x.asMagnitudeBytes().hex), y: \(sharedSecretH.y.asMagnitudeBytes().hex)")
            // swiftlint:enable line_length
            mappedPoint = try domain.addPoints(mappingBasePoint.w, sharedSecretH) // MAP G = (S*G) + H
        }
        // Ephemeral data
        // swiftlint:disable line_length
        CardReaderNFC.logger.debug("Mapped point x: \(mappedPoint.x.asMagnitudeBytes().toHex, privacy: .public), y: \(mappedPoint.y.asMagnitudeBytes().toHex, privacy: .public)")
        // swiftlint:enable line_length
        let mappedDomain = try Domain.instance(
            name: domain.name + " Mapped",
            p: domain.p,
            a: domain.a,
            b: domain.b,
            gx: mappedPoint.x,
            gy: mappedPoint.y,
            order: domain.order,
            cofactor: domain.cofactor
        )
        let (terminalEphemeralPubKey, terminalEphemeralPrivKey) = mappedDomain.makeKeyPair()
        let ephemeralKey = try await self.tag.sendPaceCommand(
            records: [try TLV(
                tag: 0x83,
                publicKey: terminalEphemeralPubKey
            )],
            tagExpected: 0x84
        )
        CardReaderNFC.logger.debug("Card Ephermal key \(ephemeralKey.value.toHex)")
        guard let ephemeralCardPubKey = try ECPublicKey(domain: mappedDomain, point: ephemeralKey.value)
        else { throw IdCardInternalError.authenticationFailed }

        // Derive shared secret and session keys
        let sharedSecret = try terminalEphemeralPrivKey.sharedSecret(pubKey: ephemeralCardPubKey)
        CardReaderNFC.logger.debug("Shared secret \(sharedSecret.toHex)")
        ksEnc = CardReaderNFC.KDF(key: sharedSecret, counter: 1)
        ksMac = CardReaderNFC.KDF(key: sharedSecret, counter: 2)
        CardReaderNFC.logger.debug("KS.Enc \(self.ksEnc.toHex)")
        CardReaderNFC.logger.debug("KS.Mac \(self.ksMac.toHex)")

        // Mutual authentication
        let macCalc = try AES.CMAC(key: ksMac)

        let macHeader = TLV(tag: 0x7f49, records: [
            TLV(tag: 0x06, value: mappingType.data),
            TLV(tag: 0x86, bytes: try ephemeralCardPubKey.x963Representation())
        ])
        let macValue = try await self.tag.sendPaceCommand(
            records: [TLV(
                tag: 0x85,
                bytes: (
                    try macCalc.authenticate(
                        bytes: macHeader.data
                    )
                )
            )],
            tagExpected: 0x86
        )
        CardReaderNFC.logger.debug("Mac response \(macValue.data.toHex)")

        // verify chip's MAC
        let macResult = TLV(tag: 0x7f49, records: [
            TLV(tag: 0x06, value: mappingType.data),
            TLV(tag: 0x86, bytes: try terminalEphemeralPubKey.x963Representation())
        ])
        if macValue.value != Data(try macCalc.authenticate(bytes: macResult.data)) {
            throw IdCardInternalError.authenticationFailed
        }
    }

    private func getDO87(_ apdu: NFCISO7816APDU) throws -> Data {
        if let data = apdu.data, !data.isEmpty {
            let ivValue = try AES.CBC(key: ksEnc).encrypt(SSC)
            let encData = try AES.CBC(key: ksEnc, ivVal: ivValue).encrypt(data.addPadding())
            if apdu.instructionCode & 0x01 == 0 {
                return TLV(tag: 0x87, bytes: [0x01] + encData).data
            } else {
                return TLV(tag: 0x85, bytes: encData).data
            }
        } else {
            return Data()
        }
    }

    private func getDO97(_ apdu: NFCISO7816APDU) throws -> Data {
        if apdu.expectedResponseLength > 0 {
            return TLV(
                tag: 0x97,
                bytes: [UInt8(
                    apdu.expectedResponseLength == 256 ? 0 : apdu.expectedResponseLength
                )]
            ).data
        } else {
            return Data()
        }
    }

    private func getTLVs(
        _ response: Data,
    ) throws -> (tlvEnc: TKTLVRecord?, tlvRes: TKTLVRecord?, tlvMac: TKTLVRecord?) {
        var tlvEnc: TKTLVRecord?
        var tlvRes: TKTLVRecord?
        var tlvMac: TKTLVRecord?
        for tlv in TLV.sequenceOfRecords(from: response) ?? [] {
            switch tlv.tag {
            case 0x85, 0x87: tlvEnc = tlv
            case 0x99: tlvRes = tlv
            case 0x8E: tlvMac = tlv
            default: CardReaderNFC.logger.debug("Unknown tag")
            }
        }
        return (tlvEnc, tlvRes, tlvMac)
    }

    func transmit(_ apduData: Bytes) async throws -> (responseData: Bytes, sw: UInt16) {
        CardReaderNFC.logger.debug("Plain >: \(apduData.toHex)")
        guard let apdu = NFCISO7816APDU(data: Data(apduData)) else {
            throw IdCardInternalError.invalidAPDU
        }
        _ = SSC.increment()
        let DO87 = try getDO87(apdu)
        let DO97 = try getDO97(apdu)
        let cmdHeader: Bytes = [apdu.instructionClass | 0x0C, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter]
        let MValue = cmdHeader.addPadding() + DO87 + DO97
        let NValue = SSC + MValue
        let mac = try AES.CMAC(key: ksMac).authenticate(bytes: NValue.addPadding())
        let DO8E = TLV(tag: 0x8E, bytes: mac).data
        let send = DO87 + DO97 + DO8E
        let response = try await tag.sendCommand(
            cls: cmdHeader[0],
            ins: cmdHeader[1],
            p1Byte: cmdHeader[2],
            p2Byte: cmdHeader[3],
            data: send,
            leByte: 256
        )
        let (tlvEnc, tlvRes, tlvMac) = try getTLVs(response)
        guard let tlvRes else {
            throw IdCardInternalError.missingRESTag
        }
        guard let tlvMac else {
            throw IdCardInternalError.missingMACTag
        }
        let KValue = SSC.increment() + (tlvEnc?.data ?? Data()) + tlvRes.data
        if try Data(AES.CMAC(key: ksMac).authenticate(bytes: KValue.addPadding())) != tlvMac.value {
            throw IdCardInternalError.invalidMACValue
        }
        guard let tlvEnc else {
            CardReaderNFC.logger.debug("Plain <: \(tlvRes.value.toHex)")
            return (.init(), UInt16(tlvRes.value[0], tlvRes.value[1]))
        }
        let ivValue = try AES.CBC(key: ksEnc).encrypt(SSC)
        let responseData = try (try AES.CBC(key: ksEnc, ivVal: ivValue)
            .decrypt(tlvEnc.tag == 0x85 ? tlvEnc.value : tlvEnc.value[1...]))
            .removePadding()
        CardReaderNFC.logger.debug("Plain <:  \(responseData.toHex) \(tlvRes.value.toHex)")
        return (Bytes(responseData), UInt16(tlvRes.value[0], tlvRes.value[1]))
    }

    // MARK: - Utils
    // swiftlint:disable force_unwrapping
    static private func pseudoRandomNumberMappingAES(
        sVal: any AES.DataType,
        tVal: any AES.DataType,
        domain: Domain
    ) throws -> BInt {
        let lVal = sVal.count * 8
        let kVal = tVal.count * 8

        let c0Val: Bytes
        let c1Val: Bytes
        switch lVal {
        case 128:
            c0Val = Bytes(hex: "a668892a7c41e3ca739f40b057d85904")!
            c1Val = Bytes(hex: "a4e136ac725f738b01c1f60217c188ad")!
        case 192, 256:
            c0Val = Bytes(hex: "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676")!
            c1Val = Bytes(hex: "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517")!
        default:
            throw IdCardInternalError.authenticationFailed
        }

        let cipher = AES.CBC(key: tVal)
        var key = try cipher.encrypt(sVal)

        var xVal = Bytes()
        var nVal = 0
        while nVal * lVal < domain.p.bitWidth + 64 {
            let cipher = AES.CBC(key: key.prefix(kVal / 8))
            key = try cipher.encrypt(c0Val)
            xVal += try cipher.encrypt(c1Val)
            nVal += 1
        }

        return BInt(magnitude: xVal).mod(domain.p)
    }

    /**
     * https://www.icao.int/Security/FAL/TRIP/Documents/TR%20-%20Supplemental%20Access%20Control%20V1.1.pdf
     * A.2.1. Implementation for affine coordinates
     */
    static private func pointEncodeIM(tVal: BInt, domain: Domain) -> Point {
        let pVal = domain.p
        let aVal = domain.a
        let bVal = domain.b

        // 1. α = -t^2 mod p
        let alpha = (-(tVal ** 2)).mod(pVal)

        // 2. X2 = -ba^-1 (1 + (α + α^2)^-1) mod p
        // Hint  = -b(1 + α + α^2)(a(α + α^2))^(p-2) mod p
        let alphaPlusAlphaSqrt = alpha + alpha ** 2
        let x2Val = ((-bVal * (1 + alphaPlusAlphaSqrt)) * (aVal * alphaPlusAlphaSqrt).expMod(pVal - 2, pVal)).mod(pVal)

        // 3. X3 = α * X2 mod p
        let x3Val = (alpha * x2Val).mod(pVal)

        // 4. h2 = (X2)^3 + a * X2 + b mod p
        let h2Val = (x2Val ** 3 + aVal * x2Val + bVal).mod(pVal)

        // 5. h3 = (X3)^3 + a * X3 + b mod p
        // Unused: let h3 = (X3 ** 3 + a * X3 + b).mod(p)

        // 6. U = t^3 * h2 mod p
        let UVal = (tVal ** 3 * h2Val).mod(pVal)

        // 7. A = (h2)^(p - 1 - (p + 1) / 4) mod p
        // Hint: modular exponentiation with exponent p-1-(p+1)/4.
        let AVal = h2Val.expMod(pVal - BInt.ONE - (pVal + BInt.ONE) / BInt.FOUR, pVal)

        // 8. A^2 * h2 mod p = 1 -> (x, y) = (X2, A h2 mod p)
        // 9. (x, y) = (X3, A U mod p)
        return (AVal ** 2 * h2Val).mod(pVal) == BInt.ONE ?
            Point(x2Val, (AVal * h2Val).mod(pVal)) :
            Point(x3Val, (AVal * UVal).mod(pVal))
    }

    static private func decryptNonce<T: AES.DataType>(CAN: String, encryptedNonce: T) throws -> Bytes {
        let decryptionKey = KDF(key: Bytes(CAN.utf8), counter: 3)
        let cipher = AES.CBC(key: decryptionKey)
        return try cipher.decrypt(encryptedNonce)
    }

    static private func KDF(key: Bytes, counter: UInt8) -> Bytes {
        var keydata = key + Bytes(repeating: 0x00, count: 4)
        keydata[keydata.count - 1] = counter
        return SHA256(data: keydata)
    }

    static private func SHA256(data: Bytes) -> Bytes {
        Bytes(unsafeUninitializedCapacity: Int(CC_SHA256_DIGEST_LENGTH)) { buffer, initializedCount in
            CC_SHA256(data, CC_LONG(data.count), buffer.baseAddress)
            initializedCount = Int(CC_SHA256_DIGEST_LENGTH)
        }
    }

    static private func random(count: Int) throws -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        if result != errSecSuccess {
            throw IdCardInternalError.authenticationFailed
        }
        return data
    }
    // swiftlint:enable force_unwrapping
}


// MARK: - Extensions

extension DataProtocol {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }

    func chunked(into size: Int) -> [SubSequence] {
        stride(from: 0, to: count, by: size).map {
            self[index(startIndex, offsetBy: $0) ..< index(startIndex, offsetBy: Swift.min($0 + size, count))]
        }
    }

    func removePadding() throws -> SubSequence {
        var index = endIndex
        while index != startIndex {
            formIndex(before: &index)
            if self[index] == 0x80 {
                return self[startIndex..<index]
            } else if self[index] != 0x00 {
                throw IdCardInternalError.failedToRemovePadding
            }
        }
        throw IdCardInternalError.failedToRemovePadding
    }
}

extension UInt16 {
    init(_ p1Byte: UInt8, _ p2Byte: UInt8) {
        self = (UInt16(p1Byte) << 8) | UInt16(p2Byte)
    }
}

