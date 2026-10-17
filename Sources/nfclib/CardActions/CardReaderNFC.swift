// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import OSLog
import CoreNFC
import CryptoTokenKit
internal import SwiftECC
internal import BigInt

@MainActor
class CardReaderNFC: CardReader {
    private static let logger = Logger(subsystem: "ee.ria.nfc-iOS-lib", category: "CardReaderNFC")
    // swiftlint:disable identifier_name
    enum PasswordType: UInt8 {
        case id_PasswordType_MRZ = 1 // 0.4.0.127.0.7.2.2.12.1
        case id_PasswordType_CAN = 2 // 0.4.0.127.0.7.2.2.12.2
        var data: String {
            switch self {
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
            switch self {
            case .EC256r1: .instance(curve: .EC256r1)
            case .EC384r1: .instance(curve: .EC384r1)
            case .EC521r1: .instance(curve: .EC521r1)
            case .BP256r1: .instance(curve: .BP256r1)
            case .BP384r1: .instance(curve: .BP384r1)
            case .BP512r1: .instance(curve: .BP512r1)
            }
        }
    }

    let tag: SendableISO7816Tag
    var ksEnc: Bytes = AES.Zero
    var ksMac: Bytes = AES.Zero
    var SSC: Bytes = AES.Zero

    init(_ tag: NFCISO7816Tag, CAN: String) async throws {
        self.tag = SendableISO7816Tag(tag: tag)

        CardReaderNFC.logger.debug("Select CardAccess")
        _ = try await self.tag.sendCommand(cls: 0x00, ins: 0xA4, p1Byte: 0x02, p2Byte: 0x0C, data: Data([0x01, 0x1C]))
        CardReaderNFC.logger.debug("Read CardAccess")
        let data = try await self.tag.sendCommand(cls: 0x00, ins: 0xB0, p1Byte: 0x00, p2Byte: 0x00, leByte: 256)

        let sanitizedData = sanitizedTLV(data)
        guard let (mappingType, parameterId) = TLV.sequenceOfRecords(from: sanitizedData)?
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
        CardReaderNFC.logger.debugSensitive("Challenge \(nonceEnc.value.toHex)")
        let nonce = try CardReaderNFC.decryptNonce(CAN: CAN, encryptedNonce: nonceEnc.value)
        CardReaderNFC.logger.debugSensitive("Nonce \(nonce.toHex)")

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
            CardReaderNFC.logger.debugSensitive("Mapping key \(mappingKey.value.toHex)")
            guard let cardPubKey = try ECPublicKey(domain: domain, point: mappingKey.value)
            else { throw IdCardInternalError.authenticationFailed }
            mappedPoint = try CardReaderNFC.mapNonceGM(
                nonce: nonce, terminalPrivateKey: terminalPrivKey, cardPublicKey: cardPubKey, domain: domain)
        }
        guard !mappedPoint.infinity else { throw IdCardInternalError.authenticationFailed }
        // Ephemeral data
        CardReaderNFC.logger.debugSensitive("Mapped point x: \(mappedPoint.x.asMagnitudeBytes().toHex), " +
                                            "y: \(mappedPoint.y.asMagnitudeBytes().toHex)")
        let mappedDomain = try domain.withGenerator(mappedPoint)
        let (terminalEphemeralPubKey, terminalEphemeralPrivKey) = mappedDomain.makeKeyPair()
        let ephemeralKey = try await self.tag.sendPaceCommand(
            records: [try TLV(
                tag: 0x83,
                publicKey: terminalEphemeralPubKey
            )],
            tagExpected: 0x84
        )
        CardReaderNFC.logger.debugSensitive("Card Ephermal key \(ephemeralKey.value.toHex)")
        guard let ephemeralCardPubKey = try ECPublicKey(domain: mappedDomain, point: ephemeralKey.value)
        else { throw IdCardInternalError.authenticationFailed }
        guard ephemeralCardPubKey.w != terminalEphemeralPubKey.w
        else { throw IdCardInternalError.authenticationFailed }

        // Derive shared secret and session keys
        let sharedSecret = try terminalEphemeralPrivKey.sharedSecret(pubKey: ephemeralCardPubKey)
        CardReaderNFC.logger.debugSensitive("Shared secret \(sharedSecret.toHex)")
        ksEnc = CardReaderNFC.KDF(key: sharedSecret, counter: 1)
        ksMac = CardReaderNFC.KDF(key: sharedSecret, counter: 2)
        CardReaderNFC.logger.debugSensitive("KS.Enc \(self.ksEnc.toHex)")
        CardReaderNFC.logger.debugSensitive("KS.Mac \(self.ksMac.toHex)")

        // Mutual authentication
        func authToken(for publicKey: ECPublicKey) throws -> Bytes.SubSequence {
            try CardReaderNFC.authToken(for: publicKey, protocolId: mappingType.data, macKey: ksMac)
        }

        let cardToken = try await self.tag.sendPaceCommand(
            records: [TLV(tag: 0x85, bytes: try authToken(for: ephemeralCardPubKey))],
            tagExpected: 0x86)
        CardReaderNFC.logger.debugSensitive("Mac response \(cardToken.data.toHex)")

        // verify chip's MAC
        guard try cardToken.value.elementsEqual(authToken(for: terminalEphemeralPubKey))
        else { throw IdCardInternalError.authenticationFailed }
    }

    private func sanitizedTLV(_ data: Data) -> Data {
        guard data.count >= 2 else { return data }

        var index = 1
        let firstLengthByte = data[index]
        index += 1

        let valueLength: Int

        if firstLengthByte & 0x80 == 0 {
            valueLength = Int(firstLengthByte)
        } else {
            let lengthByteCount = Int(firstLengthByte & 0x7F)

            guard data.count >= index + lengthByteCount else {
                return data
            }

            valueLength = data[index..<(
                index + lengthByteCount
            )].reduce(0) { ($0 << 8) | Int($1) }

            index += lengthByteCount
        }

        let totalLength = index + valueLength
        return data.prefix(min(totalLength, data.count))
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
        CardReaderNFC.logger.debugSensitive("Plain >: \(apduData.toHex)")
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
        guard let tlvMac, response.suffix(tlvMac.data.count) == tlvMac.data else {
            throw IdCardInternalError.missingMACTag
        }
        let KValue = SSC.increment() + response.dropLast(tlvMac.data.count)
        if try Data(AES.CMAC(key: ksMac).authenticate(bytes: KValue.addPadding())) != tlvMac.value {
            throw IdCardInternalError.invalidMACValue
        }
        guard tlvRes.value.count == 2 else {
            throw IdCardInternalError.invalidResponse(message: "Invalid DO99 length")
        }
        guard let tlvEnc else {
            CardReaderNFC.logger.debugSensitive("Plain <: \(tlvRes.value.toHex)")
            return (.init(), UInt16(tlvRes.value[0], tlvRes.value[1]))
        }
        guard tlvEnc.tag == 0x85 || tlvEnc.value.first == 0x01 else {
            throw IdCardInternalError.dataPaddingError
        }
        let ivValue = try AES.CBC(key: ksEnc).encrypt(SSC)
        let responseData = try (try AES.CBC(key: ksEnc, ivVal: ivValue)
            .decrypt(tlvEnc.tag == 0x85 ? tlvEnc.value : tlvEnc.value.dropFirst()))
            .removePadding()
        CardReaderNFC.logger.debugSensitive("Plain <:  \(responseData.toHex) \(tlvRes.value.toHex)")
        return (Bytes(responseData), UInt16(tlvRes.value[0], tlvRes.value[1]))
    }

    // MARK: - PACE steps

    /// Generic Mapping: Ĝ = s·G + H, where H is the ECDH shared point of the mapping key pairs.
    static func mapNonceGM(
        nonce: Bytes,
        terminalPrivateKey: ECPrivateKey,
        cardPublicKey: ECPublicKey,
        domain: Domain
    ) throws -> Point {
        let mappingBasePoint = try domain.multiplyPoint(domain.g, BInt(magnitude: nonce)) // S*G
        CardReaderNFC.logger.debugSensitive("Card Key x: \(mappingBasePoint.x.asMagnitudeBytes().toHex), " +
                                            "y: \(mappingBasePoint.y.asMagnitudeBytes().toHex)")
        let sharedSecretH = try domain.multiplyPoint(cardPublicKey.w, terminalPrivateKey.s)
        CardReaderNFC.logger.debugSensitive("Shared Secret x: \(sharedSecretH.x.asMagnitudeBytes().toHex), " +
                                            "y: \(sharedSecretH.y.asMagnitudeBytes().toHex)")
        return try domain.addPoints(mappingBasePoint, sharedSecretH) // MAP G = (S*G) + H
    }

    /// Authentication token: CMAC over the public key data object 7F49 { 06 protocol OID, 86 point }.
    static func authToken(for publicKey: ECPublicKey, protocolId: Data, macKey: Bytes) throws -> Bytes.SubSequence {
        let input = TLV(tag: 0x7f49, records: [
            TLV(tag: 0x06, value: protocolId),
            try TLV(tag: 0x86, publicKey: publicKey)
        ])
        return try AES.CMAC(key: macKey).authenticate(bytes: input.data)
    }

    // Integrated Mapping constants c0 and c1, ICAO 9303-11 section 4.4.3.3.2
    private static let c0AES128: Bytes = [
        0xA6, 0x68, 0x89, 0x2A, 0x7C, 0x41, 0xE3, 0xCA,
        0x73, 0x9F, 0x40, 0xB0, 0x57, 0xD8, 0x59, 0x04
    ]
    private static let c1AES128: Bytes = [
        0xA4, 0xE1, 0x36, 0xAC, 0x72, 0x5F, 0x73, 0x8B,
        0x01, 0xC1, 0xF6, 0x02, 0x17, 0xC1, 0x88, 0xAD
    ]
    private static let c0AES256: Bytes = [
        0xD4, 0x63, 0xD6, 0x52, 0x34, 0x12, 0x4E, 0xF7,
        0x89, 0x70, 0x54, 0x98, 0x6D, 0xCA, 0x0A, 0x17,
        0x4E, 0x28, 0xDF, 0x75, 0x8C, 0xBA, 0xA0, 0x3F,
        0x24, 0x06, 0x16, 0x41, 0x4D, 0x5A, 0x16, 0x76
    ]
    private static let c1AES256: Bytes = [
        0x54, 0xBD, 0x72, 0x55, 0xF0, 0xAA, 0xF8, 0x31,
        0xBE, 0xC3, 0x42, 0x3F, 0xCF, 0x39, 0xD6, 0x9B,
        0x6C, 0xBF, 0x06, 0x66, 0x77, 0xD0, 0xFA, 0xAE,
        0x5A, 0xAD, 0xD9, 0x9D, 0xF8, 0xE5, 0x35, 0x17
    ]

    /// Integrated Mapping pseudo-random function Rp(s, t), ICAO 9303-11 section 4.4.3.3.2.
    /// The chip's nonce s is l bits, the terminal's nonce t is k bits (the AES key size),
    /// and the result is reduced mod p.
    static func pseudoRandomNumberMappingAES(
        sVal: any DataType,
        tVal: any DataType,
        domain: Domain
    ) throws -> BInt {
        let lVal = sVal.count * 8
        let kVal = tVal.count * 8

        let c0Val: Bytes
        let c1Val: Bytes
        switch lVal {
        case 128:
            c0Val = c0AES128
            c1Val = c1AES128
        case 256:
            c0Val = c0AES256
            c1Val = c1AES256
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

    /// Integrated Mapping point encoding fG(t), ICAO 9303-11 Appendix B.2 (affine coordinates).
    /// Requires p ≡ 3 mod 4, which holds for all supported curves.
    static func pointEncodeIM(tVal: BInt, domain: Domain) -> Point {
        let pVal = domain.p
        let aVal = domain.a
        let bVal = domain.b

        // 1. α = -t^2 mod p
        let alpha = (-(tVal ** 2)).mod(pVal)

        // 2. X2 = -ba^-1 (1 + (α + α^2)^-1) mod p
        // Hint  = -b(1 + α + α^2)(a(α + α^2))^(p-2) mod p
        let alphaPlusAlphaSquared = alpha + alpha ** 2
        let x2Val = ((-bVal * (1 + alphaPlusAlphaSquared)) *
                     (aVal * alphaPlusAlphaSquared).expMod(pVal - 2, pVal)).mod(pVal)

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
        // 10. [f](x, y) is skipped: the cofactor f is 1 for all supported curves
        return (AVal ** 2 * h2Val).mod(pVal) == BInt.ONE ?
            Point(x2Val, (AVal * h2Val).mod(pVal)) :
            Point(x3Val, (AVal * UVal).mod(pVal))
    }

    static private func decryptNonce<T: DataType>(CAN: String, encryptedNonce: T) throws -> Bytes {
        let decryptionKey = KDF(key: Bytes(CAN.utf8), counter: 3)
        let cipher = AES.CBC(key: decryptionKey)
        return try cipher.decrypt(encryptedNonce)
    }

    /// PACE key derivation for AES-256: SHA-256(key || 32-bit big-endian counter).
    /// Counter 1 derives KS.Enc, 2 KS.MAC and 3 Kπ from the password.
    static func KDF(key: Bytes, counter: UInt8) -> Bytes {
        sha(hashLength: .bits256, data: key + [0, 0, 0, counter])
    }

    // MARK: - Utils

    static private func random(count: Int) throws -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        if result != errSecSuccess {
            throw IdCardInternalError.authenticationFailed
        }
        return data
    }
}
