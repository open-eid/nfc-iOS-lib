import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt

class CardReaderNFC: CardReader {

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
        var data: Data { return Data(hex: rawValue)! }
    }
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

    let tag: NFCISO7816Tag
    var ksEnc: Bytes
    var ksMac: Bytes
    var SSC: Bytes = AES.Zero

    init(_ tag: NFCISO7816Tag, CAN: String) async throws {
        self.tag = tag

        print("Select CardAccess")
        _ = try await tag.sendCommand(cls: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: Data([0x01, 0x1C]))
        print("Read CardAccess")
        let data = try await tag.sendCommand(cls: 0x00, ins: 0xB0, p1: 0x00, p2: 0x00, le: 256)

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

        _ = try await tag.sendCommand(cls: 0x00, ins: 0x22, p1: 0xc1, p2: 0xa4, records: [
            TLV(tag: 0x80, value: mappingType.data),
            TLV(tag: 0x83, bytes: [PasswordType.id_PasswordType_CAN.rawValue]),
            TLV(tag: 0x84, bytes: [parameterId.rawValue]),
        ])

        // Step1 - General Authentication
        let nonceEnc = try await tag.sendPaceCommand(records: [], tagExpected: 0x80)
        print("Challenge \(nonceEnc.value.toHex)")
        let nonce = try CardReaderNFC.decryptNonce(CAN: CAN, encryptedNonce: nonceEnc.value)
        print("Nonce \(nonce.toHex)")

        // Step2
        let (terminalPubKey, terminalPrivKey) = domain.makeKeyPair()
        let mappingKey = try await tag.sendPaceCommand(records: [try TLV(tag: 0x81, publicKey: terminalPubKey)], tagExpected: 0x82)
        print("Mapping key \(mappingKey.value.toHex)")
        guard let cardPubKey = try ECPublicKey(domain: domain, point: mappingKey.value)
        else { throw IdCardInternalError.authenticationFailed }

        // Mapping
        let nonceS = BInt(magnitude: nonce)
        let mappingBasePoint = ECPublicKey(privateKey: try ECPrivateKey(domain: domain, s: nonceS)) // S*G
        print("Card Key x: \(mappingBasePoint.w.x.asMagnitudeBytes().toHex), y: \(mappingBasePoint.w.y.asMagnitudeBytes().toHex)")
        let sharedSecretH = try domain.multiplyPoint(cardPubKey.w, terminalPrivKey.s)
        print("Shared Secret x: \(sharedSecretH.x.asMagnitudeBytes().toHex), y: \(sharedSecretH.y.asMagnitudeBytes().toHex)")
        let mappedPoint = try domain.addPoints(mappingBasePoint.w, sharedSecretH) // MAP G = (S*G) + H

        // Ephemeral data
        print("Mapped point x: \(mappedPoint.x.asMagnitudeBytes().toHex), y: \(mappedPoint.y.asMagnitudeBytes().toHex)")
        let mappedDomain = try Domain.instance(name: domain.name + " Mapped", p: domain.p, a: domain.a, b: domain.b, gx: mappedPoint.x, gy: mappedPoint.y, order: domain.order, cofactor: domain.cofactor)
        let (terminalEphemeralPubKey, terminalEphemeralPrivKey) = mappedDomain.makeKeyPair()
        let ephemeralKey = try await tag.sendPaceCommand(records: [try TLV(tag: 0x83, publicKey: terminalEphemeralPubKey)], tagExpected: 0x84)
        print("Card Ephermal key \(ephemeralKey.value.toHex)")
        guard let ephemeralCardPubKey = try ECPublicKey(domain: mappedDomain, point: ephemeralKey.value)
        else { throw IdCardInternalError.authenticationFailed }

        // Derive shared secret and session keys
        let sharedSecret = try terminalEphemeralPrivKey.sharedSecret(pubKey: ephemeralCardPubKey)
        print("Shared secret \(sharedSecret.toHex)")
        ksEnc = CardReaderNFC.KDF(key: sharedSecret, counter: 1)
        ksMac = CardReaderNFC.KDF(key: sharedSecret, counter: 2)
        print("KS.Enc \(ksEnc.toHex)")
        print("KS.Mac \(ksMac.toHex)")

        // Mutual authentication
        let macCalc = try AES.CMAC(key: ksMac)

        let macHeader = TLV(tag: 0x7f49, records: [
            TLV(tag: 0x06, value: mappingType.data),
            TLV(tag: 0x86, bytes: try ephemeralCardPubKey.x963Representation())
        ])
        let macValue = try await tag.sendPaceCommand(records: [TLV(tag: 0x85, bytes: (try macCalc.authenticate(bytes: macHeader.data)))], tagExpected: 0x86)
        print("Mac response \(macValue.data.toHex)")

        // verify chip's MAC
        let macResult = TLV(tag: 0x7f49, records: [
            TLV(tag: 0x06, value: mappingType.data),
            TLV(tag: 0x86, bytes: try terminalEphemeralPubKey.x963Representation())
        ])
        if macValue.value != Data(try macCalc.authenticate(bytes: macResult.data)) {
            throw IdCardInternalError.authenticationFailed
        }
    }

    func transmit(_ apduData: Bytes) async throws -> (responseData: Bytes, sw: UInt16) {
        print("Plain >: \(apduData.toHex)")
        guard let apdu = NFCISO7816APDU(data: Data(apduData)) else {
            throw IdCardInternalError.invalidAPDU
        }
        _ = SSC.increment()
        let DO87: Data
        if let data = apdu.data, !data.isEmpty {
            let iv = try AES.CBC(key: ksEnc).encrypt(SSC)
            let enc_data = try AES.CBC(key: ksEnc, iv: iv).encrypt(data.addPadding())
            DO87 = TLV(tag: 0x87, bytes: [0x01] + enc_data).data
        } else {
            DO87 = Data()
        }
        let DO97: Data
        if apdu.expectedResponseLength > 0 {
            DO97 = TLV(tag: 0x97, bytes: [UInt8(apdu.expectedResponseLength == 256 ? 0 : apdu.expectedResponseLength)]).data
        } else {
            DO97 = Data()
        }
        let cmd_header: Bytes = [apdu.instructionClass | 0x0C, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter]
        let M = cmd_header.addPadding() + DO87 + DO97
        let N = SSC + M
        let mac = try AES.CMAC(key: ksMac).authenticate(bytes: N.addPadding())
        let DO8E = TLV(tag: 0x8E, bytes: mac).data
        let send = DO87 + DO97 + DO8E
        let response = try await tag.sendCommand(cls: cmd_header[0], ins: cmd_header[1], p1: cmd_header[2], p2: cmd_header[3], data: send, le: 256)
        var tlvEnc: TKTLVRecord?
        var tlvRes: TKTLVRecord?
        var tlvMac: TKTLVRecord?
        for tlv in TLV.sequenceOfRecords(from: response) ?? [] {
            switch tlv.tag {
            case 0x87: tlvEnc = tlv
            case 0x99: tlvRes = tlv
            case 0x8E: tlvMac = tlv
            default: print("Unknown tag")
            }
        }
        guard let tlvRes else {
            throw IdCardInternalError.missingRESTag
        }
        guard let tlvMac else {
            throw IdCardInternalError.missingMACTag
        }
        let K = SSC.increment() + (tlvEnc?.data ?? Data()) + tlvRes.data
        if try Data(AES.CMAC(key: ksMac).authenticate(bytes: K.addPadding())) != tlvMac.value {
            throw IdCardInternalError.invalidMACValue
        }
        guard let tlvEnc else {
            print("Plain <: \(tlvRes.value.toHex)")
            return (.init(), UInt16(tlvRes.value[0], tlvRes.value[1]))
        }
        let iv = try AES.CBC(key: ksEnc).encrypt(SSC)
        let responseData = try (try AES.CBC(key: ksEnc, iv: iv).decrypt(tlvEnc.value[1...])).removePadding()
        print("Plain <:  \(responseData.toHex) \(tlvRes.value.toHex)")
        return (Bytes(responseData), UInt16(tlvRes.value[0], tlvRes.value[1]))
    }

    // MARK: - Utils

    static private func decryptNonce<T : AES.DataType>(CAN: String, encryptedNonce: T) throws -> Bytes {
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
}

extension UInt16 {
    init(_ p1: UInt8, _ p2: UInt8) {
        self = (UInt16(p1) << 8) | UInt16(p2)
    }
}
