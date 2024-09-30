//
//  OperationAuthenticate.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import Foundation
@_implementationOnly import SwiftECC
import CoreNFC
import CryptoTokenKit
import BigInt

enum AuthenticateError: Error {
    case general
}

struct OperationAuthenticate {
    // MARK: - PACE
    func mutualAuthenticate(tag: NFCISO7816Tag, CAN: String) async throws -> (Bytes, Bytes)? {
        do {
            let oid = "04007f00070202040204" // id-PACE-ECDH-GM-AES-CBC-CMAC-256
            // + CAN
            _ = try await tag.sendCommand(cls: 0x00, ins: 0x22, p1: 0xc1, p2: 0xa4, data: Data(hex: "800a\(oid)830102")!, le: 256)
            let nonceTag = try await tag.sendPaceCommand(records: [], tagExpected: 0x80)
            print("Challenge \(nonceTag.data.toHex)")
            let nonce = try decryptNonce(encryptedNonce: nonceTag.value, CAN: CAN)
            print("Nonce \(nonce.toHex)")
            let domain = Domain.instance(curve: .EC256r1)

            // Mapping data
            let (terminalPubKey, terminalPrivKey) = domain.makeKeyPair()
            let mappingTag = try await tag.sendPaceCommand(records: [try TKBERTLVRecord(tag: 0x81, publicKey: terminalPubKey)], tagExpected: 0x82)
            print("Mapping key \(mappingTag.data.toHex)")
            let cardPubKey = try ECPublicKey(domain: domain, tlv: mappingTag)!

            // Mapping
            let nonceS = BInt(magnitude: nonce)
            let mappingBasePoint = ECPublicKey(privateKey: try ECPrivateKey(domain: domain, s: nonceS)) // S*G
            print("Card Key x: \(mappingBasePoint.w.x.asMagnitudeBytes().toHex), y: \(mappingBasePoint.w.y.asMagnitudeBytes().toHex)")
            let sharedSecretH = try domain.multiplyPoint(cardPubKey.w, terminalPrivKey.s)
            print("Shared Secret x: \(sharedSecretH.x.asMagnitudeBytes().toHex), y: \(sharedSecretH.y.asMagnitudeBytes().toHex)")
            let mappedPoint = try domain.addPoints(mappingBasePoint.w, sharedSecretH) // MAP G = (S*G) + H
            print("Mapped point x: \(mappedPoint.x.asMagnitudeBytes().toHex), y: \(mappedPoint.y.asMagnitudeBytes().toHex)")
            let mappedDomain = try Domain.instance(name: domain.name + " Mapped", p: domain.p, a: domain.a, b: domain.b, gx: mappedPoint.x, gy: mappedPoint.y, order: domain.order, cofactor: domain.cofactor)

            // Ephemeral data
            let (terminalEphemeralPubKey, terminalEphemeralPrivKey) = mappedDomain.makeKeyPair()
            let ephemeralTag = try await tag.sendPaceCommand(records: [try TKBERTLVRecord(tag: 0x83, publicKey: terminalEphemeralPubKey)], tagExpected: 0x84)
            print("Card Ephermal key \(ephemeralTag.data.toHex)")
            let ephemeralCardPubKey = try ECPublicKey(domain: mappedDomain, tlv: ephemeralTag)!

            // Derive shared secret and session keys
            let sharedSecret = try terminalEphemeralPrivKey.sharedSecret(pubKey: ephemeralCardPubKey)
            print("Shared secret \(sharedSecret.toHex)")
            let ksEnc = KDF(key: sharedSecret, counter: 1)
            let ksMac = KDF(key: sharedSecret, counter: 2)
            print("KS.Enc \(ksEnc.toHex)")
            print("KS.Mac \(ksMac.toHex)")

            // Mutual authentication
            let macHeader = Bytes(hex: "7f494f060a\(oid)8641")!
            let macCalc = try AES.CMAC(key: Bytes(ksMac))
            let ephemeralCardPubKeyBytes = try ephemeralCardPubKey.x963Representation()
            let macTag = try await tag.sendPaceCommand(records: [TKBERTLVRecord(tag: 0x85, bytes: (try macCalc.authenticate(bytes: macHeader + ephemeralCardPubKeyBytes, count: 8)))], tagExpected: 0x86)
            print("Mac response \(macTag.data.toHex)")

            // verify chip's MAC and return session keys
            let terminalEphemeralPubKeyBytes = try terminalEphemeralPubKey.x963Representation()
            if  macTag.value == Data(try macCalc.authenticate(bytes: macHeader + terminalEphemeralPubKeyBytes, count: 8)) {
                return (ksEnc, ksMac)
            }
            return nil
        } catch {
            print(error)
            if let e = error as? IdCardInternalError {
                switch e {
                case .invalidResponse(message: let message):
                    if message == "6300" {
                        throw IdCardInternalError.canAuthenticationFailed
                    } else {
                        throw IdCardInternalError.authenticationFailed
                    }
                default:
                    throw IdCardInternalError.authenticationFailed
                }
            } else {
                throw IdCardInternalError.authenticationFailed
            }
        }
    }
}


