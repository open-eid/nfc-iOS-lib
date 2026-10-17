// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import BigInt
import Foundation
import SwiftECC
import Testing
@testable import nfclib

// ICAO Doc 9303 Part 11 worked examples on BrainpoolP256r1.
// Both use AES-128 session keys and an MRZ password with a SHA-1 KDF, so Kπ and the session keys
// are taken from the examples instead of derived; every other step runs through the library code.

private func scalar(_ hex: String) -> BInt {
    BInt(magnitude: Bytes(hex: hex)!)
}

private func publicKey(_ hex: String, domain: Domain) throws -> ECPublicKey {
    try #require(try ECPublicKey(domain: domain, point: Data(hex: "04" + hex)!))
}

/// Appendix G.1: PACE with ECDH Generic Mapping
@MainActor
struct PACEGenericMappingExampleTests {
    let domain = Domain.instance(curve: .BP256r1)
    let protocolId = Data(hex: "04007F00070202040202")!
    let kPi = Bytes(hex: "89DED1B2 6624EC1E 634C1989 302849DD")!
    let nonce = Bytes(hex: "3F00C4D3 9D153F2B 2A214A07 8D899B22")!
    let encryptedNonce = Bytes(hex: "95A3A016 522EE98D 01E76CB6 B98B42C3")!

    let terminalMappingPrivateKey = scalar("7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99")
    let terminalMappingPublicKey = """
        7ACF3EFC 982EC455 65A4B155 129EFBC7 4650DCBF A6362D89 6FC70262 E0C2CC5E \
        544552DC B6725218 799115B5 5C9BAA6D 9F6BC3A9 618E70C2 5AF71777 A9C4922D
        """
    let chipMappingPublicKey = """
        824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57 \
        30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54
        """
    let mappedGeneratorX = scalar("8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2")
    let mappedGeneratorY = scalar("8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522")

    let terminalPrivateKey = scalar("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595")
    let terminalPublicKey = """
        2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C \
        3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462
        """
    let chipPublicKey = """
        9E880F84 2905B8B3 181F7AF7 CAA9F0EF B743847F 44A306D2 D28C1D9E C65DF6DB \
        7764B222 77A2EDDC 3C265A9F 018F9CB8 52E111B7 68B32690 4B59A019 3776F094
        """
    let sharedSecret = Bytes(hex: "28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")!
    let ksMac = Bytes(hex: "FE251C78 58B356B2 4514B3BD 5F4297D1")!

    @Test func decryptsNonce() throws {
        #expect(try AES.CBC(key: kPi).decrypt(encryptedNonce) == nonce)
    }

    func mappedDomain() throws -> Domain {
        let mappedGenerator = try CardReaderNFC.mapNonceGM(
            nonce: nonce,
            terminalPrivateKey: try ECPrivateKey(domain: domain, s: terminalMappingPrivateKey),
            cardPublicKey: try publicKey(chipMappingPublicKey, domain: domain),
            domain: domain)
        return try domain.withGenerator(mappedGenerator)
    }

    @Test func terminalMappingKeyMatches() throws {
        let key = ECPublicKey(privateKey: try ECPrivateKey(domain: domain, s: terminalMappingPrivateKey))
        #expect(key.w == (try publicKey(terminalMappingPublicKey, domain: domain)).w)
    }

    @Test func mapsNonce() throws {
        let generator = try mappedDomain().g
        #expect(generator.x == mappedGeneratorX)
        #expect(generator.y == mappedGeneratorY)
    }

    @Test func agreesOnSharedSecret() throws {
        let mappedDomain = try mappedDomain()
        let privateKey = try ECPrivateKey(domain: mappedDomain, s: terminalPrivateKey)
        #expect(ECPublicKey(privateKey: privateKey).w == (try publicKey(terminalPublicKey, domain: mappedDomain)).w)
        #expect(try privateKey.sharedSecret(pubKey: try publicKey(chipPublicKey, domain: mappedDomain)) == sharedSecret)
    }

    @Test func computesAuthenticationTokens() throws {
        let mappedDomain = try mappedDomain()
        let terminalToken = try CardReaderNFC.authToken(
            for: try publicKey(chipPublicKey, domain: mappedDomain), protocolId: protocolId, macKey: ksMac)
        let chipToken = try CardReaderNFC.authToken(
            for: try publicKey(terminalPublicKey, domain: mappedDomain), protocolId: protocolId, macKey: ksMac)
        #expect(Bytes(terminalToken) == Bytes(hex: "C2B0BD78 D94BA866")!)
        #expect(Bytes(chipToken) == Bytes(hex: "3ABB9674 BCE93C08")!)
    }
}

/// Appendix H.1: PACE with ECDH Integrated Mapping
@MainActor
struct PACEIntegratedMappingExampleTests {
    let domain = Domain.instance(curve: .BP256r1)
    let protocolId = Data(hex: "04007F00070202040402")!
    let kPi = Bytes(hex: "591468CD A83D6521 9CCCB856 0233600F")!
    let nonce = Bytes(hex: "2923BE84 E16CD6AE 529049F1 F1BBE9EB")!
    let encryptedNonce = Bytes(hex: "143DC40C 08C8E891 FBED7DED B92B64AD")!
    let nonceT = Bytes(hex: "5DD4CBFC 96F5453B 130D890A 1CDBAE32")!
    let pseudoRandom = scalar("A2F8FF2D F50E52C6 599F386A DCB595D2 29F6A167 ADE2BE5F 2C3296AD D5B7430E")
    let mappedGeneratorX = scalar("8E82D315 59ED0FDE 92A4D049 8ADD3C23 BABA94FB 77691E31 E90AEA77 FB17D427")
    let mappedGeneratorY = scalar("4C1AE14B D0C3DBAC 0C871B7F 36081693 64437CA3 0AC243A0 89D3F266 C1E60FAD")

    let terminalPrivateKey = scalar("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595")
    let terminalPublicKey = """
        89CBA23F FE96AA18 D824627C 3E934E54 A9FD0B87 A95D1471 DC1C0ABF DCD640D4 \
        6755DE9B 7B778280 B6BEBD57 439ADFEB 0E21FD4E D6DF4257 8C13418A 59B34C37
        """
    let chipPublicKey = """
        67F78E5F 7F768608 2B293E8D 087E0569 16D0F74B C01A5F89 57D0DE45 691E51E8 \
        932B69A9 62B52A09 85AD2C0A 271EE6A1 3A8ADDDC D1A3A994 B9DED257 F4D22753
        """
    let sharedSecret = Bytes(hex: "4F150FDE 1D4F0E38 E95017B8 91BAE171 33A0DF45 B0D3E18B 60BA7BEA FDC2C713")!
    let ksMac = Bytes(hex: "B01E89E3 D9E8719E 586B50B4 A7506E0B")!

    @Test func decryptsNonce() throws {
        #expect(try AES.CBC(key: kPi).decrypt(encryptedNonce) == nonce)
    }

    func mappedDomain() throws -> Domain {
        let pseudoRandom = try CardReaderNFC.pseudoRandomNumberMappingAES(sVal: nonce, tVal: nonceT, domain: domain)
        let mappedGenerator = CardReaderNFC.pointEncodeIM(tVal: pseudoRandom, domain: domain)
        return try domain.withGenerator(mappedGenerator)
    }

    @Test func pseudoRandomNumberMapping() throws {
        let value = try CardReaderNFC.pseudoRandomNumberMappingAES(sVal: nonce, tVal: nonceT, domain: domain)
        #expect(value == pseudoRandom)
    }

    @Test func mapsNonce() throws {
        let generator = try mappedDomain().g
        #expect(generator.x == mappedGeneratorX)
        #expect(generator.y == mappedGeneratorY)
    }

    @Test func agreesOnSharedSecret() throws {
        let mappedDomain = try mappedDomain()
        let privateKey = try ECPrivateKey(domain: mappedDomain, s: terminalPrivateKey)
        #expect(ECPublicKey(privateKey: privateKey).w == (try publicKey(terminalPublicKey, domain: mappedDomain)).w)
        #expect(try privateKey.sharedSecret(pubKey: try publicKey(chipPublicKey, domain: mappedDomain)) == sharedSecret)
    }

    @Test func computesAuthenticationTokens() throws {
        let mappedDomain = try mappedDomain()
        let terminalToken = try CardReaderNFC.authToken(
            for: try publicKey(chipPublicKey, domain: mappedDomain), protocolId: protocolId, macKey: ksMac)
        let chipToken = try CardReaderNFC.authToken(
            for: try publicKey(terminalPublicKey, domain: mappedDomain), protocolId: protocolId, macKey: ksMac)
        #expect(Bytes(terminalToken) == Bytes(hex: "450F02B8 6F6A0909")!)
        #expect(Bytes(chipToken) == Bytes(hex: "75D4D96E 8D5B0308")!)
    }
}
