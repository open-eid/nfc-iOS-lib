// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Testing
@testable import nfclib

// NIST SP 800-38A / 800-38B example plaintext
private let message = Bytes(hex: """
    6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 \
    30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710
    """)!
private let key128 = Bytes(hex: "2b7e151628aed2a6abf7158809cf4f3c")!
private let key256 = Bytes(hex: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")!

struct AESCBCTests {
    // NIST SP 800-38A F.2.5 / F.2.6 CBC-AES256
    let ivVal = Bytes(hex: "000102030405060708090a0b0c0d0e0f")!
    let cipherText = Bytes(hex: """
        f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d \
        39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b
        """)!

    @Test func encryptAES256() throws {
        #expect(try AES.CBC(key: key256, ivVal: ivVal).encrypt(message) == cipherText)
    }

    @Test func decryptAES256() throws {
        #expect(try AES.CBC(key: key256, ivVal: ivVal).decrypt(cipherText) == message)
    }

    @Test func rejectsPartialBlock() {
        #expect(throws: IdCardInternalError.self) {
            try AES.CBC(key: key256).encrypt(Bytes(repeating: 0, count: 15))
        }
    }
}

struct AESCMACTests {
    // RFC 4493 section 2.3
    @Test func subkeysAES128() throws {
        let cmac = try AES.CMAC(key: key128)
        #expect(cmac.k1Bytes == Bytes(hex: "fbeed618357133667c85e08f7236a8de")!)
        #expect(cmac.k2Bytes == Bytes(hex: "f7ddac306ae266ccf90bc11ee46d513b")!)
    }

    // RFC 4493 section 4, examples 1-4
    @Test(arguments: [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe")
    ])
    func macAES128(length: Int, expected: String) throws {
        let mac = try AES.CMAC(key: key128).authenticate(bytes: Bytes(message.prefix(length)), count: 16)
        #expect(Bytes(mac) == Bytes(hex: expected)!)
    }

    // NIST SP 800-38B appendix D.3
    @Test(arguments: [
        (0, "028962f61b7bf89efc6b551f4667d983"),
        (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
        (40, "aaf3d8f1de5640c232f5b169b9c911e6"),
        (64, "e1992190549f6ed5696a2c056c315410")
    ])
    func macAES256(length: Int, expected: String) throws {
        let mac = try AES.CMAC(key: key256).authenticate(bytes: Bytes(message.prefix(length)), count: 16)
        #expect(Bytes(mac) == Bytes(hex: expected)!)
    }

    @Test func defaultTruncationIs8Bytes() throws {
        let mac = try AES.CMAC(key: key256).authenticate(bytes: message)
        #expect(Bytes(mac) == Bytes(hex: "e1992190549f6ed5")!)
    }
}
