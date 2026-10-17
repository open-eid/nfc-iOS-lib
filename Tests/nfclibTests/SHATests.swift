// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Testing
@testable import nfclib

// NIST FIPS 180-4 example messages
private let message448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
private let message896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" +
    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

struct SHATests {
    @Test(arguments: [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (message448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    ])
    func sha256(message: String, expected: String) {
        #expect(sha(hashLength: .bits256, data: Bytes(message.utf8)) == Bytes(hex: expected)!)
    }

    @Test(arguments: [
        ("", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da" +
            "274edebfe76f65fbd51ad2f14898b95b"),
        ("abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" +
            "8086072ba1e7cc2358baeca134c825a7"),
        (message896, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712" +
            "fcc7c71a557e2db966c3e9fa91746039")
    ])
    func sha384(message: String, expected: String) {
        #expect(sha(hashLength: .bits384, data: Bytes(message.utf8)) == Bytes(hex: expected)!)
    }

    @Test(arguments: [
        ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        ("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (message896, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018" +
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
    ])
    func sha512(message: String, expected: String) {
        #expect(sha(hashLength: .bits512, data: Bytes(message.utf8)) == Bytes(hex: expected)!)
    }
}
