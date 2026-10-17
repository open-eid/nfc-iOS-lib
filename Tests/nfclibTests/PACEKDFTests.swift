// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Testing
@testable import nfclib

// ICAO 9303-11 KDF for AES-256: SHA-256(key || counter), with the counter as 4 bytes big-endian.
// The ICAO worked examples only cover the SHA-1 variant, so the expected values were computed
// independently with shasum.
@MainActor
struct PACEKDFTests {
    // Shared secret from ICAO 9303-11 Appendix G.1
    let sharedSecret = Bytes(hex: "28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")!

    @Test func derivesEncryptionKey() {
        #expect(CardReaderNFC.KDF(key: sharedSecret, counter: 1) ==
                Bytes(hex: "8419651a9932a555fe20d96406746a82f750f4ccb3d6be786d4630bcc681bf0e")!)
    }

    @Test func derivesMACKey() {
        #expect(CardReaderNFC.KDF(key: sharedSecret, counter: 2) ==
                Bytes(hex: "aa35fdb8d201bc2fd2bd98550c6fe549568c5e769be67f04733673b7c910a59f")!)
    }

    @Test func derivesPasswordKeyFromCAN() {
        #expect(CardReaderNFC.KDF(key: Bytes("123456".utf8), counter: 3) ==
                Bytes(hex: "8df3278fb32026e66277357fcd6c826dbeb3de32088b2531757d753940185923")!)
    }
}
