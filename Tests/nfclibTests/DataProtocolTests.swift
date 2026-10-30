// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import Testing
@testable import nfclib

struct HexParsingTests {
    @Test(arguments: [
        ("a668892a", [0xa6, 0x68, 0x89, 0x2a]),
        ("A6 68 89 2A", [0xa6, 0x68, 0x89, 0x2a]),
        ("00ff", [0x00, 0xff]),
        ("", [])
    ] as [(String, Bytes)])
    func parsesValidHex(hex: String, expected: Bytes) {
        #expect(Bytes(hex: hex) == expected)
    }

    @Test(arguments: ["0011zz22", "+f", "-1", "abc", "0x12", "12 3"])
    func rejectsInvalidHex(hex: String) {
        #expect(Bytes(hex: hex) == nil)
    }

    @Test func parsesIntoData() {
        #expect(Data(hex: "04007f00") == Data([0x04, 0x00, 0x7f, 0x00]))
    }

    @Test func roundTripsThroughToHex() {
        let bytes: Bytes = [0x00, 0x7f, 0x80, 0xff]
        #expect(Bytes(hex: bytes.toHex) == bytes)
    }
}

struct XORTests {
    @Test func xorsEqualLengthBytes() {
        let lhs: Bytes = [0x0f, 0xf0, 0xaa]
        let rhs: Bytes = [0xff, 0xff, 0x55]
        #expect(lhs ^ rhs == [0xf0, 0x0f, 0xff])
    }

    @Test func xorsSliceWithNonZeroStartIndex() {
        let slice = Data([0x01, 0x02, 0x03, 0x04]).dropFirst()
        #expect(slice ^ Data([0x02, 0x03, 0x04]) == Data([0x00, 0x00, 0x00]))
    }
}

struct SendSequenceCounterTests {
    @Test func incrementsLastByte() {
        var ssc = Bytes(hex: "000000000000000000000000000000fe")!
        #expect(ssc.increment() == Bytes(hex: "000000000000000000000000000000ff")!)
    }

    @Test func carriesIntoNextByte() {
        var ssc = Bytes(hex: "000000000000000000000000000000ff")!
        #expect(ssc.increment() == Bytes(hex: "00000000000000000000000000000100")!)
    }

    @Test func wrapsAround() {
        var ssc = Bytes(repeating: 0xff, count: 16)
        #expect(ssc.increment() == AES.Zero)
    }
}

struct PaddingTests {
    // ISO/IEC 9797-1 padding method 2
    @Test func padsPartialBlock() {
        #expect(Bytes(hex: "0102")!.addPadding() == Bytes(hex: "01028000000000000000000000000000")!)
    }

    @Test func padsFullBlockWithExtraBlock() {
        let block = Bytes(repeating: 0x11, count: 16)
        #expect(block.addPadding() == block + Bytes(hex: "80000000000000000000000000000000")!)
    }

    @Test func removesPadding() throws {
        #expect(Bytes(try Bytes(hex: "01028000000000000000000000000000")!.removePadding()) == Bytes(hex: "0102")!)
    }

    @Test func rejectsMissingPaddingMarker() {
        #expect(throws: IdCardInternalError.self) {
            try Bytes(hex: "01020000000000000000000000000000")!.removePadding()
        }
    }
}
