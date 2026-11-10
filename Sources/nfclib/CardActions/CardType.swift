// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

public enum CardType: String, Sendable, CaseIterable {
    case idemiaEstonia
    case thalesEstonia
    case idemiaLatvia
}

public extension CardType {
    /**
     * The card types accepted when a caller passes no explicit allow-list.
     *
     * An integrator who genuinely wants every supported card type must say so via ``allCards``,
     * so a future release of this library adding a country variant cannot silently widen the set
     * of cards that the integrator's app accepts.
     */
    static let estonianCards: Set<CardType> = [.idemiaEstonia, .thalesEstonia]

    static let allCards: Set<CardType> = Set(CardType.allCases)
}

extension CardType {
    private static let knownHistoricalBytes: [(bytes: Bytes, cardType: CardType)] = [
        ([0x00, 0x12, 0x23, 0x3F, 0x53, 0x65, 0x49, 0x44, 0x0F, 0x90, 0x00], .idemiaEstonia),
        ([0x00, 0x12, 0x23, 0x3F, 0x54, 0x65, 0x49, 0x44, 0x32, 0x0F, 0x90, 0x00], .idemiaEstonia),
        // Two Thales variants differ only in the third byte. Both are kept until a real tap
        // settles which one ships — matching neither would reject every Thales card.
        ([0x80, 0x31, 0xB8, 0x53, 0x65, 0x49, 0x44, 0x64, 0xB0, 0x85, 0x05, 0x10, 0x12, 0x23, 0x3F], .thalesEstonia),
        ([0x80, 0x31, 0xD8, 0x53, 0x65, 0x49, 0x44, 0x64, 0xB0, 0x85, 0x05, 0x10, 0x12, 0x23, 0x3F], .thalesEstonia),
        ([0x00, 0x12, 0x42, 0x8F, 0x53, 0x65, 0x49, 0x44, 0x0F, 0x90, 0x00], .idemiaLatvia),
        ([0x00, 0x12, 0x42, 0x8F, 0x54, 0x65, 0x49, 0x44, 0x32, 0x0F, 0x90, 0x00], .idemiaLatvia)
    ]

    init?(historicalBytes: Data?) {
        guard let historicalBytes else { return nil }
        let bytes = Bytes(historicalBytes)
        guard let match = CardType.knownHistoricalBytes.first(where: { $0.bytes == bytes }) else {
            return nil
        }
        self = match.cardType
    }
}
