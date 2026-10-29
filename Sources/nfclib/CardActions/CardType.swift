// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

public enum CardType: String, Sendable, CaseIterable {
    case id1
    case thales
    case latviaIdemia
}

public extension CardType {
    /**
     * The card types accepted when a caller passes no explicit allow-list.
     *
     * An integrator who genuinely wants every supported card type must say so via ``allCards``,
     * so a future release of this library adding a country variant cannot silently widen the set
     * of cards that the integrator's app accepts.
     */
    static let estonianCards: Set<CardType> = [.id1, .thales]

    static let allCards: Set<CardType> = Set(CardType.allCases)
}

extension CardType {
    private static let knownHistoricalBytes: [(bytes: Bytes, cardType: CardType)] = [
        (Bytes(hex: "00 12 23 3F 53 65 49 44 0F 90 00"), .id1),
        (Bytes(hex: "00 12 23 3F 54 65 49 44 32 0F 90 00"), .id1),
        // Android lists only D8; this repo's Thales ATR carries B8 in the same position. Both
        // are kept until a real tap settles it — matching neither would reject every Thales card.
        (Bytes(hex: "80 31 B8 53 65 49 44 64 B0 85 05 10 12 23 3F"), .thales),
        (Bytes(hex: "80 31 D8 53 65 49 44 64 B0 85 05 10 12 23 3F"), .thales),
        (Bytes(hex: "00 12 42 8F 53 65 49 44 0F 90 00"), .latviaIdemia),
        (Bytes(hex: "00 12 42 8F 54 65 49 44 32 0F 90 00"), .latviaIdemia)
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
