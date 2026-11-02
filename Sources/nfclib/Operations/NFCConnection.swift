// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
@preconcurrency import CoreNFC

@MainActor
public class NFCConnection {
    public init() {}
    public func setup(_ session: NFCTagReaderSession, tags: [NFCTag]) async throws -> NFCISO7816Tag {
        if tags.count > 1 {
            session.invalidate(errorMessage: "Failed to read data")
            throw IdCardInternalError.multipleTagsDetected
        }

        guard let firstTag = tags.first else {
            session.invalidate(errorMessage: "Failed to read data")
            throw IdCardInternalError.invalidTag
        }

        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                session.connect(to: firstTag) { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            }
        } catch {
            session.invalidate(errorMessage: "Failed to read data")
            throw IdCardInternalError.connectionFailed
        }

        guard case let .iso7816(tag) = firstTag else {
            session.invalidate(errorMessage: "Failed to read data")
            throw IdCardInternalError.invalidTag
        }

        return tag
    }

    /**
     * Detect the card by ATS historical bytes and return the matching implementation.
     *
     * - Parameters:
     *   - tag: The connected ISO 7816 tag.
     *   - CAN: The card access number printed on the card.
     *   - allowedCardTypes: required restriction on accepted card types. Use
     *     ``CardType/allCards`` to opt in to every supported card type.
     * - Throws: ``IdCardInternalError/cardNotSupported`` if the ATS is unknown, or the detected
     *   card type is not in `allowedCardTypes`.
     */
    @MainActor
    public func getCardCommands(
        _: NFCTagReaderSession,
        tag: NFCISO7816Tag,
        CAN: String,
        allowedCardTypes: Set<CardType> = CardType.estonianCards
    ) async throws -> CardCommands {
        if let historicalBytes = tag.historicalBytes {
            guard let detectedCardType = CardType(historicalBytes: historicalBytes),
                  allowedCardTypes.contains(detectedCardType) else {
                throw IdCardInternalError.cardNotSupported
            }
            let reader = try await CardReaderNFC(tag, CAN: CAN)
            switch detectedCardType {
            case .latviaIdemia: return LatviaIdemia(reader: reader)
            case .id1, .thales: return try await cardCommandsBySelectedAID(reader: reader, tag: tag)
            }
        }

        let reader = try await CardReaderNFC(tag, CAN: CAN)
        let commands = try await cardCommandsBySelectedAID(reader: reader, tag: tag)
        guard allowedCardTypes.contains(commands.cardType) else {
            throw IdCardInternalError.cardNotSupported
        }
        return commands
    }

    private func cardCommandsBySelectedAID(reader: CardReader, tag: NFCISO7816Tag) async throws -> CardCommands {
        guard let aid = Bytes(hex: tag.initialSelectedAID) else {
            throw IdCardInternalError.connectionFailed
        }

        // Try Idemia with explicit AID
        if let cmd = Idemia(reader: reader, aid: aid) {
            return cmd
        }
        // Try Thales with explicit AID
        if let cmd = Thales(reader: reader, aid: aid) {
            return cmd
        }
        // Try Idemia selecting AID
        if let cmd = await Idemia(reader: reader, selectAID: true) {
            return cmd
        }
        // Try Thales selecting AID
        if let cmd = await Thales(reader: reader, selectAID: true) {
            return cmd
        }

        throw IdCardInternalError.cardNotSupported
    }
}
