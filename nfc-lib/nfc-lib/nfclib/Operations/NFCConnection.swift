// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
@preconcurrency import CoreNFC
import BigInt
import CryptoTokenKit

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
            try await session.connect(to: firstTag)
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

    @MainActor
    public func getCardCommands(_: NFCTagReaderSession, tag: NFCISO7816Tag, CAN: String) async throws -> CardCommands {
        let initialSelectedAID = tag.initialSelectedAID
        let reader = try await CardReaderNFC(tag, CAN: CAN)
        guard let aid = Bytes(hex: initialSelectedAID) else {
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

