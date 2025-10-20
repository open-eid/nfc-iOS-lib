//
//  NFCConnection.swift
//  IdCardLib
//
/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import Foundation
@preconcurrency import CoreNFC
import BigInt
import CryptoTokenKit

@MainActor
public class NFCConnection {
    func setup(_ session: NFCTagReaderSession, tags: [NFCTag]) async throws -> NFCISO7816Tag {
        if tags.count > 1 {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
            throw IdCardInternalError.multipleTagsDetected
        }

        guard let firstTag = tags.first else {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
            throw IdCardInternalError.invalidTag
        }

        do {
            try await session.connect(to: firstTag)
        } catch {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
            throw IdCardInternalError.connectionFailed
        }

        guard case let .iso7816(tag) = firstTag else {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
            throw IdCardInternalError.invalidTag
        }

        return tag
    }

    @MainActor
    func getCardCommands(_: NFCTagReaderSession, tag: NFCISO7816Tag, CAN: String) async throws -> CardCommands {
        let initialSelectedAID = tag.initialSelectedAID
        let reader = try await CardReaderNFC(tag, CAN: CAN)
        guard let aid = Bytes(hex: initialSelectedAID) else {
            throw IdCardInternalError.connectionFailed
        }
        guard let cardCommands: CardCommands = Idemia(
            reader: reader,
            aid: aid
        ) ?? Thales(
            reader: reader,
            aid: aid
        ) else {
            throw IdCardInternalError.cardNotSupported
        }
        return cardCommands
    }
}
