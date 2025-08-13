//
//  NFCConnection.swift
//  nfclib
//
//  Created by Timo Kallaste on 20.12.2023.
//

import Foundation
import CoreNFC
import BigInt
import CryptoTokenKit

class NFCConnection {
    func setup(_ session: NFCTagReaderSession, tags: [NFCTag]) async throws -> NFCISO7816Tag {
        if tags.count > 1 {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
            throw IdCardInternalError.multipleTagsDetected
        }

        guard let firstTag = tags.first,
              case let .iso7816(tag) = firstTag else {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
            throw(IdCardInternalError.invalidTag)
        }

        do {
            try await session.connect(to: firstTag)
        } catch {
            session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
        }
        return tag
    }

    func getCardCommands(_ session: NFCTagReaderSession, tag: NFCISO7816Tag, CAN: String) async throws -> CardCommands {
        let reader = try await CardReaderNFC(tag, CAN: CAN)
        guard let aid = Bytes(hex: tag.initialSelectedAID) else {
            throw IdCardInternalError.connectionFailed
        }
        guard let cardCommands: CardCommands = Idemia(reader: reader, aid: aid) ?? Thales(reader: reader, aid: aid) else {
            throw IdCardInternalError.cardNotSupported
        }
        return cardCommands
    }
}
