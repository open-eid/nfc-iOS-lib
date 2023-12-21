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

public enum TagReadingError: Error {
    case invalidTag
    case nfcNotSupported
    case connectionFailed
    case multipleTagsDetected
    case couldNotVerifyChipsMAC
    case cancelledByUser
    case sessionInvalidated
}

class NFCConnection {
    func setup(_ session: NFCTagReaderSession, tags: [NFCTag]) async throws -> NFCISO7816Tag {
        if tags.count > 1 {
            session.invalidate(errorMessage: "More than 1 tag is detected, please remove all tags and try again.")
            throw TagReadingError.multipleTagsDetected
        }

        guard let firstTag = tags.first,
              case let .iso7816(tag) = firstTag else {
            session.invalidate(errorMessage: "Invalid tag.")
            throw(TagReadingError.invalidTag)
        }

        do {
            try await session.connect(to: firstTag)
        } catch {
            session.invalidate(errorMessage: "Unable to connect to tag.")
        }
        return tag
    }
}
