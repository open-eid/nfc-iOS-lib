// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CoreNFC

@MainActor final public class OperationReadPublicData: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private let nfcMessage: String = "Please place your ID card against the smart device"
    private let connection = NFCConnection()
    private var continuation: CheckedContinuation<CardInfo, Error>?

    public func startReading(CAN: String) async throws -> CardInfo {
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }

            self.CAN = CAN
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationReadPublicData: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            do {
                session.alertMessage = "Hold your ID card against your smart device until the data is read"
                let tag = try await connection.setup(session, tags: tags)
                let cardCommands = try await connection.getCardCommands(session, tag: tag, CAN: CAN)
                let cardInfo = try await cardCommands.readPublicData()

                continuation?.resume(with: .success(cardInfo))
                session.alertMessage = "Data read"
                session.invalidate()
            } catch {
                session.invalidate(errorMessage: "Failed to read data")
                continuation?.resume(throwing: error)
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError _: Error) {
        self.session = nil
    }
}
