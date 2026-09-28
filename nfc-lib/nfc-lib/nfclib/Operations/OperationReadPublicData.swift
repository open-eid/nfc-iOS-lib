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
import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt

@MainActor final public class OperationReadPublicData: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private let nfcMessage: String = "Please place your ID card against the smart device"
    private let connection = NFCConnection()
    private var continuation: CheckedContinuation<CardInfo, Error>?

    public func startReading(CAN: String) async throws -> CardInfo {
        return try await withCheckedThrowingContinuation { continuation in
            guard self.continuation == nil else {
                continuation.resume(throwing: IdCardInternalError.operationInProgress)
                return
            }
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                self.finish(.failure(IdCardInternalError.nfcNotSupported))
                return
            }

            self.CAN = CAN
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: DispatchQueue.main)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }

    private func finish(_ result: Result<CardInfo, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(with: result)
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

                finish(.success(cardInfo))
                session.alertMessage = "Data read"
                session.invalidate()
            } catch {
                finish(.failure(error))
                session.invalidate(errorMessage: "Failed to read data")
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        guard session === self.session else { return }
        self.session = nil
        finish(.failure(IdCardInternalError.mapSessionInvalidation(error)))
    }
}
