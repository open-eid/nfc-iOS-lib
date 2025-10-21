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
import Security

public enum UnblockPINError: Error {
    case missingRequiredParameter
    case failed
    case general
}

@MainActor
public class OperationUnblockPin: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var codeType: CodeType?
    private var puk: SecureData?
    private var newPin: SecureData?
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    private let connection = NFCConnection()
    private var continuation: CheckedContinuation<Void, Error>?

    public func startReading(CAN: String, codeType: CodeType, puk: SecureData, newPin: SecureData) async throws {

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }

            self.CAN = CAN
            self.codeType = codeType
            self.puk = puk
            self.newPin = newPin
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationUnblockPin: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.session = nil
            }

            guard let codeType = self.codeType, let puk = self.puk, let newPin = self.newPin else {
                self.continuation?.resume(throwing: UnblockPINError.missingRequiredParameter)
                session.invalidate(errorMessage: "PINi vahetamine ebaõnnestus")
                return
            }
            do {
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
                let tag = try await self.connection.setup(session, tags: tags)
                let cardCommands = try await self.connection.getCardCommands(session, tag: tag, CAN: self.CAN)
                do {
                    try await cardCommands.unblockCode(codeType, puk: puk, newCode: newPin)
                } catch {
                    throw UnblockPINError.failed
                }

                self.continuation?.resume(with: .success(()))
                session.alertMessage = "PIN vahetatud"
                session.invalidate()
            } catch {
                session.invalidate(errorMessage: "PINi vahetamine ebaõnnestus")
                self.continuation?.resume(throwing: error)
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError _: Error) {
        self.session = nil
    }
}
