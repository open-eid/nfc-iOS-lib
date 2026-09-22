// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CoreNFC

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
    private let nfcMessage: String = "Please place your ID card against the smart device"
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
                session.invalidate(errorMessage: "PIN change failed")
                return
            }
            do {
                session.alertMessage = "Hold your ID card against your smart device until the data is read"
                let tag = try await self.connection.setup(session, tags: tags)
                let cardCommands = try await self.connection.getCardCommands(session, tag: tag, CAN: self.CAN)
                do {
                    try await cardCommands.unblockCode(codeType, puk: puk, newCode: newPin)
                } catch {
                    throw UnblockPINError.failed
                }

                self.continuation?.resume(with: .success(()))
                session.alertMessage = "PIN changed"
                session.invalidate()
            } catch {
                session.invalidate(errorMessage: "PIN change failed")
                self.continuation?.resume(throwing: error)
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError _: Error) {
        self.session = nil
    }
}
