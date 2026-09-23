// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt
import CryptoKit

@MainActor
public class OperationSignHash: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var PIN: SecureData = SecureData([0x00])
    private var hashToSign: Data?
    private let nfcMessage: String = "Please place your ID card against the smart device"
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection = NFCConnection()

    public func startSigning(CAN: String, PIN2: SecureData, hash: Data) async throws -> Data {

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
            self.PIN = PIN2
            self.hashToSign = hash

            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: DispatchQueue.main)
            updateAlertMessage(step: 0)
            session?.begin()
        }
    }

    private func updateAlertMessage(step: Int) {
        let stepMessages = [
            "Please place your ID card against the smart device",
            "Hold your ID card against your smart device until the data is read",
            "Reading data please wait",
            "Signing in progress please wait"
        ]

        let stepMessage = stepMessages[min(step, stepMessages.count - 1)]
        let progressBar = ProgressBar(currentStep: step)
        var message = stepMessage
        message += "\n\n\(progressBar.generate())"
        session?.alertMessage = message
    }

    private func finish(_ result: Result<Data, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        PIN = SecureData([0x00])
        continuation.resume(with: result)
    }
}

extension OperationSignHash: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {

        Task { @MainActor in
            do {
                updateAlertMessage(step: 1)
                guard let hashToSign else {
                    throw IdCardInternalError.invalidAPDU
                }
                let pin2 = PIN
                let tag = try await connection.setup(session, tags: tags)
                updateAlertMessage(step: 2)
                let cardCommands = try await connection.getCardCommands(session, tag: tag, CAN: CAN)
                updateAlertMessage(step: 3)
                let signatureValue = try await cardCommands.calculateSignature(for: hashToSign, withPin2: pin2)
                finish(.success(signatureValue))
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
