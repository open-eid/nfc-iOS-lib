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
import CryptoKit

@MainActor
public class OperationSignHash: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var PIN: SecureData = SecureData([0x00])
    private var hashToSign: Data?
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection = NFCConnection()

    public func startSigning(CAN: String, PIN2: SecureData, hash: Data) async throws -> Data {

        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }
            self.CAN = CAN
            self.PIN = PIN2
            self.hashToSign = hash

            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            updateAlertMessage(step: 0)
            session?.begin()
        }
    }

    private func updateAlertMessage(step: Int) {
        let stepMessages = [
            "Palun asetage oma ID-kaart vastu nutiseadet.",
            "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse.",
            "Andmete lugemine käib, palun oodake.",
            "Signeerimine käib, palun oodake."
        ]

        let stepMessage = stepMessages[min(step, stepMessages.count - 1)]
        let progressBar = ProgressBar(currentStep: step)
        var message = stepMessage
        message += "\n\n\(progressBar.generate())"
        session?.alertMessage = message
    }
}

extension OperationSignHash: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {

        Task { @MainActor in
            do {
                updateAlertMessage(step: 1)
                guard let hashToSign else {
                    return
                }
                let tag = try await connection.setup(session, tags: tags)
                updateAlertMessage(step: 2)
                let cardCommands = try await connection.getCardCommands(session, tag: tag, CAN: CAN)
                updateAlertMessage(step: 3)
                let signatureValue = try await cardCommands.calculateSignature(for: hashToSign, withPin2: PIN)
                continuation?.resume(with: .success(signatureValue))
                session.alertMessage = "Andmed loetud"
                session.invalidate()
            } catch {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                continuation?.resume(throwing: error)
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError _: Error) {
        self.session = nil
    }
}
