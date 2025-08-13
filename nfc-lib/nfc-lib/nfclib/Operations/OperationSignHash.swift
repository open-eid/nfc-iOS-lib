//
//  OperationSignHash.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 03.12.2023.
//

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt
import CryptoKit

class OperationSignHash: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var PIN: String = ""
    private var hashToSign: Data?
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    private var continuation: CheckedContinuation<Data, Error>?
    private var connection = NFCConnection()

    public func startSigning(CAN: String, PIN2: String, hash: Data) async throws -> Data {

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

extension OperationSignHash: NFCTagReaderSessionDelegate {
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
     
        Task {
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

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) { }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }
}
