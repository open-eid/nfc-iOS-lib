//
//  OperationReadCertificate.swift
//  nfc-lib
//
//  Created by Riivo Ehrlich on 07.12.2023.
//

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

class OperationUnblockPin: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var codeType: CodeType?
    private var puk: String?
    private var newPin: String?
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    private let connection = NFCConnection()
    private var continuation: CheckedContinuation<Void, Error>?

    public func startReading(CAN: String, codeType: CodeType, puk: String, newPin: String) async throws -> Void {

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

extension OperationUnblockPin: NFCTagReaderSessionDelegate {
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            defer {
                self.session = nil
            }

            guard let codeType, let puk, let newPin else {
                continuation?.resume(throwing: UnblockPINError.missingRequiredParameter)
                session.invalidate(errorMessage: "PINi vahetamine ebaõnnestus")
                return
            }
            do {
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
                let tag = try await connection.setup(session, tags: tags)
                let cardCommands = try await connection.getCardCommands(session, tag: tag, CAN: CAN)
                do {
                    try await cardCommands.unblockCode(codeType, puk: puk, newCode: newPin)
                } catch {
                    throw UnblockPINError.failed
                }

                continuation?.resume(with: .success(()))
                session.alertMessage = "PIN vahetatud"
                session.invalidate()
            } catch {
                session.invalidate(errorMessage: "PINi vahetamine ebaõnnestus")
                continuation?.resume(throwing: error)
            }
        }
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) { }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }
}

