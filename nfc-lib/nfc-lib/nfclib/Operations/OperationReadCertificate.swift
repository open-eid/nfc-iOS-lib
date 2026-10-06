// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
internal import SwiftECC
import BigInt
import Security

// MARK: - Local Types

public enum ReadCertificateError: Error {
    case certificateUsageNotSpecified
    case failedToReadCertificate
    case general
}

public enum CertificateUsage {
    case auth
    case sign
}

// Allow CoreNFC types to cross async boundaries in this controlled context
extension NFCTagReaderSession: @unchecked @retroactive Sendable {}
extension NFCTag: @unchecked @retroactive Sendable {}

@MainActor
public class OperationReadCertificate: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var certUsage: CertificateUsage!
    private let nfcMessage: String = "Please place your ID card against the smart device"
    private let connection = NFCConnection()
    private var continuation: CheckedContinuation<SecCertificate, Error>?

    public func startReading(CAN: String, certUsage: CertificateUsage) async throws -> SecCertificate {

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
            self.certUsage = certUsage
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: DispatchQueue.main)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }

    private func finish(_ result: Result<SecCertificate, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(with: result)
    }
}

extension OperationReadCertificate: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor in
            guard let certUsage else {
                finish(.failure(ReadCertificateError.certificateUsageNotSpecified))
                session.invalidate(errorMessage: "Failed to read data")
                return
            }
            do {
                session.alertMessage = "Hold your ID card against your smart device until the data is read"
                let tag = try await connection.setup(session, tags: tags)
                let cardCommands = try await connection.getCardCommands(session, tag: tag, CAN: CAN)
                do {
                    switch certUsage {
                    case .auth:
                        let cert = try await cardCommands.readAuthenticationCertificate()
                        let x509Certificate = try convertBytesToX509Certificate(cert)
                        finish(.success(x509Certificate))
                    case .sign:
                        let cert = try await cardCommands.readSignatureCertificate()
                        let x509Certificate = try convertBytesToX509Certificate(cert)
                        finish(.success(x509Certificate))
                    }
                    session.alertMessage = "Data read"
                    session.invalidate()
                } catch {
                    finish(.failure(ReadCertificateError.failedToReadCertificate))
                    session.invalidate(errorMessage: "Failed to read data")
                }
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
