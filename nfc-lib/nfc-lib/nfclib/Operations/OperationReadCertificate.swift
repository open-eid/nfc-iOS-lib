// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation
import CoreNFC
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
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }

            self.CAN = CAN
            self.certUsage = certUsage
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationReadCertificate: @MainActor NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor in
            defer {
                self.session = nil
            }

            guard let certUsage else {
                continuation?.resume(throwing: ReadCertificateError.certificateUsageNotSpecified)
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
                        continuation?.resume(with: .success(x509Certificate))
                    case .sign:
                        let cert = try await cardCommands.readSignatureCertificate()
                        let x509Certificate = try convertBytesToX509Certificate(cert)
                        continuation?.resume(with: .success(x509Certificate))
                    }
                    session.alertMessage = "Data read"
                    session.invalidate()
                } catch {
                    session.invalidate(errorMessage: "Failed to read data")
                    continuation?.resume(throwing: ReadCertificateError.failedToReadCertificate)
                }
            } catch {
                session.invalidate(errorMessage: "Failed to read data")
                continuation?.resume(throwing: error)
            }
        }
    }

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) { }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError _: Error) {
        Task { @MainActor in
            self.session = nil
        }
    }
}
