//
//  OperationReadCertificate.swift
//  IdCardLib
//
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
    // TODO: Use a proper message that is localised
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
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

extension OperationReadCertificate: NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task { @MainActor in
            defer {
                self.session = nil
            }

            guard let certUsage else {
                continuation?.resume(throwing: ReadCertificateError.certificateUsageNotSpecified)
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                return
            }
            do {
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
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
                    session.alertMessage = "Andmed loetud"
                    session.invalidate()
                } catch {
                    session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                    continuation?.resume(throwing: ReadCertificateError.failedToReadCertificate)
                }
            } catch {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
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
