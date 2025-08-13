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

public enum ReadCertificateError: Error {
    case certificateUsageNotSpecified
    case failedToReadCertificate
    case general
}

enum CertificateUsage {
    case auth
    case sign
}

class OperationReadCertificate: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var certUsage: CertificateUsage!
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
            // TODO: Use a proper message that is localised
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationReadCertificate: NFCTagReaderSessionDelegate {
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
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
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) { }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }
}
