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
import SwiftECC
import BigInt
import Security

public enum ReadCertificateError: Error {
    case certificateUsageNotSpecified
    case failedToReadCertificate
    case general
}

class OperationReadCertificate: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var certUsage: CertificateUsage!
    private let nfcMessage: String = "Put card against phone"
    private var continuation: CheckedContinuation<SecCertificate, Error>?
    
    public func startReading(CAN: String, certUsage: CertificateUsage) async throws -> SecCertificate {
        
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                // TODO: Handle this case properly
                continuation.resume(throwing: TagReadingError.nfcNotSupported)
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
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            defer {
                self.session = nil
            }
            
            guard let checkedUsage = self.certUsage else {
                continuation?.resume(throwing: ReadCertificateError.certificateUsageNotSpecified)
                session.invalidate(errorMessage: "Certificate usage not specified")
                return
            }
            do {
                session.alertMessage = "Authenticating with card."
                let tag = try await NFCConnection().setup(session, tags: tags)
                if let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) {
                    let idCard = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))
                    do {
                        let certBytes = try await idCard.readCert(tag: tag, usage: checkedUsage)
                        let x509Certificate = try convertBytesToX509Certificate(certBytes)
                        continuation?.resume(with: .success(x509Certificate))
                    } catch {
                        continuation?.resume(throwing: ReadCertificateError.failedToReadCertificate)
                    }
                    // Done with the session, invalidate
                    session.invalidate()
                } else {
                    continuation?.resume(throwing: TagReadingError.couldNotVerifyChipsMAC)
                }
            } catch {
                session.invalidate(errorMessage: "Failed to authenticate with card.")
                continuation?.resume(throwing: error)
            }
        }
    }
    
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // TODO: Anyhing we want to do here?
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let readerError = error as? NFCReaderError,
           readerError.code == .readerSessionInvalidationErrorUserCanceled {
            continuation?.resume(throwing: TagReadingError.cancelledByUser)
        } else {
            continuation?.resume(throwing: TagReadingError.sessionInvalidated)
        }
        self.session = nil
    }
}
