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
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    private var continuation: CheckedContinuation<SecCertificate, Error>?
    
    public func startReading(CAN: String, certUsage: CertificateUsage) async throws -> SecCertificate {
        
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                // TODO: Handle this case properly
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
            
            guard let checkedUsage = self.certUsage else {
                continuation?.resume(throwing: ReadCertificateError.certificateUsageNotSpecified)
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                return
            }
            do {
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
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
                    session.alertMessage = "Andmed loetud"
                    session.invalidate()
                } else {
                    continuation?.resume(throwing: IdCardInternalError.couldNotVerifyChipsMAC)
                }
            } catch {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                continuation?.resume(throwing: error)
            }
        }
    }
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // TODO: Anyhing we want to do here?
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }
}
