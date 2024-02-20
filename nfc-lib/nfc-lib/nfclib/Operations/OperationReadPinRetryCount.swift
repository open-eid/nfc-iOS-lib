//
//  OperationReadPinRetryCount.swift
//  nfclib
//
//  Created by Riivo Ehrlich on 15.02.2024.
//

import Foundation
import CoreNFC
import SwiftECC

class OperationReadPinRetryCount: NSObject {
    
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private var pinType: PinType?
    private var continuation: CheckedContinuation<Int, Error>?
    private let nfcMessage: String = "Palun asetage oma ID-kaart vastu nutiseadet."
    
    public func startReading(CAN: String, pinType: PinType) async throws -> Int {
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            
            guard NFCTagReaderSession.readingAvailable else {
                continuation.resume(throwing: IdCardInternalError.nfcNotSupported)
                return
            }
            
            self.CAN = CAN
            self.pinType = pinType
            
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationReadPinRetryCount: NFCTagReaderSessionDelegate {
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // no-op
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.session = nil
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            do {
                guard let safePinType = pinType else {
                    continuation?.resume(throwing: IdCardInternalError.invalidState)
                    return
                }
                
                session.alertMessage = "Hoidke ID-kaarti vastu nutiseadet kuni andmeid loetakse."
                let tag = try await NFCConnection().setup(session, tags: tags)
                if let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) {
                    let card = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))
                    try await card.selectMF(tag: tag)
                    if(safePinType == .pin2) {
                        try await card.selectQSCDAid(tag: tag)
                    }
                    let _ = try await card.sendWrapped(tag: tag, cls: 0x00, ins: 0x20, p1: 0x00, p2: safePinType.data, data: Data(), le: 256)
                } else {
                    continuation?.resume(throwing: IdCardInternalError.couldNotVerifyChipsMAC)
                }
            } catch let error as IdCardInternalError {
                if case .sendCommandFailed(message: let message) = error {
                    let pinError = NFCIdCard().getPinError(message)
                    guard let safePinError = pinError else {
                        continuation?.resume(throwing: IdCardInternalError.invalidState)
                        session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                        return
                    }
                    
                    switch pinError {
                    case .remainingPinRetryCount(let retryCount):
                        continuation?.resume(with: .success(retryCount))
                        session.alertMessage = "Andmed loetud"
                        session.invalidate()
                    default:
                        continuation?.resume(throwing: safePinError)
                        session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                    }
                } else {
                    continuation?.resume(throwing: error)
                    session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                }
            } catch {
                session.invalidate(errorMessage: "Andmete lugemine ebaõnnestus")
                continuation?.resume(throwing: error)
            }
        }
    }
}
