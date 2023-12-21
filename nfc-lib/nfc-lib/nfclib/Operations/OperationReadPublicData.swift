//
//  OperationReadPublicData.swift
//  nfc-lib
//
//  Created by Timo Kallaste on 30.11.2023.
//

import Foundation
import CoreNFC
import CommonCrypto
import CryptoTokenKit
import SwiftECC
import BigInt

enum ReadPublicDataError: Error {
    case general
}

class OperationReadPublicData: NSObject {
    private var session: NFCTagReaderSession?
    private var CAN: String = ""
    private let nfcMessage: String = "Put card against phone"
    private let connection = NFCConnection()
    private var continuation: CheckedContinuation<CardInfo, Error>?

    public func startReading(CAN: String) async throws -> CardInfo {
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            guard NFCTagReaderSession.readingAvailable else {
                // TODO: Handle this case properly
                continuation.resume(throwing: TagReadingError.nfcNotSupported)
                return
            }

            self.CAN = CAN
            session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
            session?.alertMessage = nfcMessage
            session?.begin()
        }
    }
}

extension OperationReadPublicData: NFCTagReaderSessionDelegate {
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Task {
            do {
                session.alertMessage = "Authenticating with card."
                let tag = try await connection.setup(session, tags: tags)
                if let (ksEnc, ksMac) = try await OperationAuthenticate().mutualAuthenticate(tag: tag, CAN: CAN) {
                    print("Mutual authentication successfull")
                    let card = NFCIdCard(ksEnc: ksEnc, ksMac: ksMac, SSC: Bytes(repeating: 0x00, count: AES.BlockSize))
                    session.alertMessage = "Selecting File"
                    try await card.selectDF(tag: tag, file: Data()) // Select MF (Master File)
                    try await card.selectDF(tag: tag, file: Data([0x50, 0x00])) // Select DF 5000
                    print("DF 5000 selected")
                    session.alertMessage = "Reading Data"
                    do {
                        let givenName = try await card.read(field: .firstName, tag: tag)
                        let surname = try await card.read(field: .surname, tag: tag)
                        let personalCode = try await card.read(field: .personalCode, tag: tag)
                        let citizenship = try await card.read(field: .citizenship, tag: tag)
                        let dateOfExpiry = try await card.read(field: .dateOfExpiry, tag: tag)

                        let cardInfo = CardInfo(givenName: givenName,
                                                surname: surname,
                                                personalCode: personalCode,
                                                citizenship: citizenship,
                                                dateOfExpiry: dateOfExpiry)
                        continuation?.resume(with: .success(cardInfo))
                        session.invalidate()
                    } catch {
                        continuation?.resume(throwing: error)
                    }
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
