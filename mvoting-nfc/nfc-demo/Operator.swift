// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import nfclib
import Foundation
import Security
import CoreNFC

public struct SignResult: Sendable {
    public let signedData: Data
    public let signingCertificate: Data
}

public struct Operator: Sendable {
    public init() {}
}

extension Operator: CardOperations {
    public func isNFCSupported() -> Bool {
        NFCTagReaderSession.readingAvailable
    }
    
    public func readPublicInfo(CAN: String) async throws -> CardInfo {
        do {
            let result = try await OperationReadPublicData().startReading(CAN: CAN)
            return result
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }
    
    public func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .auth)
            return cert
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }

    public func readSigningCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .sign)
            return cert
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }

    public func loadWebEIDAuthenticationData(CAN: String, pin1: SecureData, challenge: String, origin: String) async throws -> WebEidData {
        do {
            let webEidData = try await OperationAuthenticateWithWebEID().startReading(CAN: CAN, pin1: pin1, challenge: challenge, origin: origin)
            return webEidData
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }
    
    public func sign(CAN: String, hash: Data, pin2: SecureData) async throws -> Data {
        do {
            let signature = try await OperationSignHash().startSigning(CAN: CAN, PIN2: pin2, hash: hash)
            return signature
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }

    public func unblockPin1(CAN: String, puk: SecureData, newCode: SecureData) async throws {
        do {
            try await OperationUnblockPin().startReading(CAN: CAN, codeType: .pin1, puk: puk, newPin: newCode)
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }

    public func unblockPin2(CAN: String, puk: SecureData, newCode: SecureData) async throws {
        do {
            try await OperationUnblockPin().startReading(CAN: CAN, codeType: .pin2, puk: puk, newPin: newCode)
        } catch let error as IdCardInternalError {
            throw error.getIdCardError()
        } catch {
            throw IdCardError.sessionError
        }
    }
}
