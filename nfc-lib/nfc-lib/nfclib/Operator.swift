/*
 * Copyright 2017 - 2023 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import Foundation
import Security
import CoreNFC

public struct SignResult {
    public let signedData: Data
    public let signingCertificate: Data
}

public struct Operator {
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
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
    
    public func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .auth)
            return cert
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }

    public func readSigningCertificate(CAN: String) async throws -> SecCertificate {
        do {
            let cert = try await OperationReadCertificate().startReading(CAN: CAN, certUsage: .sign)
            return cert
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }

    public func loadWebEIDAuthenticationData(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData {
        do {
            let webEidData = try await OperationAuthenticateWithWebEID(CAN: CAN, pin1: pin1, challenge: challenge, origin: origin).startReading()
            return webEidData
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
    
    public func sign(CAN: String, hash: Data, pin2: String) async throws -> Data {
        do {
            let signature = try await OperationSignHash().startSigning(CAN: CAN, PIN2: pin2, hash: hash)
            return signature
        } catch {
            guard let e = error as? IdCardInternalError else {
                throw IdCardError.sessionError
            }
            throw e.getIdCardError()
        }
    }
}
