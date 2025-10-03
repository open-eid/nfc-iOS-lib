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

public enum IdCardError: Error {
    case wrongCAN,
         wrongPIN(triesLeft: Int),
         invalidNewPIN,
         sessionError
}

public enum IdCardInternalError: Error {
    case missingRESTag,
         missingMACTag,
         invalidMACValue,
         failedReadingField(CardField),
         hexConversionFailed,
         AESCBCError,
         sendCommandFailed(message: String),
         invalidResponse(message: String),
         swError(UInt16),
         pinVerificationFailed,
         remainingPinRetryCount(Int),
         invalidNewPin,
         notSupportedCodeType,
         dataPaddingError,
         invalidAPDU,
         authenticationFailed,
         canAuthenticationFailed,
         invalidTag,
         cardNotSupported,
         nfcNotSupported,
         connectionFailed,
         multipleTagsDetected,
         couldNotVerifyChipsMAC,
         cancelledByUser,
         sessionInvalidated,
         notSupportedAlgorithm

    public func getIdCardError() -> IdCardError {
        switch self {
        case .missingRESTag,
                .missingMACTag,
                .invalidMACValue,
                .failedReadingField,
                .hexConversionFailed,
                .AESCBCError,
                .sendCommandFailed,
                .dataPaddingError,
                .invalidAPDU,
                .invalidResponse,
                .swError,
                .notSupportedCodeType,
                .authenticationFailed,
                .invalidTag,
                .cardNotSupported,
                .nfcNotSupported,
                .connectionFailed,
                .multipleTagsDetected,
                .couldNotVerifyChipsMAC,
                .cancelledByUser,
                .sessionInvalidated,
                .notSupportedAlgorithm:
            return .sessionError
        case .canAuthenticationFailed:
            return .wrongCAN
        case .pinVerificationFailed:
            return .wrongPIN(triesLeft: 0)
        case .remainingPinRetryCount(let value):
            return .wrongPIN(triesLeft: value)
        case .invalidNewPin:
            return .invalidNewPIN
        }
    }
}

public struct PinError: Error {
    let msg: String
    let remainingCount: Int
}
