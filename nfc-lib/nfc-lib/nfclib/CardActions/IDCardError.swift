// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import CoreNFC

public enum IdCardError: Error {
    case wrongCAN,
         wrongPIN(codeType: CodeType, triesLeft: Int),
         invalidNewPIN,
         sessionError,
         notActivated
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
         pinVerificationFailed(codeType: CodeType),
         remainingPinRetryCount(codeType: CodeType, count: Int),
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
         readerProcessFailed,
         failedToRemovePadding,
         notSupportedAlgorithm,
         operationInProgress,
         notActivated

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
                .readerProcessFailed,
                .failedToRemovePadding,
                .notSupportedAlgorithm,
                .operationInProgress:
            return .sessionError
        case .notActivated:
            return .notActivated
        case .canAuthenticationFailed:
            return .wrongCAN
        case .pinVerificationFailed(let codeType):
            return .wrongPIN(codeType: codeType, triesLeft: 0)
        case .remainingPinRetryCount(let codeType, let count):
            return .wrongPIN(codeType: codeType, triesLeft: count)
        case .invalidNewPin:
            return .invalidNewPIN
        }
    }
}

extension IdCardInternalError {
    static func mapSessionInvalidation(_ error: Error) -> Error {
        guard let readerError = error as? NFCReaderError else { return error }
        switch readerError.code {
        case .readerSessionInvalidationErrorUserCanceled:
            return IdCardInternalError.cancelledByUser
        case .readerSessionInvalidationErrorSessionTimeout:
            return IdCardInternalError.sessionInvalidated
        default:
            return error
        }
    }
}
