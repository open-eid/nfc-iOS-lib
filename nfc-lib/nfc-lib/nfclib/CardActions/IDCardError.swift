// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
         readerProcessFailed,
         failedToRemovePadding,
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
                .readerProcessFailed,
                .failedToRemovePadding,
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
