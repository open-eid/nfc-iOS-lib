public enum IdCardError: Error {
    case wrongCAN,
         wrongPIN(triesLeft: Int),
         invalidNewPIN,
         sessionError
}

enum IdCardInternalError: Error {
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
         sessionInvalidated
    
    func getIdCardError() -> IdCardError {
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
                .sessionInvalidated:
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

struct PinError: Error {
    let msg: String
    let remainingCount: Int
}
