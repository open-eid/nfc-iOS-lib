// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

public enum UnblockPINError: Error {
    case missingRequiredParameter
    case general
}

@MainActor
public class OperationUnblockPin {
    public init() {}

    public func startReading(CAN: String, codeType: CodeType, puk: SecureData, newPin: SecureData) async throws {
        try await NFCConnection.run(successMessage: "PIN changed", onError: { (error: $0, message: "PIN change failed") }) { connection in
            let cardCommands = try await connection.connect(
                CAN: CAN,
                message: "Please place your ID card against the smart device",
                detectedMessage: "Hold your ID card against your smart device until the data is read"
            )
            try Task.checkCancellation()
            try await cardCommands.unblockCode(codeType, puk: puk, newCode: newPin)
        }
    }
}
