// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

@MainActor
public class OperationSignHash {
    public init() {}

    public func startSigning(CAN: String, PIN2: SecureData, hash: Data) async throws -> Data {
        try await NFCConnection.run { connection in
            let cardCommands = try await connection.connect(
                CAN: CAN,
                message: alertMessage(step: 0),
                detectedMessage: alertMessage(step: 2)
            )
            connection.message(alertMessage(step: 3))
            try Task.checkCancellation()
            return try await cardCommands.calculateSignature(for: hash, withPin2: PIN2)
        }
    }

    private func alertMessage(step: Int) -> String {
        let stepMessages = [
            "Please place your ID card against the smart device",
            "Hold your ID card against your smart device until the data is read",
            "Reading data please wait",
            "Signing in progress please wait"
        ]

        let stepMessage = stepMessages[min(step, stepMessages.count - 1)]
        let progressBar = ProgressBar(currentStep: step)
        return "\(stepMessage)\n\n\(progressBar.generate())"
    }
}
