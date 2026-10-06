// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

struct ProgressBar {
    private let totalSteps: Int
    private let currentStep: Int

    init(currentStep: Int, totalSteps: Int = 4) {
        self.currentStep = currentStep
        self.totalSteps = totalSteps
    }

    func generate() -> String {
        if currentStep > 0 {
            return (0..<totalSteps).map { $0 < currentStep ? "🔵" : "⚪️" }.joined(separator: " ")
        } else {
            return ""
        }
    }
}
