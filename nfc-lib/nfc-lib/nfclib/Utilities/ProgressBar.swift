//
//  ProgressBar.swift
//  nfclib
//
//  Created by Kevin Mihkelson on 05.12.2024.
//

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
