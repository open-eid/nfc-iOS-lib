// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import SwiftUI
import CryptoKit
import nfclib

struct ContentView: View {
    enum HashMethod: String, CaseIterable, Equatable {
        case sha254 = "SHA-256"
        case sha384 = "SHA-384"
    }

    @State private var viewModel = ViewModel()
    @State private var challenge: String = "fake_challenge"
    @State private var origin: String = "https://valimised.ee"
    @State private var dataToSign: String = "JÕEORG"
    @State private var can: String = ""
    @State private var pin1: SecureData = SecureData([0x00])
    @State private var pin2: SecureData = SecureData([0x00])
    @State private var puk: SecureData = SecureData([0x00])
    @State private var selectedMethod: HashMethod = .sha254
    @State private var allowLatvianCards: Bool = false
    let methods = HashMethod.allCases

    private var allowedCardTypes: Set<CardType> {
        allowLatvianCards ? CardType.allCards : CardType.estonianCards
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                VStack {
                    Text("challenge:")
                    TextField("challenge", text: $challenge)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                }
                .padding()
                VStack {
                    Text("origin:")
                    TextField("origin", text: $origin)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .padding()
                }
                codeTextField(placeholder: "CAN", text: $can)
                codeTextField(placeholder: "PIN1", text: $pin1)
                codeTextField(placeholder: "PIN2", text: $pin2)
                codeTextField(placeholder: "PUK", text: $puk)
                VStack {
                    Text("Data to sign (text)")
                    TextField("Data to sign", text: $dataToSign)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    VStack {
                        Picker("Hash Method", selection: $selectedMethod) {
                            ForEach(methods, id: \.self) {
                                Text($0.rawValue)
                            }
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        .onChange(of: selectedMethod) {
                            viewModel.computeHash(selectedMethod, dataToSign)
                        }
                        .onAppear {
                            viewModel.computeHash(selectedMethod, dataToSign)
                        }
                    }
                    Text(viewModel.hashedDataString ?? "")
                        .textSelection(.enabled)
                        .padding()
                    Text("Card info")
                        .font(.system(size: 30))
                    Text(viewModel.cardInfo?.formattedDescription ?? "")
                        .textSelection(.enabled)
                }
                .padding()
            }
            .padding()
            Toggle("Accept Latvian ID cards", isOn: $allowLatvianCards)
                .padding(.horizontal)

            Text("Available operations")
                .font(.system(size: 30))
            VStack(spacing: 40) {
                Button("Read Public Info") {
                    guard can.count >= 6 else {
                        return
                    }
                    Task {
                        await viewModel.readPublicInfo(can: can, allowedCardTypes: allowedCardTypes)
                    }
                }

                Button("Read Authentication Certificate") {
                    guard can.count >= 6 else {
                        return
                    }
                    Task {
                        await viewModel.readAuthenticationCertificate(can: can, allowedCardTypes: allowedCardTypes)
                    }
                }

                Button("Read Signing Certificate") {
                    guard can.count >= 6 else {
                        return
                    }
                    Task {
                        await viewModel.readSigningCertificate(can: can, allowedCardTypes: allowedCardTypes)
                    }
                }

                Button("Authenticate") {
                    guard can.count >= 6,
                          pin1.count >= 4,
                          !challenge.isEmpty,
                          !origin.isEmpty else {
                        return
                    }
                    Task {
                        await viewModel.authenticate(can: can, pin1: pin1, challenge: challenge, origin: origin, allowedCardTypes: allowedCardTypes)
                    }
                }

                Button("Sign") {
                    guard can.count >= 6,
                          pin2.count >= 5 else {
                        return
                    }
                    Task {
                        await viewModel.sign(can: can, pin2: pin2, allowedCardTypes: allowedCardTypes)
                    }
                }
                Button("Unblock PIN1") {
                    guard can.count >= 6,
                          puk.count >= 8,
                          pin1.count >= 4
                    else { return }
                    Task {
                        await viewModel.unblockPin1(can: can, puk: puk, newCode: pin1, allowedCardTypes: allowedCardTypes)
                    }
                }
                Button("Unblock PIN2") {
                    guard can.count >= 6,
                          puk.count >= 8,
                          pin2.count >= 5
                    else { return }
                    Task {
                        await viewModel.unblockPin2(can: can, puk: puk, newCode: pin2, allowedCardTypes: allowedCardTypes)
                    }
                }
            }
            .tint(.yellow)
            .padding()

            VStack(spacing: 20) {
                if let errorMessage = viewModel.errorMessage {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
                Text("Card data")
                Text(viewModel.cardInfo.map { "Card: \($0.cardType.rawValue)" } ?? "")
                Text(viewModel.cardInfo?.formattedDescription ?? "")
                    .textSelection(.enabled)
                Text("Web-eid data")
                Text(viewModel.webEidData?.formattedDescription ?? "")
                    .textSelection(.enabled)
            }
            .padding()

            Text("Certificates")
                .font(.system(size: 30))
            VStack(spacing: 20) {
                Text("Auth certificate:")
                Text(viewModel.authCert ?? "")
                    .textSelection(.enabled)
                Text("Signing certificate:")
                Text(viewModel.signingCert ?? "")
                    .textSelection(.enabled)
            }
            .padding()

            Text("Signing result")
                .font(.system(size: 30))
            Text(viewModel.signingResult ?? "")
                .textSelection(.enabled)
        }

    }

    private func codeTextField(placeholder: String, text: Binding<String>) -> some View {
        VStack {
            Text("\(placeholder):")
            TextField(placeholder, text: text)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .keyboardType(.numberPad)
                .padding()
        }
    }
    
    private func codeTextField(
        placeholder: String,
        text: Binding<SecureData>,
        useSecureField: Bool = true
    ) -> some View {
        let bridge = Binding<String>(
            get: {
                ""
            },
            set: { newValue in
                let bytes = Array(newValue.utf8)
                let newSecure = SecureData(bytes)
                text.wrappedValue.secureZero()
                text.wrappedValue = newSecure
            }
        )

        return VStack(alignment: .leading, spacing: 6) {
            Text("\(placeholder):")
            Group {
                if useSecureField {
                    SecureField(placeholder, text: bridge)
                } else {
                    TextField(placeholder, text: bridge)
                }
            }
            .textFieldStyle(.roundedBorder)
            .keyboardType(.numberPad)
            .textContentType(.oneTimeCode)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .padding(.vertical, 4)
        }
    }
}


extension ContentView {

    @MainActor @Observable class ViewModel {
        let cardOperator = Operator()
        var cardInfo: CardInfo?
        var webEidData: WebEidData?
        var authCert: String?
        var signingCert: String?
        var signingResult: String?
        var hashedData: Data?
        var hashedDataString: String?
        var errorMessage: String?

        private func report(_ error: Error) {
            guard let idCardError = error as? IdCardError else {
                errorMessage = "Failed: \(error)"
                return
            }
            switch idCardError {
            case .cardNotSupported: errorMessage = "Card not supported"
            case .wrongCAN: errorMessage = "Wrong CAN"
            case .wrongPIN(let codeType, let triesLeft):
                errorMessage = "Wrong \(codeType.name), \(triesLeft) tries left"
            case .invalidNewPIN: errorMessage = "New PIN rejected by the card"
            case .notActivated: errorMessage = "Card not activated"
            case .sessionError: errorMessage = "Session failed"
            }
        }

        func computeHash(_ selectedMethod: HashMethod, _ dataToHashString: String) {
            guard let dataToHash = dataToHashString.data(using: .utf8) else { return }
            var data: Data!
            switch selectedMethod {
                case .sha384:
                    data = SHA384.hash(data: dataToHash).data
                case .sha254:
                    data = SHA256.hash(data: dataToHash).data
            }

            hashedDataString = data.hexStr
            hashedData = data
        }

        func readPublicInfo(can: String, allowedCardTypes: Set<CardType>) async {
            errorMessage = nil
            do {
                let cardInfo = try await cardOperator.readPublicInfo(
                    CAN: can, allowedCardTypes: allowedCardTypes)
                self.cardInfo = cardInfo
            } catch {
                report(error)
            }
        }

        func readAuthenticationCertificate(can: String, allowedCardTypes: Set<CardType>) async {
            errorMessage = nil
            do {
                let cert = try await cardOperator.readAuthenticationCertificate(
                    CAN: can, allowedCardTypes: allowedCardTypes)
                guard let certSummary = SecCertificateCopySubjectSummary(cert) as? String else {
                    self.authCert = "Failed!"
                    return
                }
                self.authCert = "summary: \(certSummary)"
            } catch {
                report(error)
            }
        }

        func readSigningCertificate(can: String, allowedCardTypes: Set<CardType>) async {
            errorMessage = nil
            do {
                let cert = try await cardOperator.readSigningCertificate(
                    CAN: can, allowedCardTypes: allowedCardTypes)
                guard let certSummary = SecCertificateCopySubjectSummary(cert) as? String else {
                    self.signingCert = "Failed!"
                    return
                }
                self.signingCert = "summary: \(certSummary)"
            } catch {
                report(error)
            }
        }

        func sign(can: String, pin2: SecureData, allowedCardTypes: Set<CardType>) async {
            guard let data = hashedData else { return }
            errorMessage = nil
            do {
                let signResult = try await cardOperator.sign(
                    CAN: can, hash: data, pin2: pin2, allowedCardTypes: allowedCardTypes)
                self.signingResult = signResult.hexStr
            } catch {
                report(error)
            }
        }

        func authenticate(can: String, pin1: SecureData, challenge: String, origin: String, allowedCardTypes: Set<CardType>) async {
            errorMessage = nil
            do {
                let webEidResult = try await cardOperator.loadWebEIDAuthenticationData(
                    CAN: can, pin1: pin1, challenge: challenge, origin: origin,
                    allowedCardTypes: allowedCardTypes)
                self.webEidData = webEidResult
            } catch {
                report(error)
            }
        }

        func unblockPin1(can: String, puk: SecureData, newCode: SecureData, allowedCardTypes: Set<CardType>) async {
            errorMessage = nil
            do {
                try await cardOperator.unblockPin1(
                    CAN: can, puk: puk, newCode: newCode, allowedCardTypes: allowedCardTypes)
            } catch {
                report(error)
            }
        }

        func unblockPin2(can: String, puk: SecureData, newCode: SecureData, allowedCardTypes: Set<CardType>) async {
            errorMessage = nil
            do {
                try await cardOperator.unblockPin2(
                    CAN: can, puk: puk, newCode: newCode, allowedCardTypes: allowedCardTypes)
            } catch {
                report(error)
            }
        }
    }
}

extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}

extension Data {
    static let hexAlphabet = Array("0123456789abcdef".unicodeScalars)
    var hexStr: String {
        String(reduce(into: "".unicodeScalars) { result, value in
            result.append(Self.hexAlphabet[Int(value / 0x10)])
            result.append(Self.hexAlphabet[Int(value % 0x10)])
        })
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
