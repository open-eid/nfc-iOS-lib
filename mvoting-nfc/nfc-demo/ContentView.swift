//
//  ContentView.swift
//  mvoting-nfc
//
//  Created by Timo Kallaste on 07.11.2023.
//

import SwiftUI
import CryptoKit
import nfclib

struct ContentView: View {
    enum HashMethod: String, CaseIterable, Equatable {
        case sha254 = "SHA-256"
        case sha384 = "SHA-384"
    }

    @StateObject private var viewModel = ViewModel()
    @State private var can: String = "566195"
    @State private var challenge: String = "fake_challenge"
    @State private var origin: String = "https://valimised.ee"
    @State private var dataToSign: String = "JÕEORG"
    @State private var pin1: String = ""
    @State private var pin2: String = ""
    @State private var selectedMethod: HashMethod = .sha254
    let methods = HashMethod.allCases

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
                VStack {
                    Text("CAN:")
                    TextField("CAN", text: $can)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .padding()
                }
                VStack {
                    Text("PIN1:")
                    SecureField("PIN1", text: $pin1)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .padding()
                }
                VStack {
                    Text("PIN2:")
                    SecureField("PIN2", text: $pin2)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .padding()
                }
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
                        .onChange(of: selectedMethod, perform: { value in
                            viewModel.computeHash(selectedMethod, dataToSign)
                        })
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
            Text("Available operations")
                .font(.system(size: 30))
            VStack(spacing: 40) {
                Button("Read Public Info") {
                    guard can.count >= 6 else {
                        return
                    }
                    Task {
                        await viewModel.readPublicInfo(can: can)
                    }
                }

                Button("Read Authentication Certificate") {
                    guard can.count >= 6 else {
                        return
                    }
                    Task {
                        await viewModel.readAuthenticationCertificate(can: can)
                    }
                }

                Button("Read Signing Certificate") {
                    guard can.count >= 6 else {
                        return
                    }
                    Task {
                        await viewModel.readSigningCertificate(can: can)
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
                        await viewModel.authenticate(can: can, pin1: pin1, challenge: challenge, origin: origin)
                    }
                }

                Button("Sign") {
                    guard can.count >= 6,
                          pin2.count >= 5 else {
                        return
                    }
                    Task {
                        await viewModel.sign(can: can, pin2: pin2)
                    }
                }
            }
            .tint(.yellow)
            .padding()

            VStack(spacing: 20) {
                Text("Card data")
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
}

extension ContentView {

    @MainActor class ViewModel: ObservableObject {
        let cardOperator = Operator()
        @Published var cardInfo: CardInfo?
        @Published var webEidData: WebEidData?
        @Published var authCert: String?
        @Published var signingCert: String?
        @Published var signingResult: String?
        @Published var hashedData: Data?
        @Published var hashedDataString: String?

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

        func readPublicInfo(can: String) async {
            do {
                let cardInfo = try await cardOperator.readPublicInfo(CAN: can)
                self.cardInfo = cardInfo

            } catch {

            }
        }

        func readAuthenticationCertificate(can: String) async {
            do {
                let cert = try await cardOperator.readAuthenticationCertificate(CAN: can)
                guard let certSummary = SecCertificateCopySubjectSummary(cert) as? String else {
                    self.authCert = "Failed!"
                    return
                }
                self.authCert = "summary: \(certSummary)"
            } catch {
                // Handle error here
            }
        }

        func readSigningCertificate(can: String) async {
            do {
                let cert = try await cardOperator.readAuthenticationCertificate(CAN: can)
                guard let certSummary = SecCertificateCopySubjectSummary(cert) as? String else {
                    self.signingCert = "Failed!"
                    return
                }
                self.authCert = "summary: \(certSummary)"
            } catch {
                // Handle error here
            }
        }

        func sign(can: String, pin2: String) async {
            guard let data = hashedData else { return }
            do {
                let signResult = try await cardOperator.sign(CAN: can, hash: data, pin2: pin2)
                let stringResult = signResult.hexStr
                self.signingResult = stringResult
            } catch {
                // Handle error here
            }
        }

        func authenticate(can: String, pin1: String, challenge: String, origin: String) async {
            do {
                let webEidResult = try await cardOperator.loadWebEIDAuthenticationData(CAN: can, pin1: pin1, challenge: challenge, origin: origin)
                self.webEidData = webEidResult
            } catch {
                // Handle error here
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
