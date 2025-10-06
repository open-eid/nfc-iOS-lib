- [Overview](#overview)  
- [Demo Application Run Guide](#demo-application-run-guide)  
- [Integration Guide](#integration-guide)  
  - [Application Requirements](#application-requirements)  
    - [Enable NFC Capability](#enable-nfc-capability)  
    - [Update Info.plist](#update-infoplist)  
    - [Build the Library](#build-the-library)  
    - [Add the Library to the Application](#add-the-library-to-the-application)  
- [Library Interfaces for ID Card Communication](#library-interfaces-for-id-card-communication)  

# Overview

The NFC-ID library provides functionality to use ID card authentication and digital signing over the NFC interface. Two platform-specific versions of the library are available – one for Android and one for iOS.  

The NFC-ID library is not intended for public use. It is a low-level technical library that delegates user interaction to the application itself. In the long term, it is not safe to allow end users to enter their ID card PIN codes directly into every mobile app. For secure ID card interaction, a trusted user interface, and additional required features, a dedicated mobile application must be developed in the future. Such a solution would also allow faster updates to the application and enable quick adjustments of countermeasures in case of attacks.  

The NFC-ID library was originally developed within the m-valimiste project, based on the need to use the ID card inside the m-Voting client application.  

# Demo Application Run Guide
- Open **mvtng-nfc-demo.xcworkspace**. This workspace includes both the demo app and the `nfclib` library.  
- Wait until **Swift Package Manager** dependencies are fully downloaded.  
- Select **Product → Run**.  

⚠️ The simulator is not supported, since it does not provide NFC functionality.  

# Integration Guide

## Application Requirements
### Enable NFC Capability
You must configure your Xcode project to request NFC capability access:

- In the project navigator, select your project.  
- Select your app target, then go to the **Signing & Capabilities** tab.  
- Click **+ Capability**.  
- Search for **Near Field Communication Tag Reading** and add it to your project.  

### Update Info.plist
You must declare NFC usage in your **Info.plist** file to explain why the application requires access to this technology.

- Open your **Info.plist** file.  
- Add a new key: **Privacy – NFC Scan Usage Description** (`NFCReaderUsageDescription`).  
- Set its value to a string explaining why the app requires NFC access. This text will be displayed to the user the first time the app attempts to use NFC.  

### Build the Library
The goal is to build an `.xcframework` bundle that can be added as a dependency to other projects.

- Run the script `build_xcframework.sh`, located at `nfc-lib/nfc-lib/build_xcframework.sh`.  
  - After execution, the project’s **build** folder will contain the file **nfclib.xcframework**.  

### Add the Library to the Application
- Open the project where you want to integrate the `nfclib` library.  
- Select the project, then under **TARGETS**, choose the correct target.  
- In the **General** tab of the target, find the **Frameworks and Libraries** section.  
- Click **+ → Add Other… → Add Files… → Select nfclib.xcframework**.  

The NFC library is now integrated into your application.  

# Library Interfaces for ID Card Communication
The library provides the following operation classes for ID card communication:
- `OperationReadPublicData` - Reads cardholder information
- `OperationReadCertificate` - Extracts authentication/signing certificates
- `OperationSignHash` - Performs a signing operation using the provided hash and PIN
- `OperationUnblockPin` - Unblock PIN1 or PIN2 using PUK
- `OperationAuthenticateWithWebEID` - Web-eID authentication flow

For a complete integration example, see the demo app's `CardOperations` protocol (`mvoting-nfc/nfc-demo/CardOperations.swift`) and its implementation in `Operator.swift`, which provides a convenient wrapper around these operations: 

Returns whether NFC is supported on the device:  
```swift
public func isNFCSupported() -> Bool
```

Asynchronously reads public information about the cardholder from the card:
```swift
public func readPublicInfo(CAN: String) async throws -> CardInfo
```

Asynchronously reads the authentication certificate from the card:
```swift
public func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate
```

Asynchronously reads the signing certificate from the card:
```swift
public func readSigningCertificate(CAN: String) async throws -> SecCertificate
```

Retrieves data required for WebEID authentication, using the provided credentials and challenge:
```swift
public func loadWebEIDAuthenticationData(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData
```

Performs a signing operation using a precomputed hash (only SHA-384 supported) and the PIN2 code:
```swift
public func sign(CAN: String, hash: Data, pin2: String) async throws -> Data
```

Unblocks PIN1 using the PUK code and sets a new PIN:
```swift
public func unblockPin1(CAN: String, puk: String, newCode: String) async throws
```

Unblocks PIN2 using the PUK code and sets a new PIN:
```swift
public func unblockPin2(CAN: String, puk: String, newCode: String) async throws
```