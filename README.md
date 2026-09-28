- [Overview](#overview)  
- [Demo Application Run Guide](#demo-application-run-guide)  
- [Integration Guide](#integration-guide)  
  - [Application Requirements](#application-requirements)  
    - [Enable NFC Capability](#enable-nfc-capability)  
    - [Update Info.plist](#update-infoplist)  
    - [Add the Library as a Swift Package](#add-the-library-as-a-swift-package)
- [Library Interfaces for ID Card Communication](#library-interfaces-for-id-card-communication)  
- [Logging](#logging)  
  - [Enabling Sensitive Logs (Debug Only)](#enabling-sensitive-logs-debug-only)  

# Overview

The NFC-ID library provides functionality to use ID card authentication and digital signing over the NFC interface. Two platform-specific versions of the library are available – one for Android and one for iOS.  

The NFC-ID library is not intended for public use. It is a low-level technical library that delegates user interaction to the application itself. In the long term, it is not safe to allow end users to enter their ID card PIN codes directly into every mobile app. For secure ID card interaction, a trusted user interface, and additional required features, a dedicated mobile application must be developed in the future. Such a solution would also allow faster updates to the application and enable quick adjustments of countermeasures in case of attacks.  

The NFC-ID library was originally developed within the m-valimiste project, based on the need to use the ID card inside the m-Voting client application.  

# Demo Application Run Guide
- Open **mvoting-nfc/nfc-demo.xcodeproj**. The demo app uses the Swift package at the repository root.
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

### Add the Library as a Swift Package
- In Xcode, choose **File → Add Package Dependencies… → Add Local…** and select this repository's root directory. For a remote dependency, use the repository URL and select a revision containing `Package.swift`.
- Add the `IdCardLib` product to your app target. Import the library in Swift with `import nfclib`.
- Set the app's minimum deployment target to iOS 18 or later.

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

# Logging

The library logs through Apple's unified logging system (`OSLog`), under the subsystem `ee.ria.nfc-iOS-lib`. Most of it is harmless diagnostics – operation steps, reader status, errors. A separate set of logs (plaintext APDUs with **PIN1, PIN2, PUK**, session keys, and cryptographic intermediates) is sensitive and stays off unless you turn it on while debugging.

## Enabling Sensitive Logs (Debug Only)

> [!CAUTION]
> These logs print PIN1, PIN2, PUK, and session keys in plaintext. Never enable them in a production / App Store build.

While debugging, turn them on from your app – usually at startup, behind your own debug setting:

```swift
import nfclib

NFCLibLogging.isEnabled = true  // Default is false
```

Set it back to `false` to turn them off again. The demo already wires this up in `nfc_demoApp.swift` (`mvoting-nfc/nfc-demo`), so the quickest way to try it is to switch that line to `true`.

This only has an effect when the library was built with sensitive logging compiled in. For local package debugging, add `.define("ENABLE_LOGGING")` to the `nfclib` target's `swiftSettings` in `Package.swift`. Remove it before a production build so the sensitive logging code is stripped from the binary. Your app should also leave `NFCLibLogging.isEnabled` set to `false` in production.

Once enabled, the sensitive logs appear under the same subsystem as everything else.  
