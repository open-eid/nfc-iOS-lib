public enum CodeType: UInt {
    case puk = 0
    case pin1 = 1
    case pin2 = 2
}

/**
 * A protocol defining commands for interacting with a smart card.
 */
public protocol CardCommands: AnyObject {
    var canChangePUK: Bool { get }
    /**
     * Reads public data from the card.
     *
     * - Throws: An error if the operation fails.
     * - Returns: The personal data read from the card.
     */
    func readPublicData() async throws -> CardInfo

    /**
     * Reads the authentication certificate from the card.
     *
     * - Throws: An error if the operation fails.
     * - Returns: The authentication certificate as `Data`.
     */
    func readAuthenticationCertificate() async throws -> Data

    /**
     * Reads the signature certificate from the card.
     *
     * - Throws: An error if the operation fails.
     * - Returns: The signature certificate as `Data`.
     */
    func readSignatureCertificate() async throws -> Data

    /**
     * Reads the PIN or PUK code counter record.
     *
     * - Parameter type: The type of record to read.
     * - Throws: An error if the operation fails.
     * - Returns: The remaining attempts as an `UInt8`.
     */
    func readCodeTryCounterRecord(_ type: CodeType) async throws -> UInt8

    /**
     * Changes the PIN or PUK code.
     *
     * - Parameters:
     *   - type: The type of code to change (e.g., `CodeType.Puk`, `CodeType.Pin1`, `CodeType.Pin2`).
     *   - code: The new PIN/PUK code.
     *   - verifyCode: The current PIN or PUK code for verification.
     * - Throws: An error if the operation fails.
     */
    func changeCode(_ type: CodeType, to code: String, verifyCode: String) async throws

    /**
     * Verifies a PIN or PUK code.
     *
     * - Parameters:
     *   - type: The type of code to verify (e.g., `CodeType.Puk`, `CodeType.Pin1`, `CodeType.Pin2`).
     *   - code: The PIN/PUK code to verify.
     * - Throws: An error if the verification fails.
     */
    func verifyCode(_ type: CodeType, code: String) async throws

    /**
     * Unblocks a PIN using the PUK code.
     *
     * - Parameters:
     *   - type: The type of code to unblock (`CodeType.Pin1` or `CodeType.Pin2`).
     *   - puk: The current PUK code for verification.
     *   - newCode: The new PIN code.
     * - Throws: An error if the operation fails.
     */
    func unblockCode(_ type: CodeType, puk: String, newCode: String) async throws

    /**
     * Authenticates using a cryptographic challenge.
     *
     * - Parameters:
     *   - hash: The challenge hash to be signed.
     *   - pin1: PIN 1 for authentication.
     * - Throws: An error if the operation fails.
     * - Returns: The authentication response as `Data`.
     */
    func authenticate(for hash: Data, withPin1 pin1: String) async throws -> Data

    /**
     * Calculates a digital signature for the given hash.
     *
     * - Parameters:
     *   - hash: The hash to be signed.
     *   - pin2: PIN 2 for verification.
     * - Throws: An error if the operation fails.
     * - Returns: The signature as `Data`.
     */
    func calculateSignature(for hash: Data, withPin2 pin2: String) async throws -> Data

    /**
     * Decrypts data using PIN 1.
     *
     * - Parameters:
     *   - hash: The data to be decrypted.
     *   - pin1: PIN 1 for verification.
     * - Throws: An error if the operation fails.
     * - Returns: The decrypted data.
     */
    func decryptData(_ hash: Data, withPin1 pin1: String) async throws -> Data
}
