// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

import Foundation

public struct CardInfo: Sendable, Hashable {
    public var givenName: String
    public var surname: String
    public var personalCode: String
    /// Cardholder's citizenship as held in the on-card personal-data file. Empty for cards that
    /// do not expose it over NFC — the Latvian card, where ``issuingCountry`` is read instead.
    public var citizenship: String
    public var documentNumber: String
    /// Expiry date of the physical document, as printed on the card. Empty for cards that do not
    /// expose it over NFC — the Latvian card, where ``certificateExpiryDate`` is read instead.
    public var dateOfExpiry: String
    public var dateAndPlaceOfBirth: String
    /// ISO 3166-1 alpha-2 country code of the certificate issuer (subject RDN `C`). This is the
    /// issuing country, *not* the cardholder's citizenship: a foreign resident's card still
    /// carries the issuer's code. Empty for cards whose personal data is read from EF files.
    public var issuingCountry: String
    /// `notAfter` of the on-card authentication certificate. Typically shorter than the document
    /// expiry. Set only for cards whose personal data comes from the certificate.
    public var certificateExpiryDate: Date?
    public var cardType: CardType

    public init(
        givenName: String = "",
        surname: String = "",
        personalCode: String = "",
        citizenship: String = "",
        documentNumber: String = "",
        dateOfExpiry: String = "",
        dateAndPlaceOfBirth: String = "",
        issuingCountry: String = "",
        certificateExpiryDate: Date? = nil,
        cardType: CardType = .thales
    ) {
        self.givenName = givenName
        self.surname = surname
        self.personalCode = personalCode
        self.citizenship = citizenship
        self.documentNumber = documentNumber
        self.dateOfExpiry = dateOfExpiry
        self.dateAndPlaceOfBirth = dateAndPlaceOfBirth
        self.issuingCountry = issuingCountry
        self.certificateExpiryDate = certificateExpiryDate
        self.cardType = cardType
    }

    public var dateOfBirth: Date? {
        switch cardType {
        case .latviaIdemia: return PersonalCodeParser.latvianDateOfBirth(personalCode)
        case .id1, .thales: return PersonalCodeParser.estonianDateOfBirth(personalCode)
        }
    }

    public static func dateOfBirth(fromPersonalCode personalCode: String) -> Date? {
        PersonalCodeParser.estonianDateOfBirth(personalCode)
    }

    public static func dateOfBirth(fromLatvianPersonalCode personalCode: String) -> Date? {
        PersonalCodeParser.latvianDateOfBirth(personalCode)
    }

    public var formattedDescription: String {
        var description = """
        Name: \(givenName) \(surname)
        Personal Code: \(personalCode)
        Citizenship: \(citizenship)
        Document number: \(documentNumber)
        Date of Expiry: \(dateOfExpiry)
        """
        if !issuingCountry.isEmpty {
            description += "\nIssuing Country: \(issuingCountry)"
        }
        if let certificateExpiryDate {
            description += "\nCertificate Expiry: \(CardInfo.dateFormatter.string(from: certificateExpiryDate))"
        }
        return description
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "dd.MM.yyyy"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        return formatter
    }()
}

public enum CardField: Int, Sendable {
    case surname = 1,
         firstName,
         sex,
         citizenship,
         dateAndPlaceOfBirth,
         personalCode,
         documentNr,
         dateOfExpiry
}
