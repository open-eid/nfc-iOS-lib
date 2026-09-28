// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

public struct CardInfo: Sendable, Hashable {
    public var givenName: String
    public var surname: String
    public var personalCode: String
    public var citizenship: String
    public var documentNumber: String
    public var dateOfExpiry: String

    public init(
        givenName: String = "",
        surname: String = "",
        personalCode: String = "",
        citizenship: String = "",
        documentNumber: String = "",
        dateOfExpiry: String = ""
    ) {
        self.givenName = givenName
        self.surname = surname
        self.personalCode = personalCode
        self.citizenship = citizenship
        self.documentNumber = documentNumber
        self.dateOfExpiry = dateOfExpiry
    }

    public var formattedDescription: String {
        """
        Name: \(givenName) \(surname)
        Personal Code: \(personalCode)
        Citizenship: \(citizenship)
        Document number: \(documentNumber)
        Date of Expiry: \(dateOfExpiry)
        """
    }
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
