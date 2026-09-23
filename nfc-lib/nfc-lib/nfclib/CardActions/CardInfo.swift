/*
 * Copyright 2017 - 2025 Riigi Infosüsteemi Amet
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

import Foundation

public struct CardInfo: Sendable, Hashable {
    public var givenName: String
    public var surname: String
    public var personalCode: String
    public var citizenship: String
    public var documentNumber: String
    public var dateOfExpiry: String
    public var dateAndPlaceOfBirth: String

    public init(
        givenName: String = "",
        surname: String = "",
        personalCode: String = "",
        citizenship: String = "",
        documentNumber: String = "",
        dateOfExpiry: String = "",
        dateAndPlaceOfBirth: String = ""
    ) {
        self.givenName = givenName
        self.surname = surname
        self.personalCode = personalCode
        self.citizenship = citizenship
        self.documentNumber = documentNumber
        self.dateOfExpiry = dateOfExpiry
        self.dateAndPlaceOfBirth = dateAndPlaceOfBirth
    }

    public var dateOfBirth: Date? { CardInfo.dateOfBirth(fromPersonalCode: personalCode) }

    public static func dateOfBirth(fromPersonalCode personalCode: String) -> Date? {
        let digits = Array(personalCode)
        guard digits.count >= 7, digits.prefix(7).allSatisfy(\.isWholeNumber) else { return nil }

        let century: Int
        switch digits[0].wholeNumberValue {
        case 1, 2: century = 1800
        case 3, 4: century = 1900
        case 5, 6: century = 2000
        case 7, 8: century = 2100
        default: return nil
        }

        guard let yearInCentury = Int(String(digits[1...2])),
              let month = Int(String(digits[3...4])),
              let day = Int(String(digits[5...6])) else { return nil }

        var components = DateComponents()
        components.year = century + yearInCentury
        components.month = month
        components.day = day

        let calendar = Calendar(identifier: .gregorian)
        guard let date = calendar.date(from: components) else { return nil }

        let rounded = calendar.dateComponents([.year, .month, .day], from: date)
        guard rounded.year == components.year,
              rounded.month == month,
              rounded.day == day else { return nil }
        return date
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
