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

public struct CardInfo: Sendable {
    public var givenName: String
    public var surname: String
    public var personalCode: String
    public var citizenship: String
    public var dateOfExpiry: String

    public init(
        givenName: String = "",
        surname: String = "",
        personalCode: String = "",
        citizenship: String = "",
        dateOfExpiry: String = ""
    ) {
        self.givenName = givenName
        self.surname = surname
        self.personalCode = personalCode
        self.citizenship = citizenship
        self.dateOfExpiry = dateOfExpiry
    }

    public var formattedDescription: String {
        """
        Name: \(givenName) \(surname)
        Personal Code: \(personalCode)
        Citizenship: \(citizenship)
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
