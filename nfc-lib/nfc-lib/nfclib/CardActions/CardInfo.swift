public struct CardInfo {
    public var givenName: String
    public var surname: String
    public var personalCode: String
    public var citizenship: String
    public var dateOfExpiry: String

    public init(givenName: String = "", surname: String = "", personalCode: String = "", citizenship: String = "", dateOfExpiry: String = "") {
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

enum CardField: Int {
    case surname = 1,
         firstName,
         sex,
         citizenship,
         dateAndPlaceOfBirth,
         personalCode,
         documentNr,
         dateOfExpiry
}
