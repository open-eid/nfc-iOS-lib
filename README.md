- [Ülevaade](#ülevaade)
- [Demorakenduse jooksutamise juhed](#demorakenduse-jooksutamise-juhend)
- [Integreerimise juhed](#integreerimise-juhend)
  - [Rakenduse nõuded](#rakenduse-nõuded)
  - [Lubada NFC Võimekus](#lubada-nfc-võimekus)
  - [Uuendada Info.plist](uuendada-info-plist)
  - [Teegi ehitamine](#teegi-ehitamine)
  - [Teegi lisamine rakendusse](#teegi-lisamine-rakendusse)
- [Teegi liidesed id-kaardiga suhtluseks](#teegi-liidesed-id---kaardiga-suhtluseks)

# Ülevaade 

NFC-ID teek pakub võimalust kasutada ID-kaardi autentimis- ja signeerimisfunktsionaalsust üle NFC liidese. Teegist on kaks versiooni - Android ja iOS platvormile.

NFC-ID teek ei ole mõeldud avalikuks kasutamiseks. Tegemist on tehnilise taseme teegiga, mis delegeerib kasutajaga suhtlemise rakendusele. Pikema aja jooksul ei ole ohutu võimaldada lõppkasutajal sisestada oma ID-kaardi PIN-koode igasse mobiilirakendusse. ID-kaardiga suhtluseks, usaldusväärse kasutajaliidese ning muude vajalike funktsioonide jaoks on vajalik luua tulevikus spetsiaalne mobiilirakendus. Selline lahendus võimaldab edaspidi mobiilirakendust kiiremini uuendada ning rünnete korral kaitsemeetmeid kohandada ja täiendada. 
NFC-ID teek on arendatud m-valimiste projektis lähtudes vajadusest kasutada ID-kaarti m valijarakenduses. 

# Demorakenduse jooksutamise juhed
- Avada mvtng-nfc-demo.xcworkspace. Antud töökeskkond sisaldab endas nii demorakendust kui nfclib teeki.
- Oodata, kuni Swift Package Manager'i sõltuvused laetakse alla
- Product -> Run

Simulaator pole toetatud, sest simulaatoril puudub NFC tugi.

# Integreerimise juhed

## Rakenduse nõuded
### Lubada NFC Võimekus
Xcode projektis tuleb seadistada NFC võimekuse loa küsimine

- Projekti navigaatoris valida oma projekt.
- Valida oma rakenduse sihtmärk ja seejärel minna vahelehele "Signing & Capabilities".
- Klikkida nupul "+ Capability".
- Otsida "Near Field Communication Tag Reading" ja lisada see oma projekti.

### Uuendada Info.plist
Info.plist failis peab deklareerima NFC kasutuse, et selgitada, miks rakendus vajab juurdepääsu sellele tehnoloogiale.

- Avada oma Info.plist fail.
- Lisada uus võti Privacy - NFC Scan Usage Description (NFCReaderUsageDescription).
- Määrata selle väärtuseks string, mis kirjeldab, miks rakendus vajab juurdepääsu NFC-le. See kirjeldus kuvatakse kasutajale esmakordselt, kui rakendus üritab NFC-d kasutada.

### Teegi ehitamine
Eesmärk on ehitada .framework failikogumik, mida saab lisata sõltuvusena teistesse projektidesse.

- Ava nfclib.xcodeproj
- Product -> Build
  - Selle tagajärjel ilmub xCode'i kaustapuu vaates Products kausta alla nfclib framework.
- Parem klikk -> Show in Finder
  - See avab failisüsteemis kausta, kus on nfclib.framework

### Teegi lisamine rakendusse
- Ava projekt, kuhu soovid integreerida nfclib teegi
- Vali projekt ja TARGETS menüü all õige programm
- Selle tagajärjel peaks olema nähtav General osa sihtprogrammi kohta
- Otsida Frameworks and Libraries
- Vajutada + -> Add Other... -> Add Files -> Valida nfclib.framework

Nüüd on nfc teek rakendusse integreeritud.

# Teegi liidesed id-kaardiga suhtluseks
Kõik avalikud operatsioonid on kirjeldatud `CardOperations` protokollis.

Järgnevalt on nimetatud operatsioonid, mida teek võimaldab.

Tagastab, kas NFC on seadmel toetatud.
`public func isNFCSupported() -> Bool`

Loeb asünkroonselt kaardilt avalikku teavet kaardi omaniku kohta
`public func readPublicInfo(CAN: String) async throws -> CardInfo`

Loeb asünkroonselt kaardilt autentimise sertifikaadi.
`public func readAuthenticationCertificate(CAN: String) async throws -> SecCertificate`

Loeb asünkroonselt kaardilt allkirjastamise sertifikaadi.
`public func readSigningCertificate(CAN: String) async throws -> SecCertificate`

Hangib andmeid WebEID autentimiseks, kasutades antud volikirju ja väljakutset.
`public func loadWebEIDAuthenticationData(CAN: String, pin1: String, challenge: String, origin: String) async throws -> WebEidData`

Viib läbi allkirjastamise operatsiooni, kasutades eelnevalt arvutatud räsi (toetatud on ainult SHA-384) ja PIN-koodi
`public func sign(CAN: String, hash: Data, pin2: String) async throws -> Data`
