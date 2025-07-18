## Dart library for ICAO Machine Readable Travel Documents standard - Enhanced Biometric Passport Scanner
This library is an enhanced implementation of the [ICAO 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303) standard, combining the capabilities of two proven libraries to create a comprehensive solution for passport scanning and biometric data extraction.

## About This Library

We have created this new library based on the following established libraries:
- [MRZ-Scanner-flutter](https://github.com/Krishak15/MRZ-Scanner-flutter) - for Machine Readable Zone (MRZ) scanning using Google ML Kit
- [dmrtd](https://github.com/ZeroPass/dmrtd) - for reading biometric passport data via NFC

Our enhanced implementation is specifically designed to work with passports from **Angelsaxion countries and the European Union**, providing optimized support for these regions' passport formats and security features.

## Integration with Yivi

This library is designed for integration with the [Yivi app](https://yivi.app) to generate passport-based credentials, enabling secure and verifiable digital identity solutions. The library provides the foundation for creating trusted digital credentials derived from physical passport data.

## Key features
* **Enhanced MRZ Recognition**: Advanced Machine Readable Zone scanning using Google ML Kit with improved accuracy for EU and Angelsaxion passport formats
* **Comprehensive NFC Reading**: Full implementation of PACE & BAC session key establishment protocols
* **Regional Optimization**: Specifically tuned for Angelsaxion countries and EU passport standards
* **Yivi Integration Ready**: Designed for seamless integration with Yivi credential generation
* Reading all elementary files from MRTD, e.g.: EF.DG1, EF.DG2, EF.DG11, EF.DG12, EF.DG15 ...  
  *Note: most of files are not fully parsed yet.*
* Executing `Active Authentication` on MRTD (i.e.: sign arbitrary data with passport)
* Basic implementation of ICC ISO7816-4 smart card standard
* Implementation of ISO 9797 Algorithm 3 MAC and padding scheme

## Library structure
dmrtd.dart - public passport API  
extensions.dart - exposes library's dart [extensions](lib/src/extension)  
internal.dart - exposes internal components of the library such as MrtdApi, ICC and crypto

## Usage
1) Include `dmrtd` library in your project's `pubspec.yaml` file:
```
dependencies:
  dmrtd:
    path: '<path_to_dmrtd_folder>'
```
2) Run
 ```
 flutter pub get
 ```

**Example:**  
*Note: See also [example](example) app*

```dart
import 'package:dmrtd/dmrtd.dart';

try {
  final nfc = NfcProvider();
  await nfc.connect(iosAlertMessage: "Hold your iPhone near Passport");

  final passport = Passport(nfc);

  nfc.setIosAlertMessage("Reading EF.CardAccess ...");
  final cardAccess = await passport.readEfCardAccess();

  _nfc.setIosAlertMessage("Initiating session with PACE or BAC...");
  //set MrtdData
  mrtdData.isPACE = true; //initialize with PACE(set false if you want to do with DBA)
  mrtdData.isDBA = accessKey.PACE_REF_KEY_TAG == 0x01 ? true : false;

  if (isPace) {
    //PACE session
    await passport.startSessionPACE(accessKey, mrtdData.cardAccess!);
  } else {
    //BAC session
    await passport.startSession(accessKey as DBAKey);
  }

  nfc.setIosAlertMessage(formatProgressMsg("Reading EF.COM ...", 0));
  final efcom = await passport.readEfCOM();

  nfc.setIosAlertMessage(formatProgressMsg("Reading Data Groups ...", 20));
  EfDG1 dg1;
  if (efcom.dgTags.contains(EfDG1.TAG)) {
    dg1 = await passport.readEfDG1();
  }

  EfDG2 dg2;
  if (efcom.dgTags.contains(EfDG2.TAG)) {
    dg2 = await passport.readEfDG2();
  }

  EfDG14 dg14;
  if (efcom.dgTags.contains(EfDG14.TAG)) {
    dg14 = await passport.readEfDG14();
  }

  EfDG15 dg15;
  Uint8List sig;
  if (efcom.dgTags.contains(EfDG15.TAG)) {
    dg15 = await passport.readEfDG15();
    nfc.setIosAlertMessage(formatProgressMsg("Doing AA ...", 60));
    sig  = await passport.activeAuthenticate(Uint8List(8));
  }

  nfc.setIosAlertMessage(formatProgressMsg("Reading EF.SOD ...", 80));
  final sod = await passport.readEfSOD();
}
on Exception catch(e) {
  final se = e.toString().toLowerCase();
  String alertMsg = "An error has occurred while reading Passport!";
  if (e is PassportError) {
      if (se.contains("security status not satisfied")) {
        alertMsg = "Failed to initiate session with passport.\nCheck input data!";
    }
  }

  if (se.contains('timeout')){
    alertMsg = "Timeout while waiting for Passport tag";
  }
  else if (se.contains("tag was lost")) {
    alertMsg = "Tag was lost. Please try again!";
  }
  else if (se.contains("invalidated by user")) {
    alertMsg = "";
  }

  errorAlertMsg = alertMsg;
}
finally {
  if (errorAlertMsg?.isNotEmpty) {
    await _nfc.disconnect(iosErrorMessage: errorAlertMsg);
    if (!Platform.isIOS) {
    // Show error to the user
    }
  }
  else {
    await _nfc.disconnect(iosAlertMessage: formatProgressMsg("Finished", 100));
  }
}
```

## Supported Regions

This library has been specifically optimized for:
- **Angelsaxion Countries**: United States, United Kingdom, Canada, Australia, New Zealand
- **European Union**: All EU member states with enhanced support for EU passport security features

## Other documentation
* [ICAO 9303 Specifications Common to all MRTDs](https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf)
* [ICAO 9303 Specifications for Machine Readable Passports (MRPs) and other TD3 Size MRTDs](https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf)
* [ICAO 9303 eMRTD logical data structure](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)
* [ICAO 9303 Security mechanisms for MRTDs](https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)

## License
This project is licensed under the terms of the GNU Lesser General Public License (LGPL) for open-source use and a Commercial License for proprietary use. See the [LICENSE.LGPL](/LICENSE.LGPL) and [LICENSE.COMMERCIAL](/LICENSE.COMMERCIAL) files for details.