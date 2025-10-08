// lib/src/proto/iso7816/bap_key.dart
import 'dart:convert' show latin1;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import '../../../dmrtd.dart';
import '../../../internal.dart';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';

import '../../lds/asn1ObjectIdentifiers.dart';

const SEED_LEN_BAP = 16;

/// BAP key for eDL: KSeed is the first 16 bytes of the MRZ input (no hashing).
class BAPKey extends BacKey {
  static final _log = Logger("AccessKey.BAPKey");

  // ICAO 9303 p11 MSE:Set AT reference (MRZ / secret) — keep 0x01
  @override
  int PACE_REF_KEY_TAG = 0x01;

  final String _mrz;
  Uint8List? _cachedSeed;

  BAPKey(String mrz) : _mrz = mrz;

  /// KSeed = first 16 Latin-1 bytes of the MRZ after removing whitespace and filler '<'.
  @override
  Uint8List get keySeed {
    if (_cachedSeed == null) {
      final normalized = _mrz.toUpperCase().replaceAll(RegExp(r'\s+'), '');
      if (normalized.isEmpty) {
        throw ArgumentError('MRZ must not be empty');
      }
      final hash = sha1.convert(latin1.encode(normalized)).bytes;
      _cachedSeed = Uint8List.fromList(hash.sublist(0, SEED_LEN_BAP));
      _log.sdDebug("BAP keySeed: ${_cachedSeed!.hex()}");
    }
    return _cachedSeed!;
  }

  /// Kenc (DES-EDE) for SM.
  @override
  Uint8List get encKey => DeriveKey.desEDE(keySeed);

  /// Kmac (ISO9797-1 Alg.3) for SM.
  @override
  Uint8List get macKey => DeriveKey.iso9797MacAlg3(keySeed);

  /// Required by AccessKey even if we don’t use PACE. Keep standard derivations.
  @override
  Uint8List Kpi(CipherAlgorithm cipherAlgorithm, KEY_LENGTH keyLength) {
    if (cipherAlgorithm == CipherAlgorithm.DESede) {
      return DeriveKey.desEDE(keySeed, paceMode: true);
    } else if (cipherAlgorithm == CipherAlgorithm.AES &&
        keyLength == KEY_LENGTH.s128) {
      return DeriveKey.aes128(keySeed, paceMode: true);
    } else if (cipherAlgorithm == CipherAlgorithm.AES &&
        keyLength == KEY_LENGTH.s192) {
      return DeriveKey.aes192(keySeed, paceMode: true);
    } else if (cipherAlgorithm == CipherAlgorithm.AES &&
        keyLength == KEY_LENGTH.s256) {
      return DeriveKey.aes256(keySeed, paceMode: true);
    }
    throw ArgumentError.value(
        cipherAlgorithm, 'cipherAlgorithm', 'Unsupported for Kpi');
  }

  @override
  String toString() {
    Logger("AccessKey.BAPKey").warning(
        "BAPKey.toString() exposes sensitive material; avoid in prod.");
    return "BAPKey{mrz: $_mrz, keySeed: ${keySeed.hex()}, "
        "encKey: ${encKey.hex()}, macKey: ${macKey.hex()}}";
  }
}
