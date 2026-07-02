// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';

void main() {
  group('AESChiperSelector', () {
    test('selects the cipher matching the requested key length', () {
      expect(AESChiperSelector.getChiper(size: KEY_LENGTH.s128).size, 16);
      // Regression test: an AES-192 request used to return an AES-128 cipher.
      expect(AESChiperSelector.getChiper(size: KEY_LENGTH.s192).size, 24);
      expect(AESChiperSelector.getChiper(size: KEY_LENGTH.s256).size, 32);
    });
  });

  group('AESCipher CBC IV handling', () {
    final key = Uint8List(16); // 16-byte AES-128 key
    final data = Uint8List(16); // one block
    final iv = Uint8List(AES_BLOCK_SIZE);

    test('encrypt throws in CBC mode when no IV is supplied', () {
      final cipher = AESCipher128();
      expect(
        () => cipher.encrypt(data: data, key: key),
        throwsA(isA<AESCipherError>()),
      );
    });

    test('decrypt throws in CBC mode when no IV is supplied', () {
      final cipher = AESCipher128();
      expect(
        () => cipher.decrypt(data: data, key: key),
        throwsA(isA<AESCipherError>()),
      );
    });

    test('encrypt/decrypt round-trips in CBC mode with an explicit IV', () {
      final cipher = AESCipher128();
      final ct = cipher.encrypt(data: data, key: key, iv: iv);
      final pt = cipher.decrypt(data: ct, key: key, iv: iv);
      expect(pt, equals(data));
    });

    test('ECB mode does not require an IV', () {
      final cipher = AESCipher128();
      final ct = cipher.encrypt(
          data: data, key: key, mode: BLOCK_CIPHER_MODE.ECB);
      final pt = cipher.decrypt(
          data: ct, key: key, mode: BLOCK_CIPHER_MODE.ECB);
      expect(pt, equals(data));
    });
  });
}
