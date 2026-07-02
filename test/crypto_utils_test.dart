// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:dmrtd/src/crypto/crypto_utils.dart';

void main() {
  group('constantTimeEquals', () {
    test('returns true for identical byte sequences', () {
      final a = Uint8List.fromList([0x00, 0x01, 0x02, 0xff]);
      final b = Uint8List.fromList([0x00, 0x01, 0x02, 0xff]);
      expect(constantTimeEquals(a, b), isTrue);
    });

    test('returns true for two empty sequences', () {
      expect(constantTimeEquals(Uint8List(0), Uint8List(0)), isTrue);
    });

    test('returns false when a byte differs', () {
      final a = Uint8List.fromList([0x00, 0x01, 0x02, 0xff]);
      final b = Uint8List.fromList([0x00, 0x01, 0x02, 0xfe]);
      expect(constantTimeEquals(a, b), isFalse);
    });

    test('returns false when the first byte differs', () {
      final a = Uint8List.fromList([0x01, 0x02, 0x03]);
      final b = Uint8List.fromList([0xff, 0x02, 0x03]);
      expect(constantTimeEquals(a, b), isFalse);
    });

    test('returns false for different lengths (prefix match)', () {
      final a = Uint8List.fromList([0x01, 0x02, 0x03]);
      final b = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      expect(constantTimeEquals(a, b), isFalse);
      // and the other way around, without indexing past the shorter list
      expect(constantTimeEquals(b, a), isFalse);
    });

    test('accepts plain List<int> as well as Uint8List', () {
      expect(constantTimeEquals(<int>[1, 2, 3], <int>[1, 2, 3]), isTrue);
      expect(constantTimeEquals(<int>[1, 2, 3], <int>[1, 2, 4]), isFalse);
    });
  });
}
