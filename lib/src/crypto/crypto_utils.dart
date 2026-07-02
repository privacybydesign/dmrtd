//  Copyright © 2020 ZeroPass. All rights reserved.
import 'dart:math';
import 'dart:typed_data';

Uint8List randomBytes(int length) {
  final random = Random.secure();
    var intBytes = List<int>.generate(length, (i) => random.nextInt(256));
    return Uint8List.fromList(intBytes);
}

/// Compares two byte sequences [a] and [b] in constant time.
///
/// Unlike `==`, `ListEquality().equals` or `List.equals`, this does not
/// short-circuit on the first differing byte, so the running time does not
/// leak how many leading bytes matched. Use it whenever the comparison
/// involves secret material such as a MAC, cryptogram or authentication token.
///
/// Returns `true` only when both sequences have the same length and identical
/// contents. A length mismatch is folded into the accumulator so the result is
/// still correct, without indexing past the shorter list.
bool constantTimeEquals(List<int> a, List<int> b) {
  var diff = a.length ^ b.length;
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}