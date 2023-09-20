import 'dart:typed_data';

import 'package:coinlib/coinlib.dart';

// { "<address>": <amount> }
// eg { "bc1....": 1000 }
typedef OutputMap = Map<ECPublicKey, int>;

class HashWriter {
  final _byteData = ByteData(32);

  void write(OutPoint outpoint) {
    final hashBytes = outpoint.hash;
    _byteData.buffer.asUint8List().setAll(0, hashBytes);
    _byteData.setUint32(28, outpoint.n, Endian.little);
  }

  Uint8List getSHA256() {
    return sha256Hash(_byteData.buffer.asUint8List());
  }
}

class V0SilentPaymentDestination {
  ECPublicKey scanPubKey;
  ECPublicKey spendPubKey;
  int amount;

  V0SilentPaymentDestination(
      {required this.scanPubKey, required this.spendPubKey, required this.amount});
}

class SilentPaymentRecipient {
  ECPublicKey scanPubKey;
  List<OutputMap> outputs;

  SilentPaymentRecipient(this.scanPubKey) : outputs = [];
}

class PrivateKey {
  ECPrivateKey ecPrivateKey;
  bool isTaproot;
  PrivateKey({required this.ecPrivateKey, required this.isTaproot});
}

class RecipientAddress {
  final String address;
  final int amount;

  RecipientAddress({required this.address, required this.amount});
}
