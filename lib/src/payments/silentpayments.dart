import 'dart:typed_data';

import 'package:bitcoin_flutter/src/utils/types.dart';
import 'package:coinlib/coinlib.dart';

class SilentPayment {
  SilentPayment() {
    _init();
  }

  _init() {
    loadCoinlib();
  }

  List<Output> createOutputs(
    List<PrivateKey> inputPrivateKeys,
    List<OutPoint> outpoints,
    List<RecipientAddress> recipientAddresses, {
    String hrp = 'sprt',
  }) {
    final sumOfPrivateKeys = sumInputPrivKeys(inputPrivateKeys);
    final outpointHash = hashOutpoints(outpoints);

    final paymentGroups = <String, List<_PaymentGroup>>{};

    for (final recipient in recipientAddresses) {
      final silentPaymentAddress = decodeSilentPaymentAddress(recipient.address, hrp);
      final scanKey = silentPaymentAddress.scanKey;
      final spendKey = silentPaymentAddress.spendKey;

      if (paymentGroups.containsKey(scanKey.toString())) {
        paymentGroups[scanKey.toString()]!.add(_PaymentGroup(spendKey, recipient.amount));
      } else {
        paymentGroups[scanKey.toString()] = [_PaymentGroup(spendKey, recipient.amount)];
      }
    }

    final outputs = <Output>[];
    for (final entry in paymentGroups.entries) {
      final scanKeyHex = entry.key;
      final paymentGroup = entry.value;
      final scanKey = Uint8List.fromList(hex.decode(scanKeyHex));
      final ecdhSecret = secp256k1.derive(
        secp256k1.publicKeyTweakMul(scanKey, outpointHash, true),
        sumOfPrivateKeys,
        true,
      );

      var n = 0;
      for (final payment in paymentGroup) {
        final tweak =
            SHA256().convert(Uint8List.fromList([...ecdhSecret, ...serializeUint32(n)])).bytes;

        final publicKey = secp256k1.publicKeyTweakAdd(
          payment.spendKey,
          tweak,
          true,
        );

        outputs.add(Output(pubkey: publicKey, value: payment.amount));
        n++;
      }
    }

    return outputs;
  }
}

ECPrivateKey sumInputPrivKeys(List<PrivateKey> senderSecretKeys) {
  final secKey = senderSecretKeys[0].ecPrivateKey;
  final isTaproot = senderSecretKeys[0].isTaproot;
  ECPrivateKey sumSecKey = secKey;

  if (isTaproot && secKey.pubkey.hex.startsWith('03')) {
    sumSecKey = sumSecKey.negate()!;
  }

  if (senderSecretKeys.length > 1) {
    for (int i = 1; i < senderSecretKeys.length; i++) {
      final senderSecKey = senderSecretKeys[i].ecPrivateKey;
      final senderIsTaproot = senderSecretKeys[i].isTaproot;
      ECPrivateKey tempKey = senderSecKey;
      if (senderIsTaproot && senderSecKey.pubkey.hex.startsWith('03')) {
        tempKey = tempKey.negate()!;
      }
      sumSecKey = sumSecKey.tweak(tempKey.data)!;
    }
  }

  return secKey;
}

Uint8List prepareScalarECDHInput(List<PrivateKey> senderSecretKeys, List<OutPoint> txOutpoints) {
  ECPrivateKey sumInputSecretKeys = sumInputPrivKeys(senderSecretKeys);
  Uint8List outpointsHash = hashOutpoints(txOutpoints);
  return sumInputSecretKeys.multiplyTweak(outpointsHash.begin());
}

List<SilentPaymentRecipient> groupSilentPaymentAddresses(
    List<V0SilentPaymentDestination> silentPaymentDestinations) {
  final recipientGroups = <ECPublicKey, List<OutputMap>>{};
  final recipients = <SilentPaymentRecipient>[];

  for (final destination in silentPaymentDestinations) {
    final scanPubKey = destination.scanPubKey;
    final spendPubKey = destination.spendPubKey;
    final amount = destination.amount;

    if (recipientGroups.containsKey(scanPubKey)) {
      recipientGroups[scanPubKey]!.add({
        spendPubKey: amount,
      });
    } else {
      recipientGroups[scanPubKey] = [
        {spendPubKey: amount}
      ];
    }
  }

  recipientGroups.forEach((scanPubKey, outputs) {
    final recipient = SilentPaymentRecipient(scanPubKey);

    outputs.forEach((output) {
      recipient.outputs.add(output);
    });

    recipients.add(recipient);
  });

  return recipients;
}

Uint8List hashOutpoints(List<OutPoint> txOutpoints) {
  // Make a local copy of the outpoints so we can sort them before hashing.
  // This is to ensure the sender and receiver deterministically arrive at the same outpoint hash,
  // regardless of how the outpoints are ordered in the transaction.

  List<OutPoint> outpoints = List.from(txOutpoints);
  outpoints.sort();

  HashWriter h = HashWriter();
  for (OutPoint outpoint in outpoints) {
    h.write(outpoint);
  }

  return h.getSHA256();
}
