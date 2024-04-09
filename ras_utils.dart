import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:pointycastle/asn1/primitives/asn1_octet_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

const BEGIN_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----';
const END_PRIVATE_KEY = '-----END PRIVATE KEY-----';

 const BEGIN_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----';
 const END_PUBLIC_KEY = '-----END PUBLIC KEY-----';

AsymmetricKeyPair generateRSAKeyPair({int keySize = 2048}) {
  var keyParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), keySize, 12);

  var secureRandom = getSecureRandom();

  var rngParams = ParametersWithRandom(keyParams, secureRandom);
  var generator = RSAKeyGenerator();
  generator.init(rngParams);

  return generator.generateKeyPair();
}

SecureRandom getSecureRandom() {
  var secureRandom = FortunaRandom();
  var random = Random.secure();
  var seeds = <int>[];
  for (var i = 0; i < 32; i++) {
    seeds.add(random.nextInt(255 + 1));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
  return secureRandom;
}

String encodeRSAPrivateKeyToPem(RSAPrivateKey rsaPrivateKey,{bool isPemFormat = true}) {
  var version = ASN1Integer(BigInt.from(0));

  var algorithmSeq = ASN1Sequence();
  var algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList(
      [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]));
  var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  var privateKeySeq = ASN1Sequence();
  var modulus = ASN1Integer(rsaPrivateKey.n);
  var publicExponent = ASN1Integer(BigInt.parse('65537'));
  var privateExponent = ASN1Integer(rsaPrivateKey.privateExponent);
  var p = ASN1Integer(rsaPrivateKey.p);
  var q = ASN1Integer(rsaPrivateKey.q);
  var dP = rsaPrivateKey.privateExponent! % (rsaPrivateKey.p! - BigInt.from(1));
  var exp1 = ASN1Integer(dP);
  var dQ = rsaPrivateKey.privateExponent! % (rsaPrivateKey.q! - BigInt.from(1));
  var exp2 = ASN1Integer(dQ);
  var iQ = rsaPrivateKey.q!.modInverse(rsaPrivateKey.p!);
  var co = ASN1Integer(iQ);

  privateKeySeq.add(version);
  privateKeySeq.add(modulus);
  privateKeySeq.add(publicExponent);
  privateKeySeq.add(privateExponent);
  privateKeySeq.add(p);
  privateKeySeq.add(q);
  privateKeySeq.add(exp1);
  privateKeySeq.add(exp2);
  privateKeySeq.add(co);
  var publicKeySeqOctetString =
      ASN1OctetString(octets: Uint8List.fromList(privateKeySeq.encode()));

  var topLevelSeq = ASN1Sequence();
  topLevelSeq.add(version);
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqOctetString);
  var dataBase64 = base64.encode(topLevelSeq.encode());
  var chunks = chunk(dataBase64, 64);
  if(isPemFormat) {
    final a = '$BEGIN_PRIVATE_KEY\n${chunks.join('\n')}\n$END_PRIVATE_KEY';
    return a;
  }
  else{
    return chunks.join('\n');
  }
}

 String encodeRSAPublicKeyToPem(RSAPublicKey publicKey) {
var algorithmSeq = ASN1Sequence();
var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
algorithmSeq.add(ASN1ObjectIdentifier.fromName('rsaEncryption'));
algorithmSeq.add(paramsAsn1Obj);

var publicKeySeq = ASN1Sequence();
publicKeySeq.add(ASN1Integer(publicKey.modulus));
publicKeySeq.add(ASN1Integer(publicKey.exponent));
var publicKeySeqBitString =
ASN1BitString(stringValues: Uint8List.fromList(publicKeySeq.encode()));

var topLevelSeq = ASN1Sequence();
topLevelSeq.add(algorithmSeq);
topLevelSeq.add(publicKeySeqBitString);
var dataBase64 = base64.encode(topLevelSeq.encode());
var chunks = StringUtils.chunk(dataBase64, 64);

return '$BEGIN_PUBLIC_KEY\n${chunks.join('\n')}\n$END_PUBLIC_KEY';
}
List<String> chunk(String s, int chunkSize) {
  var chunked = <String>[];
  for (var i = 0; i < s.length; i += chunkSize) {
    var end = (i + chunkSize < s.length) ? i + chunkSize : s.length;
    chunked.add(s.substring(i, end));
  }
  return chunked;
}

RSAPrivateKey rsaPrivateKeyFromDERBytes(Uint8List bytes) {
  var asn1Parser = ASN1Parser(bytes);
  var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
  var privateKey = topLevelSeq.elements![2];

  asn1Parser = ASN1Parser(privateKey.valueBytes);
  var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

  var modulus = pkSeq.elements![1] as ASN1Integer;
  //ASN1Integer publicExponent = pkSeq.elements[2] as ASN1Integer;
  var privateExponent = pkSeq.elements![3] as ASN1Integer;
  var p = pkSeq.elements![4] as ASN1Integer;
  var q = pkSeq.elements![5] as ASN1Integer;

  var rsaPrivateKey = RSAPrivateKey(
      modulus.integer!, privateExponent.integer!, p.integer, q.integer);

  return rsaPrivateKey;
}

Uint8List getBytesFromPEMString(String pem,
{bool checkHeader = false}) {
var lines = LineSplitter.split(pem)
    .map((line) => line.trim())
    .where((line) => line.isNotEmpty)
    .toList();
var base64;
if (checkHeader) {
if (lines.length < 2 ||
!lines.first.startsWith('-----BEGIN') ||
!lines.last.startsWith('-----END')) {
throw ArgumentError('The given string does not have the correct '
'begin/end markers expected in a PEM file.');
}
base64 = lines.sublist(1, lines.length - 1).join('');
} else {
base64 = lines.join('');
}

return Uint8List.fromList(base64Decode(base64));
}


String generateToken(String time, String userId, String deviceToken, String priKey) {
  final byte = getBytesFromPEMString(priKey);
  final privateKey = rsaPrivateKeyFromDERBytes(byte);

  final signer = RSASigner(SHA256Digest(), '0609608648016503040201');

  signer.init(
    true,
    PrivateKeyParameter<RSAPrivateKey>(privateKey),
  );

  final data = utf8.encode('$userId-$deviceToken-$time');
  final signature = signer.generateSignature(data) as RSASignature;
  final signedBytes = signature.bytes;

  return base64.encode(signedBytes);
}
