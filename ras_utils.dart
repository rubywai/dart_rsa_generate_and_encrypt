import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_null.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:pointycastle/asn1/primitives/asn1_octet_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/asymmetric/api.dart';

void main() async {
  String public = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzoN1rGpG4oIam1m2fup1ruY5e
nRGxF9KJtnhc2XZZoTn2mRz+oqFJEvgN0DsfNrjpAJRModM9qHFx4u2wEZgSjHvI
2IgVp0t5R2Ji/v3bwwcYKy9MUhL6Qp24EYyi6awh8uK8BovNCM7IzWFOgBxTtOJ8
oBUkko01QfIIG+uoAQIDAQAB
-----END PUBLIC KEY-----''';
  String private = '''-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCzoN1rGpG4oIam1m2fup1ruY5enRGxF9KJtnhc2XZZoTn2mRz+
oqFJEvgN0DsfNrjpAJRModM9qHFx4u2wEZgSjHvI2IgVp0t5R2Ji/v3bwwcYKy9M
UhL6Qp24EYyi6awh8uK8BovNCM7IzWFOgBxTtOJ8oBUkko01QfIIG+uoAQIDAQAB
An8l48jQzsnuJ+4/QvvctYB/OKTPUFJrCJtgcRzyeOx9+4Q+gA2dqLBcuaOZRlMy
Qli+zWB6yafFWcKUQ0nf2dY5t86wubsSAaHrSMDCASjLIJJeVDEqPe+Gj+w3RAXw
vb8MW4l7I9T3sSRukn0CnIhGU0KT8+znTHQrAvxNFFbZAkEA+yyTC2FSEGrGqKEx
Vao0ZBegnyoWIN26Xyh+i0c1mZKYHNw363NbMIo3VLQRrnQ08OzXNXE4pxKH+ACN
s1wAjwJBALcUYq619D42YmwpSoPLIUWAFHZmbQYQbO+N+wBlopP0nE6CimC5HsTI
uMAqefnAXRIEU9CM5h3u+6zFVCyi9m8CQQD4JXqEtLppw8POl6nw8z3dYUZr2R2R
jN1y48PZgBmhRqYHZT3N3OLLmtG9WkVZsC8ZkzOu9dO9o943EvzrpUpbAkEAliv9
iiusDX/Umb4A5jwvrW+S2U/I6+l7QcBne/riMZS6xddkJFSUvXubt9zfspIshYPR
MEby1ujZve0az4ZYtwJAa00wn3MncsMiYkwmPIqIruAT5AMkTHLGhddaEFmuQ/kP
xrVrCDQlcV53PNeRoldVb2YSXu58gMeI/SOQIgKMzw==
-----END RSA PRIVATE KEY-----''';
  final publicKey = publicKeyEncryptor<RSAPublicKey>(public);
  final privKey = publicKeyEncryptor<RSAPrivateKey>(private);

  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  Encrypter encrypter;
  Encrypted encrypted;
  String decrypted;

  print('public key is ${encodePublicKeyToPem(publicKey)}');
  print('private key is ${encodePrivateKeyToPem(privKey)}');


  // PKCS1 (Default)
  encrypter = Encrypter(RSA(publicKey: publicKey, privateKey: privKey));
  encrypted = encrypter.encrypt(plainText);
  decrypted = encrypter.decrypt(encrypted);

  print('PKCS1 (Default)');
  print(decrypted);


  // OAEP (SHA1)
  encrypter = Encrypter(
    RSA(publicKey: publicKey, privateKey: privKey, encoding: RSAEncoding.OAEP),
  );
  encrypted = encrypter.encrypt(plainText);
  decrypted = encrypter.decrypt(encrypted);

  print('\nOAEP (SHA1)');
  print(decrypted);


  // OAEP (SHA256)
  encrypter = Encrypter(
      RSA(
        publicKey: publicKey,
        privateKey: privKey,
        encoding: RSAEncoding.OAEP,
        digest: RSADigest.SHA256,
      )
  );
  encrypted = encrypter.encrypt(plainText);
  decrypted = encrypter.decrypt(encrypted);

  print('\nOAEP (SHA256)');
  print(decrypted);

}

T publicKeyEncryptor<T extends RSAAsymmetricKey>(String str){
  final key = str.trim();
  final parser = RSAKeyParser();
  return parser.parse(key) as T;
}

String encodePublicKeyToPem(RSAPublicKey publicKey) {
  var algorithmSeq = ASN1Sequence();
  var algorithmAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]));
  var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x05, 0x00]));
  algorithmSeq.add(algorithmAsn1Obj);
  algorithmSeq.add(paramsAsn1Obj);

  var modulus = ASN1Integer(publicKey.modulus);
  var publicExponent = ASN1Integer(publicKey.publicExponent);

  var publicKeySeq = ASN1Sequence();
  publicKeySeq.add(modulus);
  publicKeySeq.add(publicExponent);

  var publicKeySeqBitString = ASN1BitString(stringValues: Uint8List.fromList(publicKeySeq.encode()));

  var topLevelSeq = ASN1Sequence();
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(publicKeySeqBitString);

  var dataBase64 = base64.encode(topLevelSeq.encode());

  return "-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----";
}

String encodePrivateKeyToPemq(RSAPrivateKey privateKey) {
  var version = ASN1Integer(BigInt.from(0));

  var algorithmSeq = ASN1Sequence();
  algorithmSeq.add(ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]))); // RSA encryption OID
  algorithmSeq.add(ASN1Null()); // Null parameters for RSA

  var privateKeySeq = ASN1Sequence();
  privateKeySeq.add(version);
  privateKeySeq.add(ASN1Integer(privateKey.modulus!));
  privateKeySeq.add(ASN1Integer(BigInt.parse('65537')));
  privateKeySeq.add(ASN1Integer(privateKey.privateExponent!));
  privateKeySeq.add(ASN1Integer(privateKey.p!));
  privateKeySeq.add(ASN1Integer(privateKey.q!));

  var privateKeyOctetString = ASN1OctetString(octets: Uint8List.fromList(privateKeySeq.encode()));

  var topLevelSeq = ASN1Sequence();
  topLevelSeq.add(algorithmSeq);
  topLevelSeq.add(privateKeyOctetString);

  var dataBase64 = base64.encode(topLevelSeq.encode());

  return "-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----";
}



 String encodePrivateKeyToPem(RSAPrivateKey rsaPrivateKey) {
var version = ASN1Integer(BigInt.from(0));
var modulus = ASN1Integer(rsaPrivateKey.n);
var publicExponent = ASN1Integer(BigInt.parse('65537'));
var privateExponent = ASN1Integer(rsaPrivateKey.privateExponent);

var p = ASN1Integer(rsaPrivateKey.p);
var q = ASN1Integer(rsaPrivateKey.q);
var dP =
rsaPrivateKey.privateExponent! % (rsaPrivateKey.p! - BigInt.from(1));
var exp1 = ASN1Integer(dP);
var dQ =
rsaPrivateKey.privateExponent! % (rsaPrivateKey.q! - BigInt.from(1));
var exp2 = ASN1Integer(dQ);
var iQ = rsaPrivateKey.q!.modInverse(rsaPrivateKey.p!);
var co = ASN1Integer(iQ);

var topLevelSeq = ASN1Sequence();
topLevelSeq.add(version);
topLevelSeq.add(modulus);
topLevelSeq.add(publicExponent);
topLevelSeq.add(privateExponent);
topLevelSeq.add(p);
topLevelSeq.add(q);
topLevelSeq.add(exp1);
topLevelSeq.add(exp2);
topLevelSeq.add(co);
var dataBase64 = base64.encode(topLevelSeq.encode());
return "-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----";
}
