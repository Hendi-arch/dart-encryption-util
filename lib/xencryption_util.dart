import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

class XEncryptionUtil {
  static const int saltLength = 32;
  static const int iterations = 10000;
  static const int keyLength = 32; // Key length in bytes (256 bits)
  static const int tagLength = 128; // GCM tag length in bytes (128 bits)

  /// Encrypts [data] using [key] and returns the Base64-encoded ciphertext.
  static String encrypt(String data, List<int> key) {
    final gSalt = generateSalt();
    final gKey = generateKey(key, gSalt);
    final encryptedData = performEncryption(utf8.encode(data), gKey);
    final encryptedDataWithSalt = combineSaltAndData(gSalt, encryptedData);
    return base64.encode(encryptedDataWithSalt);
  }

  /// Decrypts [encryptedText] using [key] and returns the plaintext.
  static String decrypt(String encryptedText, List<int> key) {
    final encryptedDataWithSalt = base64.decode(encryptedText);
    final gSalt = extractSalt(encryptedDataWithSalt);
    final encryptedData = extractEncryptedData(encryptedDataWithSalt);
    final gKey = generateKey(key, gSalt);
    final decryptedData = performDecryption(encryptedData, gKey);
    return utf8.decode(decryptedData);
  }

  /// Generates a random salt.
  static Uint8List generateSalt() {
    final sGen = Random.secure();
    final secureRandom = FortunaRandom();
    secureRandom.seed(KeyParameter(
        Uint8List.fromList(List.generate(32, (_) => sGen.nextInt(255)))));
    return Uint8List.fromList(secureRandom.nextBytes(saltLength));
  }

  /// Derives a key from [key] and [salt] using PBKDF2.
  static Uint8List generateKey(List<int> key, Uint8List salt) {
    final pbkdf2 = KeyDerivator('SHA-256/HMAC/PBKDF2');
    pbkdf2.init(Pbkdf2Parameters(salt, iterations, keyLength));
    return pbkdf2.process(Uint8List.fromList(key));
  }

  /// Performs AES-GCM encryption on [data] using [key].
  static Uint8List performEncryption(List<int> data, Uint8List key) {
    final params = AEADParameters(
        KeyParameter(key), tagLength, Uint8List(12), Uint8List(0));
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(true, params);
    return cipher.process(Uint8List.fromList(data));
  }

  /// Performs AES-GCM decryption on [encryptedData] using [key].
  static Uint8List performDecryption(List<int> encryptedData, Uint8List key) {
    final params = AEADParameters(
        KeyParameter(key), tagLength, Uint8List(12), Uint8List(0));
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(false, params);
    return cipher.process(Uint8List.fromList(encryptedData));
  }

  /// Combines [salt] and [data] into a single byte list.
  static Uint8List combineSaltAndData(Uint8List salt, Uint8List data) {
    final combined = Uint8List(salt.length + data.length);
    combined.setAll(0, salt);
    combined.setAll(salt.length, data);
    return combined;
  }

  /// Extracts the salt from [combinedData].
  static Uint8List extractSalt(Uint8List combinedData) {
    return combinedData.sublist(0, saltLength);
  }

  /// Extracts the encrypted data from [combinedData].
  static Uint8List extractEncryptedData(Uint8List combinedData) {
    return combinedData.sublist(saltLength);
  }
}
