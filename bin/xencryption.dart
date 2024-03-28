import 'package:xencryption_util/xencryption_util.dart';

void main(List<String> arguments) {
  if (arguments.isEmpty) {
    print('Usage: dart encrypt.dart <is_for_encrypt> <text_to_encrypt> [key]');
    return;
  }

  // Parse command line arguments
  final isForEncrypt =
      arguments.isNotEmpty ? bool.tryParse(arguments[0]) ?? true : true;
  final textToProcess = arguments.length > 1 ? arguments[1] : '';
  final String key =
      arguments.length > 2 ? arguments[2] : String.fromEnvironment("KEY");

  // Perform encryption or decryption based on the command line arguments
  String result;
  if (isForEncrypt) {
    result = XEncryptionUtil.encrypt(textToProcess, key.codeUnits);
  } else {
    result = XEncryptionUtil.decrypt(textToProcess, key.codeUnits);
  }

  // Print the result to the console
  print(result);
}
