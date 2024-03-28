import 'package:test/test.dart';
import 'package:xencryption_util/xencryption_util.dart';

void main() {
  const originalText = """
[
  {
    "after": [
      {
        "id": "mark-rfq-data-as-new",
        "name": "Rubah status RFQ data jadi NEW",
        "steps": [
          {
            "id": "mark-data-as-new",
            "name": "Mark Data As New",
            "uses": "http://defaultflows-api:5555/v1/milestone/stage",
            "with": {
              "data": "fieldKeys",
              "idMenu": "idMenu",
              "kanbanId": "261"
            },
            "category": "data",
            "severity": "critical",
            "http_method": "POST"
          }
        ]
      }
    ],
    "action": "INSERT",
    "before": []
  },
  {
    "after": [
      {
        "id": "inventory-order-ct-vendors-create-rfq-flow-id",
        "name": "Inventory Order Close Tender Vendors Create RFQ Flow",
        "steps": [
          {
            "id": "mark-rfq-data-as-sent-step-id",
            "name": "Mark RFQ Data As Sent",
            "uses": "http://defaultflows-api:5555/v1/milestone/stage",
            "with": {
              "data": "fieldKeys",
              "idMenu": "idMenu",
              "kanbanId": "263"
            },
            "category": "data",
            "severity": "critical",
            "depends_on": [
              "inventory-order-ct-vendors-create-rfq-step-id"
            ],
            "http_method": "POST"
          },
          {
            "id": "inventory-order-ct-vendors-create-rfq-step-id",
            "name": "Inventory Order Close Tender Vendors Create RFQ Step",
            "uses": "http://defaultflows-api:5555/v1/inventory_order/create",
            "with": {
              "vendors": "vendor",
              "inventoryRequestId": "inventoryRequestId"
            },
            "category": "data",
            "severity": "critical",
            "http_method": "POST"
          }
        ]
      }
    ],
    "action": "CREATE_RFQ",
    "before": []
  }
]
""";
  const key = "h1MWf5HsXz6YuAo7etOQbFOAxFGTikyl";

  test('testEncryptionDecryption', () {
    // Encrypt the original text
    final encryptedText = XEncryptionUtil.encrypt(originalText, key.codeUnits);
    print("encryptedText: $encryptedText");

    // Decrypt the encrypted text
    final decryptedText = XEncryptionUtil.decrypt(encryptedText, key.codeUnits);

    // Check if decryption gives back the original text
    expect(decryptedText, originalText);
  });

  test('testInvalidEncryptionKey', () {
    // Encrypt the original text
    final encryptedText = XEncryptionUtil.encrypt(originalText, key.codeUnits);

    const invalidKey = "INVALID_KEY";
    expect(() {
      // Decrypt the encrypted text with invalid key
      XEncryptionUtil.decrypt(encryptedText, invalidKey.codeUnits);
    }, throwsException);
  });

  test('testRandomnessOfEncryption', () {
    // Encrypt the original text multiple times
    final encryptedText1 = XEncryptionUtil.encrypt(originalText, key.codeUnits);
    final encryptedText2 = XEncryptionUtil.encrypt(originalText, key.codeUnits);

    // Ensure that each encryption produces different results
    expect(encryptedText1, isNot(encryptedText2));
  });
}
