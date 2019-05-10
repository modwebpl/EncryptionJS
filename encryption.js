export class encryption {

  get encryptMethodLength() {
    let encryptMethod = this.encryptMethod, aesNumber = encryptMethod.match(/\d+/)[0];
    return parseInt(aesNumber);
  }

  get encryptKeySize() {
    let aesNumber = this.encryptMethodLength;
    return parseInt(aesNumber / 8);
  }

  get encryptMethod() {
    return 'AES-256-CBC';
  }

  decrypt(encryptedString, key) {
    let json = JSON.parse(CryptoJS.enc.Utf8.stringify(CryptoJS.enc.Base64.parse(encryptedString)));
    let salt = CryptoJS.enc.Hex.parse(json.salt);
    let iv = CryptoJS.enc.Hex.parse(json.iv);
    let encrypted = json.ciphertext;
    let iterations = parseInt(json.iterations);
    
    if (iterations <= 0) iterations = 999;
    
    let encryptMethodLength = (this.encryptMethodLength / 4);// example: AES number is 256 / 4 = 64
    let hashKey = CryptoJS.PBKDF2(key, salt, {
      'hasher': CryptoJS.algo.SHA512,
      'keySize': (encryptMethodLength / 8),
      'iterations': iterations
    });

    let decrypted = CryptoJS.AES.decrypt(encrypted, hashKey, {'mode': CryptoJS.mode.CBC, 'iv': iv});
    return decrypted.toString(CryptoJS.enc.Utf8);
  }


  encrypt(string, key) {
    let iv = CryptoJS.lib.WordArray.random(16);// the reason to be 16, please read on `encryptMethod` property.

    let salt = CryptoJS.lib.WordArray.random(256);
    let iterations = 999;
    let encryptMethodLength = (this.encryptMethodLength / 4);// example: AES number is 256 / 4 = 64
    let hashKey = CryptoJS.PBKDF2(key, salt, {
      'hasher': CryptoJS.algo.SHA512,
      'keySize': (encryptMethodLength / 8),
      'iterations': iterations
    });

    let encrypted = CryptoJS.AES.encrypt(string, hashKey, {'mode': CryptoJS.mode.CBC, 'iv': iv});
    let encryptedString = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);

    let output = {
      'ciphertext': encryptedString,
      'iv': CryptoJS.enc.Hex.stringify(iv),
      'salt': CryptoJS.enc.Hex.stringify(salt),
      'iterations': iterations
    };

    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(JSON.stringify(output)));
  }
}
