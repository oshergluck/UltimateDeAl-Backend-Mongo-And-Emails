
const CryptoJS = require('crypto-js');


const generateSecretKey = (length = 64) => { // 32 bytes = 256 bits
    return CryptoJS.lib.WordArray.random(length).toString(CryptoJS.enc.Base64);
};

function decryptData(encryptedData, secretKey) {
    try {
        const rawData = CryptoJS.enc.Base64.parse(encryptedData).toString(CryptoJS.enc.Utf8);
        const bytes = CryptoJS.AES.decrypt(rawData, secretKey);
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (e) {
        console.error('Error during decryption:', e);
        return '';
    }
}

const encryptData = (data,secretKey) => {
    const encryptedData = CryptoJS.AES.encrypt(data, secretKey).toString();
    // Convert to Base64 to change the format
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(encryptedData));
  };
  

  const secretKey = generateSecretKey();
    console.log("SecretENCKey is: "+secretKey);
  console.log('Hello World Encrypted is: '+encryptData('Hello World',secretKey));
const encrypted = encryptData('Hello World', secretKey);
  console.log("After Decryption: "+decryptData(encrypted, secretKey));