function generateRSAKeyPair() {
  return new Promise((resolve, reject) => {
    // Generate RSA key pair
    window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: { name: 'SHA-256' }
      },
      true,
      ['encrypt', 'decrypt']
    ).then((keyPair) => {
      // Export public key
      return window.crypto.subtle.exportKey('spki', keyPair.publicKey).then((publicKey) => {
        // Export private key
        return window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey).then((privateKey) => {
          // Convert to Base64
          const publicKeyBase64 = arrayBufferToBase64(publicKey);
          const privateKeyBase64 = arrayBufferToBase64(privateKey);

          // Resolve with keys
          if (window.flutterJsBridge) {
              window.flutterJsBridge.sendStringToFlutter({ publicKey: publicKeyBase64, privateKey: privateKeyBase64 });
            }
          resolve({ publicKey: publicKeyBase64, privateKey: privateKeyBase64 });
        });
      });
    }).catch((error) => {
      reject(error);
    });
  });
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}


