function genRandomHexString(size) {
    var salt = new Uint8Array(size);

    crypto.getRandomValues(salt);

    saltHex = buffer.Buffer.from(salt).toString('hex');

    return saltHex;
}

function genSalt() {
    $("#user_salt").val(genRandomHexString(32));
}

function genIV() {
    $("#iv").val(genRandomHexString(16));
}

/*
Generate symmetric key using PBKDF2
salt Uint8Array - Salt to use for password derivation
passphrase Uint8Array - Passphrase to use for password derivation
callback - Callback with key parameter as Uint8Array
*/
function genKey(salt, passphrase, callback) {

    window.crypto.subtle.importKey(
        'raw', 
        passphrase, 
        {name: 'PBKDF2'}, 
        false, 
        ['deriveBits', 'deriveKey']
      ).then(function(key) {
      
        return window.crypto.subtle.deriveKey(
          { "name": 'PBKDF2',
            "salt": salt,
            // don't get too ambitious, or at least remember
            // that low-power phones will access your app
            "iterations": 5000,
            "hash": 'SHA-256'
          },
          key,
      
          // Note: for this demo we don't actually need a cipher suite,
          // but the api requires that it must be specified.s
      
          // For AES the length required to be 128 or 256 bits (not bytes)
          { "name": 'AES-CBC', "length": 256 },
      
          // Whether or not the key is extractable (less secure) or not (more secure)
          // when false, the key can only be passed as a web crypto object, not inspected
          true,
      
          // this web crypto object will only be allowed for these functions
          [ "encrypt", "decrypt" ]
        )
      }).then(function (webKey) {
      
        return crypto.subtle.exportKey("raw", webKey);
      
      }).then(function (key) {

        callback(key);

      });

}

/* 
Encrypt with symmetric key
plaintext Uint8Array - Plaintext to encrypt
key Uint8Array(32) - Key to use to encrypt plaintext
iv Uint8Array(16) - IV to use for AES
callback - Callback with ciphertext parameter as Uint8Array
*/
function symmetricEncrypt(plaintext, key, iv, callback) {

    algo = {name: 'AES-CBC', iv: iv};

    window.crypto.subtle.importKey(
        'raw', 
        key, 
        algo, 
        false, 
        ['encrypt']
    ).then(function (cryptokey) {
        return window.crypto.subtle.encrypt(
            algo,
            cryptokey,
            plaintextBuffer
        )
    }).then(function (ciphertext) {
        callback(ciphertext);
    });

}

/* 
Decrypt with symmetric key
ciphertext Uint8Array - Ciphertext to decrypt
key Uint8Array(32) - Key to use to decrypt ciphertext
iv Uint8Array(16) - IV to use for AES
callback - Callback with plaintext parameter as Uint8Array
*/
function symmetricDecrypt(plaintext, key, iv, callback) {

    algo = {name: 'AES-CBC', iv: iv};

    window.crypto.subtle.importKey(
        'raw', 
        key, 
        algo, 
        false, 
        ['decrypt']
    ).then(function (cryptokey) {
        return window.crypto.subtle.decrypt(
            algo,
            cryptokey,
            ciphertextBuffer
        )
    }).then(function (plaintext) {
        callback(plaintext);
    });

}

