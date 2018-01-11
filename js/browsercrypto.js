// Hex of DER encoded pubkey
pubkey = '30820122300d06092a864886f70d01010105000382010f003082010a0282\
010100be732432e866522d7af3e14c4933ee55b6b14925fab193429dbdad\
3381e1f1253ddefef88e23967b8fc9b9902d53dbfaa8857f52e315889c1e\
0c31eb09d1881c95ba938e92c0b8a089792f2f16193a120aca67e0b433ab\
ad74ddb7254009b6a2bedf9c035d13dc16f70fae87ea06e5141219085b97\
7e99308016030a3979cfe823b6f3d2599983ee33f22ac0b177616f0aee84\
155faa46470a472a9ac88dc2015132b9514b6724d29b2332a5a1df9bd8bd\
d1d9fde9c6f7210025ea8c91e271520220fe973825c15a6f415927095624\
97afb6b0e9c85690e9433b7a25ccea97b601d67e7c648a27e7155fefb0bc\
7120616e3a376ff326161c7dac4a589c04bb430203010001';

pubkeyBuffer = buffer.Buffer.from(pubkey, 'hex');

function genRandomHexString(size) {
    var salt = new Uint8Array(size);

    crypto.getRandomValues(salt);

    saltHex = buffer.Buffer.from(salt).toString('hex');

    return saltHex;
}

function genSalt() {
    return genRandomHexString(32);
}

function genIV() {
    return genRandomHexString(16);
}

/*
Generate symmetric key using PBKDF2
salt Uint8Array - Salt to use for password derivation
passphrase Uint8Array - Passphrase to use for password derivation
callback - Callback with key parameter as Uint8Array
*/
function genPBKDFKey(salt, passphrase, callback) {

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
            plaintext
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
function symmetricDecrypt(ciphertext, key, iv, callback) {

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
            ciphertext
        )
    }).then(function (plaintext) {
        callback(plaintext);
    });

}

//For Testing purposes
function genRSAKey() {
    window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}
        },
        true,
        ["encrypt", "decrypt"]
    ).then(function(keyPair) {
        keypair = keyPair;
    });
}

function genAESKey(callback) {

    var encryptAlgo = {
        name: "AES-CBC",
        length: 256
    }

    window.crypto.subtle.generateKey(
        encryptAlgo,
        true,
        ['encrypt']
    ).then(function(key) {
        callback(key);
    });
}

/*
Encrypt with public key
plaintext 
*/
function asymmetricEncrypt(plaintext, publickey, callback) {

    var keyAlgo = {name: "RSA-OAEP", hash: "SHA-256"};
    var encryptAlgo = {name: "RSA-OAEP"};

    window.crypto.subtle.importKey(
        'spki',
        publickey,
        keyAlgo,
        true,
        ['encrypt']
    ).then(function (key) {
        return window.crypto.subtle.encrypt(
            encryptAlgo,
            key,
            plaintext
        )
    }).then(function (ciphertext) {
        callback(ciphertext);
    });

}