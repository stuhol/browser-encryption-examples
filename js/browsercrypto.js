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

// For testing purposes
privatekey = '-----BEGIN PRIVATE KEY-----\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC+cyQy6GZSLXrz\
4UxJM+5VtrFJJfqxk0Kdva0zgeHxJT3e/viOI5Z7j8m5kC1T2/qohX9S4xWInB4M\
MesJ0YgclbqTjpLAuKCJeS8vFhk6EgrKZ+C0M6utdN23JUAJtqK+35wDXRPcFvcP\
rofqBuUUEhkIW5d+mTCAFgMKOXnP6CO289JZmYPuM/IqwLF3YW8K7oQVX6pGRwpH\
KprIjcIBUTK5UUtnJNKbIzKlod+b2L3R2f3pxvchACXqjJHicVICIP6XOCXBWm9B\
WScJViSXr7aw6chWkOlDO3olzOqXtgHWfnxkiifnFV/vsLxxIGFuOjdv8yYWHH2s\
SlicBLtDAgMBAAECggEAO1Bq9rvwmil2AJyrgKT+1o0mm+yLLmD5v10Co2cRMmRx\
55CrYsFsraDzp6pio5qAb5ncNLlqzHgq14t4cz9hz91GFYyy4fjebtJiQpz0UGSs\
HavKjPUGw+gA4XhlgGD0QNQtp9KGS+aPHcAyrk1lbSHR0AuOnCwjsdCpM7cA3CIa\
3sOi7DS2s/et5MBwPGfKfno+UcUIBV0/UcAs5eEgcLAoV3RXNyScbJaHTUv0HVPi\
Fb3OZ14QqCc1IxtNNEjUj74rc6R9qFfyaBQTfzWwrEmb3JmrEmgQFYBKbtIW+BB4\
/1aVUrfCUeCmo8n0ZUZNymgdjyNA0aCh4YrRQ5ITUQKBgQD508i0u4xORsyfsNmZ\
QcQFg0IuZM9hEyPDaY7pMm+yr883sLe8MoVDuUUrceUAXfbGNy6kvqqgy1NGYX/J\
0hZ8y3QrEC2Pn8wiDtpwHDibgZ8x5dUiTPtxgkdV/Vk77OpYG+CxQyJjiwPRXEVV\
wC/TOK3i/nOmA3bQZ33NC5o+ewKBgQDDJ8ffbBzmreiCWDXFtVuBAXY3qdLzXj3+\
7F0816aAxyi9+F/IB0kCa0fmEVGRYDkxhDhVgP6C7qRw7wz0BGOaEdROjo4M9V/c\
V3ndtAu25ArfcjMXvp36UvdHEwK3ge1moVlXkyzUmz6KHirEwVYPJa7yaO8dR2tZ\
VXJEuHi/2QKBgQDUbnh47g01NlCi7W9qORjkkyNAbepFIlBDxsuFkaSXLZWnRjZF\
6jOVTcH6WkOel0fSbnPUFGjkh2ANNbTCuUjz3tCuGXiUaw3aXAT0VZrw6Dyk4kjk\
fM9GSsA750zsft0aBMKAGJTyTe/2I161ttEz6zs5DKLsJH/wYEABjf8fZwKBgQCc\
HFFlpy1DVnB8/CUfn6CwBMRVaLMH3SaIqvk2t2dI8ofj1zB/aVx84+ai4s22FhwK\
QTNzKnntsQq4EHHzLSOj1olXwe9d7FcfgpZIxELurWMJNWgroV7sJLwMDegJdZS7\
mWxHgsLE297eS514wROfkExvO4OzjzMPRivfTxXAmQKBgQDYh03+wZFmoyoeR2RE\
XZ+aPTNtIL+Wycj+675aixL+xQhb98BTnlwysmV+Nb7l9RXN2TgmzQqiWz3OM4ps\
p9O/0nUX97c2ujwf8GJxFrKg0RSyPGkOIOgcJHhaNWdert6K7ZgKScns9wMJ1xH+\
z8s4axAxANhjeg2CCV00LPEZyg==\
-----END PRIVATE KEY-----'

privkeyBuffer = buffer.Buffer.from(privatekey, 'ascii');

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



//For Testing purposes
plaintextBuffer = buffer.Buffer.from("test", 'ascii');
ivBuffer = buffer.Buffer.from("6cc22530b5ccef1e74d065fc7d754532", 'hex');
                               
/*
Encrypt with public key

*/
function asymmetricEncrypt(plaintext, publickey, iv, callback) {

    keyAlgo = {name: "RSA-OAEP", hash: "SHA-256"};
    encryptAlgo = {name: "RSA-OAEP"};

    window.crypto.subtle.importKey(
        'spki',
        publickey,
        keyAlgo,
        true,
        ['encrypt']
    ).then(function (key) {
        console.log(key);
        return window.crypto.subtle.encrypt(
            encryptAlgo,
            key,
            plaintext
        )
    }).then(function (ciphertext) {
        callback(ciphertext);
    });

}

/*
Decrypt with private key

*/
function asymmetricDecrypt(ciphertext, privatekey, iv, callback) {

    keyAlgo = {name: "RSA-OAEP", hash: "SHA-256"};
    decryptAlgo = {name: "RSA-OAEP"};

    window.crypto.subtle.importKey(
        'pkcs8',
        privatekey,
        keyAlgo,
        true,
        ['decrypt']
    ).then(function (key) {
        return window.crypto.subtle.decrypt(
            decryptAlgo,
            key,
            cipertext
        )
    }).then(function (plaintext) {
        console.log(plaintext);
    });
}