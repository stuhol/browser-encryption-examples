// salt should be Uint8Array or ArrayBuffer
// var saltBuffer = Unibabel.hexToBuffer('e85c53e7f119d41fd7895cdc9d7bb9dd');
var saltBuffer = buffer.Buffer.from('e85c53e7f119d41fd7895cdc9d7bb9dd');

console.log("Salt: ");
console.log(saltBuffer);

// don't use naïve approaches for converting text, otherwise international
// characters won't have the correct byte sequences. Use TextEncoder when
// available or otherwise use relevant polyfills
// var passphraseKey = Unibabel.utf8ToBuffer("I hëart årt and £$¢!");
var passphraseKey = buffer.Buffer.from("passphrase");

console.log("Passphrase: ");
console.log(passphraseKey);


// You should firstly import your passphrase Uint8array into a CryptoKey
window.crypto.subtle.importKey(
  'raw', 
  passphraseKey, 
  {name: 'PBKDF2'}, 
  false, 
  ['deriveBits', 'deriveKey']
).then(function(key) {

  console.log(key);

  return window.crypto.subtle.deriveKey(
    { "name": 'PBKDF2',
      "salt": saltBuffer,
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

  console.log("Webkey:");
  console.log(webKey);

  return crypto.subtle.exportKey("raw", webKey);

}).then(function (key) {

    var proofOfSecret = key;
    // this proof-of-secret / secure-remote password
    // can now be sent in place of the user's password

    //var array = buffer.Buffer.from(buffer);

    console.log(buffer.Buffer.from(key));

});