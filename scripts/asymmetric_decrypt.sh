#!/bin/bash

OPENSSL_CMD=/usr/local/opt/openssl\@1.1/bin/openssl

if [[ $# != 4 ]]; then
    echo "Usage: $0 <RSA private key PEM path> <RSA encrypted AES key hexstring> <iv hexstring> <encrypted hexstring>"
    exit
fi

aeskey=$(./decrypt_aes_key.sh $1 $2)

echo
echo "Decrypted AES Key: $aeskey"
echo

plaintext=$(./decrypt_aes_ciphertext.sh $aeskey $3 $4)

echo
echo "Plaintext: $plaintext"
echo

