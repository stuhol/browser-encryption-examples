#!/bin/bash

OPENSSL_CMD=/usr/local/opt/openssl\@1.1/bin/openssl

if [[ $# != 3 ]]; then
    echo "Usage: $0 <RSA encrypted AES key hexstring> <iv hexstring> <encrypted hexstring>"
    exit
fi

aeskey=$(./decrypt_aes_key.sh ../pki/private_key.pem $1)

echo
echo "Decrypted AES Key: $aeskey"
echo

plaintext=$(./decrypt_aes_ciphertext.sh $aeskey $2 $3)

echo
echo "Plaintext: $plaintext"
echo

