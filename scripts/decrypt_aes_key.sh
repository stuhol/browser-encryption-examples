#!/bin/bash

OPENSSL_CMD=/usr/local/opt/openssl\@1.1/bin/openssl

if [[ $# != 2 ]]; then
    echo "Usage: $0 <private_key> <encrypted hexstring>"
    exit
fi

aeskey=$(echo -n -e $2 | xxd -p -r | eval $OPENSSL_CMD pkeyutl -decrypt -inkey $1 -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256)

echo $aeskey
