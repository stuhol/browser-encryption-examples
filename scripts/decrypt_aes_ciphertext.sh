#!/bin/bash

OPENSSL_CMD=/usr/local/opt/openssl\@1.1/bin/openssl

if [[ $# != 3 ]]; then
    echo "Usage: $0 <key hexstring> <iv hexstring> <encrypted hexstring>"
    exit
fi

plaintext=$(echo -n -e $3 | xxd -p -r | eval $OPENSSL_CMD aes-256-cbc -d -K $1 -iv $2)

echo $plaintext
