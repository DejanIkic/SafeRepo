#!/bin/bash

username="$1"
imeFajla="$2"
fajl="$3"

kljuc="../users/$username/privateKey.pem"
potpis="../signedFiles/$username.$imeFajla.signed"

openssl dgst -sha1 -sign $kljuc -out $potpis $fajl
