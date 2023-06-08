#!/bin/bash

username="$1"
imeFajla="$2"
fajl="$3"

kljuc="../users/$username/privateKey.pem"
potpis="../signedFiles/$username.$imeFajla.signed"


#generisanje javnog kljuca
javniKljuc="../users/$username/public.key"

if [[ -f "$javniKljuc" ]]; then
  #echo "Public key file already exists for username: $username"
  true
else
  openssl rsa -pubout -in $kljuc -out $javniKljuc
fi


openssl dgst -sha1 -verify $javniKljuc -signature $potpis  $fajl

