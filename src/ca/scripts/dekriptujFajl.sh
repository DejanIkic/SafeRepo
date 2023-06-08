#!/bin/bash

username="$1"
brojSegmenta="$2"
sifra="$3"
imeFajla="$4"

temp=../repo/tempD
lokacijaSegmenta=../repo/$brojSegmenta/$username.$imeFajla




openssl enc -d -aes256 -pass pass:$sifra -in $lokacijaSegmenta  -out $temp -base64