#!/bin/bash

username="$1"
brojSegmenta="$2"
sifra="$3"
imeFajla="$4"


temp="../repo/temp"
lokacijaSegmenta="../repo/$brojSegmenta/$username.$imeFajla"

openssl enc -aes256 -pass pass:$sifra -in $temp -out $lokacijaSegmenta -base64