#!/bin/bash

username="$1"

#zahtjev
openssl req -new -key ../users/$username/privateKey.pem -out ./reqs/$username.csr -config ./openssl.cnf -subj "/C=BA/ST=RS/L=Banja Luka/O=Elektrotehnicki fakultet/OU=ETF/CN=$username/emailAddress=$username@mail.com"

#potpis
openssl ca -in ./reqs/$username.csr -out ./certs/$username.crt -config ./openssl.cnf -keyfile ./private/private4096.key -passin pass:"sigurnost" -cert ./rootca.pem -batch

