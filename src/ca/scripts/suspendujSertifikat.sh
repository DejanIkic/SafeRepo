#!/bin/bash

imeSertifikata="$1"
sifra="$2"

#crlnumber=""
#crlnumberFile="./crlnumber"
#read -r crlnumber < "$crlnumberFile"


openssl ca -revoke ./certs/$imeSertifikata -crl_reason certificateHold -config ./openssl.cnf -key $sifra

#openssl ca -gencrl -out ./crl/crllist$crlnumber.crl -config ./openssl.cnf
