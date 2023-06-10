#!/bin/bash

sifra="$1"

openssl ca -gencrl -out ./crl/crllist1.crl -config ./openssl.cnf -key $sifra
