#!/bin/bash

userCert="$1"

openssl verify -crl_check -CAfile ./rootca.pem -CRLfile ./crl/crllist1.crl ./certs/$userCert
