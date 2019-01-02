#!/bin/bash -x
set -e
for C in `echo root-ca intermediate`; do
  mkdir $C
  cd $C
  mkdir certs crl newcerts private
  cd ..
  echo 1000 > $C/serial
  touch $C/index.txt $C/index.txt.attr
  echo '
[ ca ]
default_ca = CA_default
[ CA_default ]
dir            = '$C'    # Where everything is kept
certs          = $dir/certs                # Where the issued certs are kept
crl_dir        = $dir/crl                # Where the issued crl are kept
database       = $dir/index.txt            # database index file.
new_certs_dir  = $dir/newcerts            # default place for new certs.
certificate    = $dir/cacert.pem                # The CA certificate
serial         = $dir/serial                # The current serial number
crl            = $dir/crl.pem                # The current CRL
private_key    = $dir/private/ca.key.pem       # The private key
RANDFILE       = $dir/.rnd     # private random number file
nameopt        = default_ca
certopt        = default_ca
policy         = policy_match
default_days   = 18200
default_md     = sha256
[ policy_match ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:TRUE
' > $C/openssl.conf
done
openssl genrsa -out root-ca/private/ca.key 2048
openssl req -config root-ca/openssl.conf -new -x509 -days 18250 -key root-ca/private/ca.key -sha256 -extensions v3_req -out root-ca/certs/ca.crt -subj "/CN=netopeer2 test $1 Root CA"
openssl genrsa -out intermediate/private/intermediate.key 2048
openssl req -config intermediate/openssl.conf -sha256 -new -key intermediate/private/intermediate.key -out intermediate/certs/intermediate.csr -subj "/CN=netopeer2 test $1 Intermediate CA"
openssl ca -batch -config root-ca/openssl.conf -keyfile root-ca/private/ca.key -cert root-ca/certs/ca.crt -extensions v3_req -notext -md sha256 -in intermediate/certs/intermediate.csr -out intermediate/certs/intermediate.crt
mkdir out

openssl req -new -keyout out/$1.key -out out/$1.request -days 18200 -nodes -subj "/CN=netopeer2 test $1 Leaf" -newkey rsa:2048
openssl ca -batch -config root-ca/openssl.conf -keyfile intermediate/private/intermediate.key -cert intermediate/certs/intermediate.crt -out out/$1.crt -infiles out/$1.request
