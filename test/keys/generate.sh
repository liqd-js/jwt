#!/bin/bash

cd "$(dirname "$0")"

openssl genrsa -des3 -passout pass:P455PHR45E -out rsa.2048.pem 2048
openssl rsa -in rsa.2048.pem -passin pass:P455PHR45E -outform PEM -out rsa.2048.key
openssl rsa -in rsa.2048.pem -passin pass:P455PHR45E -outform PEM -pubout -out rsa.2048.pub

openssl ecparam -name secp256r1 -genkey -noout -out ec.256.key
openssl ec -in ec.256.key -pubout -out ec.256.pub

openssl ecparam -name secp384r1 -genkey -noout -out ec.384.key
openssl ec -in ec.384.key -pubout -out ec.384.pub

openssl ecparam -name secp521r1 -genkey -noout -out ec.521.key
openssl ec -in ec.521.key -pubout -out ec.521.pub
