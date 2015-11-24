#!/bin/bash

# Generate public/private key for logger/u (untrusted)
openssl genrsa -out U_Priv.pem 1024
# Extract public key
openssl rsa -in U_Priv.pem -pubout > U_Pub.pub


# Generate public/private key for server/t (trusted)
openssl genrsa -out T_Priv.pem 1024
# Extract public key
openssl rsa -in T_Priv.pem -pubout > T_Pub.pub