#!/bin/bash

# "Script to Generate RSA Public/Private key Pair"
# "Written by: Mohamed Aboutabl"

#echo "Amal sends an encrypted file to Basim using a symmetric session key"
#echo "The session key is exchanged with Basim using Basim's RSA public key"
echo
echo

# Generate  2048-bit public/private key-pair for Amal
cd amal
rm -f *.pem 
openssl genpkey .... missing stuff goes here
openssl rsa     -in  amal_priv_key.pem    -pubout -out amal_pub_key.pem

echo "====================================="
echo "Here is Amal's RSA Key Information"
echo "====================================="
openssl  .... missing stuff goes here
echo
echo "====================================="

# Now, share Amal's public key with Basim using Linux Symbolic Links
cd ../basim
rm -f *.pem
ln -s  ../amal/amal_pub_key.pem  amal_pubKey.pem

#back to dispatcher's folder
cd ..
