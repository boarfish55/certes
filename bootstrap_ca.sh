#!/bin/sh

rm -rf ca
mkdir -p ca/certs ca/private
chmod 700 ca/private
echo "01" > ca/serial
touch ca/index.txt

# Create self-signed root certificate
openssl req -x509 -nodes -config overnet.cnf -newkey rsa \
	-out ca/overnet.pem -outform PEM -days 3650 -section root_req

# Create a "client1" cert request
rm -f client1/*
mkdir -p client1
openssl req -nodes -config overnet.cnf -newkey rsa \
	-keyout client1/key.pem -keyform PEM \
	-out client1/req.pem -outform PEM \
	-subj "/O=Overnet/CN=client1.overnet.ca"

# Sign client1 cert & verify
yes | openssl ca -config overnet.cnf -in client1/req.pem -out client1/cert.pem
openssl verify -CAfile ca/overnet.pem client1/cert.pem

# Create a "client2" cert request
rm -f client2/*
mkdir -p client2
openssl req -nodes -config overnet.cnf -newkey rsa \
	-keyout client2/key.pem -keyform PEM \
	-out client2/req.pem -outform PEM \
	-subj "/O=Overnet/CN=client2.overnet.ca"

# Sign and revoke client2 cert
yes | openssl ca -config overnet.cnf -in client2/req.pem -out client2/cert.pem
openssl ca -config overnet.cnf -revoke client2/cert.pem

# Generate CRL
openssl ca -config overnet.cnf -gencrl -out ca/overnet.crl
openssl verify -CAfile ca/overnet.pem -CRLfile ca/overnet.crl \
	-crl_check client2/cert.pem

# View it and verify signature
openssl crl -in ca/overnet.crl -text -noout -CAfile ca/overnet.pem
