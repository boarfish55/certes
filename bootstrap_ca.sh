#!/bin/sh

rm -rf ca
mkdir -p ca/certs ca/private
chmod 700 ca/private
echo "01" > ca/serial
touch ca/index.txt

# Create self-signed root certificate; in a real situation, the key should
# be kept on a secure machine or even offline storage. The certificate and
# CRL will need to be deployed on all agents in the fleet.
openssl req -x509 -nodes -config overnet_authority.cnf -newkey rsa \
	-keyout ca/private/overnet_key.pem \
	-out ca/overnet.pem -outform PEM -days 365 \
	-extensions root_ext \
	-subj "/emailAddress=cert@overnet.ca/O=Overnet/CN=Overnet CA"

# Each "authority" can create and renew certs. They are intermediate
# signing authorities.
rm -f authority1/*
mkdir -p authority1
openssl req -nodes -config overnet_authority.cnf -newkey rsa \
	-keyout authority1/key.pem -keyform PEM \
	-out authority1/req.pem -outform PEM \
	-subj "/O=Overnet/CN=authority1.overnet.ca" \
	-addext "subjectAltName = DNS:authority1.overnet.ca"
# Sign authority1 cert & verify
yes | openssl ca -config overnet.cnf -in authority1/req.pem -out authority1/cert.pem
openssl verify -CAfile ca/overnet.pem authority1/cert.pem

# Create a "client1" cert request
rm -f client1/*
mkdir -p client1
openssl req -nodes -config overnet.cnf -newkey rsa \
	-keyout client1/key.pem -keyform PEM \
	-out client1/req.pem -outform PEM \
	-subj "/O=Overnet/CN=client1.overnet.ca" \
	-addext "subjectAltName = DNS:client1.overnet.ca"
# Sign client1 cert & verify
yes | openssl ca -config overnet.cnf -in client1/req.pem -out client1/cert.pem
openssl verify -CAfile ca/overnet.pem client1/cert.pem

# Create a "client2" cert request
rm -f client2/*
mkdir -p client2
openssl req -nodes -config overnet.cnf -newkey rsa \
	-keyout client2/key.pem -keyform PEM \
	-out client2/req.pem -outform PEM \
	-subj "/O=Overnet/CN=client2.overnet.ca" \
	-addext "subjectAltName = DNS:client2.overnet.ca"

# Sign and revoke client2 cert
yes | openssl ca -config overnet.cnf -in client2/req.pem -out client2/cert.pem
openssl verify -CAfile ca/overnet.pem client2/cert.pem
openssl ca -config overnet.cnf -revoke client2/cert.pem

# Generate CRL
openssl ca -config overnet.cnf -gencrl -out ca/overnet.crl
# View it and verify signature
openssl crl -in ca/overnet.crl -text -noout -CAfile ca/overnet.pem

# Test and see if client2's cert is indeed revoked, as it should
openssl verify -CAfile ca/overnet.pem -CRLfile ca/overnet.crl \
	-crl_check client2/cert.pem

