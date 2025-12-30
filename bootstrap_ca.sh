#!/bin/sh

set -e

DOMAIN=example.com
ORG=Example

rm -rf ca
mkdir -p ca/certs
echo "01" > ca/serial
touch ca/index.txt

# Create self-signed root certificate; in a real situation, the key should
# be kept on a secure machine or even offline storage. The certificate and
# CRL will need to be deployed on all agents in the fleet.
openssl req -x509 -nodes -config certalator.cnf -section root_ca \
	-newkey ed25519 -keyout ca/key.pem \
	-out ca/root.pem -outform PEM -days 365 \
	-extensions root_ext \
	-subj "/emailAddress=cert@$DOMAIN/O=$ORG/CN=$ORG CA"

# Each "authority" can create and renew certs. They are intermediate
# signing authorities.
rm -rf authority1
mkdir -p authority1/certs authority1/trust_store
echo "01" > authority1/serial
touch authority1/index.txt
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout authority1/key.pem -keyform PEM \
	-out authority1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=authority1.$DOMAIN" \
	-addext "subjectAltName = DNS:authority1.$DOMAIN"
# Sign authority1 cert & verify
yes | openssl ca -config certalator.cnf -name root_ca \
	-in authority1/req.pem -extensions intermediate_ca_ext \
	-out authority1/cert.pem
openssl verify -CAfile ca/root.pem authority1/cert.pem
cp ca/root.pem authority1/trust_store/
cp authority1/cert.pem authority1/trust_store/
openssl rehash authority1/trust_store

# Create a "ca-proxy" cert request for an mdrd daemon
rm -rf proxy1
mkdir -p proxy1
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout proxy1/key.pem -keyform PEM \
	-out proxy1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=proxy1.$DOMAIN" \
	-addext "subjectAltName=DNS:proxy1.$DOMAIN,IP:172.16.5.14,IP:fe80::c2a5:e8ff:fe29:5874"
# Sign proxy1 cert & verify
yes | openssl ca -config certalator.cnf -in proxy1/req.pem \
	-out proxy1/cert.pem -extensions intermediate_proxy_crt_ext
openssl verify -CApath authority1/trust_store proxy1/cert.pem

# Create a "client1" cert request
rm -rf client1
mkdir -p client1
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout client1/key.pem -keyform PEM \
	-out client1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=client1.$DOMAIN" \
	-addext "subjectAltName=DNS:client1.$DOMAIN,IP:172.16.5.14,IP:fe80::c2a5:e8ff:fe29:5874"
# Sign client1 cert & verify
yes | openssl ca -config certalator.cnf -in client1/req.pem \
	-out client1/cert.pem -extensions intermediate_client_crt_ext
openssl verify -CApath authority1/trust_store client1/cert.pem

# Create a "client2" cert request
rm -rf client2
mkdir -p client2
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout client2/key.pem -keyform PEM \
	-out client2/req.pem -outform PEM \
	-subj "/O=$ORG/CN=client2.$DOMAIN" \
	-addext "subjectAltName = DNS:client2.$DOMAIN"

# Sign and revoke client2 cert
yes | openssl ca -config certalator.cnf -in client2/req.pem \
	-out client2/cert.pem -extensions intermediate_client_crt_ext
openssl verify -CApath authority1/trust_store client2/cert.pem
openssl ca -config certalator.cnf -revoke client2/cert.pem

# Generate CRL
openssl ca -config certalator.cnf -section root_ca \
	-gencrl -out ca/root.crl
# View it and verify signature
openssl crl -in ca/root.crl -text -noout -CAfile ca/root.pem

# Test and see if client2's cert is indeed revoked, as it should
openssl verify -CApath authority1/trust_store -CRLfile ca/root.crl \
	-crl_check client2/cert.pem || true

echo "All good!"
