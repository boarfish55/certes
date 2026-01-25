#!/bin/sh

set -e

DOMAIN=example.com
ORG=Example

basedir=testdata

rm -rf $basedir

mkdir -p $basedir/ca/certs
echo "01" > $basedir/ca/serial
touch $basedir/ca/index.txt

# Create self-signed root certificate; in a real situation, the key should
# be kept on a secure machine or even offline storage. The certificate and
# CRL will need to be deployed on all agents in the fleet.
openssl req -x509 -nodes -config certalator.cnf -section root_ca \
	-newkey ed25519 -keyout $basedir/ca/key.pem \
	-out $basedir/ca/root.pem -outform PEM -days 365 \
	-extensions root_ext \
	-subj "/emailAddress=cert@$DOMAIN/O=$ORG/CN=$ORG CA"

# Each "authority" can create and renew certs. They are intermediate
# signing authorities.
mkdir -p $basedir/authority1/certs \
	$basedir/authority1/trust_store \
	$basedir/authority1/crl_store
echo "01" > $basedir/authority1/serial
touch $basedir/authority1/index.txt
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout $basedir/authority1/key.pem -keyform PEM \
	-out $basedir/authority1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=authority1.$DOMAIN" \
	-addext "subjectAltName = DNS:authority1.$DOMAIN,DNS:localhost"
# Sign authority1 cert & verify
yes | openssl ca -config certalator.cnf -name root_ca \
	-in $basedir/authority1/req.pem -extensions intermediate_ca_ext \
	-out $basedir/authority1/cert.pem
openssl verify -CAfile $basedir/ca/root.pem $basedir/authority1/cert.pem
cp $basedir/ca/root.pem $basedir/authority1/trust_store/
cp $basedir/authority1/cert.pem $basedir/authority1/trust_store/
openssl rehash $basedir/authority1/trust_store

# Create a "ca-proxy" cert request for an mdrd daemon
mkdir -p $basedir/proxy1
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout $basedir/proxy1/key.pem -keyform PEM \
	-out $basedir/proxy1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=proxy1.$DOMAIN" \
	-addext "subjectAltName=DNS:proxy1.$DOMAIN,DNS:localhost"
# Sign proxy1 cert & verify
yes | openssl ca -config certalator.cnf -in $basedir/proxy1/req.pem \
	-out $basedir/proxy1/cert.pem -extensions intermediate_proxy_crt_ext
openssl verify -CApath $basedir/authority1/trust_store $basedir/proxy1/cert.pem
cat $basedir/authority1/cert.pem >> $basedir/proxy1/cert.pem

# Create a "client1" cert request
mkdir -p $basedir/client1
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout $basedir/client1/key.pem -keyform PEM \
	-out $basedir/client1/req.pem -outform PEM \
	-subj "/O=$ORG/CN=client1.$DOMAIN" \
	-addext "subjectAltName=DNS:client1.$DOMAIN,DNS:`hostname -f`,IP:172.16.5.14,IP:fe80::c2a5:e8ff:fe29:5874"
# Sign client1 cert & verify
yes | openssl ca -config certalator.cnf -in $basedir/client1/req.pem \
	-out $basedir/client1/cert.pem -extensions intermediate_client_crt_ext
openssl verify -CApath $basedir/authority1/trust_store $basedir/client1/cert.pem
cat $basedir/authority1/cert.pem >> $basedir/client1/cert.pem

# Create a "client2" cert request
mkdir -p $basedir/client2
openssl req -nodes -config certalator.cnf -newkey ed25519 \
	-keyout $basedir/client2/key.pem -keyform PEM \
	-out $basedir/client2/req.pem -outform PEM \
	-subj "/O=$ORG/CN=client2.$DOMAIN" \
	-addext "subjectAltName = DNS:client2.$DOMAIN"

# Sign and revoke client2 cert
yes | openssl ca -config certalator.cnf -in $basedir/client2/req.pem \
	-out $basedir/client2/cert.pem -extensions intermediate_client_crt_ext
openssl verify -CApath $basedir/authority1/trust_store $basedir/client2/cert.pem
cat $basedir/authority1/cert.pem >> $basedir/client2/cert.pem
openssl ca -config certalator.cnf -revoke $basedir/client2/cert.pem
# Generate CRL
openssl ca -config certalator.cnf \
	-gencrl -out $basedir/authority1/authority1.crl
# View it and verify signature
openssl crl -in $basedir/authority1/authority1.crl -text -noout \
	-CApath $basedir/authority1/trust_store

# Generate root CRL
openssl ca -config certalator.cnf -section root_ca \
	-gencrl -out $basedir/ca/root.crl
# View it and verify signature
openssl crl -in $basedir/ca/root.crl -text -noout -CAfile $basedir/ca/root.pem

cp $basedir/ca/root.crl $basedir/authority1/crl_store/
cp $basedir/authority1/authority1.crl $basedir/authority1/crl_store/

# Test and see if client2's cert is indeed revoked, as it should
openssl verify -CApath $basedir/authority1/trust_store \
	-CRLfile $basedir/ca/root.crl \
	-CRLfile $basedir/authority1/authority1.crl \
	-crl_check $basedir/client2/cert.pem || true

# Load up a sample bootstrap entry for our tests. The key should
# match our sample config.
./certalator -config certalator_authority.conf.sample init-db
now=`date +%s`
valid_until=$((now + 3600))
not_after_sec=$((now + 31536000))
sqlite3 $basedir/authority1/certdb.sqlite "insert into
	bootstrap(bootstrap_key, valid_until_sec, subject, flags,
	not_before_sec, not_after_sec) values(
	unhex('9CBEBB889B04FFA750446F996589A0666DDB4B2336DA94A53B65183182DFC6FC4AA5710B5B755FAD916B9CF7DB2CFB72'),
	$valid_until,
	'/O=Example/CN=example/emailAddress=cert@example.com',
	1, $now, $not_after_sec);"

# client3 will be used to test the full bootstrap process, everything
# is generated by certalator; REQ, key and cert bootstrap.
mkdir -p $basedir/client3

echo "All good!"
