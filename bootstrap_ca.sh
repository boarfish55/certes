#!/bin/sh

mkdir -p ca
cd ca
mkdir -p certs private
chmod 700 private
echo "01" > serial
touch index.txt

# Create self-signed root certificate
openssl req -x509 -nodes -config ../overnet.cnf -newkey rsa \
        -out overnet.pem -outform PEM -days 3650 && \
	openssl x509 -in overnet.pem -text -noout
