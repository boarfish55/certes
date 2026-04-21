#!/bin/sh

set -e

fail() {
	echo "$(basename $0): $@" >&2
	exit 1
}

usage() {
	echo "Usage: $(basename $0) [-h] <command>"
	echo "       -h              Help"
	echo "       -s <config>     SSL config (default: $CERTES_SSL_CONFIG)"
	echo "       -c <config>     certes config (default: $CERTES_CONFIG)"
	echo "       -x <days>       Expiry (default: $expiry)"
	echo "       -O <org>        Set Organization name"
	echo "       -D <domain>     Set DNS domain name"
	echo "       -y              Don't ask for openssl commands"
	echo ""
	echo "Commands:"
	echo ""
	echo "        setup-root                         Create basic root CA structure"
	echo "        ca-reqs <ca cn> <proxy cn> <sans>  Create CA & proxy REQ"
	echo "        sign-ca-req                        Sign a CA REQ from STDIN"
	echo "        sign-proxy-req <sans>              Sign a proxy REQ from STDIN"
}

setup_vars()
{
	[ -z "$CERTES_SSL_CONFIG" ] && \
		CERTES_SSL_CONFIG=$CERTES_DIR/openssl.cnf
	[ -z "$CERTES_CONFIG" ] && \
		CERTES_CONFIG=$CERTES_DIR/certes.conf
	[ -z "$CERTES_MDRD_CONFIG" ] && \
		CERTES_MDRD_CONFIG=$CERTES_DIR/mdrd.conf
}

CERTES_DIR=/etc/certes
CERTES_SSL_CONFIG=""
CERTES_CONFIG=""
CERTES_MDRD_CONFIG=""
CERTES_DOMAIN=""
CERTES_ORG=""

expiry=365
do_yes=false

args=`getopt hs:d:O:D:x:yc:m: $*`
if [ $? -ne 0 ]; then
        usage
        exit 2
fi
set -- $args

while [ $# -ne 0 ]; do
	case "$1" in
		-h)
			setup_vars
			usage
			exit 0
			;;
		-c)
			CERTES_CONFIG="$2"
			shift
			shift
			;;
		-s)
			CERTES_SSL_CONFIG="$2"
			shift
			shift
			;;
		-d)
			CERTES_DIR="$2"
			shift
			shift
			;;
		-D)
			CERTES_DOMAIN="$2"
			shift
			shift
			;;
		-O)
			CERTES_ORG="$2"
			shift
			shift
			;;
		-x)
			expiry="$2"
			shift
			shift
			;;
		-y)
			do_yes=true
			shift
			;;
		--)
			shift
			break
			;;
	esac
done

export CERTES_DIR
export CERTES_DOMAIN
export CERTES_ORG

setup_vars

cd $CERTES_DIR

command="$1"
if [ -z "$command" ]; then
	usage
	exit 2
fi
shift

[ "$CERTES_DIR" = "" ] && fail "CERTES_DIR must be set"

setup_root()
{
	[ "$CERTES_DOMAIN" = "" ] && fail "CERTES_DOMAIN must be set"
	[ "$CERTES_ORG" = "" ] && fail "CERTES_ORG must be set"

	mkdir -p $CERTES_DIR/ca/certs
	echo "01" > $CERTES_DIR/ca/serial
	touch $CERTES_DIR/ca/index.txt

	# Create self-signed root certificate; in a real situation, the key
	# should be kept on a secure machine or even offline storage. The
	# certificate and CRL will need to be deployed on all agents in the
	# fleet.
	openssl req -x509 -nodes -config $CERTES_SSL_CONFIG \
		-extensions root_ext \
		-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout $CERTES_DIR/ca/key.pem \
		-out $CERTES_DIR/ca/root.pem -outform pem -days $expiry \
		-subj "/emailAddress=certes@$CERTES_DOMAIN/O=$CERTES_ORG/CN=$CERTES_ORG CA"
	openssl ca -config $CERTES_SSL_CONFIG \
		-gencrl -out $CERTES_DIR/ca/root.crl
	openssl x509 -in $CERTES_DIR/ca/root.pem -text -noout
}

ca_reqs()
{
	local ca_cn="$1"
	local proxy_cn="$2"
	local sans="$3"
	if [ -z "$ca_cn" ]; then
		fail "must specify a CN for the CA"
	fi
	if [ -z "$proxy_cn" ]; then
		proxy_cn=`hostname -f`
	fi
	if [ -z "$sans" ]; then
		sans="DNS:`hostname -f`"
	fi
	[ "$CERTES_ORG" = "" ] && fail "CERTES_ORG must be set"

	local mdrd_uid=$(egrep -o '^uid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')
	local mdrd_gid=$(egrep -o '^gid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')

	local certes_uid=$(egrep -o '^backend_uid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')
	local certes_gid=$(egrep -o '^backend_gid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')

	umask 077
	openssl req -config $CERTES_SSL_CONFIG -nodes \
		-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout $CERTES_DIR/ca_key.pem -keyform PEM \
		-out $CERTES_DIR/ca_req.pem -outform PEM \
		-subj "/O=$CERTES_ORG/CN=$ca_cn"
	[ ! -z "$certes_uid" ] && chown "$certes_uid" $CERTES_DIR/ca_key.pem
	[ ! -z "$certes_gid" ] && chgrp "$certes_gid" $CERTES_DIR/ca_key.pem

	openssl req -config $CERTES_SSL_CONFIG -nodes \
		-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-keyout $CERTES_DIR/proxy_key.pem -keyform PEM \
		-out $CERTES_DIR/proxy_req.pem -outform PEM \
		-subj "/O=$CERTES_ORG/CN=$proxy_cn" \
		-addext "subjectAltName = $sans"
	[ ! -z "$mdrd_uid" ] && chown "$mdrd_uid" $CERTES_DIR/proxy_key.pem
	[ ! -z "$mdrd_gid" ] && chgrp "$mdrd_gid" $CERTES_DIR/proxy_key.pem
	umask 022

	echo "Sign CA REQ:"
	openssl req -in $CERTES_DIR/ca_req.pem
	echo ""
	echo "Sign proxy REQ:"
	openssl req -in $CERTES_DIR/proxy_req.pem
}

sign_ca_req()
{
	local last_serial=`cat $CERTES_DIR/ca/serial`
	local req=`mktemp -t setup_ca.XXXXXX`
	echo "* Paste CA REQ here (end with Ctrl-D):"
	cat > $req
	openssl req -in $req -text
	if $do_yes; then
		yes | openssl ca -config $CERTES_SSL_CONFIG -name root_ca \
			-extensions intermediate_ca_ext \
			-in $req && \
			echo "cert written to $CERTES_DIR/ca/certs/${last_serial}.pem"
	else
		openssl ca -config $CERTES_SSL_CONFIG -name root_ca \
			-extensions intermediate_ca_ext \
			-in $req && \
			echo "cert written to $CERTES_DIR/ca/certs/${last_serial}.pem"
	fi
	rm -f $req
}

sign_proxy_req()
{
	local last_serial=`cat $CERTES_DIR/ca/serial`
	local req=`mktemp -t setup_ca.XXXXXX`
	echo "* Paste proxy REQ here (end with Ctrl-D):"
	cat > $req
	openssl req -in $req -text
	if $do_yes; then
		yes | openssl ca -config $CERTES_SSL_CONFIG -name root_ca \
			-extensions intermediate_proxy_crt_ext \
			-in $req && \
			echo "cert written to $CERTES_DIR/ca/certs/${last_serial}.pem"
	else
		openssl ca -config $CERTES_SSL_CONFIG -name root_ca \
			-extensions intermediate_proxy_crt_ext \
			-in $req && \
			echo "cert written to $CERTES_DIR/ca/certs/${last_serial}.pem"
	fi
	rm -f $req
}

case "$command" in
	setup-root)
		setup_root $@
		;;
	ca-reqs)
		ca_reqs $@
		;;
	sign-ca-req)
		sign_ca_req $@
		;;
	sign-proxy-req)
		sign_proxy_req $@
		;;
	*)
		usage
		exit 2
		;;
esac

exit 0
