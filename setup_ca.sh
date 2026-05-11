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
	echo "       -C <cn>         Set REQ commonName"
	echo "       -O <org>        Set REQ organizatioName"
	echo "       -E <email>      Set REQ emailAddress"
	echo "       -y              Don't ask for openssl commands"
	echo "       -d <dir>        Base directory for CA structure"
	echo "       -p              Don't encrypt root CA key"
	echo ""
	echo "Commands:"
	echo ""
	echo "        setup-root      Create basic root CA structure"
	echo "        ca-reqs <sans>  Create CA & proxy REQ"
	echo "        sign-ca-req     Sign a CA REQ from STDIN"
	echo "        sign-proxy-req  Sign a proxy REQ from STDIN"
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
CERTES_EMAIL=""
CERTES_ORG=""
CERTES_CN=""

expiry=365
do_yes=false
plain_key=false

while getopts hs:d:O:E:C:x:yc:m:p name; do
	case $name in
		h)
			setup_vars
			usage
			exit 0
			;;
		c)
			CERTES_CONFIG=$(realpath "$OPTARG")
			;;
		s)
			CERTES_SSL_CONFIG=$(realpath "$OPTARG")
			;;
		d)
			CERTES_DIR=$(realpath "$OPTARG")
			;;
		C)
			CERTES_CN="$OPTARG"
			;;
		E)
			CERTES_EMAIL="$OPTARG"
			;;
		O)
			CERTES_ORG="$OPTARG"
			;;
		x)
			expiry="$OPTARG"
			;;
		y)
			do_yes=true
			;;
		p)
			plain_key=true
			;;
		\?)
			usage
			exit 2
			;;
	esac
done

shift $(($OPTIND - 1))

export CERTES_DIR
export CERTES_EMAIL
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
	mkdir -p $CERTES_DIR/ca/certs
	echo "01" > $CERTES_DIR/ca/serial
	touch $CERTES_DIR/ca/index.txt

	# Create self-signed root certificate; in a real situation, the key
	# should be kept on a secure machine or even offline storage. The
	# certificate and CRL will need to be deployed on all agents in the
	# fleet.
	local nodes=""
	if $plain_key; then
		nodes="-nodes"
	fi
	if [ -z "$CERTES_CN" ]; then
		CERTES_CN=root
	fi
	if [ "$CERTES_EMAIL" != "" -a "$CERTES_ORG" != "" ]; then
		openssl req -x509 $nodes -config $CERTES_SSL_CONFIG \
			-extensions root_ext \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout $CERTES_DIR/ca/key.pem \
			-out $CERTES_DIR/ca/root.pem -outform pem -days $expiry \
			-subj "/emailAddress=$CERTES_EMAIL/O=$CERTES_ORG/CN=$CERTES_CN"
	else
		openssl req -x509 $nodes -config $CERTES_SSL_CONFIG \
			-extensions root_ext \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout $CERTES_DIR/ca/key.pem \
			-out $CERTES_DIR/ca/root.pem -outform pem -days $expiry
	fi
	echo "* Generating CRL"
	openssl ca -config $CERTES_SSL_CONFIG \
		-gencrl -out $CERTES_DIR/ca/root.crl
	openssl x509 -in $CERTES_DIR/ca/root.pem -text -noout
}

ca_reqs()
{
	local sans="$1"

	if [ "`uname -s`" = "OpenBSD" ]; then
		local hostname=`hostname`
	else
		local hostname=`hostname -f`
	fi

	local proxy_cn=$hostname
	if [ -z "$sans" ]; then
		sans="DNS:$hostname"
	fi
	if [ -z "$CERTES_CN" ]; then
		CERTES_CN=$hostname
	fi

	local mdrd_uid=$(egrep -o '^uid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')
	local mdrd_gid=$(egrep -o '^gid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')

	local certes_uid=$(egrep -o '^backend_uid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')
	local certes_gid=$(egrep -o '^backend_gid *= "*[a-zA-Z0-9\._-]+" *' \
		$CERTES_MDRD_CONFIG | cut -d= -f 2 | tr -d ' "')

	umask 077
	echo "* Creating CA REQ"
	if [ "$CERTES_ORG" != "" ]; then
		openssl req -config $CERTES_SSL_CONFIG -nodes \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout $CERTES_DIR/ca_key.pem -keyform PEM \
			-out $CERTES_DIR/ca_req.pem -outform PEM \
			-subj "/O=$CERTES_ORG/CN=$CERTES_CN"
	else
		openssl req -config $CERTES_SSL_CONFIG -nodes \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout $CERTES_DIR/ca_key.pem -keyform PEM \
			-out $CERTES_DIR/ca_req.pem -outform PEM
	fi
	[ ! -z "$certes_uid" ] && chown "$certes_uid" $CERTES_DIR/ca_key.pem
	[ ! -z "$certes_gid" ] && chgrp "$certes_gid" $CERTES_DIR/ca_key.pem

	echo "* Creating proxy REQ"
	if [ "$CERTES_ORG" != "" -a "$proxy_cn" != "" ]; then
		openssl req -config $CERTES_SSL_CONFIG -nodes \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout $CERTES_DIR/proxy_key.pem -keyform PEM \
			-out $CERTES_DIR/proxy_req.pem -outform PEM \
			-addext "subjectAltName = $sans" \
			-subj "/O=$CERTES_ORG/CN=$proxy_cn"
	else
		openssl req -config $CERTES_SSL_CONFIG -nodes \
			-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout $CERTES_DIR/proxy_key.pem -keyform PEM \
			-out $CERTES_DIR/proxy_req.pem -outform PEM \
			-addext "subjectAltName = $sans"
	fi
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
