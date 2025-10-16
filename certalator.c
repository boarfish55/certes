#include <sys/file.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "coordinator.h"
#include "certalator.h"
#include "certdb.h"
#include "flatconf.h"
#include "mdr_certalator.h"
#include "mdr_mdrd.h"
#include "util.h"
#include "xlog.h"

int          NID_overnet_roles;
int          NID_overnet_roles_idx;
X509_STORE  *store = NULL;
EVP_PKEY    *agent_key = NULL;
X509        *agent_cert = NULL;
X509        *ca_crt = NULL;
X509_CRL    *ca_crl = NULL;
int          debug = 0;
char         config_file_path[PATH_MAX] = "/etc/certalator.conf";
SSL_CTX     *agent_ssl_ctx = NULL;
SSL         *agent_ssl = NULL;
BIO         *agent_bio = NULL;
int          agent_connected = 0;
int          agent_is_authority = 0;
const char **agent_roles = NULL;

extern const struct mdr_spec *msg_bootstrap_setup;
extern const struct mdr_spec *msg_bootstrap_dialin;
extern const struct mdr_spec *msg_pack_beresp;
extern const struct mdr_spec *msg_pack_beresp_wmsg;
extern const struct mdr_spec *msg_coord_save_cert_challenge;
extern const struct mdr_spec *msg_coord_get_cert_challenge;
extern const struct mdr_spec *msg_coord_get_cert_challenge_resp;

struct certalator_flatconf certalator_conf = {
	0,
	"",
	9790,
	"ca/certdb.sqlite",
	"",
	"ca/overnet.pem",
	"ca/overnet.crl",
	"overnet_key.pem",
	"overnet_crt.pem",
	".lock",
	"agent.sock",
	4096,
	"ca/serial",
	"",
	"",

	"0x0",
	"0x0"
};

struct flatconf certalator_config_vars[] = {
	{
		"enable_coredumps",
		FLATCONF_BOOLINT,
		&certalator_conf.enable_coredumps,
		sizeof(certalator_conf.enable_coredumps)
	},
	{
		"authority_fqdn",
		FLATCONF_STRING,
		certalator_conf.authority_fqdn,
		sizeof(certalator_conf.authority_fqdn)
	},
	{
		"authority_port",
		FLATCONF_ULONG,
		&certalator_conf.authority_port,
		sizeof(certalator_conf.authority_port)
	},
	{
		"certdb_path",
		FLATCONF_STRING,
		certalator_conf.certdb_path,
		sizeof(certalator_conf.certdb_path)
	},
	{
		"bootstrap_key",
		FLATCONF_STRING,
		certalator_conf.bootstrap_key,
		sizeof(certalator_conf.bootstrap_key)
	},
	{
		"ca_file",
		FLATCONF_STRING,
		certalator_conf.ca_file,
		sizeof(certalator_conf.ca_file)
	},
	{
		"crl_file",
		FLATCONF_STRING,
		certalator_conf.crl_file,
		sizeof(certalator_conf.crl_file)
	},
	{
		"key_file",
		FLATCONF_STRING,
		certalator_conf.key_file,
		sizeof(certalator_conf.key_file)
	},
	{
		"cert_file",
		FLATCONF_STRING,
		certalator_conf.cert_file,
		sizeof(certalator_conf.cert_file)
	},
	{
		"lock_file",
		FLATCONF_STRING,
		certalator_conf.lock_file,
		sizeof(certalator_conf.lock_file)
	},
	{
		"coordinator_socket_path",
		FLATCONF_STRING,
		certalator_conf.coordinator_sock_path,
		sizeof(certalator_conf.coordinator_sock_path)
	},
	{
		"key_bits",
		FLATCONF_ULONG,
		&certalator_conf.key_bits,
		sizeof(certalator_conf.key_bits)
	},
	{
		"serial_file",
		FLATCONF_STRING,
		certalator_conf.serial_file,
		sizeof(certalator_conf.serial_file)
	},
	{
		"cert_org",
		FLATCONF_STRING,
		certalator_conf.cert_org,
		sizeof(certalator_conf.cert_org)
	},
	{
		"cert_email",
		FLATCONF_STRING,
		certalator_conf.cert_email,
		sizeof(certalator_conf.cert_email)
	},
	{
		"min_serial",
		FLATCONF_STRING,
		certalator_conf.min_serial,
		sizeof(certalator_conf.min_serial)
	},
	{
		"max_serial",
		FLATCONF_STRING,
		certalator_conf.max_serial,
		sizeof(certalator_conf.max_serial)
	},
	FLATCONF_LAST
};

void load_keys();

ssize_t
decode_overnet_roles(X509_EXTENSION *ext, char **roles, ssize_t roles_len)
{
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	ASN1_TYPE           *v;
	ssize_t              i;
	const unsigned char *p;

	asn1str = X509_EXTENSION_get_data(ext);
	p = asn1str->data;

	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&p, asn1str->length);

	if (roles == NULL) {
		/*
		 * If roles is NULL, we just return how many roles
		 * we would need to fill in.
		 */
		i = sk_ASN1_TYPE_num(seq);
		sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
		return i;
	}

	for (i = 0; i < roles_len && sk_ASN1_TYPE_num(seq) > 0; i++) {
		v = sk_ASN1_TYPE_shift(seq);
		strlcpy(roles[i], (const char *)v->value.ia5string->data,
		    CERTALATOR_MAX_ROLE_LENGTH);
		ASN1_TYPE_free(v);
	}
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return i;
}

X509_EXTENSION *
encode_overnet_roles(const char **roles)
{
	const char          **role;
	X509_EXTENSION       *ex;
	ASN1_OCTET_STRING    *asn1str;
	STACK_OF(ASN1_TYPE)  *sk;
	ASN1_TYPE            *v;
	ASN1_IA5STRING       *s;
	unsigned char        *data = NULL;
	int                   len;

	sk = sk_ASN1_TYPE_new(NULL);

	// TODO: so much error handling/cleanup to do!
	for (role = roles; *role != NULL; role++) {
		if ((s = ASN1_IA5STRING_new()) == NULL)
			return NULL;
		if (!ASN1_STRING_set(s, *role, strlen(*role)))
			return NULL;
		if ((v = ASN1_TYPE_new()) == NULL)
			return NULL;
		ASN1_TYPE_set(v, V_ASN1_IA5STRING, s);
		if (sk_ASN1_TYPE_push(sk, v) <= 0)
			return NULL;
	}

	if ((len = i2d_ASN1_SEQUENCE_ANY((STACK_OF(ASN1_TYPE) *)sk, &data)) < 0)
		return NULL;

	while (sk_ASN1_TYPE_num(sk) > 0) {
		v = sk_ASN1_TYPE_shift(sk);
		free(v->value.ia5string);
		free(v);
	}
	sk_ASN1_TYPE_free(sk);

	asn1str = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(asn1str, data, len))
		return NULL;
	free(data);

	// TODO: leak?
	ex = X509_EXTENSION_create_by_NID(NULL, NID_overnet_roles, 0, asn1str);
	ASN1_OCTET_STRING_free(asn1str);
	if (ex == NULL) {
		return NULL;
	}
	return ex;
}

int
crt_has_role(X509 *crt, const char *role, struct xerr *e)
{
	int                  roles_idx;
	X509_EXTENSION      *ext;
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	ASN1_TYPE           *v;
	ssize_t              i;
	const unsigned char *p;
	int                  found = 0;

	roles_idx = X509_get_ext_by_NID(crt, NID_overnet_roles, -1);
	if (roles_idx == -1)
		return XERRF(e, XLOG_APP, XLOG_SSLEXTNIDNOTFOUND,
		    "%s: overnetRoles extension NID not found", __func__);

	if ((ext = X509_get_ext(crt, roles_idx)) == NULL)
		return XERRF(e, XLOG_APP, XLOG_SSLEXTNOTFOUND,
		    "%s: overnetRoles extension not found", __func__);

	asn1str = X509_EXTENSION_get_data(ext);
	p = asn1str->data;

	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&p, asn1str->length);

	for (i = 0; !found && sk_ASN1_TYPE_num(seq) > 0; i++) {
		v = sk_ASN1_TYPE_shift(seq);
		if (strcmp(role, (const char *)v->value.ia5string->data) == 0)
			found = 1;
		ASN1_TYPE_free(v);
	}
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return found;
}

int
agent_connect(struct xerr *e)
{
	char host[302];

	if (certalator_conf.authority_fqdn[0] == '\0')
		return XERRF(e, XLOG_APP, XLOG_EDESTADDRREQ,
		    "no destination address was specified");

	if (agent_ssl_ctx == NULL) {
		if ((agent_ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

		SSL_CTX_set_verify(agent_ssl_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_store(agent_ssl_ctx, store);

		if (SSL_CTX_use_PrivateKey(agent_ssl_ctx, agent_key) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_PrivateKey");
		if (SSL_CTX_use_certificate(agent_ssl_ctx, agent_cert) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_certificate");
	}

	if (agent_bio == NULL) {
		if (snprintf(host, sizeof(host), "%s:%lu",
		    certalator_conf.authority_fqdn,
		    certalator_conf.authority_port) >= sizeof(host))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "resulting host:port is too long");

		if ((agent_bio = BIO_new_ssl_connect(agent_ssl_ctx)) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_new_ssl_connect");

		BIO_get_ssl(agent_bio, &agent_ssl);
		if (agent_ssl == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_get_ssl");

		SSL_set_mode(agent_ssl, SSL_MODE_AUTO_RETRY);
		BIO_set_conn_hostname(agent_bio, host);
	}

	if (!agent_connected) {
		if (BIO_do_connect(agent_bio) <= 0)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_do_connect");

		if (BIO_do_handshake(agent_bio) <= 0)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_do_handshake");
		agent_connected = 1;
	}

	return 0;
}

int
agent_send(struct mdr *m, struct xerr *e)
{
	int r;

	if (agent_connect(e) == -1)
		return -1;

	if ((r = BIO_write(agent_bio, mdr_buf(m), mdr_size(m))) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	else if (r < mdr_size(m))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");

	return 0;

}

void
usage()
{
	printf("Usage: %s [options] <command>\n", CERTALATOR_PROGNAME);
	printf("\t-help            Prints this help\n");
	printf("\t-debug           Do not fork and print errors to STDERR\n");
	printf("\t-config <conf>   Specify alternate configuration path\n");
	printf("\n");
	printf("  Commands:\n");
	printf("\tverify           Ensures the certificate is signed by our "
	    "authority\n");
	printf("\tsign             Re-signs the certificate\n");
	printf("\tmdrd-backend     Run as an mdrd backend\n");
	printf("\tbootstrap-setup  Create a bootstrap entry on the "
	    "authority\n");
}

int
verify(X509_STORE_CTX *ctx, X509 *crt, int challenge)
{
	X509_NAME *subject;
	char       common_name[256];
	int        r;

	subject = X509_get_subject_name(crt);
	if (subject == NULL) {
		xlog(LOG_ERR, NULL, "X509_get_subject_name: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (X509_NAME_get_text_by_NID(subject, NID_commonName,
	    common_name, sizeof(common_name)) == -1) {
		xlog(LOG_ERR, NULL, "X509_NAME_get_text_by_NID: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	// TODO: do a challenge on the client and its cert name. The peer
	// IP on the connection should match one of the subjectAltNames, or
	// the commonName of the cert. If there's no match, deny.
	if (challenge) {
	}

	if (!X509_STORE_CTX_init(ctx, store, crt, NULL)) {
		X509_STORE_CTX_cleanup(ctx);
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if ((r = X509_verify_cert(ctx)) <= 0) {
		X509_STORE_CTX_cleanup(ctx);
		xlog(LOG_ERR, NULL, "X509_verify_cert: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	X509_STORE_CTX_cleanup(ctx);

	// TODO: remove, no need during verify
	//roles_idx = X509_get_ext_by_NID(crt, NID_overnet_roles, -1);
	//if (roles_idx == -1)
	//	xlog(LOG_ERR, NULL,
	//	    "%s: overnetRoles extension not found", __func__);

	//if ((ex = X509_get_ext(crt, roles_idx)) == NULL) {
	//	xlog(LOG_ERR, NULL, "X509_get_ext: %s",
	//	    ERR_error_string(ERR_get_error(), NULL));
	//	return -1;
	//}

	//roles = malloc(CERTALATOR_MAX_ROLES *
	//    (sizeof(char *) + CERTALATOR_MAX_ROLE_LENGTH));
	//if (roles == NULL) {
	//	xlog_strerror(LOG_ERR, errno, "%s: malloc", __func__);
	//	return -1;
	//}

	//bzero(roles, CERTALATOR_MAX_ROLES *
	//    (sizeof(char *) + CERTALATOR_MAX_ROLE_LENGTH));
	//for (i = 0; i < CERTALATOR_MAX_ROLES; i++)
	//	roles[i] = (char *)roles +
	//	    (CERTALATOR_MAX_ROLES * sizeof(char *)) +
	//	    (i * CERTALATOR_MAX_ROLE_LENGTH);

	//n = decode_overnet_roles(ex, roles, CERTALATOR_MAX_ROLES);
	//if (n == -1) {
	//	free(roles);
	//	return -1;
	//}

	//for (i = 0; i < n; i++)
	//	xlog(LOG_INFO, NULL, "role: %s\n", roles[i]);
	//free(roles);
	return 0;
}

int
open_wflock(const char *path, int flags, mode_t mode, int lk)
{
	int             fd;
	struct timespec tp = {0, 1000000}, req, rem;  /* 1ms */

	for (;;) {
		if ((fd = open(path, flags, mode)) == -1)
			return -1;

		if (flock(fd, lk|LOCK_NB) == 0)
			return fd;

		if (errno != EWOULDBLOCK)
			break;

		close(fd);
		memcpy(&req, &tp, sizeof(req));
		while (nanosleep(&req, &rem) == -1)
			memcpy(&req, &rem, sizeof(req));
	}
	return -1;
}

BIGNUM *
new_serial(struct xerr *e)
{
	BIGNUM  *min_bn = NULL;
	BIGNUM  *max_bn = NULL;
	BIGNUM  *v = NULL;
	int      fd = -1, fdtmp;
	char    *p;
	ssize_t  r;
	int      l;
	char     buf[MAX_HEX_SERIAL_LENGTH + 1];
	char     tmpfile[PATH_MAX];

	if (!BN_hex2bn(&min_bn, certalator_conf.min_serial)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
		return NULL;
	}

	if (!BN_hex2bn(&max_bn, certalator_conf.max_serial)) {
		BN_free(min_bn);
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
		return NULL;
	}

	if (snprintf(tmpfile, sizeof(tmpfile), "%s.new",
	    certalator_conf.serial_file) >= sizeof(tmpfile)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "tmpfile name too long");
		goto fail;
	}

	/*
	 * We get an exclusive lock while we write the new serial to a
	 * tmp file and overwrite the serial file. This way other processes
	 * may not read or write while we are incrementing the serial.
	 */
	if ((fd = open_wflock(certalator_conf.serial_file,
	    O_RDWR|O_CREAT, 0666, LOCK_EX)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "open_wflock");
		goto fail;
	}

	r = read(fd, buf, sizeof(buf));
	if (r == -1) {
		XERRF(e, XLOG_ERRNO, errno, "read");
		goto fail;
	}

	if (r > 0) {
		if (buf[r - 1] != '\n') {
			XERRF(e, XLOG_APP, XLOG_BADSERIALFILE,
			    "serial file does not end in newline, "
			    "or the value is too large");
			goto fail;
		}
		buf[r - 1] = '\0';
		for (p = buf; *p; p++) {
			if (!((*p >= '0' && *p <= '9') ||
			    (*p >= 'a' && *p <= 'f') ||
			    (*p >= 'A' && *p <= 'F'))) {
				XERRF(e, XLOG_APP, XLOG_BADSERIALFILE,
				    "serial is not a valid hex integer");
				goto fail;
			}
		}
		if (!BN_hex2bn(&v, buf)) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
			goto fail;
		}

		if (BN_cmp(v, min_bn) == -1) {
			XERRF(e, XLOG_APP, XLOG_BADSERIALFILE,
			    "saved serial is less than min_serial");
			goto fail;
		}

		if (!BN_add_word(v, 1)) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "BN_add_word");
			goto fail;
		}

		if (BN_cmp(v, max_bn) > 0) {
			XERRF(e, XLOG_APP, XLOG_MAXSERIALREACHED,
			    "max_serial exceeded");
			goto fail;
		}
	} else {
		if ((v = BN_dup(min_bn)) == NULL) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "BN_dup");
			goto fail;
		}
	}

	if ((p = BN_bn2hex(v)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_bn2hex");
		goto fail;
	}

	l = snprintf(buf, sizeof(buf), "%s\n", p);
	OPENSSL_free(p);
	if (l >= sizeof(buf)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "computed serial is too large");
		goto fail;
	}

	if ((fdtmp = open(tmpfile, O_WRONLY|O_CREAT, 0666)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "open");
		goto fail;
	}
	r = write(fdtmp, buf, l);
	if (r == -1) {
		close(fdtmp);
		XERRF(e, XLOG_ERRNO, errno, "write");
		goto fail;
	}
	if (r < l) {
		close(fdtmp);
		XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "short write on serial file");
		goto fail;
	}
	fsync(fdtmp);
	close(fdtmp);
	if (rename(tmpfile, certalator_conf.serial_file) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "rename");
		goto fail;
	}

	BN_free(min_bn);
	BN_free(max_bn);
	close(fd);

	return v;
fail:
	BN_free(min_bn);
	BN_free(max_bn);
	if (fd > -1)
		close(fd);
	return NULL;
}

int
add_ext(X509V3_CTX *ctx, X509 *crt, int nid, char *value)
{
	X509_EXTENSION *ex;
	if (!(ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value)))
		return 0;
	return X509_add_ext(crt, ex, -1);
}

X509 *
sign(X509 *crt, const char **roles)
{
	X509           *newcrt;
	BIGNUM         *serial;
	X509_EXTENSION *ex;
	X509V3_CTX      ctx;
	int             san_idx;
	struct xerr     e;

	// TODO: verify first?

	X509V3_set_ctx(&ctx, agent_cert, crt, NULL, NULL, 0);

	if ((newcrt = X509_new()) == NULL) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_new");
		return NULL;
	}
	if (!X509_set_version(newcrt, 2)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_set_version");
		return NULL;
	}

	serial = new_serial(xerrz(&e));
	if (serial == NULL)
		return NULL;

	if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(newcrt)) == NULL) {
		BN_free(serial);
		XERRF(&e, XLOG_SSL, ERR_get_error(), "BN_to_ASN1_INTEGER");
		return NULL;
	}
	BN_free(serial);

	if (!X509_set_issuer_name(newcrt, X509_get_subject_name(agent_cert))) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_set_issuer_name");
		return NULL;
	}

	if (!X509_set_subject_name(newcrt, X509_get_subject_name(crt))) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_set_subject_name");
		return NULL;
	}

	if (!X509_set_pubkey(newcrt, X509_get0_pubkey(crt))) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_set_pubkey");
		return NULL;
	}

	X509_gmtime_adj(X509_get_notBefore(newcrt), 0);
	X509_gmtime_adj(X509_get_notAfter(newcrt), 86400);

	san_idx = X509_get_ext_by_NID(crt, NID_subject_alt_name, -1);
	if (san_idx == -1) {
		XERRF(&e, XLOG_APP, XLOG_NOENT,
		    "subjectAltName extension not found");
		return NULL;
	}
	if ((ex = X509_get_ext(crt, san_idx)) == NULL) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_get_ext");
		return NULL;
	}
	if (!X509_add_ext(newcrt, ex, -1)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_add_ext");
		return NULL;
	}

	if (!add_ext(&ctx, newcrt, NID_basic_constraints,
	    "critical,CA:false")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_basic_constraints");
		return NULL;
	}
	if (!add_ext(&ctx, newcrt, NID_key_usage,
	    "critical,nonRepudiation,digitalSignature,keyEncipherment")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "add_ext / NID_key_usage");
		return NULL;
	}
	if (!add_ext(&ctx, newcrt, NID_ext_key_usage,
	    "serverAuth,clientAuth")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_ext_key_usage");
		return NULL;
	}
	if (!add_ext(&ctx, newcrt, NID_subject_key_identifier, "hash")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_subject_key_identifier");
		return NULL;
	}
	if (!add_ext(&ctx, newcrt, NID_authority_key_identifier,
	    "keyid,issuer")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_authority_key_identifier");
		return NULL;
	}

	// TODO: need to add the subjectAltNames

	ex = encode_overnet_roles(roles);
	if (!X509_add_ext(newcrt, ex, -1)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_add_ext / roles");
		return NULL;
	}

	if (!X509_sign(newcrt, agent_key, EVP_sha256())) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_sign");
		return NULL;
	}

	return newcrt;
}

int
b64enc(char *dst, size_t dst_sz, const uint8_t *bytes, size_t sz, struct xerr *e)
{
	BIO *b, *b64;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	if ((b = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(b64);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
	}
	BIO_push(b64, b);

	if (BIO_write(b64, bytes, sizeof(sz)) <= 0) {
		BIO_free_all(b64);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	}
	BIO_flush(b64);

	if (BIO_read(b, dst, dst_sz) != dst_sz) {
		BIO_free_all(b64);
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "short read for base64 bootstrap key");
	}
	BIO_free_all(b64);
	return 0;
}

// TODO: for boostrapping from the certalator server; this will generate a timed
// challenge and can tie roles to the challenge. Boostrapping can also invoke a
// shell command to perform a action to bring up the server (i.e. DHCP
// reservation & reboot, cloud calls, etc.) The server must remember the
// challenge until it expires.  Active challenges can be kept in an sqlite DB,
// alongside available serial ranges and next allocatable serial.
// When a client sends a successful response to this challenge, along with an
// X509 REQ, the server can sign it if the commonName and subjectAltNames
// match.
/*
 * Create a bootstrap entry with certificate parameters and a challenge key
 * to be used when an agent connects with a DIALIN call.
 * This will populate and save a bootstrap_entry in the certdb.
 */
int
authority_bootstrap_setup(const char *cn, const char **sans,
    size_t sans_sz, const char **roles, size_t roles_sz, uint32_t cert_expiry,
    uint32_t timeout, struct xerr *e)
{
	int                     i;
	uint8_t                 buf[CERTALATOR_BOOTSTRAP_KEY_LENGTH];
	char                    subject[CERTALATOR_MAX_SUBJET_LENGTH];
	struct bootstrap_entry  be;
	struct timespec         tp;

	if (snprintf(subject, sizeof(subject), "/O=%s/CN=%s/emailAddress=%s",
	    certalator_conf.cert_org, cn, certalator_conf.cert_email) >=
	    sizeof(subject))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "resulting subject name is too long for commonName %s", cn);

	arc4random_buf(buf, sizeof(buf));

	if (b64enc(be.bootstrap_key, sizeof(be.bootstrap_key),
	    buf, sizeof(buf), e) == -1)
		return -1;

	clock_gettime(CLOCK_REALTIME, &tp);

	be.valid_until_sec = tp.tv_sec + timeout;
	be.not_before_sec = tp.tv_sec;
	be.not_after_sec = tp.tv_sec + cert_expiry;
	be.subject = subject;

	for (i = 0; i < roles_sz; i++)
		if (strlen(roles[i]) > CERTALATOR_MAX_ROLE_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "role name %s longer than limit of %d",
			    roles[i], CERTALATOR_MAX_ROLE_LENGTH);

	for (i = 0; i < sans_sz; i++)
		if (strlen(sans[i]) > CERTALATOR_MAX_SAN_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "SAN name %s longer than limit of %d",
			    sans[i], CERTALATOR_MAX_SAN_LENGTH);

	be.roles = (char **)roles;
	be.roles_sz = roles_sz;
	be.sans = (char **)sans;
	be.sans_sz = sans_sz;

	return certdb_put_bootstrap(&be, e);
}

void
authority_bootstrap_usage()
{
	printf("Usage: %s bootstrap-setup [options] <cn> <roles...>\n",
	    CERTALATOR_PROGNAME);
	printf("\t--help        Prints this help\n");
	printf("\t--timeout     Validity of bootstrap entry in "
	    "seconds (default 600)\n");
	printf("\t--cert_expiry Validity of certificate in "
	    "seconds (default 7*86400)\n");
	printf("\t--san         Adds a Subject Alt Name to this "
	    "bootstrap entry\n");
	printf("\t--role        Adds a role to this bootstrap entry\n");
}

int
authority_bootstrap_setup_msg(struct mdr *m, struct xerr *e)
{
	const char      *subject;
	const char     **roles = NULL;
	int32_t          roles_sz;
	const char     **sans = NULL;
	int32_t          sans_sz;
	uint32_t         cert_expiry, timeout;
	struct mdr_out   m_out[4];

	if (mdr_unpack_payload(m, msg_bootstrap_setup, m_out, 4) == MDR_FAIL)
		return -1;

	subject = m_out[0].v.s.bytes;
	sans_sz = mdr_out_array_length(&m_out[1].v.as);
	roles_sz = mdr_out_array_length(&m_out[2].v.as);
	cert_expiry = m_out[3].v.u32;
	timeout = m_out[4].v.u32;

	if ((sans = malloc(sizeof(char *) * (sans_sz + 1))) == NULL)
		goto fail;
	if ((roles = malloc(sizeof(char *) * (roles_sz + 1))) == NULL)
		goto fail;

	if (mdr_out_array_s(&m_out[1].v.as, sans, sans_sz) == MDR_FAIL)
		goto fail;
	if (mdr_out_array_s(&m_out[2].v.as, roles, roles_sz) == MDR_FAIL)
		goto fail;

	if (authority_bootstrap_setup(subject, sans, sans_sz, roles,
	    roles_sz, cert_expiry, timeout, e) == -1)
		goto fail;

	free(sans);
	free(roles);
	return 0;
fail:
	free(sans);
	free(roles);
	return -1;
}

int
authority_bootstrap_setup_cli(int argc, char **argv, struct xerr *e)
{
	int        opt, r;
	uint32_t   timeout = 600;
	uint32_t   cert_expiry = 7 * 86400;
	char     **roles = NULL;
	size_t     roles_sz = 0;
	char     **sans = NULL;
	size_t     sans_sz = 0;

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			authority_bootstrap_usage();
			exit(0);
		}

		if (strcmp(argv[opt], "-timeout") == 0) {
			opt++;
			if (opt > argc) {
				authority_bootstrap_usage();
				exit(1);
			}
			timeout = atoi(argv[opt]);
			continue;
		}

		if (strcmp(argv[opt], "-cert_expiry") == 0) {
			opt++;
			if (opt > argc) {
				authority_bootstrap_usage();
				exit(1);
			}
			cert_expiry = atoi(argv[opt]);
			continue;
		}

		if (strcmp(argv[opt], "-san") == 0) {
			opt++;
			if (opt > argc) {
				authority_bootstrap_usage();
				exit(1);
			}
			sans = strlist_add(sans, argv[opt]);
			if (sans == NULL)
				err(1, "strlist_add");
			sans_sz++;
			continue;
		}

		if (strcmp(argv[opt], "-role") == 0) {
			opt++;
			if (opt > argc) {
				authority_bootstrap_usage();
				exit(1);
			}
			roles = strlist_add(roles, argv[opt]);
			if (roles == NULL)
				err(1, "strlist_add");
			roles_sz++;
			continue;
		}
	}

	if (opt >= argc) {
		authority_bootstrap_usage();
		exit(1);
	}

	r = authority_bootstrap_setup(argv[opt], (const char **)sans, sans_sz,
	    (const char **)roles, roles_sz, cert_expiry, timeout, e);
	free(sans);
	free(roles);
	return r;
}

int
agent_new_req(const char *subject)
{
	// TODO: look at acme-client/keyproc.c:77
	X509_REQ  *req;
	X509_NAME *name = NULL;
	char      *token, *field, *value, *t;
	char      *save1, *save2;
	char       subject2[CERTALATOR_MAX_SUBJET_LENGTH];

	if ((req = X509_REQ_new()) == NULL) {
		warnx("X509_REQ_new");
		return -1;
	}

	if (!X509_REQ_set_version(req, 2)) {
		warnx("X509_REQ_set_version");
		return -1;
	}

	if (!X509_REQ_set_pubkey(req, agent_key)) {
		warnx("X509_REQ_set_pubkey");
		return -1;
	}

	if ((name = X509_NAME_new()) == NULL) {
		warnx("X509_NAME_new");
		return -1;
	}

	strlcpy(subject2, subject, sizeof(subject2));

	for (t = subject2; ; t = NULL) {
		token = strtok_r(t, "/", &save1);
		if (token == NULL)
			break;

		if (strcmp(token, "") == 0)
			continue;

		printf("token: %s\n", token);

		field = strtok_r(token, "=", &save2);
		if (field == NULL) {
			// TODO: error, malformed
			break;
		}

		if (strcmp(field, "CN") != 0 &&
		    strcmp(field, "O") != 0 &&
		    strcmp(field, "emailAddress") != 0) {
			// TODO: error, unsupported subject field
			break;
		}

		value = strtok_r(NULL, "=", &save2);
		if (value == NULL) {
			// TODO: error, malformed
			break;
		}

		if (!X509_NAME_add_entry_by_txt(name, field,
		    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0)) {
			warnx("X509_NAME_add_entry_by_txt: %s=%s",
			    field, value);
			return -1;
		}

	}

	if (!X509_REQ_set_subject_name(req, name)) {
		warnx("X509_req_set_subject_name");
		return -1;
	}

	err(1, "not implemented");
	// TODO: must return a FILE pointer to the cert.
	return 0;
}

// TODO: client-side for the above; given a challenge and roles, we can
// generate a REQ with those roles, create our REQ and pick and DNS/CommonName
// we can answer to, then contact the server, passing the challenge to get the
// REQ signed. This can also generate the private key.
//
//
// We'll need to know:
// - The subject name
// - The subjectAltName (possibly multiple)
// - NOT the roles associated with with the challenge;
//   those are kept server-side
// - Validity period (capped by the server, but could be shorter)
// Most other things are decided by the cert issuer.
/*
 * Contact the authority to send our bootstrap key in order to obtain
 * our certificate parameters and create our key and REQ.
 */
FILE *
agent_bootstrap_dialin(struct xerr *e)
{
	struct mdr       m;
	char             buf[1024];
	char            *subject = NULL;
	char             req_id[CERTALATOR_REQ_ID_LENGTH];
	char             challenge[CERTALATOR_CHALLENGE_LENGTH];
	struct mdr_in    m_in[2];
	struct mdr_out   m_out[1];
	struct timespec  now;
	int              try;

	if (strlen(certalator_conf.bootstrap_key) !=
	    CERTALATOR_BOOTSTRAP_KEY_LENGTH_B64) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "bad bootstrap key format in configuration; bad length");
		return NULL;
	}

	/*
	 * The req_id is just echoed back to us by the authority, which we
	 * then use to find the challenge sent to us on another connection.
	 */
	clock_gettime(CLOCK_REALTIME, &now);

	if (snprintf(req_id, sizeof(req_id), "%d-%lu.%lu", getpid(),
	    now.tv_sec, now.tv_nsec) >= sizeof(req_id)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "resulting req_id too long; this is a bug");
		return NULL;
	}

	m_in[0].type = MDR_S;
	m_in[0].v.s.bytes = req_id;
	m_in[1].type = MDR_S;
	m_in[1].v.s.bytes = certalator_conf.bootstrap_key;
	if (mdr_pack(&m, buf, sizeof(buf), msg_bootstrap_dialin,
	    MDR_F_NONE, m_in, 2) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_pack/msg_bootstrap_dialin");
		return NULL;
	}

	if (agent_send(&m, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	for (try = 0; try < 10; try++) {
		m_in[0].type = MDR_S;
		m_in[0].v.s.bytes = req_id;
		if (mdr_pack(&m, buf, sizeof(buf), msg_coord_get_cert_challenge,
		    MDR_F_NONE, m_in, 1) == MDR_FAIL) {
			XERRF(e, XLOG_ERRNO, errno,
			    "mdr_pack/msg_coord_get_cert_challenge");
			return NULL;
		}

		if (coordinator_send(&m, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		if (coordinator_recv(&m, buf, sizeof(buf), xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		if (mdr_dcv(&m) ==
		    MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP)
			break;

		/* Retry for any other answer */
	}

	if (try == 10) {
		XERRF(e, XLOG_APP, XLOG_TIMEOUT, "challenge timed out");
		return NULL;
	}

	if (mdr_unpack_payload(&m, msg_coord_get_cert_challenge_resp,
	    m_out, 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
		return NULL;
	}

	strlcpy(challenge, m_out[1].v.s.bytes, sizeof(challenge));

	// TODO: then create the new req to be signed. We mostly need this
	// for the public key; the rest is populated by the authority.
	if (agent_new_req(subject) == -1)
		return NULL;

	// TODO: send the req along with the challenge

	return NULL;
}

int
authority_challenge(struct bootstrap_entry *be, struct xerr *e)
{
	// TODO:

	// We connect to the subject, with a 
	// MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK message.
	//

	// Save the challenge in our shared tasks

	//for (i = 0; i < MAX_ACTIVE_CHALLENGES; i++) {
	//	if (!authority_challenge.challenges[i].in_use)
	//		break;
	//}

	// TODO: couldn't find a challenge slot
	//if (i == MAX_ACTIVE_CHALLENGES)
	//	return -1;

	// arc5random_buf ...
	// b64enc ..
	//authority_challenge.challenges[i].in_use = 1;
	//strlcpy(authority_challenge.challenges[i].secret, yo,
	//    sizeof(authority_challenge.challenges[i].secret));
	return 0;
}

int
authority_bootstrap_dialin(struct mdr *m, struct mdr *msg, struct xerr *e)
{
	// TODO: we receive the one-time-key from a client then
	// need to contact it over its CommonName to confirm
	// they are who they claim to be.
	// msg should have the one time key.

	struct bootstrap_entry be;
	struct mdr_out         m_out[1];

	if (mdr_unpack_payload(msg, msg_bootstrap_dialin, m_out, 1) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");

	if (m_out[0].v.s.sz != CERTALATOR_BOOTSTRAP_KEY_LENGTH)
		return XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap key received from client has incorrect length");

	if (certdb_get_bootstrap(&be, m_out[0].v.s.bytes, e) == -1)
		return -1;

	// Then we challenge the client by connecting to its CommonName
	// as per our DB
	if (authority_challenge(&be, e) == -1)
		return -1;

	// Then send a quick MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK_RESP
	// to inform the challenge is out.

	return 0;
}

FILE *
new_privkey()
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY     *pkey = NULL;
	FILE         *f;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL)
		goto fail;

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto fail;

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,
	    certalator_conf.key_bits) <= 0)
		goto fail;

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		goto fail;

	if ((f = fopen(certalator_conf.key_file, "w")) == NULL)
		err(1, "fopen");

	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
		goto fail;

	if (fclose(f) == EOF)
		err(1, "fclose: %s", certalator_conf.key_file);

	if ((f = fopen(certalator_conf.key_file, "r")) == NULL)
		err(1, "fopen: %s", certalator_conf.key_file);

	return f;
fail:
	ERR_print_errors_fp(stderr);
	exit(1);
}

void
load_keys()
{
	FILE        *f;
#ifndef __OpenBSD__
	int          pkey_sz;
#endif
	struct xerr  e;

	if ((f = fopen(certalator_conf.key_file, "r")) == NULL) {
		if (errno == ENOENT) {
			warnx("no private key found, generating one");
			f = new_privkey();
		} else
			err(1, "fopen");
	}
	if ((agent_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

#ifndef __OpenBSD__
	if (!(pkey_sz = EVP_PKEY_size(agent_key))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/* pledge() doesn't allow mlock() */
	if (mlock(agent_key, pkey_sz) == -1)
		err(1, "mlock");
#endif
	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");
	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((f = fopen(certalator_conf.ca_file, "r")) == NULL)
		err(1, "fopen: %s", certalator_conf.ca_file);
	if ((ca_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);
	if (!X509_STORE_add_cert(store, ca_crt)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((f = fopen(certalator_conf.crl_file, "r")) == NULL)
		err(1, "fopen: %s", certalator_conf.crl_file);
	if ((ca_crl = PEM_read_X509_CRL(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);
	if (!X509_STORE_add_crl(store, ca_crl)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((f = fopen(certalator_conf.cert_file, "r")) == NULL) {
		if (errno != ENOENT)
			err(1, "fopen: %s", certalator_conf.cert_file);
		f = agent_bootstrap_dialin(&e);
	}
	if ((agent_cert = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if (!X509_STORE_add_cert(store, agent_cert)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	agent_is_authority = crt_has_role(agent_cert,
	    ROLE_AUTHORITY, xerrz(&e));

	if (agent_is_authority == -1) {
		xlog(LOG_ERR, &e, "%s: crt_has_role", __func__);
		exit(1);
	}

	/*
	 * We're not calling X509_LOOKUP_free() as this causes a segfault
	 * if we try reusing X509_LOOKUP_file().
	 */
}

int
mdrd_backend()
{
	int               r, fd;
	struct mdr        m, msg;
	char              buf[32768];
	uint64_t          id;
	X509             *peer_cert = NULL;
	X509_STORE_CTX   *ctx;
	struct sigaction  act;
	struct xerr       e;
	struct mdr_in     m_in[5];

	xlog_init(CERTALATOR_PROGNAME, NULL, NULL, 1);

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sigaction", __func__);
		return 1;
	}

	load_keys();

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	// TODO: we'll end up polling here between stdin and the agent's
	// unix socket in case we get a control message of some sort.
	while ((r = mdr_read_from_fd(&m, MDR_F_NONE,
	    0, buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_read_from_fd", __func__);
			goto fail;
		}

		if (mdr_dcv(&m) != MDR_DCV_MDRD_BEREQ) {
			xlog(LOG_NOTICE, NULL,
			    "%s: unexpected message DCV received: %x",
			    __func__, mdr_dcv(&m));
			continue;
		}

		if (mdrd_unpack_bereq(&m, &id, &fd, &msg,
		    &peer_cert) == MDR_FAIL) {
			if (errno == EAGAIN)
				xlog(LOG_ERR, NULL,
				    "%s: mdrd_unpack_bereq: missing bytes "
				    "in payload", __func__);
			else
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdrd_unpack_bereq", __func__);
			continue;
		}

		if (mdr_domain(&msg) != MDR_DOMAIN_CERTALATOR) {
			xlog(LOG_NOTICE, NULL,
			    "%s: expected a certalator message (domain=%x) "
			    "but got %x", __func__, mdr_domain(&msg));
			continue;
		}

		if (peer_cert == NULL) {
			if (mdr_dcv(&msg) !=
			    MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN) {
				xlog(LOG_NOTICE, NULL,
				    "%s: client did not provide a cert; only "
				    "a bootstrap setup message (id=%x) can be "
				    "processed but got %x", __func__,
				    MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP,
				    mdr_dcv(&msg));
				continue;
			}

			if (!agent_is_authority) {
				xlog(LOG_ERR, NULL, "%s: we are not an "
				    "authority and client has no certificate",
				    __func__);
				m_in[0].type = MDR_U32;
				m_in[0].v.u32 = id;
				m_in[1].type = MDR_I32;
				m_in[1].v.i32 = fd;
				m_in[2].type = MDR_U32;
				m_in[2].v.u32 = MDRD_ST_NOCERT;
				m_in[3].type = MDR_U32;
				m_in[3].v.u32 = MDRD_BERESP_F_CLOSE;
				if (mdr_pack(&m, buf, sizeof(buf),
				    msg_pack_beresp, MDR_F_NONE, m_in, 4)
				    == MDR_FAIL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: mdr_pack", __func__);
					goto fail;
				}
				if (write(1, mdr_buf(&m), mdr_size(&m))
				    < mdr_size(&m)) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: writeall", __func__);
					goto fail;
				}
				continue;
			}

			if (authority_bootstrap_dialin(&m, &msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);
			continue;
		}

		if (verify(ctx, peer_cert, 0) != 0) {
			xlog(LOG_NOTICE, NULL, "%s: verify failed for client "
			    "on fd %d", __func__, fd);
			if (peer_cert != NULL)
				X509_free(peer_cert);
			m_in[0].type = MDR_U32;
			m_in[0].v.u32 = id;
			m_in[1].type = MDR_I32;
			m_in[1].v.i32 = fd;
			m_in[2].type = MDR_U32;
			m_in[2].v.u32 = MDRD_ST_CERTFAIL;
			m_in[3].type = MDR_U32;
			m_in[3].v.u32 = MDRD_BERESP_F_CLOSE;
			if (mdr_pack(&m, buf, sizeof(buf), msg_pack_beresp,
			    MDR_F_NONE, m_in, 4) == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdr_pack", __func__);
				goto fail;
			}
			if (write(1, mdr_buf(&m), mdr_size(&m))
			    < mdr_size(&m)) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: writeall", __func__);
				goto fail;
			}
			continue;
		}

		switch (mdr_dcv(&msg)) {
		case MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP:
			// TODO: client needs to have the "bootstrap" role
			if (authority_bootstrap_setup_msg(&msg, &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);
			break;
		case MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK:
			// TODO: needs to have role "agent", and the client
			// needs to have the "authority" role
			break;
		default:
			// TODO: fail
		}

		// TODO: currently this only echoes back
		X509_free(peer_cert);

		m_in[0].type = MDR_U32;
		m_in[0].v.u32 = id;
		m_in[1].type = MDR_I32;
		m_in[1].v.i32 = fd;
		m_in[2].type = MDR_U32;
		m_in[2].v.u32 = MDRD_ST_OK;
		m_in[3].type = MDR_U32;
		m_in[3].v.u32 = 0;
		m_in[4].type = MDR_M;
		// TODO: send meaningful response
		m_in[4].v.m = &msg;
		if (mdr_pack(&m, buf, sizeof(buf), msg_pack_beresp_wmsg,
		    MDR_F_NONE, m_in, 5) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_pack", __func__);
			goto fail;
		}
		if (write(1, mdr_buf(&m), mdr_size(&m)) < mdr_size(&m)) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: writeall", __func__);
			goto fail;
		}
	}
	X509_STORE_CTX_free(ctx);
	return 0;
fail:
	X509_STORE_CTX_free(ctx);
	return 1;
}

void
cleanup()
{
	flatconf_free(certalator_config_vars);
	if (ca_crt != NULL) {
		X509_free(ca_crt);
		ca_crt = NULL;
	}
	if (ca_crl != NULL) {
		X509_CRL_free(ca_crl);
		ca_crl = NULL;
	}
	if (agent_cert != NULL) {
		X509_free(agent_cert);
		agent_cert = NULL;
	}
	if (agent_key != NULL) {
		EVP_PKEY_free(agent_key);
		agent_key = NULL;
	}
	if (store != NULL) {
		X509_STORE_free(store);
		store = NULL;
	}
}

int
main(int argc, char **argv)
{
	int             opt, status;
	char           *command;
	size_t          sz;
	FILE           *f;
	X509           *crt, *newcrt;
	X509_STORE_CTX *ctx;
	struct xerr     e;
	char            crtpath[PATH_MAX];

	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			usage();
			exit(0);
		}
		if (strcmp(argv[opt], "-config") == 0) {
			opt++;
			if (opt > argc) {
				authority_bootstrap_usage();
				exit(1);
			}
			strlcpy(config_file_path, argv[opt],
			    sizeof(config_file_path));
			continue;
		}
		if (strcmp(argv[opt], "-debug") == 0) {
			debug = 1;
			continue;
		}
	}

	if (opt >= argc) {
		usage();
		exit(1);
	}

	umask(077);

	if (flatconf_read(config_file_path, certalator_config_vars, NULL) == -1)
		err(1, "config_vars_read");

	if (certalator_conf.authority_port > 65535 ||
	    certalator_conf.authority_port == 0)
		errx(1, "authority_port must be non-zero and <= 65535");

	if (strncmp(certalator_conf.min_serial, "0x", 2) != 0)
		errx(1, "min_serial does not begin with \"0x\"");
	sz = strlen(certalator_conf.min_serial) - 2;
	memmove(certalator_conf.min_serial,
	    certalator_conf.min_serial + 2, sz);
	certalator_conf.min_serial[sz] = '\0';
	if (!is_hex_str(certalator_conf.min_serial))
		errx(1, "min_serial is not a valid hex integer");

	if (strncmp(certalator_conf.max_serial, "0x", 2) != 0)
		errx(1, "max_serial does not begin with \"0x\"");
	sz = strlen(certalator_conf.max_serial) - 2;
	memmove(certalator_conf.max_serial,
	    certalator_conf.max_serial + 2, sz);
	certalator_conf.max_serial[sz] = '\0';
	if (!is_hex_str(certalator_conf.max_serial))
		errx(1, "max_serial is not a valid hexadecimal integer");

	NID_overnet_roles = OBJ_create("1.3.6.1.4.1.35910.3.1",
	    "overnetRoles", "Overnet Security Roles");
	if (NID_overnet_roles == NID_undef)
		err(1, "OBJ_create");

	command = argv[opt++];

	if (certdb_init(certalator_conf.certdb_path, &e) == -1) {
		xlog(LOG_ERR, &e, "certdb_init");
		return -1;
	}

	load_mdr_defs();

	if (strcmp(command, "verify") == 0) {
		if (opt >= argc)
			errx(1, "no certificate file provided");
		if ((f = fopen(argv[opt], "r")) == NULL)
			err(1, "fopen");
		if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);
		if ((ctx = X509_STORE_CTX_new()) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		status = verify(ctx, crt, 0);
		X509_STORE_CTX_free(ctx);
	} else if (strcmp(command, "sign") == 0) {
		if (opt >= argc)
			errx(1, "no certificate file provided");

		load_keys();

		if ((f = fopen(argv[opt], "r")) == NULL)
			err(1, "fopen: %s", argv[opt]);
		if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);

		newcrt = sign(crt, (const char **)argv + opt + 1);
		if (newcrt == NULL) {
			xlog(LOG_ERR, &e, "sign");
			exit(1);
		}

		snprintf(crtpath, sizeof(crtpath), "%s.new", argv[opt]);
		if ((f = fopen(crtpath, "w")) == NULL)
			err(1, "fopen: %s", crtpath);
		if (!PEM_write_X509(f, newcrt)) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);
	} else if (strcmp(command, "mdrd-backend") == 0) {
		status = mdrd_backend();
	} else if (strcmp(command, "bootstrap-setup") == 0) {
		if (authority_bootstrap_setup_cli(argc - opt,
		    argv + opt, &e) == -1) {
			xlog(LOG_ERR, &e, "bootstrap");
			return -1;
		}
	} else {
		usage();
		status = 1;
	}
	cleanup();
	return status;
}
