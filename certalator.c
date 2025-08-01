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
#include "certalator.h"
#include "certdb.h"
#include "flatconf.h"
#include "mdr_certalator.h"
#include "mdr_mdrd.h"
#include "util.h"
#include "xlog.h"

#define MAX_HEX_SERIAL_LENGTH 32

const char *program = "certalator";
int         NID_overnet_roles;
X509_STORE *store = NULL;
EVP_PKEY   *priv_key = NULL;
X509       *ca_crt = NULL;
int         debug = 0;
char        config_file_path[PATH_MAX] = "/etc/certalator.conf";
SSL_CTX    *agent_ssl_ctx = NULL;
SSL        *agent_ssl = NULL;
BIO        *agent_bio = NULL;
int         agent_connected = 0;

struct mdr_def msgdef_bootstrap_setup = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP,
	"certalator.bootstrap_setup",
	{
		MDR_S,
		MDR_AS,
		MDR_AS,
		MDR_U32,
		MDR_U32,
		MDR_LAST
	}
};
struct mdr_def msgdef_bootstrap_dialin = {
	MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN,
	"certalator.bootstrap_dialin",
	{
		MDR_S,
		MDR_LAST
	}
};

const struct mdr_spec *msg_bootstrap_setup;
const struct mdr_spec *msg_bootstrap_dialin;
const struct mdr_spec *msg_pack_beresp;
const struct mdr_spec *msg_pack_beresp_wmsg;

struct {
	int    enable_coredumps;

	char   certdb_path[PATH_MAX];
	char   bootstrap_key[CERTDB_BOOTSTRAP_KEY_LENGTH + 1];
	char   ca_file[PATH_MAX];
	char   crl_file[PATH_MAX];
	char   key_file[PATH_MAX];
	char   serial_file[PATH_MAX];
	char   cert_org[256];
	char   cert_email[512];

	/* Leave space for "0x" and terminating zero */
	char   min_serial[MAX_HEX_SERIAL_LENGTH + 3];
	char   max_serial[MAX_HEX_SERIAL_LENGTH + 3];
} certalator_conf = {
	0,
	"ca/certdb.sqlite",
	"",
	"ca/overnet.pem",
	"ca/overnet.crl",
	"ca/private/overnet_key.pem",
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
	if ((s = ASN1_IA5STRING_new()) == NULL)
		return NULL;
	if (!ASN1_STRING_set(s, "agent", 5))
		return NULL;
	if ((v = ASN1_TYPE_new()) == NULL)
		return NULL;
	ASN1_TYPE_set(v, V_ASN1_IA5STRING, s);
	if (sk_ASN1_TYPE_push(sk, v) <= 0)
		return NULL;

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
agent_connect(struct xerr *e)
{
	if (agent_ssl_ctx == NULL) {
		if ((agent_ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

		SSL_CTX_set_verify(agent_ssl_ctx, SSL_VERIFY_PEER, NULL);

		// TODO: don't use OS-provided certs
		//if (!SSL_CTX_set_default_verify_paths(ctx))
		//	return XERRF(e, XLOG_SSL, ERR_get_error(),
		//	    "SSL_CTX_set_default_verify_paths");

		if (SSL_CTX_use_PrivateKey(agent_ssl_ctx, priv_key) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_PrivateKey");
		if (SSL_CTX_use_certificate(agent_ssl_ctx, ca_crt) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_certificate");
	}

	if (agent_bio == NULL) {
		if ((agent_bio = BIO_new_ssl_connect(agent_ssl_ctx)) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_new_ssl_connect");

		BIO_get_ssl(agent_bio, &agent_ssl);
		if (agent_ssl == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_get_ssl");

		SSL_set_mode(agent_ssl, SSL_MODE_AUTO_RETRY);

		BIO_set_conn_hostname(agent_bio, "localhost:9790");
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
	printf("Usage: %s [options] <command>\n", program);
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
verify(X509_STORE_CTX *ctx, X509 *crt)
{
	int              roles_idx;
	X509_EXTENSION  *ex;
	X509_NAME       *subject;
	char             common_name[256];
	int              r, i;
	char           **roles;
	ssize_t          n;

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

	roles_idx = X509_get_ext_by_NID(crt, NID_overnet_roles, -1);
	if (roles_idx == -1)
		xlog(LOG_ERR, NULL,
		    "%s: overnetRoles extension not found", __func__);

	if ((ex = X509_get_ext(crt, roles_idx)) == NULL) {
		xlog(LOG_ERR, NULL, "X509_get_ext: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	roles = malloc(CERTALATOR_MAX_ROLES *
	    (sizeof(char *) + CERTALATOR_MAX_ROLE_LENGTH));
	if (roles == NULL) {
		xlog_strerror(LOG_ERR, errno, "%s: malloc", __func__);
		return -1;
	}

	bzero(roles, CERTALATOR_MAX_ROLES *
	    (sizeof(char *) + CERTALATOR_MAX_ROLE_LENGTH));
	for (i = 0; i < CERTALATOR_MAX_ROLES; i++)
		roles[i] = (char *)roles +
		    (CERTALATOR_MAX_ROLES * sizeof(char *)) +
		    (i * CERTALATOR_MAX_ROLE_LENGTH);

	n = decode_overnet_roles(ex, roles, CERTALATOR_MAX_ROLES);
	if (n == -1) {
		free(roles);
		return -1;
	}

	for (i = 0; i < n; i++)
		xlog(LOG_INFO, NULL, "role: %s\n", roles[i]);
	free(roles);
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
new_serial()
{
	BIGNUM  *min_bn = NULL;
	BIGNUM  *max_bn = NULL;
	BIGNUM  *v = NULL;
	int      fd, fdtmp;
	char    *p;
	ssize_t  r;
	int      l;
	char     buf[MAX_HEX_SERIAL_LENGTH + 1];
	char     tmpfile[PATH_MAX];

	if (!BN_hex2bn(&min_bn, certalator_conf.min_serial)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!BN_hex2bn(&max_bn, certalator_conf.max_serial)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (snprintf(tmpfile, sizeof(tmpfile), "%s.new",
	    certalator_conf.serial_file) >= sizeof(tmpfile))
		errx(1, "tmpfile name too long");

	/*
	 * We get an exclusive lock while we write the new serial to a
	 * tmp file and overwrite the serial file. This way other processes
	 * may not read or write while we are incrementing the serial.
	 */
	if ((fd = open_wflock(certalator_conf.serial_file,
	    O_RDWR|O_CREAT, 0666, LOCK_EX)) == -1)
		err(1, "open_wflock");
	r = read(fd, buf, sizeof(buf));
	if (r == -1)
		err(1, "read");
	if (r > 0) {
		if (buf[r - 1] != '\n')
			errx(1, "serial file does not end in newline, "
			    "or the value is too large");
		buf[r - 1] = '\0';
		for (p = buf; *p; p++) {
			if (!((*p >= '0' && *p <= '9') ||
			    (*p >= 'a' && *p <= 'f') ||
			    (*p >= 'A' && *p <= 'F'))) {
				errx(1, "serial is not a valid hex integer");
			}
		}
		if (!BN_hex2bn(&v, buf)) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}

		if (BN_cmp(v, min_bn) == -1)
			errx(1, "saved serial is less than min_serial");

		if (!BN_add_word(v, 1)) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		if (BN_cmp(v, max_bn) > 0) {
			close(fd);
			BN_free(min_bn);
			BN_free(max_bn);
			warnx("max_serial exceeded");
			return NULL;
		}
	} else {
		if ((v = BN_dup(min_bn)) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}

	BN_free(min_bn);
	BN_free(max_bn);

	if ((p = BN_bn2hex(v)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	l = snprintf(buf, sizeof(buf), "%s\n", p);
	if (l >= sizeof(buf))
		errx(1, "computed serial is too large");
	OPENSSL_free(p);

	if ((fdtmp = open(tmpfile, O_WRONLY|O_CREAT, 0666)) == -1)
		err(1, "open");
	r = write(fdtmp, buf, l);
	if (r == -1)
		err(1, "write");
	if (r < l)
		errx(1, "short write on serial file");
	fsync(fdtmp);
	close(fdtmp);
	if (rename(tmpfile, certalator_conf.serial_file) == -1)
		err(1, "rename");
	close(fd);

	return v;
}

int
add_ext(X509V3_CTX *ctx, X509 *crt, int nid, char *value)
{
	X509_EXTENSION *ex;
	if (!(ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value)))
		return 0;
	return X509_add_ext(crt, ex, -1);
}

int
sign(const char *cert_path, const char **roles)
{
	X509           *crt, *newcrt;
	FILE           *f;
	char            new_cert[PATH_MAX];
	BIGNUM         *serial;
	X509_EXTENSION *ex;
	X509V3_CTX      ctx;
	int             san_idx;

	load_keys();

	if ((f = fopen(cert_path, "r")) == NULL)
		err(1, "fopen");
	if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	X509V3_set_ctx(&ctx, ca_crt, crt, NULL, NULL, 0);

	if ((newcrt = X509_new()) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_set_version(newcrt, 2)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	serial = new_serial();
	if (serial == NULL)
		exit(1);

	if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(newcrt)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	BN_free(serial);

	if (!X509_set_issuer_name(newcrt, X509_get_subject_name(ca_crt))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!X509_set_subject_name(newcrt, X509_get_subject_name(crt))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!X509_set_pubkey(newcrt, X509_get0_pubkey(crt))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	X509_gmtime_adj(X509_get_notBefore(newcrt), 0);
	X509_gmtime_adj(X509_get_notAfter(newcrt), 86400);

	san_idx = X509_get_ext_by_NID(crt, NID_subject_alt_name, -1);
	if (san_idx == -1)
		errx(1, "subjectAltName extension not found");
	if ((ex = X509_get_ext(crt, san_idx)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_add_ext(newcrt, ex, -1)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!add_ext(&ctx, newcrt, NID_basic_constraints, "critical,CA:false")) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!add_ext(&ctx, newcrt, NID_key_usage, "critical,nonRepudiation,digitalSignature,keyEncipherment")) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!add_ext(&ctx, newcrt, NID_ext_key_usage, "serverAuth,clientAuth")) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!add_ext(&ctx, newcrt, NID_subject_key_identifier, "hash")) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!add_ext(&ctx, newcrt, NID_authority_key_identifier, "keyid,issuer")) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// TODO: need to add the subjectAltNames

	ex = encode_overnet_roles(roles);
	if (!X509_add_ext(newcrt, ex, -1)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!X509_sign(newcrt, priv_key, EVP_sha256())) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	snprintf(new_cert, sizeof(new_cert), "%s.new", cert_path);
	if ((f = fopen(new_cert, "w")) == NULL)
		err(1, "fopen");
	if (!PEM_write_X509(f, newcrt)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

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
int
authority_bootstrap_setup(const char *cn, const char **sans,
    size_t sans_sz, const char **roles, size_t roles_sz, uint32_t cert_expiry,
    uint32_t timeout, struct xerr *e)
{
	char                    buf[48];
	char                    subject[CERTALATOR_MAX_SUBJET_LENGTH];
	BIO                    *b, *b64;
	struct bootstrap_entry  be;
	struct timespec         tp;

	if (snprintf(subject, sizeof(subject), "/O=%s/CN=%s/emailAddress=%s",
	    certalator_conf.cert_org, cn, certalator_conf.cert_email) >=
	    sizeof(subject))
		return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "resulting subject name is too long for commonName %s",
		    cn);

	if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	if ((b = BIO_new(BIO_s_mem())) == NULL) {
		BIO_free(b64);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
	}
	BIO_push(b64, b);

	arc4random_buf(buf, sizeof(buf));

	if (BIO_write(b64, buf, sizeof(buf)) <= 0) {
		BIO_free_all(b64);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	}
	BIO_flush(b64);

	if (BIO_read(b, be.bootstrap_key, sizeof(be.bootstrap_key))
	    != (int)sizeof(be.bootstrap_key)) {
		BIO_free_all(b64);
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "short read for base64 bootstrap key");
	}
	BIO_free_all(b64);

	clock_gettime(CLOCK_REALTIME, &tp);

	// TODO: make this configurable
	/* A bootstrap key is valid for 10 minutes */
	be.valid_until_sec = tp.tv_sec + timeout;
	be.not_before_sec = tp.tv_sec;
	/* A cert is valid for 7 days */
	be.not_after_sec = tp.tv_sec + cert_expiry;

	be.subject = subject;
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
	    program);
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

	if (!X509_REQ_set_pubkey(req, priv_key)) {
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
// We'll need to know:
// - The subject name
// - The subjectAltName (possibly multiple)
// - NOT the roles associated with with the challenge;
//   those are kept server-side
// - Validity period (capped by the server, but could be shorter)
// Most other things are decided by the cert issuer.
FILE *
agent_bootstrap_dialin(struct xerr *e)
{
	// TODO: agent-side bootstrap initiation, passing a one-time-key
	// to the authority. We'll receive the parameters like CommonName,
	// SANs, etc. from which we create a key & req.

	// TODO: get the one time key from our config, contact the
	// authoritah, get subject, SANs and roles.

	struct mdr     m;
	char           buf[64];
	char          *subject = NULL;
	struct mdr_in  m_in[0];

	m_in[0].type = MDR_S;
	m_in[0].v.s.bytes = certalator_conf.bootstrap_key;
	if (mdr_pack(&m, buf, sizeof(buf), msg_bootstrap_dialin,
	    MDR_F_NONE, m_in, 1) == MDR_FAIL) {
		// TODO: err
		return NULL;
	}

	// TODO: send the damn thing
	if (agent_send(&m, e) == -1) {
		// TODO: err
		return NULL;
	}

	if (agent_new_req(subject) == -1)
		return NULL;

	return NULL;
}

int
authority_bootstrap_dialin(struct mdr *msg, struct xerr *e)
{
	// TODO: wereceive the one-time-key from a client then
	// need to contact it over its CommonName to confirm
	// they are who they claim to be.
	// msg should have the one time key.

	//struct bootstrap_entry be;

	//if (certdb_get_bootstrap(&be, btkey, e) == -1)
	//	return -1;

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

	// TODO: make bits configurable
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
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
	int          pkey_sz;
	X509_LOOKUP *lookup;
	struct xerr  e;

	if ((f = fopen(certalator_conf.key_file, "r")) == NULL) {
		if (errno == ENOENT) {
			warnx("no private key found, generating one");
			f = new_privkey();
		} else
			err(1, "fopen");
	}
	if ((priv_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if (!(pkey_sz = EVP_PKEY_size(priv_key))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
#ifndef __OpenBSD__
	/* pledge() doesn't allow mlock() */
	if (mlock(priv_key, pkey_sz) == -1)
		err(1, "mlock");
#endif
	if ((f = fopen(certalator_conf.ca_file, "r")) == NULL) {
		if (errno != ENOENT)
			err(1, "fopen");
		f = agent_bootstrap_dialin(&e);
	}
	if ((ca_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");
	if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_cert_file(lookup, certalator_conf.ca_file,
	    X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_crl_file(lookup, certalator_conf.crl_file,
	    X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL)) {
		ERR_print_errors_fp(stderr);
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
	int               r;
	struct mdr        m, msg;
	char              buf[32768];
	uint64_t          id;
	int               fd;
	X509             *peer_cert = NULL;
	X509_STORE_CTX   *ctx;
	struct sigaction  act;
	struct xerr       e;
	struct mdr_in     m_in[5];

	load_keys();

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	xlog_init(program, NULL, NULL, 1);

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1)
		return -1;

	while ((r = mdr_read_from_fd(&m, MDR_F_NONE,
	    0, buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_unpack_from_fd", __func__);
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

			// TODO: check if we have role "authority", without
			// which we cannot issue certs, so we should fail.

			if (authority_bootstrap_dialin(&msg, &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);

			continue;
		}

		if (verify(ctx, peer_cert) != 0) {
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
	return -1;
}

void
cleanup()
{
	flatconf_free(certalator_config_vars);
	if (ca_crt != NULL) {
		X509_free(ca_crt);
		ca_crt = NULL;
	}
	if (priv_key != NULL) {
		EVP_PKEY_free(priv_key);
		priv_key = NULL;
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
	X509           *crt;
	X509_STORE_CTX *ctx;
	struct xerr     e;

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

	if (mdr_register_builtin_specs() == MDR_FAIL)
		err(1, "mdr_register_builtin_specs");
	if ((msg_bootstrap_setup =
	    mdr_register_spec(&msgdef_bootstrap_setup)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_bootstrap_dialin =
	    mdr_register_spec(&msgdef_bootstrap_dialin)) == NULL)
		err(1, "mdr_register_spec");
	if ((msg_pack_beresp = mdr_registry_get(MDR_DCV_MDRD_BERESP)) == NULL)
		err(1, "mdr_registry_get");
	if ((msg_pack_beresp_wmsg =
	    mdr_registry_get(MDR_DCV_MDRD_BERESP_WMSG)) == NULL)
		err(1, "mdr_registry_get");

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
			xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
			    ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
		status = verify(ctx, crt);
		X509_STORE_CTX_free(ctx);
	} else if (strcmp(command, "sign") == 0) {
		if (opt >= argc)
			errx(1, "no certificate file provided");
		status = sign(argv[opt], (const char **)argv + opt + 1);
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
