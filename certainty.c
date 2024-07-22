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
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "certainty.h"
#include "config_vars.h"
#include "mdr_certainty.h"
#include "mdr_mdrd.h"
#include "util.h"
#include "xlog.h"

#define MAX_HEX_SERIAL_LENGTH 32

const char *program = "certainty";
int         NID_overnet_roles;
X509_STORE *store = NULL;
EVP_PKEY   *priv_key = NULL;
X509       *ca_crt = NULL;
int         debug = 0;
char        config_file_path[PATH_MAX] = "/etc/certainty.conf";

extern char *optarg;
extern int   optind, opterr, optopt;

struct {
	int   enable_coredumps;

	char  ca_file[PATH_MAX];
	char  crl_file[PATH_MAX];
	char  key_file[PATH_MAX];
	char  serial_file[PATH_MAX];

	/* Leave space for "0x" and terminating zero */
	char  min_serial[MAX_HEX_SERIAL_LENGTH + 3];
	char  max_serial[MAX_HEX_SERIAL_LENGTH + 3];
} certainty_conf = {
	0,
	"ca/overnet.pem",
	"ca/overnet.crl",
	"ca/private/overnet_key.pem",
	"ca/serial",
	"0x0",
	"0x0"
};

struct config_vars certainty_config_vars[] = {
	{
		"enable_coredumps",
		CONFIG_VARS_BOOLINT,
		&certainty_conf.enable_coredumps,
		sizeof(certainty_conf.enable_coredumps)
	},
	{
		"ca_file",
		CONFIG_VARS_STRING,
		certainty_conf.ca_file,
		sizeof(certainty_conf.ca_file)
	},
	{
		"crl_file",
		CONFIG_VARS_STRING,
		certainty_conf.crl_file,
		sizeof(certainty_conf.crl_file)
	},
	{
		"key_file",
		CONFIG_VARS_STRING,
		certainty_conf.key_file,
		sizeof(certainty_conf.key_file)
	},
	{
		"serial_file",
		CONFIG_VARS_STRING,
		certainty_conf.serial_file,
		sizeof(certainty_conf.serial_file)
	},
	{
		"min_serial",
		CONFIG_VARS_STRING,
		certainty_conf.min_serial,
		sizeof(certainty_conf.min_serial)
	},
	{
		"max_serial",
		CONFIG_VARS_STRING,
		certainty_conf.max_serial,
		sizeof(certainty_conf.max_serial)
	},
	CONFIG_VARS_LAST
};

void load_keys();

ssize_t
decode_overnet_roles(X509_EXTENSION *ext, char **roles, ssize_t roles_len)
{
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	ASN1_TYPE           *v;
	ssize_t              i;

	asn1str = X509_EXTENSION_get_data(ext);

	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&asn1str->data, asn1str->length);
	for (i = 0; i < roles_len && sk_ASN1_TYPE_num(seq) > 0; i++) {
		v = sk_ASN1_TYPE_shift(seq);
		strlcpy(roles[i], (const char *)v->value.ia5string->data,
		    CERTAINTY_MAX_ROLE_LENGTH);
		free(v);
	}
	sk_ASN1_TYPE_free(seq);
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

void
usage()
{
	printf("Usage: %s [options] <command>\n", program);
	printf("\t-h            Prints this help\n");
	printf("\t-d            Do not fork and print errors to STDERR\n");
	printf("\t-f            Do not fork\n");
	printf("\t-c <conf>     Specify alternate configuration path\n");
	printf("\n");
	printf("  Commands:\n");
	printf("\tverify <certificate>            Ensures the certificate is signed by "
	    "our\n");
	printf("\t                                authority\n");
	printf("\tsign <certificate> [roles...]   Re-signs the certificate\n");
	printf("\tmdrd-backend                    Run as an mdrd backend\n");
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

	roles = malloc(CERTAINTY_MAX_ROLES *
	    (sizeof(char *) + CERTAINTY_MAX_ROLE_LENGTH));
	if (roles == NULL) {
		xlog_strerror(LOG_ERR, errno, "%s: malloc", __func__);
		return -1;
	}
	bzero(roles, CERTAINTY_MAX_ROLES *
	    (sizeof(char *) + CERTAINTY_MAX_ROLE_LENGTH));
	for (i = 0; i < CERTAINTY_MAX_ROLES; i++)
		roles[i] = (char *)roles +
		    (CERTAINTY_MAX_ROLES * sizeof(char *)) +
		    (i * CERTAINTY_MAX_ROLE_LENGTH);

	n = decode_overnet_roles(ex, roles, CERTAINTY_MAX_ROLES);
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

	if (!BN_hex2bn(&min_bn, certainty_conf.min_serial)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!BN_hex2bn(&max_bn, certainty_conf.max_serial)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (snprintf(tmpfile, sizeof(tmpfile), "%s.new",
	    certainty_conf.serial_file) >= sizeof(tmpfile))
		errx(1, "tmpfile name too long");

	/*
	 * We get an exclusive lock while we write the new serial to a
	 * tmp file and overwrite the serial file. This way other processes
	 * may not read or write while we are incrementing the serial.
	 */
	if ((fd = open_wflock(certainty_conf.serial_file,
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
	if (rename(tmpfile, certainty_conf.serial_file) == -1)
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

// TODO: for bootstrapping; a new client will send a REQ, preceded with
// a shared key (response to challenge); the shared key will have been supplied by
// by the certainty service and the client must send it. If the challenge is
// successful, certainty signs de REQ. The roles are also passed by
// certainty at creation and tied with the challenge, added to the REQ
// by the client.
int
sign_req()
{
	return 0;
}

// TODO: for boostrapping from the certainty server; this will generate a timed
// challenge and can tie roles to the challenge. Boostrapping can also invoke a
// shell command to perform a action to bring up the server (i.e. DHCP
// reservation & reboot, cloud calls, etc.) The server must remember the
// challenge until it expires.  Active challenges can be kept in an sqlite DB,
// alongside available serial ranges and next allocatable serial.
// When a client sends a successful response to this challenge, along with an
// X509 REQ, the server can sign it if the commonName and subjectAltNames
// match.
int
boostrap_req()
{
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
int
agent_boostrap_req()
{
	// TODO: look at acme-client/keyproc.c:77
	X509_REQ *req;

	if ((req = X509_REQ_new()) == NULL) {
		warnx("X509_REQ_new");
		return 0;
	}

	if (!X509_REQ_set_version(req, 2)) {
		warnx("X509_REQ_set_version");
		return 0;
	}

//	if (!X509_REQ_set_pubkey(x, pkey)) {
//		warnx("X509_REQ_set_pubkey");
//	}

	return 0;
}

// TODO: agent_* functions will run on the certainty agent on client hosts.
// On boostrap, they will need to generate a new REQ with the set of roles
// sent by certainty.
int
agent_new_req()
{
	return 0;
}

// TODO: agent_* functions will run on the certainty agent on client hosts.
// On bootstrap, after generating the REQ, this function will contact
// the certainty server that initiated the bootstrap.
// sent by certainty.
int
agent_sign_req()
{
	return 0;
}

void
load_keys()
{
	FILE        *f;
	int          pkey_sz;
	X509_LOOKUP *lookup;

	if ((f = fopen(certainty_conf.key_file, "r")) == NULL)
		err(1, "fopen");
	if ((priv_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if (!(pkey_sz = EVP_PKEY_size(priv_key))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (mlock(priv_key, pkey_sz) == -1)
		err(1, "mlock");

	if ((f = fopen(certainty_conf.ca_file, "r")) == NULL)
		err(1, "fopen");
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
	if (!X509_load_cert_file(lookup, certainty_conf.ca_file,
	    X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_crl_file(lookup, certainty_conf.crl_file,
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

	while ((r = mdr_unpack_from_fd(&m, 0, buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_unpack_from_fd", __func__);
			goto fail;
		}

		if (mdr_namespace(&m) != MDR_NS_MDRD ||
		    mdr_id(&m) != MDR_ID_MDRD_BEREQ) {
			xlog(LOG_NOTICE, NULL,
			    "%s: invalid mdr namespace or id", __func__);
			goto fail;
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

		if (peer_cert == NULL || verify(ctx, peer_cert) != 0) {
			if (peer_cert != NULL)
				X509_free(peer_cert);
			if (mdrd_pack_beresp(&m, buf, sizeof(buf), id, fd,
			    MDRD_ST_CERTFAIL,
			    MDRD_BERESP_F_CLOSE, NULL) == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdrd_pack_beresp", __func__);
				goto fail;
			}
		} else {
			// TODO: currently this only echoes back
			// TODO: double-free?
			X509_free(peer_cert);
			if (mdrd_pack_beresp(&m, buf, sizeof(buf), id, fd,
			    MDRD_ST_OK, MDRD_BERESP_F_MSG,
			    &msg) == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdrd_pack_beresp", __func__);
				goto fail;
			}
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
	config_vars_free(certainty_config_vars);
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

	while ((opt = getopt(argc, argv, "c:hd")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'c':
			strlcpy(config_file_path, optarg,
			    sizeof(config_file_path));
			break;
		case 'd':
			debug = 1;
			/* fallthrough; debug implies foreground */
		}
	}

	if (config_vars_read(config_file_path, certainty_config_vars) == -1)
		err(1, "config_vars_read");

	if (strncmp(certainty_conf.min_serial, "0x", 2) != 0)
		errx(1, "min_serial does not begin with \"0x\"");
	sz = strlen(certainty_conf.min_serial) - 2;
	memmove(certainty_conf.min_serial,
	    certainty_conf.min_serial + 2, sz);
	certainty_conf.min_serial[sz] = '\0';
	if (!is_hex_str(certainty_conf.min_serial))
		errx(1, "min_serial is not a valid hex integer");

	if (strncmp(certainty_conf.max_serial, "0x", 2) != 0)
		errx(1, "max_serial does not begin with \"0x\"");
	sz = strlen(certainty_conf.max_serial) - 2;
	memmove(certainty_conf.max_serial,
	    certainty_conf.max_serial + 2, sz);
	certainty_conf.max_serial[sz] = '\0';
	if (!is_hex_str(certainty_conf.max_serial))
		errx(1, "max_serial is not a valid hexadecimal integer");

	if (optind >= argc) {
		usage();
		exit(1);
	}

	NID_overnet_roles = OBJ_create("1.3.6.1.4.1.35910.3.1",
	    "overnetRoles", "Overnet Security Roles");
	if (NID_overnet_roles == NID_undef)
		err(1, "OBJ_create");

	command = argv[optind++];

	if (strcmp(command, "verify") == 0) {
		if (optind >= argc)
			errx(1, "no certificate file provided");
		if ((f = fopen(argv[optind], "r")) == NULL)
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
		if (optind >= argc)
			errx(1, "no certificate file provided");
		status = sign(argv[optind], (const char **)argv + optind + 1);
	} else if (strcmp(command, "mdrd-backend") == 0) {
		status = mdrd_backend();
	} else {
		usage();
		status = 1;
	}
	cleanup();
	return status;
}
