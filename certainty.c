#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
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
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "config_vars.h"
#include "util.h"
#include "tlsev.h"
#include "xlog.h"

#define MAX_HEX_SERIAL_LENGTH 32

const char *program = "certainty";
const char *daemon_name = "certaintyd";
int         NID_overnet_roles;
X509_STORE *store;
EVP_PKEY   *priv_key;
X509       *ca_crt;

struct tlsev_listener listener;

volatile sig_atomic_t shutdown_triggered = 0;

int  foreground = 0;
int  debug = 0;
int  ssl_data_idx;
char config_file_path[PATH_MAX] = "/etc/certainty.conf";

extern char *optarg;
extern int   optind, opterr, optopt;

struct {
	char *unpriv_user;
	char *unpriv_group;

	char  pid_file[PATH_MAX];
	char  ca_file[PATH_MAX];
	char  crl_file[PATH_MAX];
	char  key_file[PATH_MAX];
	char  serial_file[PATH_MAX];

	/* Leave space for "0x" and terminating zero */
	char  min_serial[MAX_HEX_SERIAL_LENGTH + 3];
	char  max_serial[MAX_HEX_SERIAL_LENGTH + 3];

	uint64_t port;
	uint64_t listen_backlog;
	uint64_t prefork;
	uint64_t max_clients;
	uint64_t socket_timeout;
} certainty_conf = {
	"_certainty",
	"_certainty",
	"/var/run/certainty.pid",
	"ca/overnet.pem",
	"ca/overnet.crl",
	"ca/private/overnet_key.pem",
	"ca/serial",
	"0x0",
	"0x0",
	9790,
	128,
	4,
	1000,
	10
};

struct config_vars certainty_config_vars[] = {
	{
		"unpriv_user",
		CONFIG_VARS_PWNAM,
		&certainty_conf.unpriv_user,
		0
	},
	{
		"unpriv_group",
		CONFIG_VARS_GRNAM,
		&certainty_conf.unpriv_group,
		0
	},
	{
		"pid_file",
		CONFIG_VARS_STRING,
		certainty_conf.pid_file,
		sizeof(certainty_conf.pid_file)
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
	{
		"port",
		CONFIG_VARS_ULONG,
		&certainty_conf.port,
		sizeof(certainty_conf.port)
	},
	{
		"listen_backlog",
		CONFIG_VARS_ULONG,
		&certainty_conf.listen_backlog,
		sizeof(certainty_conf.listen_backlog)
	},
	{
		"prefork",
		CONFIG_VARS_ULONG,
		&certainty_conf.prefork,
		sizeof(certainty_conf.prefork)
	},
	{
		"max_clients",
		CONFIG_VARS_ULONG,
		&certainty_conf.max_clients,
		sizeof(certainty_conf.max_clients)
	},
	{
		"socket_timeout",
		CONFIG_VARS_ULONG,
		&certainty_conf.socket_timeout,
		sizeof(certainty_conf.socket_timeout)
	},
	CONFIG_VARS_LAST
};

/*
 *  The verification callback can be used to customise the operation of
 *  certificate verification, for instance by overriding error conditions or
 *  logging errors for debugging purposes.
 *
 *  The ok parameter to the callback indicates the value the callback should
 *  return to retain the default behaviour. If it is zero then an error
 *  condition is indicated. If it is 1 then no error occurred. If the flag
 *  X509_V_FLAG_NOTIFY_POLICY is set then ok is set to 2 to indicate the policy
 *  checking is complete.
 */
int
verify_callback(int ok, X509_STORE_CTX *ctx)
{
	int e;
	if (!ok) {
		e = X509_STORE_CTX_get_error(ctx);
		fprintf(stderr, "error: %s\n",
		    X509_verify_cert_error_string(e));
	}
	return ok;
}

int
verify_callback_daemon(int ok, X509_STORE_CTX *ctx)
{
	int           e;
	SSL          *ssl;
	X509         *err_cert;
	struct tlsev *t;
	char          name[256];
	char          hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	ssl = X509_STORE_CTX_get_ex_data(ctx,
	    SSL_get_ex_data_X509_STORE_CTX_idx());
	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	t = SSL_get_ex_data(ssl, ssl_data_idx);

	if (getnameinfo((struct sockaddr *)&t->peer_addr,
	    sizeof(struct sockaddr_in6), hbuf, sizeof(hbuf), sbuf,
	    sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		hbuf[0] = '?';
		hbuf[1] = '\0';
		sbuf[0] = '?';
		sbuf[1] = '\0';
	}

	if (!ok) {
		X509_NAME_oneline(X509_get_subject_name(err_cert),
		    name, sizeof(name));
		e = X509_STORE_CTX_get_error(ctx);
		xlog(LOG_NOTICE, NULL, "verify error for %s (%s:%s): %s\n",
		    name, hbuf, sbuf, X509_verify_cert_error_string(e));
	}
	return ok;
}

int
decode_overnet_roles(X509_EXTENSION *ext)
{
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	ASN1_TYPE           *v;

	asn1str = X509_EXTENSION_get_data(ext);

	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&asn1str->data, asn1str->length);
	while (sk_ASN1_TYPE_num(seq) > 0) {
		v = sk_ASN1_TYPE_shift(seq);
		printf("role: %s\n", v->value.ia5string->data);
		free(v);
	}
	sk_ASN1_TYPE_free(seq);
	return 0;
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
	printf("\tdaemon                          Run certainty daemon\n");
}

int
verify(const char *cert_path)
{
	int             roles_idx;
	X509           *crt;
	X509_EXTENSION *ex;
	X509_NAME      *subject;
	char            common_name[256];
	FILE           *f;
	int             r;
	X509_STORE_CTX *ctx;

	if ((f = fopen(cert_path, "r")) == NULL)
		err(1, "fopen");
	if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	subject = X509_get_subject_name(crt);
	if (subject == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (X509_NAME_get_text_by_NID(subject, NID_commonName,
	    common_name, sizeof(common_name)) == -1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	printf("Common name: %s\n", common_name);

	// TODO: do a challenge on the client and its cert name. The peer
	// IP on the connection should match one of the subjectAltNames, or
	// the commonName of the cert. If there's no match, deny.

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_STORE_CTX_init(ctx, store, crt, NULL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((r = X509_verify_cert(ctx)) < 0) {
		ERR_print_errors_fp(stderr);
		errx(1, "X509_verify_cert error");
	} else if (r == 0) {
		ERR_print_errors_fp(stderr);
		errx(1, "X509_verify_cert failed");
	}

	roles_idx = X509_get_ext_by_NID(crt, NID_overnet_roles, -1);
	if (roles_idx == -1)
		errx(1, "overnetRoles extension not found");
	if ((ex = X509_get_ext(crt, roles_idx)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	return decode_overnet_roles(ex);
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
handle_signals(int sig)
{
	xlog(LOG_NOTICE, NULL, "signal received: %d", sig);
	shutdown_triggered = 1;
	tlsev_shutdown(&listener);
}

int
daemon_in_cb(struct tlsev *t, const char *buf, size_t n, void *data)
{
	return tlsev_reply(t, buf, n);
}

int
do_daemon(const char **argv)
{
	SSL_CTX             *ctx;
	struct xerr          e;
	int                  lsock;
	struct sockaddr_in6  sa;
	int                  one = 1;
	int                  n_children;
	int                  wstatus;
	pid_t                pid;
	struct sigaction     act;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = handle_signals;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		err(1, "sigaction");
	}

	if (!foreground) {
		if (daemonize(daemon_name, certainty_conf.pid_file,
		    0, 0, &e) == -1) {
			xerr_print(&e);
			exit(1);
		}
	}

	if (geteuid() == 0) {
		if (drop_privileges(certainty_conf.unpriv_group,
		    certainty_conf.unpriv_user, &e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
	}

#ifdef __OpenBSD__
	if (unveil(certainty_conf.ca_file, "rw") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", certainty_conf.ca_file);
		exit(1);
	}
	if (unveil(certainty_conf.crl_file, "rw") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", certainty_conf.crl_file);
		exit(1);
	}
	if (unveil(certainty_conf.key_file, "r") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", certainty_conf.key_file);
		exit(1);
	}
	if (unveil(certainty_conf.serial_file, "rw") == -1) {
		xlog_strerror(LOG_ERR, errno,
		    "unveil: %s", certainty_conf.serial_file);
		exit(1);
	}
	if (pledge("stdio rpath wpath cpath inet flock dns proc", "") == -1) {
		xlog_strerror(LOG_ERR, errno, "pledge");
		exit(1);
	}
#endif

	if ((ctx = SSL_CTX_new(TLS_method())) == NULL) {
		xlog(LOG_ERR, NULL, "SSL_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	SSL_CTX_set_security_level(ctx, 3);
	SSL_CTX_set_cert_store(ctx, store);
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback_daemon);

	if (SSL_CTX_use_certificate(ctx, ca_crt) != 1) {
		xlog(LOG_ERR, NULL, "SSL_CTX_use_certificate: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey(ctx, priv_key) != 1) {
		xlog(LOG_ERR, NULL, "SSL_CTX_use_PrivateKey: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		exit(1);
	}

	if ((lsock = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		exit(1);
	}

	if (setsockopt(lsock, SOL_SOCKET,
	    SO_REUSEADDR, &one, sizeof(one)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		exit(1);
	}

	bzero(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;
	memcpy(&sa.sin6_addr, &in6addr_any, sizeof(in6addr_any));
	sa.sin6_port = htons(certainty_conf.port);
	if (bind(lsock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		xlog_strerror(LOG_ERR, errno, "bind");
		exit(1);
	}

	if (listen(lsock, certainty_conf.listen_backlog) == -1) {
		xlog_strerror(LOG_ERR, errno, "listen");
		exit(1);
	}

	ssl_data_idx = SSL_get_ex_new_index(0, "tlsev_idx", NULL, NULL, NULL);
	if (tlsev_init(&listener, ctx, lsock, certainty_conf.socket_timeout,
	    certainty_conf.max_clients, ssl_data_idx,
	    &daemon_in_cb, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "tlsev_init");
		exit(1);
	}

	if (certainty_conf.prefork <= 0 || foreground) {
		tlsev_run(&listener);
		SSL_CTX_free(ctx);
		return 0;
	}

	for (n_children = 0; n_children < certainty_conf.prefork;
	    n_children++) {
		if ((pid = fork()) == -1) {
			xlog_strerror(LOG_ERR, errno, "fork");
		} else if (pid == 0) {
			setproctitle("listener");
			tlsev_run(&listener);
			SSL_CTX_free(ctx);
			exit(0);
		}
	}

	setproctitle("parent");

	for (;;) {
		pid = waitpid(-1, &wstatus, 0);
		if (pid != -1 && !shutdown_triggered) {
			n_children--;
			if (WIFEXITED(wstatus))
				xlog(LOG_WARNING, NULL,
				    "child %d exited with status %d",
				    pid, WEXITSTATUS(wstatus));
			else
				xlog(LOG_WARNING, NULL,
				    "child %d killed by signal %d",
				    pid, WTERMSIG(wstatus));
			if ((pid = fork()) == -1) {
				xlog_strerror(LOG_ERR, errno, "fork");
			} else if (pid == 0) {
				setproctitle("listener");
				tlsev_run(&listener);
				SSL_CTX_free(ctx);
				exit(0);
			} else {
				n_children++;
			}
			continue;
		}

		if (!shutdown_triggered) {
			xlog(LOG_WARNING, NULL, "signal received but "
			    "shutdown not yet triggered");
			continue;
		}

		if (lsock > -1) {
			close(lsock);
			lsock = -1;

			sigemptyset(&act.sa_mask);
			act.sa_flags = 0;
			act.sa_handler = SIG_IGN;
			sigaction(SIGINT, &act, NULL);
			sigaction(SIGTERM, &act, NULL);

			kill(0, 15);
		}

		if (pid != -1) {
			if (WIFEXITED(wstatus))
				xlog(LOG_NOTICE, NULL,
				    "child %d exited with status %d",
				    pid, WEXITSTATUS(wstatus));
			else
				xlog(LOG_NOTICE, NULL,
				    "child %d killed by signal %d",
				    pid, WTERMSIG(wstatus));
			n_children--;
			if (n_children == 0)
				break;
		}
	}
	SSL_CTX_free(ctx);
	xlog(LOG_NOTICE, NULL, "all children exited");
	return 0;
}

void
cleanup()
{
	config_vars_free(certainty_config_vars);
}

int
main(int argc, char **argv)
{
	int          opt, r;
	char        *command;
	X509_LOOKUP *lookup;
	FILE        *f;
	size_t       sz;

	while ((opt = getopt(argc, argv, "c:hfd")) != -1) {
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
		case 'f':
			foreground = 1;
			break;
		}
	}

	if (config_vars_read(config_file_path, certainty_config_vars) == -1)
		err(1, "config_vars_read");
	atexit(&cleanup);

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
	if (certainty_conf.port < 1 || certainty_conf.port > 65535)
		errx(1, "invalid listen port specified");
	if (certainty_conf.listen_backlog < 1)
		errx(1, "invalid listen backlog size specified");

	if (optind >= argc) {
		usage();
		exit(1);
	}

	NID_overnet_roles = OBJ_create("1.3.6.1.4.1.35910.3.1",
	    "overnetRoles", "Overnet Security Roles");
	if (NID_overnet_roles == NID_undef)
		err(1, "OBJ_create");

	if ((f = fopen(certainty_conf.key_file, "r")) == NULL)
		err(1, "fopen");
	if ((priv_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if ((f = fopen(certainty_conf.ca_file, "r")) == NULL)
		err(1, "fopen");
	if ((ca_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");
	//X509_STORE_set_verify_cb_func(store, verify_callback);
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

	command = argv[optind++];

	if (strcmp(command, "verify") == 0) {
		if (optind >= argc) {
			errx(1, "no certificate file provided");
			exit(1);
		}
		return verify(argv[optind++]);
	} else if (strcmp(command, "sign") == 0) {
		if (optind >= argc) {
			errx(1, "no certificate file provided");
			exit(1);
		}
		return sign(argv[optind], (const char **)argv + optind + 1);
	} else if (strcmp(command, "daemon") == 0) {
		r = do_daemon((const char **)argv + optind + 1);
		tlsev_destroy(&listener);
		return r;
	}

	usage();
	return 1;
}
