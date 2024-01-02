#include <sys/file.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "config_vars.h"
#include "xlog.h"

#define MAX_HEX_SERIAL_LENGTH 32

const char *program = "certainty";
int         NID_overnet_roles;
X509_STORE *store;
EVP_PKEY   *priv_key;
X509       *ca_crt;

int  foreground = 0;
int  debug = 0;
char config_file_path[PATH_MAX] = "/etc/certainty.conf";

extern char *optarg;
extern int   optind, opterr, optopt;

struct {
	char pid_file[PATH_MAX];
	char ca_file[PATH_MAX];
	char crl_file[PATH_MAX];
	char key_file[PATH_MAX];
	char serial_file[PATH_MAX];

	/* Leave space for "0x" and terminating zero */
	char min_serial[MAX_HEX_SERIAL_LENGTH + 3];
	char max_serial[MAX_HEX_SERIAL_LENGTH + 3];
} certainty_conf = {
	"/var/run/certainty.pid",
	"ca/overnet.pem",
	"ca/overnet.crl",
	"ca/private/overnet_key.pem",
	"ca/serial",
	"0x0",
	"0x0"
};

struct config_vars certainty_config_vars[] = {
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
int
boostrap_req()
{
	return 0;
}

// TODO: client-side for the above; given a challenge and roles, we can
// generate a REQ with those roles, create our REQ and pick and DNS/CommonName
// we can answer to, then contact the server, passing the challenge to get the
// REQ signed.
int
agent_boostrap_req()
{
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

int
daemon_pid(const char *pid_path, int nochdir, int noclose)
{
	pid_t pid;
	int   pid_fd;
	char  pid_line[32];
	int   null_fd;

	if ((pid_fd = open(pid_path, O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1)
		err(1, "open");

	if (flock(pid_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			errx(1, "pid file %s is already locked; "
			    "is another instance running?", pid_path);
		}
		err(1, "flock");
	}

	if ((pid = fork()) == -1)
		err(1, "fork");

	if (pid == 0)
		_exit(0);

	if (!nochdir && chdir("/") == -1)
		err(1, "chdir");

	if (!noclose) {
		if ((null_fd = open("/dev/null", O_RDWR)) == -1)
			err(1, "open");

		dup2(null_fd, STDIN_FILENO);
		dup2(null_fd, STDOUT_FILENO);
		dup2(null_fd, STDERR_FILENO);
		if (null_fd > 2)
			close(null_fd);
	}

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(pid_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "write");
		_exit(1);
	}

	if (fsync(pid_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "fsync");
		_exit(1);
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int          opt;
	char        *command;
	X509_LOOKUP *lookup;
	FILE        *f;
	size_t       sz;
	char        *p;

	xlog_init(program, NULL, NULL, 1);

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
		case 'f':
			foreground = 1;
			break;
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
	for (p = certainty_conf.min_serial; *p; p++) {
		if (!((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f') ||
		    (*p >= 'A' && *p <= 'F'))) {
			errx(1, "min_serial is not a valid hex integer");
		}
	}

	if (strncmp(certainty_conf.max_serial, "0x", 2) != 0)
		errx(1, "max_serial does not begin with \"0x\"");
	sz = strlen(certainty_conf.max_serial) - 2;
	memmove(certainty_conf.max_serial,
	    certainty_conf.max_serial + 2, sz);
	certainty_conf.max_serial[sz] = '\0';
	for (p = certainty_conf.max_serial; *p; p++) {
		if (!((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f') ||
		    (*p >= 'A' && *p <= 'F'))) {
			errx(1,
			    "min_serial is not a valid hexadecimal integer");
		}
	}

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
	X509_STORE_set_verify_cb_func(store, verify_callback);
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
	}

	/*
	 * Without args, we run in daemon mode
	 */

	return 1;
}
