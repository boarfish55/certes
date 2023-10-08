#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <err.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *program = "certainty";
char        ca_file[PATH_MAX] = "ca/overnet.pem";
char        crl_file[PATH_MAX] = "ca/overnet.crl";
int         overnet_roles_nid;
X509_STORE *store;

extern char *optarg;
extern int   optind, opterr, optopt;

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
	ASN1_OCTET_STRING *asn1str;
	unsigned char *data, *p;
	int len, type, ex_len;

	asn1str = X509_EXTENSION_get_data(ext);
	data = asn1str->data;
	ex_len = asn1str->length;
	for (p = data + 2; p < data + ex_len; ) {
		type = *p++;
		if (type != V_ASN1_IA5STRING) {
			warnx("expected V_ASN1_IA5STRING, got %d", type);
			return -1;
		}
		len = *p++;
		printf("role=%.*s\n", len, p);
		p += len;
	}
	return 0;
}

int
valid_time(X509 *crt)
{
	ASN1_TIME *tm, *tm_now;

	tm_now = ASN1_TIME_set(NULL, time(0));

	tm = X509_get_notAfter(crt);
	if (tm == NULL) {
		warnx("notAfter is garbage");
		return -1;
	}
	if (ASN1_TIME_compare(tm, tm_now) == -1) {
		warnx("cert is expired");
		return -1;
	}

	tm = X509_get_notBefore(crt);
	if (tm == NULL) {
		warnx("notAfter is garbage");
		return -1;
	}
	if (ASN1_TIME_compare(tm, tm_now) == 1) {
		warnx("cert is not yet valid");
		return -1;
	}
	return 0;
}

void
usage()
{
	printf("Usage: %s [options] <command>\n", program);
	printf("    -h                      Prints this help\n");
	printf("    -C <ca file>            Specify an alternate Certificate Authority\n");
	printf("\n");
	printf("  Commands:\n");
	printf("    verify <certificate>    Ensures the certificate is signed by "
	    "our\n");
	printf("                            authority\n");
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

	if ((crt = X509_new()) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

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
	if (valid_time(crt) == -1) {
		errx(1, "cert is not valid");
	}

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

	roles_idx = X509_get_ext_by_NID(crt, overnet_roles_nid, -1);
	if (roles_idx == -1)
		errx(1, "overnetRoles extension not found");
	if ((ex = X509_get_ext(crt, roles_idx)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	return decode_overnet_roles(ex);
}

int
main(int argc, char **argv)
{
	int          opt;
	char        *command;
	X509_LOOKUP *lookup;

	while ((opt = getopt(argc, argv, "hC:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'C':
			strlcpy(ca_file, optarg, sizeof(ca_file));
			break;
		}
	}

	if (optind >= argc) {
		usage();
		exit(1);
	}

	overnet_roles_nid = OBJ_create("1.3.6.1.4.1.35910.3.1",
	    "overnetRoles", "Overnet Security Roles");
	if (overnet_roles_nid == NID_undef)
		err(1, "OBJ_create");

	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");
	X509_STORE_set_verify_cb_func(store, verify_callback);
	if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_cert_file(lookup, ca_file, X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!X509_load_crl_file(lookup, crl_file, X509_FILETYPE_PEM)) {
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
	}

	usage();
	return 1;
}
