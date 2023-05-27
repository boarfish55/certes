#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <err.h>

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
decode_crap(X509_EXTENSION *ext)
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

int
main()
{
	X509_STORE             *store;
	X509_LOOKUP            *lookup;
	X509                   *crt;
	X509_EXTENSION         *ex;
	FILE                   *f;
	int                     overnet_roles_nid;
	int                     roles_idx;
	X509_NAME              *subject;
	char                    common_name[256];

	crt = X509_new();

	if ((store = X509_STORE_new()) == NULL)
		err(1, "X509_STORE_new");
	X509_STORE_set_verify_cb_func(store, verify_callback);

	if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (!X509_load_cert_file(lookup, "ca/overnet.pem", X509_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	X509_LOOKUP_free(lookup);

	if ((f = fopen("ca/overnet.pem", "r")) == NULL)
		err(1, "fopen");
	if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	overnet_roles_nid = OBJ_create("1.3.6.1.4.1.35910.3.1",
	    "overnetRoles", "Overnet Security Roles");
	if (overnet_roles_nid == NID_undef)
		err(1, "OBJ_create");

	roles_idx = X509_get_ext_by_NID(crt, overnet_roles_nid, -1);
	if (roles_idx == -1)
		errx(1, "overnetRoles extension not found");
	if ((ex = X509_get_ext(crt, roles_idx)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
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

	printf("name: %s\n", common_name);
	if (!valid_time(crt)) {
		errx(1, "cert is not valid");
	}

	return decode_crap(ex);
}
