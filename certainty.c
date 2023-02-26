#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
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
main()
{
	X509_STORE        *store;
	X509_LOOKUP       *lookup;
	X509              *crt;
	X509_EXTENSION    *ex;
	FILE              *f;
	int                overnet_roles_nid;
	int                roles_idx;
	ASN1_OCTET_STRING *asn1str;
	ASN1_OBJECT       *asn1obj;

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

	asn1str = X509_EXTENSION_get_data(ex);
	asn1obj = X509_EXTENSION_get_object(ex);

	return 0;
}
