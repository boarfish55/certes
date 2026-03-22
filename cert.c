#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include "agent.h"
#include "certalator.h"
#include "cert.h"
#include "util.h"

extern struct certalator_flatconf certalator_conf;

int NID_certalator_roles;
int NID_certalator_roles_idx;

int
cert_init(struct xerr *e)
{
	NID_certalator_roles = OBJ_create("1.3.6.1.4.1.35910.3.1",
	    "certalatorRoles", "Certalator Security Roles");
	if (NID_certalator_roles == NID_undef)
		return XERRF(e, XLOG_ERRNO, errno, "OBJ_create");
	return 0;
}

ssize_t
cert_decode_certalator_roles(X509_EXTENSION *ext, char **roles, ssize_t roles_len)
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
cert_encode_certalator_roles(const char **roles)
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
	ex = X509_EXTENSION_create_by_NID(NULL, NID_certalator_roles, 0, asn1str);
	ASN1_OCTET_STRING_free(asn1str);
	if (ex == NULL) {
		return NULL;
	}
	return ex;
}

int
cert_has_role(X509 *crt, const char *role, struct xerr *e)
{
	int                  roles_idx;
	X509_EXTENSION      *ext;
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	ASN1_TYPE           *v;
	ssize_t              i;
	const unsigned char *p;
	int                  found = 0;

	roles_idx = X509_get_ext_by_NID(crt, NID_certalator_roles, -1);
	if (roles_idx == -1)
		return 0;

	if ((ext = X509_get_ext(crt, roles_idx)) == NULL)
		return XERRF(e, XLOG_APP, XLOG_SSLEXTNOTFOUND,
		    "%s: certalatorRoles extension not found", __func__);

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
cert_verify(X509_STORE_CTX *ctx, X509 *crt, int challenge)
{
	X509_NAME      *subject;
	char            common_name[256];
	int             r;

	if (crt == NULL) {
		xlog(LOG_ERR, NULL, "%s: no certificate", __func__);
		return -1;
	}

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

	if (!X509_STORE_CTX_init(ctx, agent_cert_store(), crt, NULL)) {
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
	//roles_idx = X509_get_ext_by_NID(crt, NID_certalator_roles, -1);
	//if (roles_idx == -1)
	//	xlog(LOG_ERR, NULL,
	//	    "%s: certalatorRoles extension not found", __func__);

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

	//n = decode_certalator_roles(ex, roles, CERTALATOR_MAX_ROLES);
	//if (n == -1) {
	//	free(roles);
	//	return -1;
	//}

	//for (i = 0; i < n; i++)
	//	xlog(LOG_INFO, NULL, "role: %s\n", roles[i]);
	//free(roles);
	return 0;
}

BIGNUM *
cert_new_serial(struct xerr *e)
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
cert_add_ext(X509V3_CTX *ctx, X509 *crt, int nid, char *value)
{
	X509_EXTENSION *ex;
	if ((ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value)) == NULL)
		return 0;
	return X509_add_ext(crt, ex, -1);
}

int
cert_is_selfsigned(X509 *crt)
{
	if (X509_NAME_cmp(X509_get_subject_name(crt),
	    X509_get_issuer_name(crt)) == 0)
		return 1;

	return 0;
}

X509 *
cert_sign(X509 *crt, X509 *issuer, EVP_PKEY *key, const char **roles)
{
	X509           *newcrt;
	BIGNUM         *serial;
	X509_EXTENSION *ex;
	X509V3_CTX      ctx;
	int             san_idx;
	struct xerr     e;

	// TODO: verify first?

	X509V3_set_ctx(&ctx, issuer, crt, NULL, NULL, 0);

	if ((newcrt = X509_new()) == NULL) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_new");
		return NULL;
	}
	if (!X509_set_version(newcrt, 2)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_set_version");
		return NULL;
	}

	serial = cert_new_serial(xerrz(&e));
	if (serial == NULL)
		return NULL;

	if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(newcrt)) == NULL) {
		BN_free(serial);
		XERRF(&e, XLOG_SSL, ERR_get_error(), "BN_to_ASN1_INTEGER");
		return NULL;
	}
	BN_free(serial);

	if (!X509_set_issuer_name(newcrt, X509_get_subject_name(issuer))) {
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

	if (!cert_add_ext(&ctx, newcrt, NID_basic_constraints,
	    "critical,CA:false")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_basic_constraints");
		return NULL;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_key_usage,
	    "critical,nonRepudiation,digitalSignature")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "add_ext / NID_key_usage");
		return NULL;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_ext_key_usage,
	    "serverAuth,clientAuth")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_ext_key_usage");
		return NULL;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_subject_key_identifier, "hash")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_subject_key_identifier");
		return NULL;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_authority_key_identifier,
	    "keyid,issuer")) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_authority_key_identifier");
		return NULL;
	}

	// TODO: need to add the subjectAltNames

	ex = cert_encode_certalator_roles(roles);
	if (!X509_add_ext(newcrt, ex, -1)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_add_ext / roles");
		return NULL;
	}

	if (!X509_sign(newcrt, key, NULL)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_sign");
		return NULL;
	}

	return newcrt;
}

static int
cert_self(char *name, size_t name_sz, struct xerr *e)
{
	char             p[256];
	int              r;
	struct addrinfo  hints;
	struct addrinfo *addrs;
	struct addrinfo *ai;

	if (gethostname(p, sizeof(p)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "gethostname");

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((r = getaddrinfo(p, NULL, &hints, &addrs)) != 0)
		return XERRF(e, XLOG_EAI, r, "getaddrinfo");

	for (ai = addrs; ai != NULL; ai = ai->ai_next) {
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    name, name_sz, NULL, 0, 0) != 0)
			continue;

		if (strcmp(name, "localhost") != 0)
			break;
	}
	freeaddrinfo(addrs);

	if (ai != NULL)
		return 0;

	return XERRF(e, XLOG_APP, XLOG_NOENT, "no name found");
}

static X509 *
cert_selfsign(EVP_PKEY *pkey, struct xerr *e)
{
	X509        *newcrt;
	X509V3_CTX   ctx;
	X509_NAME   *name;
	char         hostname[NI_MAXHOST];

	if (cert_self(hostname, sizeof(hostname), xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	if ((newcrt = X509_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_new");
		return NULL;
	}

	if (!X509_set_version(newcrt, 2)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_version");
		goto fail;
	}

	if (BN_to_ASN1_INTEGER(BN_value_one(),
	    X509_get_serialNumber(newcrt)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_to_ASN1_INTEGER");
		goto fail;
	}

	if ((name = X509_NAME_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_NAME_new");
		goto fail;
	}

	if (!X509_NAME_add_entry_by_txt(name, "CN",
	    MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_NAME_add_entry_by_txt: CN=%s", hostname);
		X509_NAME_free(name);
		goto fail;
	}

	if (!X509_NAME_add_entry_by_txt(name, "O",
	    MBSTRING_ASC, (unsigned char *)certalator_conf.cert_org,
	    -1, -1, 0)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_NAME_add_entry_by_txt: O=%s",
		    certalator_conf.cert_org);
		X509_NAME_free(name);
		goto fail;
	}

	if (!X509_NAME_add_entry_by_txt(name, "emailAddress",
	    MBSTRING_ASC, (unsigned char *)certalator_conf.cert_email,
	    -1, -1, 0)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_NAME_add_entry_by_txt: emailAddress=%s",
		    certalator_conf.cert_email);
		X509_NAME_free(name);
		goto fail;
	}

	if (!X509_set_subject_name(newcrt, name)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_subject_name");
		X509_NAME_free(name);
		goto fail;
	}

	if (!X509_set_issuer_name(newcrt, name)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_issuer_name");
		goto fail;
	}

	if (!X509_set_pubkey(newcrt, pkey)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_pubkey");
		goto fail;
	}

	X509_gmtime_adj(X509_get_notBefore(newcrt), 0);
	X509_gmtime_adj(X509_get_notAfter(newcrt), 86400);

	X509V3_set_ctx(&ctx, newcrt, newcrt, NULL, NULL, 0);

	if (!cert_add_ext(&ctx, newcrt, NID_basic_constraints,
	    "critical,CA:false")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_basic_constraints");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_key_usage,
	    "critical,nonRepudiation,digitalSignature,keyEncipherment")) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "add_ext / NID_key_usage");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_ext_key_usage,
	    "serverAuth,clientAuth")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_ext_key_usage");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_subject_key_identifier, "hash")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_subject_key_identifier");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_authority_key_identifier,
	    "keyid,issuer")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "add_ext / NID_authority_key_identifier");
		goto fail;
	}

	if (!X509_sign(newcrt, pkey, NULL)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_sign");
		goto fail;
	}

	return newcrt;
fail:
	X509_free(newcrt);
	return NULL;
}

/*
 * Create a key and a temporary self-signed cert just so we
 * can perform our bootstrap process over TLS.
 */
int
cert_new_privkey(struct xerr *e)
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY     *pkey = NULL;
	FILE         *f;
	X509         *selfcrt;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL)) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EVP_PKEY_CTX_new_id");

	if (EVP_PKEY_keygen_init(ctx) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EVP_PKEY_keygen_init");

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EVP_PKEY_keygen");

	if ((f = fopen(certalator_conf.key_file, "w")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    certalator_conf.key_file);

	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "PEM_write_PrivateKey");
		fclose(f);
		return -1;
	}

	if (fclose(f) == EOF)
		return XERRF(e, XLOG_ERRNO, errno, "fclose: %s",
		    certalator_conf.key_file);

	/*
	 * If we don't have a key, we certainly don't
	 * have a cert. In fact, this is our first run.
	 * We'll need a temporary self-signed cert during
	 * our first run.
	 */
	if ((selfcrt = cert_selfsign(pkey, e)) == NULL)
		return XERR_PREPENDFN(e);
	if ((f = fopen(certalator_conf.cert_file, "w")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    certalator_conf.cert_file);
	if (!PEM_write_X509(f, selfcrt)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
		fclose(f);
		return -1;
	}
	if (fclose(f) == EOF)
		return XERRF(e, XLOG_ERRNO, errno, "fclose: %s",
		    certalator_conf.cert_file);

	X509_free(selfcrt);

	return 0;
}

int
cert_subject_cn(const char *subject, char *cn, size_t cn_sz, struct xerr *e)
{
	char  subject2[CERTALATOR_MAX_SUBJET_LENGTH];
	char *token, *field, *value, *t;
	char *save1, *save2;

	strlcpy(subject2, subject, sizeof(subject2));

	for (t = subject2; ; t = NULL) {
		token = strtok_r(t, "/", &save1);
		if (token == NULL)
			break;

		if (strcmp(token, "") == 0)
			continue;

		field = strtok_r(token, "=", &save2);
		if (field == NULL)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "malformed subject");

		if (strcmp(field, "CN") != 0)
			continue;

		value = strtok_r(NULL, "=", &save2);
		if (value == NULL)
			return XERRF(e, XLOG_APP, XLOG_INVAL,
			    "malformed subject");

		if (strlcpy(cn, value, cn_sz) >= cn_sz)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "CN does not fit in buffer");

		return 0;
	}

	return XERRF(e, XLOG_APP, XLOG_NOENT, "no CN in subject");
}
