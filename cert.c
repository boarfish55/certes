/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/param.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "agent.h"
#include "certes.h"
#include "certdb.h"
#include "cert.h"
#include "util.h"

extern struct certes_flatconf certes_conf;

int NID_certes_roles;

const char *key_usage = "critical,digitalSignature,keyEncipherment";

int
cert_init(struct xerr *e)
{
	NID_certes_roles = OBJ_create(certes_conf.roles_oid,
	    "certesRoles", "Certalator Security Roles");
	if (NID_certes_roles == NID_undef)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "OBJ_create");
	return 0;
}

X509_EXTENSION *
cert_encode_certes_roles(const char **roles, size_t sz)
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

	for (role = roles; sz > 0 && *role != NULL; role++, sz--) {
		if ((s = ASN1_IA5STRING_new()) == NULL)
			goto fail;
		if (!ASN1_STRING_set(s, *role, strlen(*role))) {
			ASN1_IA5STRING_free(s);
			goto fail;
		}
		if ((v = ASN1_TYPE_new()) == NULL) {
			ASN1_IA5STRING_free(s);
			goto fail;
		}
		ASN1_TYPE_set(v, V_ASN1_IA5STRING, s);
		if (sk_ASN1_TYPE_push(sk, v) <= 0) {
			ASN1_TYPE_free(v);
			ASN1_IA5STRING_free(s);
			goto fail;
		}
	}
	/*
	 * Encode our stack to DER, store it in &data, then free the stack.
	 */
	if ((len = i2d_ASN1_SEQUENCE_ANY((STACK_OF(ASN1_TYPE) *)sk, &data)) < 0)
		goto fail;
	sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);

	/*
	 * Copy our DER-encoded stack of roles in an ASN1 octet string,
	 * then free the DER data.
	 */
	asn1str = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(asn1str, data, len)) {
		free(data);
		ASN1_OCTET_STRING_free(asn1str);
		goto fail;
	}
	free(data);

	ex = X509_EXTENSION_create_by_NID(NULL, NID_certes_roles, 0, asn1str);
	if (ex == NULL) {
		ASN1_OCTET_STRING_free(asn1str);
		goto fail;
	}
	ASN1_OCTET_STRING_free(asn1str);
	return ex;
fail:
	if (sk != NULL)
		sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
	return NULL;
}

int
cert_foreach_role(X509 *crt, int(*cb)(const char *, void *), void *args,
    struct xerr *e)
{
	int                  roles_idx;
	char                 role[CERTES_MAX_ROLE_LENGTH];
	X509_EXTENSION      *ext;
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	ASN1_TYPE           *v;
	ssize_t              i;
	const unsigned char *p;

	roles_idx = X509_get_ext_by_NID(crt, NID_certes_roles, -1);
	if (roles_idx == -1)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "%s: certesRoles extension not found", __func__);

	if ((ext = X509_get_ext(crt, roles_idx)) == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "%s: certesRoles extension not found", __func__);

	asn1str = X509_EXTENSION_get_data(ext);
	p = asn1str->data;

	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&p, asn1str->length);

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		v = sk_ASN1_TYPE_value(seq, i);
		if (v->type != V_ASN1_IA5STRING) {
			sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
			return XERRF(e, XLOG_APP, XLOG_INVALID,
			    "%s: certesRoles contains non-string values",
			    __func__);
		}
		strlcpy(role, (const char *)v->value.ia5string->data,
		    MIN(sizeof(role), v->value.ia5string->length + 1));
		if (!cb(role, args))
			break;
	}
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return 0;
}

int
cert_copy_extension(X509 *crt, X509_REQ *req, int nid, struct xerr *e)
{
	int                       i;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	X509_EXTENSION           *ext;
	ASN1_OBJECT              *obj;
	int                       status = 0;

	exts = X509_REQ_get_extensions(req);
	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		ext = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		if (OBJ_obj2nid(obj) == nid)
			if (!X509_add_ext(crt, ext, -1)) {
				status = XERRF(e, XLOG_SSL, ERR_get_error(),
				    "X509_add_ext");
				goto end;
			}
	}
end:
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return status;
}

struct has_role_args
{
	const char *role;
	int         found;
};

static int
has_role(const char *role, void *args)
{
	struct has_role_args *a = (struct has_role_args *)args;

	if (strcmp(role, a->role) == 0) {
		a->found = 1;
		return 0;
	}

	return 1;
}

int
cert_has_role(X509 *crt, const char *role, struct xerr *e)
{
	int                  r;
	struct has_role_args a = { role, 0 };

	r = cert_foreach_role(crt, &has_role, &a, xerrz(e));
	if (r == -1 && !xerr_is(e, XLOG_APP, XLOG_NOTFOUND))
		return XERR_PREPENDFN(e);
	return a.found;
}

int
cert_foreach_san(X509 *crt, int(*cb)(const char *, void *), void *args,
    struct xerr *e)
{
	STACK_OF(GENERAL_NAME) *sans = NULL;
	GENERAL_NAME           *gname;
	char                    name[512];
	int                     i, namelen;

	sans = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(crt,
	    NID_subject_alt_name, NULL, NULL);
	if (sans == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "subjectAltName extension not found");

	for (i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
		gname = sk_GENERAL_NAME_value(sans, i);
		switch (gname->type) {
		case GEN_DNS:
			namelen = ASN1_STRING_length(gname->d.dNSName);
			snprintf(name, sizeof(name), "DNS:%.*s", namelen,
			    ASN1_STRING_get0_data(gname->d.dNSName));
			break;
		case GEN_IPADD:
			namelen = ASN1_STRING_length(gname->d.iPAddress);
			if (namelen != 4 && namelen != 16)
				return XERRF(e, XLOG_APP, XLOG_FAIL,
				    "subjectAltName of type iPAddress "
				    "has invalid length");
			if (inet_ntop((namelen == 16) ? AF_INET6 : AF_INET,
			    ASN1_STRING_get0_data(gname->d.iPAddress),
			    name, sizeof(name)) == NULL)
				return XERRF(e, XLOG_APP, XLOG_FAIL,
				    "subjectAltName of type iPAddress "
				    "could not be decoded");
			break;
		default:
			GENERAL_NAMES_free(sans);
			return XERRF(e, XLOG_APP, XLOG_FAIL,
			    "unknown subjectAltName type");
		}
		if (!cb(name, args))
			break;
	}
	GENERAL_NAMES_free(sans);
	return 0;
}

int
cert_req_foreach_san(X509_REQ *req, int(*cb)(const char *, void *), void *args,
    struct xerr *e)
{
	STACK_OF(GENERAL_NAME)   *sans = NULL;
	GENERAL_NAME             *gname;
	char                      name[512];
	int                       i;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	int                       status = 0;
	int                       namelen;

	if ((exts = X509_REQ_get_extensions(req)) == NULL) {
		status = XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "subjectAltName extension not found");
		goto end;
	}

	sans = X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL);
	if (sans == NULL) {
		status = XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "subjectAltName extension not found");
		goto end;
	}

	for (i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
		gname = sk_GENERAL_NAME_value(sans, i);
		switch (gname->type) {
		case GEN_DNS:
			namelen = ASN1_STRING_length(gname->d.dNSName);
			snprintf(name, sizeof(name), "DNS:%.*s", namelen,
			    ASN1_STRING_get0_data(gname->d.dNSName));
			break;
		case GEN_IPADD:
			namelen = ASN1_STRING_length(gname->d.iPAddress);
			if (namelen != 4 && namelen != 16) {
				status = XERRF(e, XLOG_APP, XLOG_FAIL,
				    "subjectAltName of type iPAddress "
				    "has invalid length");
				goto end;
			}
			if (inet_ntop((namelen == 16) ? AF_INET6 : AF_INET,
			    ASN1_STRING_get0_data(gname->d.iPAddress),
			    name, sizeof(name)) == NULL) {
				status = XERRF(e, XLOG_APP, XLOG_FAIL,
				    "subjectAltName of type iPAddress "
				    "could not be decoded");
				goto end;
			}
			break;
		default:
			GENERAL_NAMES_free(sans);
			status = XERRF(e, XLOG_APP, XLOG_FAIL,
			    "unknown subjectAltName type");
			goto end;
		}
		if (!cb(name, args))
			break;
	}
end:
	if (sans != NULL)
		GENERAL_NAMES_free(sans);
	if (exts != NULL)
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return status;
}

struct has_san_args
{
	const char *san;
	int         found;
};

static int
has_san(const char *san, void *args)
{
	struct has_san_args *a = (struct has_san_args *)args;

	if (strcmp(san, a->san) == 0) {
		a->found = 1;
		return 0;
	}

	return 1;
}

int
cert_has_san(X509 *crt, const char *san, struct xerr *e)
{
	int                 r;
	struct has_san_args a = { san, 0 };

	r = cert_foreach_san(crt, &has_san, &a, xerrz(e));
	if (r == -1)
		return XERR_PREPENDFN(e);
	return a.found;
}

X509_NAME *
cert_subject_from_str(const char *subject, struct xerr *e)
{
	char       subject2[CERTES_MAX_SUBJET_LENGTH];
	char      *token, *field, *value, *t;
	char      *save1, *save2;
	X509_NAME *name;

	if (strlcpy(subject2, subject, sizeof(subject2)) >= sizeof(subject2)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW, "subject is too long");
		return NULL;
	}

	if ((name = X509_NAME_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_NAME_new");
		return NULL;
	}

	for (t = subject2; ; t = NULL) {
		token = strtok_r(t, "/", &save1);
		if (token == NULL)
			break;

		if (strcmp(token, "") == 0)
			continue;

		field = strtok_r(token, "=", &save2);
		if (field == NULL) {
			XERRF(e, XLOG_APP, XLOG_INVALID, "malformed subject");
			goto fail;
		}

		value = strtok_r(NULL, "=", &save2);
		if (value == NULL) {
			XERRF(e, XLOG_APP, XLOG_INVALID, "malformed subject");
			goto fail;
		}

		if (!X509_NAME_add_entry_by_txt(name, field,
		    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0)) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_NAME_add_entry_by_txt: %s=%s",
			    field, value);
			goto fail;
		}
	}
	return name;
fail:
	X509_NAME_free(name);
	return NULL;
}

int
cert_verify(X509_STORE_CTX *ctx, X509 *crt)
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

	if (!X509_STORE_CTX_init(ctx, agent_cert_store(), crt, NULL)) {
		X509_STORE_CTX_cleanup(ctx);
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if ((r = X509_verify_cert(ctx)) <= 0) {
		X509_STORE_CTX_cleanup(ctx);
		xlog((r == 0) ? LOG_WARNING : LOG_ERR, NULL,
		    "X509_verify_cert: %s", X509_verify_cert_error_string(
		    X509_STORE_CTX_get_error(ctx)));
		return -1;
	}

	X509_STORE_CTX_cleanup(ctx);
	return 0;
}

BIGNUM *
cert_new_serial(struct xerr *e)
{
	BIGNUM      *min_bn = NULL;
	BIGNUM      *max_bn = NULL;
	BIGNUM      *v = NULL;
	char        *p;
	char         buf[MAX_HEX_SERIAL_LENGTH + 1];
	struct xerr  e2;

	if (!BN_hex2bn(&min_bn, certes_conf.min_serial)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
		return NULL;
	}

	if (!BN_hex2bn(&max_bn, certes_conf.max_serial)) {
		BN_free(min_bn);
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
		return NULL;
	}

	if (certdb_last_serial(buf, sizeof(buf), xerrz(e)) == -1) {
		if (!xerr_is(e, XLOG_APP, XLOG_NOTFOUND)) {
			XERR_PREPENDFN(e);
			return NULL;
		}
		if (certdb_init_serial(certes_conf.min_serial,
		    xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}
		strlcpy(buf, certes_conf.min_serial, sizeof(buf));
		if (!BN_hex2bn(&v, buf)) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
			goto fail;
		}
		BN_free(min_bn);
		BN_free(max_bn);
		return v;
	}

	for (p = buf; *p; p++) {
		if (!((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f') ||
		    (*p >= 'A' && *p <= 'F'))) {
			XERRF(e, XLOG_APP, XLOG_INVALID,
			    "serial is not a valid hex integer");
			goto fail;
		}
	}

	if (!BN_hex2bn(&v, buf)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
		goto fail;
	}

	/*
	 * Set our serial to min_serial if the previously stored value
	 * was less than this. This could happen if we update the
	 * configuration to set a new range for our serials.
	 */
	if (BN_cmp(v, min_bn) < 0) {
		BN_free(v);
		v = NULL;
		if ((v = BN_dup(min_bn)) == NULL) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "BN_dup");
			goto fail;
		}
	} else {
		if (!BN_add_word(v, 1)) {
			XERRF(e, XLOG_SSL, ERR_get_error(), "BN_add_word");
			goto fail;
		}
	}

	if (BN_cmp(v, max_bn) > 0) {
		XERRF(e, XLOG_APP, XLOG_LIMITED, "max_serial exceeded");
		goto fail;
	}

	if ((p = BN_bn2hex(v)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_bn2hex");
		goto fail;
	}
	if (snprintf(buf, sizeof(buf), "%s\n", p) >= sizeof(buf)) {
		free(p);
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "computed serial is too large");
		goto fail;
	}
	if (certdb_update_serial(p, xerrz(e)) == -1) {
		free(p);
		XERR_PREPENDFN(e);
		goto fail;
	}
	free(p);

	BN_free(min_bn);
	BN_free(max_bn);

	return v;
fail:
	if (certdb_rollback_txn(xerrz(&e2)) == -1)
		xlog(LOG_ERR, &e2, __func__);
	if (v != NULL)
		BN_free(v);
	if (min_bn != NULL)
		BN_free(min_bn);
	if (max_bn != NULL)
		BN_free(max_bn);
	return NULL;
}

int
cert_add_ext(X509V3_CTX *ctx, X509 *crt, int nid, const char *value)
{
	X509_EXTENSION *ex;
	int             st;

	if ((ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value)) == NULL)
		return 0;
	st = X509_add_ext(crt, ex, -1);
	X509_EXTENSION_free(ex);
	return st;
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
cert_sign_req(X509_REQ *req, const char *subject, time_t not_before_sec,
    time_t not_after_sec, const char **roles, size_t roles_sz,
    const char **sans, size_t sans_sz, const char *ext_key_usage,
    struct xerr *e)
{
	X509           *newcrt = NULL;
	BIGNUM         *serial = NULL;
	X509_EXTENSION *ex;
	X509V3_CTX      ctx;
	X509_NAME      *name;
	char           *sans_joined = NULL;

	X509V3_set_ctx(&ctx, agent_cert(), NULL, req, NULL, 0);

	if ((newcrt = X509_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_new");
		return NULL;
	}
	if (!X509_set_version(newcrt, 2)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_version");
		goto fail;
	}

	serial = cert_new_serial(xerrz(e));
	if (serial == NULL) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(newcrt)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_to_ASN1_INTEGER");
		goto fail;
	}

	if (!X509_set_issuer_name(newcrt,
	    X509_get_subject_name(agent_cert()))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_issuer_name");
		goto fail;
	}

	if (subject != NULL) {
		name = cert_subject_from_str(subject, xerrz(e));
		if (name == NULL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		if (!X509_set_subject_name(newcrt, name)) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_set_subject_name");
			X509_NAME_free(name);
			goto fail;
		}
		X509_NAME_free(name);
	} else {
		if (!X509_set_subject_name(newcrt,
		    X509_REQ_get_subject_name(req))) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_set_subject_name");
			return NULL;
		}
	}

	if (!X509_set_pubkey(newcrt, X509_REQ_get0_pubkey(req))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_pubkey");
		return NULL;
	}

	X509_time_adj(X509_get_notBefore(newcrt), 0, &not_before_sec);
	X509_time_adj(X509_get_notAfter(newcrt), 0, &not_after_sec);

	if (sans_sz > 0) {
		if ((strlist_join(sans, sans_sz, &sans_joined, ',')) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "strlist_join");
			return NULL;
		}
		if (!cert_add_ext(&ctx, newcrt, NID_subject_alt_name,
		    sans_joined)) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "cert_add_ext/NID_subject_alt_name");
			goto fail;
		}
	}

	if (!cert_add_ext(&ctx, newcrt, NID_basic_constraints,
	    "critical,CA:false")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_basic_constraints");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_key_usage, key_usage)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_key_usage");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_ext_key_usage, ext_key_usage)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_ext_key_usage");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_subject_key_identifier, "hash")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_subject_key_identifier");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_authority_key_identifier,
	    "keyid,issuer")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_authority_key_identifier");
		goto fail;
	}

	if (roles_sz > 0) {
		ex = cert_encode_certes_roles(roles, roles_sz);
		if (!X509_add_ext(newcrt, ex, -1)) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_add_ext / roles");
			goto fail;
		}
		X509_EXTENSION_free(ex);
	}

	if (!X509_sign(newcrt, agent_key(), EVP_sha256())) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_sign");
		goto fail;
	}

	free(sans_joined);
	BN_free(serial);
	return newcrt;
fail:
	if (serial != NULL)
		BN_free(serial);
	if (newcrt != NULL)
		X509_free(newcrt);
	free(sans_joined);
	return NULL;
}

X509 *
cert_sign(X509 *crt, X509 *issuer, const struct cert_entry *ce,
    struct xerr *e)
{
	X509           *newcrt = NULL;
	BIGNUM         *serial = NULL;
	X509_EXTENSION *ex;
	X509V3_CTX      ctx;
	char           *sans = NULL;
	struct xerr     e2;

	X509V3_set_ctx(&ctx, issuer, crt, NULL, NULL, 0);

	if ((newcrt = X509_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_new");
		return NULL;
	}
	if (!X509_set_version(newcrt, 2)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_version");
		goto fail;
	}

	if (certdb_begin_txn(xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	serial = cert_new_serial(xerrz(e));
	if (serial == NULL)
		goto fail;

	if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(newcrt)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_to_ASN1_INTEGER");
		goto fail;
	}

	if (!X509_set_issuer_name(newcrt, X509_get_subject_name(issuer))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_issuer_name");
		goto fail;
	}

	if (!X509_set_subject_name(newcrt, X509_get_subject_name(crt))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_subject_name");
		goto fail;
	}

	if (!X509_set_pubkey(newcrt, X509_get0_pubkey(crt))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_set_pubkey");
		goto fail;
	}

	X509_gmtime_adj(X509_get_notBefore(newcrt), 0);
	X509_gmtime_adj(X509_get_notAfter(newcrt),
	    certes_conf.cert_renew_lifetime_seconds);

	if ((strlist_join((const char **)ce->sans, ce->sans_sz,
	    &sans, ',')) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "strlist_join");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_subject_alt_name, sans)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_subject_alt_name");
		goto fail;
	}

	if (!cert_add_ext(&ctx, newcrt, NID_basic_constraints,
	    "critical,CA:false")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_basic_constraints");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_key_usage, key_usage)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_key_usage");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_ext_key_usage,
	    "serverAuth,clientAuth")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_ext_key_usage");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_subject_key_identifier, "hash")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_subject_key_identifier");
		goto fail;
	}
	if (!cert_add_ext(&ctx, newcrt, NID_authority_key_identifier,
	    "keyid,issuer")) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "cert_add_ext/NID_authority_key_identifier");
		goto fail;
	}

	ex = cert_encode_certes_roles((const char **)ce->roles, ce->roles_sz);
	if (!X509_add_ext(newcrt, ex, -1)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_add_ext / roles");
		goto fail;
	}
	X509_EXTENSION_free(ex);

	if (!X509_sign(newcrt, agent_key(), EVP_sha256())) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_sign");
		goto fail;
	}

	if (certdb_commit_txn(xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	BN_free(serial);
	free(sans);
	return newcrt;
fail:
	if (serial != NULL) {
		if (certdb_rollback_txn(xerrz(&e2)) == -1)
			xlog(LOG_ERR, &e2, __func__);
		BN_free(serial);
	}
	if (newcrt != NULL)
		X509_free(newcrt);
	free(sans);
	return NULL;
}

static int
cert_self(char *name, size_t name_sz, struct xerr *e)
{
	char            *p;

	if (gethostname(name, name_sz) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "gethostname");

	p = strchr(name, '.');
	if (p != NULL)
		*p = '\0';

	return 0;
}

static X509 *
cert_selfsign(EVP_PKEY *pkey, struct xerr *e)
{
	X509        *newcrt;
	X509V3_CTX   ctx;
	X509_NAME   *name;
	char         hostname[65]; /* 64 is the standard max for commonName */

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
	    MBSTRING_ASC, (unsigned char *)certes_conf.cert_org,
	    -1, -1, 0)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_NAME_add_entry_by_txt: O=%s",
		    certes_conf.cert_org);
		X509_NAME_free(name);
		goto fail;
	}

	if (!X509_NAME_add_entry_by_txt(name, "emailAddress",
	    MBSTRING_ASC, (unsigned char *)certes_conf.cert_email,
	    -1, -1, 0)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_NAME_add_entry_by_txt: emailAddress=%s",
		    certes_conf.cert_email);
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
	if (!cert_add_ext(&ctx, newcrt, NID_key_usage, key_usage)) {
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

	if (!X509_sign(newcrt, pkey, EVP_sha256())) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_sign");
		goto fail;
	}

	return newcrt;
fail:
	X509_free(newcrt);
	return NULL;
}

int
cert_new_selfreq(EVP_PKEY *key, const X509_NAME *subject, const char *ip6,
    unsigned char **req_buf, int *req_len, struct xerr *e)
{
	/* Inspired by OpenBSD's acme-client/keyproc.c:77 */
	X509_REQ                 *req;
	X509_EXTENSION           *ex;
	char                     *sans = NULL;
	STACK_OF(X509_EXTENSION) *exts;

	if ((req = X509_REQ_new()) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_REQ_new");

	if (!X509_REQ_set_pubkey(req, key)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_REQ_set_pubkey");
		goto fail;
	}

	if (!X509_REQ_set_subject_name(req, (X509_NAME *)subject)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_req_set_subject_name");
		goto fail;
	}

	if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "sk_X509_EXTENSION_new_null");
		goto fail;
	}

	if (asprintf(&sans, "IP:%s", ip6) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "asprintf");
		goto fail;
	}

        if (!(ex = X509V3_EXT_conf_nid(NULL, NULL,
	    NID_subject_alt_name, sans))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509V3_EXT_conf_nid");
		goto fail;
	}
	sk_X509_EXTENSION_push(exts, ex);
	if (!X509_REQ_add_extensions(req, exts)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_REQ_add_extensions");
		goto fail;
        }
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	if (!X509_REQ_sign(req, key, NULL)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_reqsign");
		goto fail;
        }

	/*
	 * Serialise to DER
	 */
	*req_buf = NULL;
	*req_len = i2d_X509_REQ(req, req_buf);
	if (*req_len < 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509_REQ");
		goto fail;
	}

	/*
	 * We don't need to fully populate the REQ. We should add a SANS for
	 * our IP address so the dialback works. The authority will take care
	 * of adding all configured SANs to the cert during signing.
	 */

	X509_REQ_free(req);
	free(sans);
	return 0;
fail:
	X509_REQ_free(req);
	if (sans != NULL)
		free(sans);
	return -1;
}

/*
 * Create a key and a temporary self-signed cert just so we
 * can perform our bootstrap process over TLS.
 */
int
cert_new_privkey(struct xerr *e)
{
	EVP_PKEY     *pkey = NULL;
	EC_KEY       *ec_key = NULL;
	FILE         *f;
	int           fd;
	X509         *selfcrt = NULL;
	mode_t        save_umask;

	if ((ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EC_KEY_new_by_curve_name");
	if (!EC_KEY_generate_key(ec_key)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "EC_KEY_generate_key");
		goto fail;
	}
	if ((pkey = EVP_PKEY_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "EVP_PKEY_new");
		goto fail;
	}
	if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "EVP_PKEY_assign_EC_KEY");
		goto fail;
	}
	ec_key = NULL;
#if 0
	/*
	 * Should ED25519 support come to LibreSSL, we can use this.
	 * See:
	 *   https://github.com/libressl/portable/issues/821
	 */
	EVP_PKEY_CTX *ctx;
	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL)) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EVP_PKEY_CTX_new_id");
	if (EVP_PKEY_keygen_init(ctx) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EVP_PKEY_keygen_init");
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "EVP_PKEY_keygen");
#endif
	if ((fd = open(certes_conf.key_file,
	    O_CREAT|O_TRUNC|O_WRONLY, 0640)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "open: %s", certes_conf.key_file);
		goto fail;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		close(fd);
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    certes_conf.key_file);
		goto fail;
	}
	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "PEM_write_PrivateKey");
		fclose(f);
		goto fail;
	}
	if (fclose(f) == EOF) {
		XERRF(e, XLOG_ERRNO, errno, "fclose: %s",
		    certes_conf.key_file);
		goto fail;
	}

	/*
	 * If we don't have a key, we certainly don't
	 * have a cert. In fact, this is our first run.
	 * We'll need a temporary self-signed cert during
	 * our first run.
	 */
	if ((selfcrt = cert_selfsign(pkey, e)) == NULL) {
		XERR_PREPENDFN(e);
		goto fail;
	}
	save_umask = umask(022);
	if ((f = fopen(certes_conf.cert_file, "w")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fdopen: %s",
		    certes_conf.cert_file);
		goto fail;
	}
	umask(save_umask);
	if (!PEM_write_X509(f, selfcrt)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
		fclose(f);
		goto fail;
	}
	if (fclose(f) == EOF) {
		XERRF(e, XLOG_ERRNO, errno, "fclose: %s",
		    certes_conf.cert_file);
		goto fail;
	}

	X509_free(selfcrt);

	return 0;
fail:
	if (ec_key != NULL)
		EC_KEY_free(ec_key);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (selfcrt != NULL)
		X509_free(selfcrt);
	unlink(certes_conf.cert_file);
	unlink(certes_conf.key_file);
	return -1;
}

int
cert_subject_cn(const char *subject, char *cn, size_t cn_sz, struct xerr *e)
{
	char  subject2[CERTES_MAX_SUBJET_LENGTH];
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
			return XERRF(e, XLOG_APP, XLOG_INVALID,
			    "malformed subject");

		if (strcmp(field, "CN") != 0)
			continue;

		value = strtok_r(NULL, "=", &save2);
		if (value == NULL)
			return XERRF(e, XLOG_APP, XLOG_INVALID,
			    "malformed subject");

		if (strlcpy(cn, value, cn_sz) >= cn_sz)
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "CN does not fit in buffer");

		return 0;
	}

	return XERRF(e, XLOG_APP, XLOG_NOTFOUND, "no CN in subject");
}

int
cert_authority_cn_sane(const char *cn)
{
	int i, len;

	for (i = 0, len = strlen(cn); i < len; i++) {
		if (!isalnum(cn[i]) && cn[i] != '.')
			return 0;
	}

	return 1;
}

char *
cert_serial_to_hex(X509 *crt, struct xerr *e)
{
	BIGNUM *serial_bn;
	char   *serial_hex;

	if ((serial_bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(crt),
	    NULL)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "ASN1_INTEGER_to_BN");
		return NULL;
	}
	if ((serial_hex = BN_bn2hex(serial_bn)) == NULL) {
		BN_free(serial_bn);
		XERRF(e, XLOG_SSL, ERR_get_error(), "BN_bn2hex");
		return NULL;
	}
	BN_free(serial_bn);
	return serial_hex;
}

char *
cert_subject_oneline(X509 *crt, struct xerr *e)
{
	X509_NAME *name;
	char      *subject;

	if ((name = X509_get_subject_name(crt)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_get_subject_name");
		return NULL;
	}

	if ((subject = X509_NAME_oneline(name, NULL, 0)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_NAME_oneline");
		return NULL;
	}
	return subject;
}

int
cert_must_renew(X509 *crt, struct cert_entry *ce, struct xerr *e)
{
	int                  roles_idx;
	int                  san_idx;
	int                  i;
	X509_EXTENSION      *ex;
	ASN1_OCTET_STRING   *asn1str;
	STACK_OF(ASN1_TYPE) *seq;
	const unsigned char *p;
	time_t               expiry;
	struct tm            tm;
	struct timespec      now;
	int                  num;

	roles_idx = X509_get_ext_by_NID(crt, NID_certes_roles, -1);
	if (roles_idx == -1)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "%s: certesRoles extension not found", __func__);
	san_idx = X509_get_ext_by_NID(crt, NID_subject_alt_name, -1);
	if (san_idx == -1)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "%s: subjectAltName extension not found", __func__);

	if ((ex = X509_get_ext(crt, roles_idx)) == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "%s: certesRoles extension not found", __func__);
	asn1str = X509_EXTENSION_get_data(ex);
	p = asn1str->data;
	/*
	 * If the number of roles is not equal, or if one of the
	 * roles is not found in the cert, we must renew.
	 */
	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&p, asn1str->length);
	num = sk_ASN1_TYPE_num(seq);
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	if (num != ce->roles_sz)
		return 1;
	for (i = 0; ce->roles[i] != NULL; i++)
		if (!cert_has_role(crt, ce->roles[i], xerrz(e)))
			return 1;

	if ((ex = X509_get_ext(crt, san_idx)) == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "%s: subjectAltName extension not found", __func__);
	asn1str = X509_EXTENSION_get_data(ex);
	p = asn1str->data;
	/*
	 * If the number of roles is not equal, or if one of the
	 * roles is not found in the cert, we must renew.
	 */
	seq = d2i_ASN1_SEQUENCE_ANY(NULL,
	    (const unsigned char **)&p, asn1str->length);
	num = sk_ASN1_TYPE_num(seq);
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	if (num != ce->sans_sz)
		return 1;
	for (i = 0; ce->sans[i] != NULL; i++)
		if (!cert_has_san(crt, ce->sans[i], xerrz(e)))
			return 1;

	ASN1_TIME_to_tm(X509_get_notAfter(crt), &tm);
	expiry = timegm(&tm);

	clock_gettime(CLOCK_REALTIME, &now);
	if (expiry < now.tv_sec || expiry - now.tv_sec <
	    certes_conf.cert_min_lifetime_seconds)
		return 1;

	return 0;
}

static int
add_to_crl(const struct cert_entry *ce, void *args)
{
	X509_CRL     *crl = (X509_CRL *)args;
	ASN1_TIME    *rev_date = NULL;
	X509_REVOKED *revcrt = NULL;
	BIGNUM       *serial_bn = NULL;
	ASN1_INTEGER *serial = NULL;
	struct xerr   e;

	if ((revcrt = X509_REVOKED_new()) == NULL) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "X509_REVOKED_new");
		goto fail;
	}

	if ((rev_date = ASN1_TIME_adj(NULL, ce->revoked_at_sec, 0, 0))
	    == NULL) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "ASN1_TIME_adj");
		goto fail;
	}

	if (!X509_REVOKED_set_revocationDate(revcrt, rev_date)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "X509_REVOKED_set_revocationDate");
		goto fail;
	}

	if (!BN_hex2bn(&serial_bn, ce->serial)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "BN_hex2bn");
		goto fail;
	}
	if ((serial = BN_to_ASN1_INTEGER(serial_bn, NULL)) == NULL) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "BN_to_ASN1_INTEGER");
		goto fail;
	}

	if (!X509_REVOKED_set_serialNumber(revcrt, serial)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(),
		    "X509_REVOKED_set_serialNumber");
		goto fail;
	}

	if (!X509_CRL_add0_revoked(crl, revcrt)) {
		XERRF(&e, XLOG_SSL, ERR_get_error(), "X509_CRL_add0_revoked");
		goto fail;
	}

	ASN1_TIME_free(rev_date);
	BN_free(serial_bn);
	ASN1_INTEGER_free(serial);
	return 1;
fail:
	xlog(LOG_ERR, &e, __func__);
	if (revcrt != NULL)
		X509_REVOKED_free(revcrt);
	if (rev_date != NULL)
		ASN1_TIME_free(rev_date);
	if (serial_bn != NULL)
		BN_free(serial_bn);
	if (serial != NULL)
		ASN1_INTEGER_free(serial);
	return 0;
}

int
cert_gen_crl(struct xerr *e)
{
	// See: openbsd/src/usr.bin/openssl/ca.c:1369

	X509_CRL  *crl = NULL;
	ASN1_TIME *tmptm = NULL;
	FILE      *f = NULL;
	char       cn[256];
	X509_NAME *subject;
	char       crl_path[PATH_MAX];
	mode_t     save_umask;

	if ((crl = X509_CRL_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_CRL_new");
		return -1;
	}

	if (!X509_CRL_set_issuer_name(crl,
	    X509_get_subject_name(agent_cert()))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_CRL_set_issuer_name");
		goto fail;
	}

	if ((tmptm = X509_gmtime_adj(NULL, 0)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_gmtime_adj");
		goto fail;
	}

	if (!X509_CRL_set_lastUpdate(crl, tmptm)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_CRL_set_lastUpdate");
		goto fail;
	}
	if ((tmptm = X509_gmtime_adj(tmptm, 86400 * 365)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_gmtime_adj");
		goto fail;
	}

	if (!X509_CRL_set_nextUpdate(crl, tmptm)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_CRL_set_nextUpdate");
		goto fail;
	}
	ASN1_TIME_free(tmptm);
	tmptm = NULL;

	if (certdb_get_revoked_certs(&add_to_crl, crl, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	X509_CRL_sort(crl);

	if (!X509_CRL_sign(crl, agent_key(), EVP_sha256())) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_CRL_sign");
		goto fail;
	}

	subject =  X509_get_subject_name(agent_cert());
	if (X509_NAME_get_text_by_NID(subject, NID_commonName,
	    cn, sizeof(cn)) < 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_NAME_get_text_by_NID");
		goto fail;
	}
	if (snprintf(crl_path, sizeof(crl_path), "%s/%s.crl",
	    certes_conf.crl_path, cn) >= sizeof(crl_path)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "resulting CRL path too long");
		goto fail;
	}

	save_umask = umask(022);
	f = fopen(crl_path, "w");
	umask(save_umask);
	if (f == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s", crl_path);
		goto fail;
	}
	if (!PEM_write_X509_CRL(f, crl)) {
		fclose(f);
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509_CRL");
		goto fail;
	}
	fclose(f);

	X509_CRL_free(crl);

	return 0;
fail:
	if (tmptm != NULL)
		ASN1_TIME_free(tmptm);
	X509_CRL_free(crl);
	return -1;
}
