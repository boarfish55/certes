#ifndef CERT_H
#define CERT_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <mdr/xlog.h>
#include "certdb.h"

int             cert_init(struct xerr *);
ssize_t         cert_decode_certes_roles(X509_EXTENSION *, char **, ssize_t);
X509_EXTENSION *cert_encode_certes_roles(const char **);
int             cert_has_role(X509 *, const char *, struct xerr *);
int             cert_has_san(X509 *, const char *, struct xerr *);
int             cert_verify(X509_STORE_CTX *, X509 *, int);
BIGNUM         *cert_new_serial(struct xerr *);
int             cert_add_ext(X509V3_CTX *, X509 *, int, char *);
X509           *cert_sign(X509 *, X509 *, const struct cert_entry *,
                    struct xerr *);
X509           *cert_sign_req(X509_REQ *, const struct bootstrap_entry *,
                    struct xerr *);
int             cert_new_privkey(struct xerr *);
int             cert_subject_cn(const char *, char *, size_t, struct xerr *);
X509_NAME      *cert_subject_from_str(const char *, struct xerr *);
int             cert_is_selfsigned(X509 *crt);
int             cert_new_selfreq(EVP_PKEY *, const X509_NAME *, const char *,
                    unsigned char **, int *, struct xerr *);
char           *cert_serial_to_hex(X509 *, struct xerr *);
char           *cert_subject_oneline(X509 *, struct xerr *);
int             cert_must_renew(X509 *, struct cert_entry *, struct xerr *);

#endif
