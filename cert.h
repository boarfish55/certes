#ifndef CERT_H
#define CERT_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "xlog.h"

int             cert_init(struct xerr *);
ssize_t         cert_decode_certalator_roles(X509_EXTENSION *, char **, ssize_t);
X509_EXTENSION *cert_encode_certalator_roles(const char **);
int             cert_has_role(X509 *, const char *, struct xerr *);
int             cert_verify(X509_STORE_CTX *, X509 *, X509_STORE *, int);
BIGNUM         *cert_new_serial(struct xerr *);
int             cert_add_ext(X509V3_CTX *, X509 *, int, char *);
X509 *          cert_sign(X509 *, X509 *, EVP_PKEY *, const char **);
FILE *          cert_new_privkey();

#endif
