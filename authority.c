/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <sys/param.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <mdr/mdrd.h>
#include <mdr/util.h>
#include "authority.h"
#include "agent.h"
#include "cert.h"

extern struct certes_flatconf certes_conf;

/*
 * Create a bootstrap entry with certificate parameters and a challenge key
 * to be used when an agent connects with a DIALIN call.
 * This will populate and save a bootstrap_entry in the certdb.
 */
static int
authority_make_bootstrap(const char *cn, const char **sans,
    size_t sans_sz, const char **roles, size_t roles_sz, uint32_t cert_expiry,
    uint32_t timeout, uint32_t flags, struct xerr *e)
{
	int                    i;
	char                   subject[CERTES_MAX_SUBJET_LENGTH] = "";
	struct bootstrap_entry be;
	struct timespec        tp;

	if (flags & CERTDB_BOOTSTRAP_FLAG_SETCN) {
		if (snprintf(subject, sizeof(subject),
		    "/O=%s/CN=%s/emailAddress=%s", certes_conf.cert_org,
		    cn, certes_conf.cert_email) >= sizeof(subject))
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "resulting subject name is too long "
			    "for commonName %s", cn);
	}

	arc4random_buf(be.bootstrap_key, sizeof(be.bootstrap_key));

	clock_gettime(CLOCK_REALTIME, &tp);

	be.valid_until_sec = tp.tv_sec + timeout;
	be.not_before_sec = tp.tv_sec;
	be.not_after_sec = tp.tv_sec + cert_expiry;
	be.subject = subject;
	be.flags = flags;

	for (i = 0; i < roles_sz; i++)
		if (strlen(roles[i]) > CERTES_MAX_ROLE_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "role name %s longer than limit of %d",
			    roles[i], CERTES_MAX_ROLE_LENGTH);

	for (i = 0; i < sans_sz; i++)
		if (strlen(sans[i]) > CERTES_MAX_SAN_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "SAN name %s longer than limit of %d",
			    sans[i], CERTES_MAX_SAN_LENGTH);

	be.roles = (char **)roles;
	be.roles_sz = roles_sz;
	be.sans = (char **)sans;
	be.sans_sz = sans_sz;

	return certdb_put_bootstrap(&be, e);
}

int
authority_bootstrap_setup(struct mdrd_besession *sess, struct umdr *m,
    struct xerr *e)
{
	const char       *subject;
	const char      **roles = NULL;
	int32_t           roles_sz;
	const char      **sans = NULL;
	int32_t           sans_sz;
	uint32_t          cert_expiry, timeout, flags;
	struct umdr_vec   uv[6];

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_BOOTSTRAP, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_BOOTSTRAP " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_BOOTSTRAP " role required");
	}

	if (umdr_unpack(m, msg_bootstrap_setup, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	subject = uv[0].v.s.bytes;
	sans_sz = umdr_vec_alen(&uv[1].v.as);
	roles_sz = umdr_vec_alen(&uv[2].v.as);
	cert_expiry = uv[3].v.u32;
	timeout = uv[4].v.u32;
	flags = uv[5].v.u32;

	if ((sans = malloc(sizeof(char *) * (sans_sz + 1))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	if ((roles = malloc(sizeof(char *) * (roles_sz + 1))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}

	if (umdr_vec_as(&uv[1].v.as, sans, sans_sz + 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}
	if (umdr_vec_as(&uv[2].v.as, roles, roles_sz + 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_as");
		goto fail;
	}

	if (authority_make_bootstrap(subject, sans, sans_sz, roles,
	    roles_sz, cert_expiry, timeout, flags, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	free(sans);
	free(roles);

	if (mdrd_beout_ok(sess, MDRD_BEOUT_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout_ok");
		return -1;
	}

	return 0;
fail:
	free(sans);
	free(roles);
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
	return -1;
}

int
authority_revoke(struct mdrd_besession *sess, struct umdr *m, struct xerr *e)
{
	struct umdr_vec uv[1];
	struct pmdr     pm;
	char            pbuf[mdr_spec_base_sz(msg_reload_crls, 0)];

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (!agent_is_authority()) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_CERTADMIN, xerrz(e))) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_DENIED, ROLE_CERTADMIN " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_CERTADMIN " role required");
	}

	if (umdr_unpack(m, msg_revoke, uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	if (certdb_revoke_cert(uv[0].v.s.bytes, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	if (pmdr_pack(&pm, msg_reload_crls, NULL, 0) == MDR_FAIL)
		abort();

	if (agent_send(pmdr_buf(&pm), pmdr_size(&pm), xerrz(e)) == -1)
		xlog(LOG_ERR, e, "%s", __func__);

	if (mdrd_beout_ok(sess, MDRD_BEOUT_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout_ok");
		return -1;
	}

	return 0;
fail:
	mdrd_beout_error(sess, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failure");
	return -1;
}

/*
 * We establish a connection to the commonName in the bootstrap
 * entry to send a challenge. The agent currently connected to us
 * for bootstrap should receive it if it's really who it claims to
 * be and send it back to us.
 */
static int
authority_challenge(struct mdrd_besession *sess, const char *op_id,
    uint64_t dcv, const char *challenge_host, struct xerr *e)
{
	char                   port[6];
	int                    fd;
	struct timeval         timeout;
	SSL_CTX               *ctx = NULL;
	SSL                   *ssl = NULL;
	BIO                   *bio = NULL;
	struct pmdr            pm;
	char                   pbuf[256];
	struct pmdr_vec        pv[2];
	int                    r, status = 0;
	struct certes_session *cs = (struct certes_session *)sess->data;

	if ((cs->challenge = malloc(CERTES_CHALLENGE_LENGTH)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto befail;
	}
	arc4random_buf(cs->challenge, CERTES_CHALLENGE_LENGTH);

	if (snprintf(port, sizeof(port), "%u", CERTES_AGENT_PORT) >=
	    sizeof(port)) {
		XERRF(e, XLOG_APP, XLOG_INVALID,
		    "failed to convert agent port");
		goto befail;
	}

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto befail;
	}

	SSL_CTX_set_security_level(ctx, 3);

	if (SSL_CTX_use_PrivateKey(ctx, agent_key()) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_CTX_use_PrivateKey");
		goto befail;
	}

	if (SSL_CTX_use_certificate(ctx, agent_cert()) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_CTX_use_certificate");
		goto befail;
	}

	if ((bio = BIO_new_ssl_connect(ctx)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new_ssl_connect");
		goto befail;
	}

	BIO_get_ssl(bio, &ssl);
	if (ssl == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_get_ssl");
		goto befail;
	}

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio, challenge_host);
	BIO_set_conn_port(bio, port);

	if (BIO_do_connect(bio) <= 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "dialback failed");
		BIO_free(bio);
		SSL_CTX_free(ctx);
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_do_connect: %s", challenge_host);
	}

	timeout.tv_sec = certes_conf.agent_send_timeout_ms / 1000;
	timeout.tv_usec = certes_conf.agent_send_timeout_ms % 1000;
	fd = BIO_get_fd(bio, NULL);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto befail;
	}

	timeout.tv_sec = certes_conf.agent_recv_timeout_ms / 1000;
	timeout.tv_usec = certes_conf.agent_recv_timeout_ms % 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto befail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op_id;
	pv[1].type = MDR_B;
	pv[1].v.b.bytes = cs->challenge;
	pv[1].v.b.sz = sizeof(cs->challenge);
	if (pmdr_pack(&pm,
	    (dcv == MDR_DCV_CERTES_BOOTSTRAP_DIALBACK)
	    ? msg_bootstrap_dialback
	    : msg_cert_renew_dialback,
	    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		status = -1;
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/dialback");
	} else if ((r = BIO_write(bio, pmdr_buf(&pm), pmdr_size(&pm))) == -1) {
		status = -1;
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "error during dialback write");
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	} else if (r < pmdr_size(&pm)) {
		status = -1;
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "short write during dialback");
		XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");
	}

	BIO_flush(bio);
	BIO_free_all(bio);
	SSL_CTX_free(ctx);
	return status;
befail:
	if (bio != NULL)
		BIO_free(bio);
	if (ctx != NULL)
		SSL_CTX_free(ctx);
	beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failed");
	return -1;
}

/*
 * Incoming bootstrap request from agent. They provide a bootstrap key,
 * which we'll then use to lookup information to challenge them and issue
 * a certificate.
 */
int
authority_bootstrap_dialin(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct bootstrap_entry *be = NULL;
	struct umdr_vec         uv[3];
	struct timespec         now;
	struct certes_session  *cs = (struct certes_session *)sess->data;
	const char             *op_id;
	char                    challenge_host[256];
	X509_NAME              *subject;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)));

	if (umdr_unpack(msg, msg_bootstrap_dialin, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno,
		    "umdr_unpack/msg_bootstrap_dialin");

	op_id = uv[0].v.s.bytes;

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (uv[1].v.b.sz != CERTES_BOOTSTRAP_KEY_LENGTH) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BADMSG,
		    "bootstrap key received from client has incorrect length");
		return XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap key received from client has incorrect length");
	}

	if ((be = certdb_get_bootstrap(uv[1].v.b.bytes, uv[1].v.b.sz, e))
	    == NULL) {
		/*
		 * We never report an error if the bootstrap key is not
		 * found to mitigate enumeration attacks.
		 */
		beout_ok(sess, op_id, MDRD_BEOUT_FNONE);
		return XERR_PREPENDFN(e);
	}

	cs->req = d2i_X509_REQ(NULL, (const unsigned char **)&uv[2].v.b.bytes,
	    uv[2].v.b.sz);
	if (cs->req == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "failed to decode REQ");
		XERRF(e, XLOG_SSL, ERR_get_error(), "d2i_X509_REQ");
		goto fail;
	}

	if (be->flags & CERTDB_BOOTSTRAP_FLAG_SETCN) {
		if (cert_subject_cn(be->subject, challenge_host,
		    sizeof(challenge_host), e) == -1) {
			XERR_PREPENDFN(e);
			goto fail;
		}
	} else {
		subject = X509_REQ_get_subject_name(cs->req);
		if (subject == NULL) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_REQ_get_subject_name");
			goto fail;
		}
		if (X509_NAME_get_text_by_NID(subject, NID_commonName,
		    challenge_host, sizeof(challenge_host)) == -1) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_NAME_get_text_by_NID");
			goto fail;
		}
	}

	/*
	 * Make sure the key has not expired.
	 */
	clock_gettime(CLOCK_REALTIME, &now);
	if (now.tv_sec > be->valid_until_sec) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "bootstrap key is expired");
		XERRF(e, XLOG_APP, XLOG_TIMEOUT,
		    "bootstrap key is expired");
		goto fail;
	}

	if ((cs->bootstrap_key = malloc(CERTES_BOOTSTRAP_KEY_LENGTH))
	    == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	memcpy(cs->bootstrap_key, uv[1].v.b.bytes,
	    CERTES_BOOTSTRAP_KEY_LENGTH);

	/*
	 * Then we challenge the client by connecting to its CommonName
	 * as per our DB.
	 */
	if (authority_challenge(sess, op_id,
	    MDR_DCV_CERTES_BOOTSTRAP_DIALBACK, challenge_host, e) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}
	certdb_bootstrap_free(be);
	beout_ok(sess, op_id, MDRD_BEOUT_FNONE);
	return 0;
fail:
	certdb_bootstrap_free(be);
	return -1;
}

#ifdef __linux__
static int
pack_intermediates(X509 *crt, uint8_t **der_chain, size_t *chain_sz,
    struct xerr *e)
{
	STACK_OF(X509) *chain = NULL;
	X509           *c;
	int             i, status = 0;
	int             sz;
	uint8_t        *p, *der;

	*der_chain = NULL;
	*chain_sz = 0;

	chain = X509_build_chain(crt, NULL, agent_cert_store(), 0, NULL, NULL);
	if (chain == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_build_chain");

	if (sk_X509_num(chain) < 2) {
		XERRF(e, XLOG_APP, XLOG_FAIL, "not intermediate cert?");
		goto end;
	}

	/*
	 * We start at index 1 because we already send the cert itself.
	 * We only want intermediates.
	 */
	for (i = 1; i < sk_X509_num(chain); i++) {
		c = sk_X509_value(chain, i);
		sz = i2d_X509(c, NULL);
		if (sz < 0) {
			status = XERRF(e, XLOG_SSL, ERR_get_error(),
			    "i2d_X509");
			goto end;
		}
		*chain_sz += sz + sizeof(uint32_t);
	}

	if ((*der_chain = malloc(*chain_sz)) == NULL) {
		status = XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto end;
	}
	p = *der_chain;

	for (i = 1; i < sk_X509_num(chain); i++) {
		c = sk_X509_value(chain, i);
		der = NULL;
		sz = i2d_X509(c, &der);
		if (sz < 0) {
			free(*der_chain);
			status = XERRF(e, XLOG_SSL, ERR_get_error(),
			    "i2d_X509");
			goto end;
		}
		*((uint32_t *)p) = htobe32(sz);
		p += sizeof(uint32_t);
		memcpy(p, der, sz);
		p += sz;
		free(der);
	}
end:
	sk_X509_pop_free(chain, X509_free);
	return status;
}
#else
static int
pack_intermediates(X509 *crt, uint8_t **der_chain, size_t *chain_sz,
    struct xerr *e)
{
	int      sz;
	uint8_t *p, *der;

	*der_chain = NULL;
	*chain_sz = 0;

	/*
	 * X509_build_chain does not exist on OpenBSD, but really
	 * we should normally only have to pack this authority's
	 * cert and nothing else, so that should suffice.
	 */
	sz = i2d_X509(agent_cert(), NULL);
	if (sz < 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
	*chain_sz += sz + sizeof(uint32_t);

	if ((*der_chain = malloc(*chain_sz)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");
	p = *der_chain;

	der = NULL;
	sz = i2d_X509(agent_cert(), &der);
	if (sz < 0) {
		free(*der_chain);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
	}

	*((uint32_t *)p) = htobe32(sz);
	p += sizeof(uint32_t);
	memcpy(p, der, sz);
	free(der);

	return 0;
}
#endif

static int
authority_send_cert(struct mdrd_besession *sess, const char *op_id,
    X509 *crt, const uint8_t *crt_buf, int crt_len, struct xerr *e)
{
	uint8_t         *der_chain = NULL;
	size_t           der_sz;
	struct pmdr      pm;
	struct pmdr_vec  pv[3];
	char             pbuf[mdr_spec_base_sz(msg_send_cert,
	    certes_conf.max_cert_size * 2)];

	if (pack_intermediates(crt, &der_chain, &der_sz, xerrz(e)) == -1) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
                goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S; /* Op ID */
	pv[0].v.s = op_id;
	pv[1].type = MDR_B; /* cert */
	pv[1].v.b.bytes = crt_buf;
	pv[1].v.b.sz = crt_len;
	pv[2].type = MDR_B; /* intermediates */
	pv[2].v.b.bytes = der_chain;
	pv[2].v.b.sz = der_sz;
	if (pmdr_pack(&pm, msg_send_cert, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/msg_send_cert");
		goto fail;
	}

	if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
		goto fail;
	}

	free(der_chain);
	return 0;
fail:
	if (der_chain != NULL)
		free(der_chain);
	return -1;
}

int
authority_bootstrap_answer(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct bootstrap_entry *be = NULL;
	struct cert_entry       ce;
	struct umdr_vec         uv[2];
	struct certes_session  *cs = (struct certes_session *)sess->data;
	X509                   *crt = NULL;
	const char             *op_id;
	struct tm               tm;
	unsigned char          *crt_buf = NULL;
	int                     crt_len;

	if (umdr_unpack(msg, msg_bootstrap_answer, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_bootstrap_answer");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (memcmp(cs->challenge, uv[1].v.b.bytes,
	    MIN(sizeof(cs->challenge), uv[1].v.b.sz)) != 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "failed challenge");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    "client failed challenge");
	}

	if ((be = certdb_get_bootstrap(cs->bootstrap_key,
	    CERTES_BOOTSTRAP_KEY_LENGTH, e)) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "no such bootstrap entry");
		return XERR_PREPENDFN(e);
	}

	crt = cert_sign_req(cs->req, be, xerrz(e));
	if (crt == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}

	crt_len = i2d_X509(crt, &crt_buf);
	if (crt_len < 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
                XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
		goto fail;
	}

	bzero(&ce, sizeof(ce));
	if ((ce.serial = cert_serial_to_hex(crt, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	if ((ce.subject = cert_subject_oneline(crt, xerrz(e))) == NULL) {
		free(ce.serial);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	ce.sans = be->sans;
	ce.sans_sz = be->sans_sz;
	ce.roles = be->roles;
	ce.roles_sz = be->roles_sz;
	ASN1_TIME_to_tm(X509_get_notBefore(crt), &tm);
	ce.not_before_sec = timegm(&tm);
	ASN1_TIME_to_tm(X509_get_notAfter(crt), &tm);
	ce.not_after_sec = timegm(&tm);
	ce.flags = CERTDB_FLAG_NONE;
	ce.der = crt_buf;
	ce.der_sz = crt_len;
	if (certdb_put_cert(&ce, xerrz(e)) == -1) {
		free(ce.serial);
		free(ce.subject);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	free(ce.serial);
	free(ce.subject);

	if (authority_send_cert(sess, op_id, crt, crt_buf, crt_len,
	    xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (certdb_del_bootstrap(be, xerrz(e)) == -1)
		xlog(LOG_ERR, e, "%s", __func__);

	xlog(LOG_NOTICE, NULL, "%s: op_id %s completed", __func__, op_id);

	free(crt_buf);
	X509_free(crt);
	certdb_bootstrap_free(be);
	return 0;
fail:
	certdb_bootstrap_free(be);
	if (crt_buf != NULL)
		free(crt_buf);
	if (crt != NULL)
		X509_free(crt);
	return -1;
}

int
authority_cert_renew_answer(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct cert_entry     *ce = NULL;
	struct umdr_vec        uv[2];
	struct certes_session *cs = (struct certes_session *)sess->data;
	X509                  *crt = NULL;
	const char            *op_id;
	struct tm              tm;
	char                  *serial;
	int                    der_sz;

	if (umdr_unpack(msg, msg_bootstrap_answer, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_bootstrap_answer");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (memcmp(cs->challenge, uv[1].v.b.bytes,
	    MIN(sizeof(cs->challenge), uv[1].v.b.sz)) != 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "failed challenge");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    "client failed challenge");
	}

	if ((serial = cert_serial_to_hex(sess->cert, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		return XERR_PREPENDFN(e);
	}
	if ((ce = certdb_get_cert(serial, xerrz(e))) == NULL) {
		free(serial);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failure");
		return XERR_PREPENDFN(e);
	}
	free(serial);

	crt = cert_sign(sess->cert, agent_cert(), ce, xerrz(e));
	if (crt == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}

	/*
	 * Get the new cert serial
	 */
	if ((serial = cert_serial_to_hex(crt, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}
	free(ce->serial);
	ce->serial = serial;

	/*
	 * We can reuse 'ce' and simply modify the fields to update. But
	 * since ce->der is dynamically allocated, free it first.
	 */
	free(ce->der);
	ce->der = NULL;
	der_sz = i2d_X509(crt, &ce->der);
	if (der_sz < 0) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
                XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509");
                goto fail;
	}
	ce->der_sz = der_sz;

	ASN1_TIME_to_tm(X509_get_notBefore(crt), &tm);
	ce->not_before_sec = timegm(&tm);
	ASN1_TIME_to_tm(X509_get_notAfter(crt), &tm);
	ce->not_after_sec = timegm(&tm);

	/*
	 * We'll just write the new cert and let the old one expire.
	 * This also gives services using it time to load the new one.
	 */
	if (certdb_put_cert(ce, xerrz(e)) == -1) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (authority_send_cert(sess, op_id, crt, ce->der,
	    ce->der_sz, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	xlog(LOG_NOTICE, NULL, "%s: op_id %s completed", __func__, op_id);

	certdb_cert_free(ce);
	X509_free(crt);
	return 0;
fail:
	certdb_cert_free(ce);
	if (crt != NULL)
		X509_free(crt);
	return -1;
}

int
authority_cert_renewal_inquiry(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct umdr_vec    uv[2];
	const char        *op_id;
	char              *serial;
	struct cert_entry *ce;
	char               challenge_host[256];
	struct pmdr        pm;
	char               pbuf[1024];
	struct pmdr_vec    pv[1];

	if (umdr_unpack(msg, msg_cert_renewal_inquiry, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_cert_renewal_inquiry");

	op_id = uv[0].v.s.bytes;

	xlog(LOG_NOTICE, NULL, "%s: handling for %s, op_id=%s", __func__,
	    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);

	if (!agent_is_authority()) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_AGENT, xerrz(e))) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_DENIED,
		    ROLE_AGENT " role required");
		return XERRF(e, XLOG_APP, XLOG_DENIED,
		    ROLE_AGENT " role required");
	}

	if ((serial = cert_serial_to_hex(sess->cert, xerrz(e))) == NULL) {
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		return XERR_PREPENDFN(e);
	}
	if ((ce = certdb_get_cert(serial, xerrz(e))) == NULL) {
		free(serial);
		beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
		    "backend failed");
		return XERR_PREPENDFN(e);
	}
	free(serial);

	switch (cert_must_renew(sess->cert, ce, xerrz(e))) {
	case -1:
		XERR_PREPENDFN(e);
		goto fail;
	case 0:
		/*
		 * Cert is already up-to-date, no need to
		 * do anything
		 */
		certdb_cert_free(ce);
		beout_ok(sess, op_id, MDRD_BEOUT_FNONE);
		xlog(LOG_INFO, NULL, "%s: cert is already up-to-date "
		    "for %s, op_id=%s", __func__,
		    certes_client_name(sess, NULL, 0, xerrz(e)), op_id);
		return 0;
	default:
		/* We have to renew */
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_S;
		pv[0].v.s = op_id;
		if (pmdr_pack(&pm, msg_cert_renewal_required,
		    pv, PMDRVECLEN(pv)) == MDR_FAIL)
			abort();
		if (mdrd_beout(sess, MDRD_BEOUT_FNONE, &pm) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "mdrd_beout");
			goto fail;
		}
		break;
	}

	if (cert_subject_cn(ce->subject, challenge_host,
	    sizeof(challenge_host), e) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (authority_challenge(sess, op_id,
	    MDR_DCV_CERTES_CERT_RENEW_DIALBACK, challenge_host, e) == -1) {
		certdb_cert_free(ce);
		return XERR_PREPENDFN(e);
	}

	certdb_cert_free(ce);
	return 0;
fail:
	certdb_cert_free(ce);
	beout_error(sess, op_id, MDRD_BEOUT_FNONE, MDR_ERR_BEFAIL,
	    "backend failed");
	return -1;
}
