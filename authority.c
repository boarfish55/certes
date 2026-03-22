#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "authority.h"
#include "agent.h"
#include "cert.h"
#include "mdrd.h"
#include "util.h"

extern struct certalator_flatconf certalator_conf;

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
	char                   subject[CERTALATOR_MAX_SUBJET_LENGTH] = "";
	struct bootstrap_entry be;
	struct timespec        tp;

	if (flags & CERTDB_BOOTSTRAP_FLAG_SETCN) {
		if (snprintf(subject, sizeof(subject),
		    "/O=%s/CN=%s/emailAddress=%s", certalator_conf.cert_org,
		    cn, certalator_conf.cert_email) >= sizeof(subject))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
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
		if (strlen(roles[i]) > CERTALATOR_MAX_ROLE_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "role name %s longer than limit of %d",
			    roles[i], CERTALATOR_MAX_ROLE_LENGTH);

	for (i = 0; i < sans_sz; i++)
		if (strlen(sans[i]) > CERTALATOR_MAX_SAN_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "SAN name %s longer than limit of %d",
			    sans[i], CERTALATOR_MAX_SAN_LENGTH);

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

	if (!agent_is_authority()) {
		mdrd_beresp_error(sess, MDRD_BERESP_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUPP,
		    "we are not an authority");
	}

	if (!cert_has_role(sess->cert, ROLE_BOOTSTRAP, xerrz(e))) {
		mdrd_beresp_error(sess, MDRD_BERESP_FNONE,
		    MDR_ERR_DENIED, ROLE_BOOTSTRAP " role required");
		return XERRF(e, XLOG_APP, XLOG_ACCES,
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

	if (mdrd_beresp_ok(sess, MDRD_BERESP_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdrd_beresp_ok");
		return -1;
	}

	return 0;
fail:
	free(sans);
	free(roles);
	mdrd_beresp_error(sess, MDRD_BERESP_FNONE, MDR_ERR_BEFAIL,
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
authority_challenge(struct bootstrap_entry *be, const char *op_id,
    const uint8_t *challenge, struct xerr *e)
{
	char             chal_host[256];
	char             port[6];
	int              fd;
	struct timeval   timeout;
	SSL_CTX         *ctx;
	SSL             *ssl;
	BIO             *bio;
	struct pmdr      pm;
	char             pbuf[256];
	struct pmdr_vec  pv[2];
	int              r;

	if (snprintf(port, sizeof(port), "%u", CERTALATOR_AGENT_PORT) >=
	    sizeof(port))
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "failed to convert agent port");

	if (cert_subject_cn(be->subject, chal_host, sizeof(chal_host), e) == -1)
		return XERR_PREPENDFN(e);

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

	SSL_CTX_set_security_level(ctx, 3);

	if (SSL_CTX_use_PrivateKey(ctx, agent_key()) != 1)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "SSL_CTX_use_PrivateKey");

	if (SSL_CTX_use_certificate(ctx, agent_cert()) != 1)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "SSL_CTX_use_certificate");

	if ((bio = BIO_new_ssl_connect(ctx)) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_new_ssl_connect");

	BIO_get_ssl(bio, &ssl);
	if (ssl == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_get_ssl");

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(bio, chal_host);
	BIO_set_conn_port(bio, port);

	if (BIO_do_connect(bio) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_do_connect: %s", chal_host);

	timeout.tv_sec = certalator_conf.agent_send_timeout_ms / 1000;
	timeout.tv_usec = certalator_conf.agent_send_timeout_ms % 1000;
	fd = BIO_get_fd(bio, NULL);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
	    &timeout, sizeof(timeout)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "setsockopt");

	timeout.tv_sec = certalator_conf.agent_recv_timeout_ms / 1000;
	timeout.tv_usec = certalator_conf.agent_recv_timeout_ms % 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
	    &timeout, sizeof(timeout)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "setsockopt");

	if (BIO_do_handshake(bio) <= 0)
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "BIO_do_handshake");

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op_id;
	pv[1].type = MDR_B;
	pv[1].v.b.bytes = challenge;
	pv[1].v.b.sz = sizeof(challenge);
	if (pmdr_pack(&pm, msg_bootstrap_dialback, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno,
		    "pmdr_pack/msg_bootstrap_dialback");

	if ((r = BIO_write(bio, pmdr_buf(&pm), pmdr_size(&pm))) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	else if (r < pmdr_size(&pm))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");

	return 0;
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
	struct bootstrap_entry be;
	struct umdr_vec        uv[2];
	struct timespec        now;
	uint8_t                challenge[32];

	if (!agent_is_authority())
		return XERRF(e, XLOG_APP, XLOG_NOTSUPP,
		    "we are not an authority");

	if (umdr_unpack(msg, msg_bootstrap_dialin, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno,
		    "umdr_unpack/msg_bootstrap_dialin");

	if (uv[1].v.s.sz != CERTALATOR_BOOTSTRAP_KEY_LENGTH)
		return XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap key received from client has incorrect length");

	if (certdb_get_bootstrap(&be, uv[1].v.b.bytes, uv[1].v.b.sz, e) == -1)
		return XERR_PREPENDFN(e);

	/*
	 * Make sure the key has not expired.
	 */
	clock_gettime(CLOCK_REALTIME, &now);
	if (now.tv_sec > be.valid_until_sec)
		return XERRF(e, XLOG_APP, XLOG_TIMEOUT,
		    "bootstrap key is expired");

	/*
	 * Then we challenge the client by connecting to its CommonName
	 * as per our DB.
	 */
	arc4random_buf(challenge, sizeof(challenge));
	if (authority_challenge(&be, uv[0].v.s.bytes, challenge, e) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

int
authority_bootstrap_req(struct mdrd_besession *sess, struct umdr *msg,
    struct xerr *e)
{
	struct umdr_vec uv[3];

	if (!agent_is_authority()) {
		mdrd_beresp_error(sess, MDRD_BERESP_FNONE, MDR_ERR_NOTSUPP,
		    "we are not an authority");
		return XERRF(e, XLOG_APP, XLOG_NOTSUPP,
		    "we are not an authority");
	}

	if (umdr_unpack(msg, msg_bootstrap_req, uv, UMDRVECLEN(uv)) == MDR_FAIL)
                return XERRF(e, XLOG_ERRNO, errno,
                    "umdr_unpack/msg_bootstrap_req");

	return 0;
}
