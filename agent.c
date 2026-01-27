#include <sys/mman.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include "agent.h"
#include "certalator.h"
#include "coordinator.h"
#include "cert.h"
#include "mdr.h"
#include "xlog.h"
#include "util.h"

static EVP_PKEY    *key = NULL;
static X509        *cert = NULL;
static SSL_CTX     *ssl_ctx = NULL;
static SSL         *ssl = NULL;
static BIO         *bio = NULL;
static int          connected = 0;
static int          is_authority = 0;
static X509        *ca_crt = NULL;
static X509_STORE  *store;

extern struct certalator_flatconf certalator_conf;

static int
agent_connect(struct xerr *e)
{
	char           host[302];
	int            fd;
	struct timeval timeout;

	if (certalator_conf.authority_fqdn[0] == '\0')
		return XERRF(e, XLOG_APP, XLOG_EDESTADDRREQ,
		    "no destination address was specified");

	if (ssl_ctx == NULL) {
		if ((ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

		// TODO: make sure we are talking to a ca-proxy, optionally.
		SSL_CTX_set_security_level(ssl_ctx, 3);
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_store(ssl_ctx, store);

		if (SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_PrivateKey");
		if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_certificate");
	}

	if (bio == NULL) {
		if (snprintf(host, sizeof(host), "%s:%lu",
		    certalator_conf.authority_fqdn,
		    certalator_conf.authority_port) >= sizeof(host))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "resulting host:port is too long");

		if ((bio = BIO_new_ssl_connect(ssl_ctx)) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_new_ssl_connect");

		BIO_get_ssl(bio, &ssl);
		if (ssl == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_get_ssl");

		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		BIO_set_conn_hostname(bio, host);
	}

	if (!connected) {
		if (BIO_do_connect(bio) <= 0)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_do_connect");

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
		connected = 1;
	}

	return 0;
}

int
agent_send(struct pmdr *m, struct xerr *e)
{
	int r;

	if (agent_connect(e) == -1)
		return -1;

	if ((r = BIO_write(bio, pmdr_buf(m), pmdr_size(m))) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	else if (r < pmdr_size(m))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");

	return 0;

}

int
agent_recv(char *buf, size_t buf_sz, struct xerr *e)
{
	int r;

	if (agent_connect(e) == -1)
		return -1;

	if ((r = mdr_buf_from_BIO(bio, buf, buf_sz)) < 1)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_read");

	return r;
}

static int
agent_new_req(const char *subject, unsigned char **req_buf, size_t *req_len,
    struct xerr *e)
{
	/* Inspired by OpenBSD's acme-client/keyproc.c:77 */
	X509_REQ                 *req;
	X509_NAME                *name = NULL;
	X509_EXTENSION           *ex;
	char                     *token, *field, *value, *t;
	char                     *save1, *save2;
	char                      subject2[CERTALATOR_MAX_SUBJET_LENGTH];
	char                     *sans = NULL;
	STACK_OF(X509_EXTENSION) *exts;
	int                       sockfd;
	struct sockaddr_in6       addr;
	socklen_t                 slen = sizeof(addr);
	char                      taddr[INET6_ADDRSTRLEN];

	if ((req = X509_REQ_new()) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_REQ_new");

	if (!X509_REQ_set_version(req, 2)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_REQ_set_version");
		goto fail;
	}

	if (!X509_REQ_set_pubkey(req, key)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_REQ_set_pubkey");
		goto fail;
	}

	if ((name = X509_NAME_new()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_NAME_new");
		goto fail;
	}

	strlcpy(subject2, subject, sizeof(subject2));

	for (t = subject2; ; t = NULL) {
		token = strtok_r(t, "/", &save1);
		if (token == NULL)
			break;

		if (strcmp(token, "") == 0)
			continue;

		field = strtok_r(token, "=", &save2);
		if (field == NULL) {
			XERRF(e, XLOG_APP, XLOG_INVAL, "malformed subject");
			goto fail;
		}

		if (strcmp(field, "CN") != 0 &&
		    strcmp(field, "O") != 0 &&
		    strcmp(field, "emailAddress") != 0) {
			XERRF(e, XLOG_APP, XLOG_INVAL,
			    "unsupported subject field %s", field);
			goto fail;
		}

		value = strtok_r(NULL, "=", &save2);
		if (value == NULL) {
			XERRF(e, XLOG_APP, XLOG_INVAL, "malformed subject");
			goto fail;
		}

		if (!X509_NAME_add_entry_by_txt(name, field,
		    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0)) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_NAME_add_entry_by_txt: %s=%s", field, value);
			goto fail;
		}

	}

	if (!X509_REQ_set_subject_name(req, name)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_req_set_subject_name");
		goto fail;
	}
	name = NULL;

	if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "sk_X509_EXTENSION_new_null");
		goto fail;
	}

	if (BIO_get_fd(bio, &sockfd) <= 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_get_fd");
		goto fail;
	}
	if (getsockname(sockfd, (struct sockaddr *)&addr, &slen) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "getsockname");
		goto fail;
	}
	if (slen > sizeof(addr)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "sock name does not fit in sockaddr");
		goto fail;
	}
	if (inet_ntop(addr.sin6_family, &addr, taddr, slen) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "inet_ntop");
		goto fail;
	}
	if (asprintf(&sans, "IP:%s", taddr) == -1) {
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

	if (!X509_REQ_sign(req, key, EVP_sha256())) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_sign");
		goto fail;
        }

	/*
	 * Serialise to DER
	 */
	if ((*req_len = i2d_X509_REQ(req, NULL)) < 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "i2d_X509_REQ");
		goto fail;
	}
	if ((*req_buf = malloc(*req_len)) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		goto fail;
	}
	i2d_X509_REQ(req, req_buf);

	/*
	 * We don't need to fully populate the REQ. We should add a SANS for
	 * our IP address so the dialback works. The authority will take care
	 * of adding all configured SANs to the cert during signing.
	 */

	// TODO: leak? double-free?
	X509_REQ_free(req);
	free(sans);
	return 0;
fail:
	X509_REQ_free(req);
	if (name != NULL)
		X509_NAME_free(name);
	if (sans != NULL)
		free(sans);
	return -1;
}

int
agent_init(struct xerr *e)
{
	if (cert_init(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);
	if ((store = X509_STORE_new()) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_new");
	if (agent_load_keys(e) == -1)
		return XERR_PREPENDFN(e);
	return 0;
}

int
agent_is_authority()
{
	return is_authority;
}

/*
 * Contact the authority to send our bootstrap key in order to obtain
 * our certificate parameters and create our key and REQ.
 * TODO: this version may not work as it receives through mdrd which cannot
 * receive without a cert in the first place.
 */
FILE *
agent_bootstrap(struct xerr *e)
{
	struct umdr      um;
	struct pmdr      pm;
	struct pmdr_vec  pv[2];
	struct umdr_vec  uv[1];
	char             pbuf[16384];
	char             ubuf[16384];
	char            *subject = NULL;
	char             req_id[CERTALATOR_REQ_ID_LENGTH];
	uint8_t          bootstrap_key[CERTALATOR_BOOTSTRAP_KEY_LENGTH];
	struct timespec  now;
	int              try;
	ptrdiff_t        r;
	unsigned char   *req_buf;
	size_t           req_len;
	X509            *crt;
	FILE            *f;

	if (strlen(certalator_conf.bootstrap_key) !=
	    CERTALATOR_BOOTSTRAP_KEY_LENGTH_B64) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "bad bootstrap key format in configuration; bad length");
		return NULL;
	}

	if (b64dec(bootstrap_key, sizeof(bootstrap_key),
	    certalator_conf.bootstrap_key) < sizeof(bootstrap_key)) {
		XERRF(e, XLOG_ERRNO, errno, "%s: b64dec", __func__);
		return NULL;
	}

	/*
	 * The req_id is just echoed back to us by the authority, which we
	 * then use to find the challenge sent to us on another connection.
	 */
	clock_gettime(CLOCK_REALTIME, &now);
	if (snprintf(req_id, sizeof(req_id), "%d-%lu.%lu", getpid(),
	    now.tv_sec, now.tv_nsec) >= sizeof(req_id)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "resulting req_id too long; this is a bug");
		return NULL;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = req_id;
	pv[1].type = MDR_B;
	pv[1].v.b.bytes = bootstrap_key;
	pv[1].v.b.sz = sizeof(bootstrap_key);
	if (pmdr_pack(&pm,  msg_bootstrap_dialin, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/msg_bootstrap_dialin");
		return NULL;
	}

	if (agent_send(&pm, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	/*
	 * The coordinator should be receiving a challenge from the authority,
	 * so let's poll for a bit to see if we got it.
	 * If the bootstrap key was wrong, we won't get a dialback, the
	 * authority will quietly ignore the request.
	 */
	for (try = 0; try < 10; try++) {
		pv[0].type = MDR_S;
		pv[0].v.s = req_id;
		if (pmdr_pack(&pm, msg_coord_get_cert_challenge,
		    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
			XERRF(e, XLOG_ERRNO, errno,
			    "pmdr_pack/msg_coord_get_cert_challenge");
			return NULL;
		}

		if (coordinator_send(&pm, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		r = coordinator_recv(ubuf, sizeof(ubuf), xerrz(e));
		if (r == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
			XERRF(e, XLOG_ERRNO, errno, "umdr_init");
			return NULL;
		}

		if (umdr_dcv(&um) ==
		    MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP)
			break;

		/* Retry for any other answer */
	}
	if (try == 10) {
		XERRF(e, XLOG_APP, XLOG_TIMEOUT, "challenge timed out");
		return NULL;
	}

	if (umdr_unpack(&um, msg_coord_get_cert_challenge_resp,
	    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
		return NULL;
	}

	/*
	 * Send the challenge back to the authority.
	 */
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = uv[1].v.s.bytes;
	pv[0].v.b.sz = uv[1].v.s.sz;
	if (pmdr_pack(&pm, msg_bootstrap_answer_challenge,
	    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/msg_bootstrap_dialin");
		return NULL;
	}
	if (agent_send(&pm, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	if ((r = agent_recv(ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_init");
		return NULL;
	}

	if (umdr_dcv(&um) == MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP_FAILED) {
		XERRF(e, XLOG_APP, XLOG_BADMSG, "failed challenge");
		return NULL;
	} else if (umdr_dcv(&um) != MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "unknown message from authority");
		return NULL;
	}

	/*
	 * We passed the challenge, send our REQ.
	 */
	if (agent_new_req(subject, &req_buf, &req_len, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = req_buf;
	pv[0].v.b.sz = req_len;
	if (pmdr_pack(&pm, msg_bootstrap_req, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_pack/msg_bootstrap_req");
		return NULL;
	}
	if (agent_send(&pm, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	/*
	 * Finally, we get the cert back.
	 */
	if ((r = agent_recv(ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_init");
		return NULL;
	}
	if (umdr_dcv(&um) == MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_RESP_FAILED) {
		if (umdr_unpack(&um, msg_bootstrap_req_resp_failed,
		    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
			XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
			return NULL;
		}
		XERRF(e, XLOG_APP, XLOG_BADMSG, "signing REQ failed: %s",
		    uv[1].v.s.bytes);
		return NULL;
	} else if (umdr_dcv(&um) != MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_RESP) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "unknown message from authority");
		return NULL;
	}
	if (umdr_unpack(&um, msg_bootstrap_req_resp, uv, UMDRVECLEN(uv))
	    == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "umdr_unpack/msg_bootstrap_req_resp");
		return NULL;
	}

	crt = d2i_X509(NULL, (const unsigned char **)&uv[1].v.b.bytes,
	    uv[1].v.b.sz);
        if (crt == NULL) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap reply did not contain a valid "
		    "DER-encoded X.509");
		return NULL;
        }

	f = fopen(certalator_conf.cert_file, "w");
	if (PEM_write_X509(f, crt) == 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
		return NULL;
	}
	if (fflush(f) != 0) {
		XERRF(e, XLOG_ERRNO, errno, "fflush");
		return NULL;
	}
	rewind(f);

	return f;
}

static int
get_listen_socket(int domain, int type, unsigned short port, struct xerr *e)
{
	int                 fd;
	struct sockaddr_in6 sa6;
	struct sockaddr_in  sa;
	int                 one = 1;

	// TODO: error handling
	if ((fd = socket(domain, type, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		xlog_strerror(LOG_ERR, errno, "setsockopt");
		return -1;
	}

	if (domain == AF_INET6) {
		bzero(&sa6, sizeof(sa6));
		sa6.sin6_family = domain;
		memcpy(&sa6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
		sa6.sin6_port = htons(port);
		if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) == -1) {
			xlog_strerror(LOG_ERR, errno, "bind");
			return -1;
		}
	} else {
		bzero(&sa, sizeof(sa));
		sa.sin_family = domain;
		sa.sin_port = htons(port);
		if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
			xlog_strerror(LOG_ERR, errno, "bind");
			return -1;
		}
	}

	if (listen(fd, 5) == -1) {
		xlog_strerror(LOG_ERR, errno, "listen");
		return -1;
	}

	return fd;
}

static int
accept_agent_conn(int lsock6, int lsock4)
{
	int            cfd = -1;
	struct pollfd  pfd[2];
	int            nfds = 0;
	int            i, r;
	// TODO: make the timeout configurable? Or use recv timeout?
	struct timeval timeout = {60, 0};

	nfds++;
	pfd[0].fd = lsock6;
	pfd[0].events = POLLIN;

	if (lsock4 >= 0) {
		nfds++;
		pfd[1].fd = lsock4;
		pfd[1].events = POLLIN;
	}
poll:
	// TODO: make the timeout configurable? Or use recv timeout?
	r = poll(pfd, nfds, 60000);
	if (r == -1) {
		if (errno == EINTR)
			goto poll;
		xlog_strerror(LOG_ERR, errno, "poll");
		return -1;
	}

	if (r == 0) {
		xlog(LOG_ERR, NULL, "%s: accept timed out", __func__);
		return -1;
	}

	for (i = 0; i < r; i++) {
accept:
		if ((cfd = accept(pfd[i].fd, NULL, 0)) == 0)
			break;

		if (errno == EINTR)
			goto accept;
		xlog_strerror(LOG_ERR, errno, "accept");
	}

	if (cfd == -1) {
		xlog(LOG_ERR, NULL, "%s: accept failed for all polled "
		    "sockets; aborting", __func__);
		return -1;
	}

	if (fcntl(pfd[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		close(pfd[i].fd);
		return -1;
	}

	if (setsockopt(pfd[i].fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	    sizeof(timeout)) == -1) {
		xlog_strerror(LOG_ERR, errno, "setsockopt");
		close(pfd[i].fd);
		return -1;
	}

	return cfd;
}

/*
 * Contact the authority to send our bootstrap key in order to obtain
 * our certificate parameters and create our key and REQ.
 * TODO: this version does its own listen on a non-SSL socket, which is
 * necessary since we don't have a cert yet
 */
FILE *
agent_bootstrap2(struct xerr *e)
{
	struct umdr      um;
	struct pmdr      pm;
	struct pmdr_vec  pv[2];
	struct umdr_vec  uv[1];
	char             pbuf[16384];
	char             ubuf[16384];
	char            *subject = NULL;
	char             req_id[CERTALATOR_REQ_ID_LENGTH];
	uint8_t          bootstrap_key[CERTALATOR_BOOTSTRAP_KEY_LENGTH];
	struct timespec  now;
	ptrdiff_t        r;
	unsigned char   *req_buf;
	size_t           req_len;
	X509            *crt;
	FILE            *f;
	int              lsock6 = -1, lsock4 = -1;
	int              cfd = -1;
	int              try;

	if (strlen(certalator_conf.bootstrap_key) !=
	    CERTALATOR_BOOTSTRAP_KEY_LENGTH_B64) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "bad bootstrap key format in configuration; bad length");
		return NULL;
	}

	if (b64dec(bootstrap_key, sizeof(bootstrap_key),
	    certalator_conf.bootstrap_key) < sizeof(bootstrap_key)) {
		XERRF(e, XLOG_ERRNO, errno, "%s: b64dec", __func__);
		return NULL;
	}

	/*
	 * The req_id is just echoed back to us by the authority, which we
	 * then use to find the challenge sent to us on another connection.
	 */
	clock_gettime(CLOCK_REALTIME, &now);
	if (snprintf(req_id, sizeof(req_id), "%d-%lu.%lu", getpid(),
	    now.tv_sec, now.tv_nsec) >= sizeof(req_id)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "resulting req_id too long; this is a bug");
		return NULL;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = req_id;
	pv[1].type = MDR_B;
	pv[1].v.b.bytes = bootstrap_key;
	pv[1].v.b.sz = sizeof(bootstrap_key);
	if (pmdr_pack(&pm,  msg_bootstrap_dialin, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/msg_bootstrap_dialin");
		return NULL;
	}

	if (agent_send(&pm, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	/* Listen for the authority sending us a challenge */
	lsock6 = get_listen_socket(AF_INET6, SOCK_STREAM,
	    certalator_conf.agent_bootstrap_port, xerrz(e));
	if (lsock6 == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
#ifndef __linux__
	/*
	 * On OpenBSD (and other BSDs??), we don't get v4 compatibility when
	 * creating a v6 listening socket. This function lets us create
	 * listening sockets by family.
	 */
	lsock4 = get_listen_socket(AF_INET, SOCK_STREAM,
	    certalator_conf.agent_bootstrap_port, xerrz(e));
	if (lsock4 == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
#endif
	for (try = 0; try < 10; try++) {
		if ((cfd = accept_agent_conn(lsock6, lsock4)) == -1)
			continue;

		if ((r = mdr_buf_from_fd(cfd, ubuf, sizeof(ubuf)))
		    == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "mdr_buf_from_fd");
			continue;
		}

		if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno, "umdr_init");
			close(cfd);
			continue;
		}

		if (umdr_unpack(&um, msg_coord_get_cert_challenge_resp,
		    uv, UMDRVECLEN(uv)) != MDR_FAIL) {
			close(cfd);
			break;
		}

		close(cfd);
		xlog_strerror(LOG_ERR, errno, "umdr_unpack");
	}
	close(lsock6);
	if (lsock4 >= 0)
		close(lsock4);
	if (try == 0) {
		XERRF(e, XLOG_APP, XLOG_IO, "%s: we never got a challenge "
		    "from the authority", __func__);
		return NULL;
	}

	/*
	 * Send the challenge back to the authority.
	 */
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = uv[1].v.s.bytes;
	pv[0].v.b.sz = uv[1].v.s.sz;
	if (pmdr_pack(&pm, msg_bootstrap_answer_challenge,
	    pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "pmdr_pack/msg_bootstrap_dialin");
		return NULL;
	}
	if (agent_send(&pm, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	if ((r = agent_recv(ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_init");
		return NULL;
	}

	if (umdr_dcv(&um) == MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP_FAILED) {
		XERRF(e, XLOG_APP, XLOG_BADMSG, "failed challenge");
		return NULL;
	} else if (umdr_dcv(&um) != MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN_RESP) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "unknown message from authority");
		return NULL;
	}

	/*
	 * We passed the challenge, send our REQ.
	 */
	if (agent_new_req(subject, &req_buf, &req_len, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
	pv[0].type = MDR_B;
	pv[0].v.b.bytes = req_buf;
	pv[0].v.b.sz = req_len;
	if (pmdr_pack(&pm, msg_bootstrap_req, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_pack/msg_bootstrap_req");
		return NULL;
	}
	if (agent_send(&pm, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	/*
	 * Finally, we get the cert back.
	 */
	if ((r = agent_recv(ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}
	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_init");
		return NULL;
	}
	if (umdr_dcv(&um) == MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_RESP_FAILED) {
		if (umdr_unpack(&um, msg_bootstrap_req_resp_failed,
		    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
			XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
			return NULL;
		}
		XERRF(e, XLOG_APP, XLOG_BADMSG, "signing REQ failed: %s",
		    uv[1].v.s.bytes);
		return NULL;
	} else if (umdr_dcv(&um) != MDR_DCV_CERTALATOR_BOOTSTRAP_REQ_RESP) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "unknown message from authority");
		return NULL;
	}
	if (umdr_unpack(&um, msg_bootstrap_req_resp, uv, UMDRVECLEN(uv))
	    == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "umdr_unpack/msg_bootstrap_req_resp");
		return NULL;
	}

	crt = d2i_X509(NULL, (const unsigned char **)&uv[1].v.b.bytes,
	    uv[1].v.b.sz);
        if (crt == NULL) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap reply did not contain a valid "
		    "DER-encoded X.509");
		return NULL;
        }

	f = fopen(certalator_conf.cert_file, "w");
	if (PEM_write_X509(f, crt) == 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
		return NULL;
	}
	if (fflush(f) != 0) {
		XERRF(e, XLOG_ERRNO, errno, "fflush");
		return NULL;
	}
	rewind(f);

	return f;
}

static int
load_crl(const char *crl_path, struct xerr *e)
{
	X509_CRL *crl;
	FILE     *f;

	if ((f = fopen(crl_path, "r")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen: %s", crl_path);

	if ((crl = PEM_read_X509_CRL(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		return XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509_CRL");
	}

	fclose(f);

	if (!X509_STORE_add_crl(store, crl))
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_STORE_add_crl");
	return 0;
}

int
agent_load_keys(struct xerr *e)
{
	FILE          *f;
	DIR           *d;
	struct dirent *de;
	int            de_len;
	char           crl_path[PATH_MAX + NAME_MAX + 1];
#ifndef __OpenBSD__
	int            pkey_sz;
#endif
	if ((f = fopen(certalator_conf.key_file, "r")) == NULL) {
		if (errno == ENOENT) {
			xlog(LOG_WARNING, NULL,
			    "no private key found, generating one");
			f = cert_new_privkey(xerrz(e));
			if (f == NULL)
				return XERR_PREPENDFN(e);
		} else
			return XERRF(e, XLOG_ERRNO, errno, "fopen");
	}
	if ((key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "PEM_read_PrivateKey");
	}
	fclose(f);

#ifndef __OpenBSD__
	if (!(pkey_sz = EVP_PKEY_size(key))) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "EVP_PKEY_size");
		goto fail;
	}

	/* pledge() doesn't allow mlock() */
	if (mlock(key, pkey_sz) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "mlock");
#endif
	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_STORE_set_flags");
		goto fail;
	}

	if ((f = fopen(certalator_conf.ca_file, "r")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen");
		goto fail;
	}

	if ((ca_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509");
		goto fail;
	}
	fclose(f);
	if (!X509_STORE_add_cert(store, ca_crt)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_add_cert");
		goto fail;
	}

	if (*certalator_conf.crl_file != '\0') {
		if (load_crl(certalator_conf.crl_file, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			goto fail;
		}
	}
	if (*certalator_conf.crl_path != '\0') {
		if ((d = opendir(certalator_conf.crl_path)) == NULL) {
			XERRF(e, XLOG_ERRNO, errno, "opendir");
			goto fail;
		}

		for (;;) {
			errno = 0;
			de = readdir(d);
			if (de == NULL) {
				if (errno == 0)
					break;
				XERRF(e, XLOG_ERRNO, errno, "readdir");
				goto fail;
			}
			if (de->d_type != DT_REG)
				continue;
			de_len = strlen(de->d_name);
			if (strcmp(de->d_name + (de_len - 4), ".crl") != 0)
				continue;

			snprintf(crl_path, sizeof(crl_path), "%s/%s",
			    certalator_conf.crl_path, de->d_name);
			if (load_crl(crl_path, xerrz(e)) == -1) {
				XERR_PREPENDFN(e);
				goto fail;
			}
		}
		closedir(d);
	}

	if ((f = fopen(certalator_conf.cert_file, "r")) == NULL) {
		if (errno != ENOENT) {
			XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
			    certalator_conf.cert_file);
			goto fail;
		}
		f = agent_bootstrap2(e);
		if (f == NULL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
	}
	if ((cert = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509");
		goto fail;
	}
	fclose(f);

	if (!X509_STORE_add_cert(store, cert)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_add_cert");
		goto fail;
	}

	is_authority = cert_has_role(cert, ROLE_AUTHORITY, xerrz(e));
	if (is_authority == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	/*
	 * We're not calling X509_LOOKUP_free() as this causes a segfault
	 * if we try reusing X509_LOOKUP_file().
	 */
	return 0;
fail:
	agent_cleanup();
	return -1;
}

void
agent_cleanup()
{
	if (ca_crt != NULL) {
		X509_free(ca_crt);
		ca_crt = NULL;
	}
	if (cert != NULL) {
		X509_free(cert);
		cert = NULL;
	}
	if (key != NULL) {
		EVP_PKEY_free(key);
		key = NULL;
	}
	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
}

X509 *
agent_cert()
{
	return cert;
}

EVP_PKEY *
agent_key()
{
	return key;
}

X509_STORE *
agent_cert_store()
{
	return store;
}

