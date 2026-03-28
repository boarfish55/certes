#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include "agent.h"
#include "certalator.h"
#include "cert.h"
#include "certdb.h"
#include "mdr.h"
#include "xlog.h"
#include "util.h"

static EVP_PKEY    *key = NULL;
static X509        *cert = NULL;
static int          is_authority = 0;
static X509_STORE  *store;
static SSL_CTX     *ssl_ctx = NULL;
static uint64_t     next_authop_id = 1;

static struct timespec last_authop_purge = {0, 0};
static struct timespec last_certdb_purge = {0, 0};
static struct timespec last_cert_check = {0, 0};
static int             agent_fd = -1;
static int             cert_fetch_in_progress = 0;

extern struct certalator_flatconf certalator_conf;

enum authop_type {
	AUTHOP_BOOTSTRAP_SETUP = 1,
	AUTHOP_BOOTSTRAP,
	AUTHOP_CERT_RENEW
};

struct authop {
	char              id[CERTALATOR_AUTHOP_ID_LENGTH];
	enum authop_type  type;
	BIO              *bio;
	struct timespec   created_at;

	SPLAY_ENTRY(authop) entries;
};

static int
authop_cmp(struct authop *a1, struct authop *a2)
{
	return strcmp(a1->id, a2->id);
}

SPLAY_HEAD(authop_tree, authop) authops = SPLAY_INITIALIZER(&authops);
SPLAY_PROTOTYPE(authop_tree, authop, entries, authop_cmp);
SPLAY_GENERATE(authop_tree, authop, entries, authop_cmp);

struct client {
	int     fd;
	void   *in_buf;
	size_t  in_buf_used;
	size_t  in_buf_sz;
	void   *out_buf;
	size_t  out_buf_used;
	size_t  out_buf_sz;

	SPLAY_ENTRY(client) entries;
};

static int
client_cmp(struct client *c1, struct client *c2)
{
	return c1->fd - c2->fd;
}

SPLAY_HEAD(client_tree, client) clients = SPLAY_INITIALIZER(&clients);
SPLAY_PROTOTYPE(client_tree, client, entries, client_cmp);
SPLAY_GENERATE(client_tree, client, entries, client_cmp);

static int client_tree_sz = 0;

static void
client_free(struct client *c)
{
	free(c->in_buf);
	free(c->out_buf);
	free(c);
	client_tree_sz--;
}

static int            agent_bootstrap(struct xerr *);
static int            agent_cert_renew_inquiry(struct xerr *);
static int            agent_bootstrap_dialback(struct umdr *, struct xerr *);
static int            agent_cert_renew_dialback(struct umdr *, struct xerr *);
static int            agent_recv_cert(struct authop *, struct xerr *);
static void           purge_authops();
static int            agent_connect(struct xerr *);
static void           agent_tasks();
static int            agent_run(int, struct xerr *);
static struct authop *authop_new(enum authop_type, struct xerr *);
static void           authop_free(struct authop *);
static int            authop_send(struct authop *, const void *, size_t,
                          struct xerr *);
static int            authop_recv(struct authop *, char *, size_t,
                          struct xerr *);
static int            load_crl(const char *, struct xerr *);
static void           bootstrap_setup_usage();
static int            agent_error(struct umdr *, struct xerr *);


static void
purge_authops()
{
	struct timespec  now;
	struct authop   *op, *next;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/* We only purge every minute */
	if (now.tv_sec - last_authop_purge.tv_sec <= 60)
		return;

	for (op = SPLAY_MIN(authop_tree, &authops); op != NULL; op = next) {
		next = SPLAY_NEXT(authop_tree, &authops, op);
		if (now.tv_sec - op->created_at.tv_sec > 60)
			authop_free(op);
	}

	clock_gettime(CLOCK_MONOTONIC, &last_authop_purge);
}

static int
agent_connect(struct xerr *e)
{
	int                fd;
	struct sockaddr_un saddr;
	struct timespec    tp = {1, 0};
	int                try;

	if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "socket");

	for (try = 0; try < 5 && agent_fd == -1; try++) {
		bzero(&saddr, sizeof(saddr));
		saddr.sun_family = AF_LOCAL;
		strlcpy(saddr.sun_path, certalator_conf.agent_sock_path,
		    sizeof(saddr.sun_path));

		if (connect(fd, (struct sockaddr *)&saddr,
		    sizeof(saddr)) == -1) {
			if (errno != ENOENT && errno != ECONNREFUSED)
				return XERRF(e, XLOG_ERRNO, errno, "connect");

			if (agent_start(xerrz(e)) == -1) {
				if (errno != EWOULDBLOCK)
					return XERR_PREPENDFN(e);
			}
			nanosleep(&tp, NULL);
			continue;
		}

		agent_fd = fd;
	}

	xlog(LOG_NOTICE, NULL, "%s: connected to backend agent", __func__);
	return 0;
}

static void
agent_tasks()
{
	struct timespec now;
	struct xerr     e;

	/*
	 * Tasks must be quick, unless it's one of bootstrap or cert
	 * renewal.
	 */
	purge_authops();

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (is_authority) {
		if (now.tv_sec > last_certdb_purge.tv_sec + 300) {
			memcpy(&last_certdb_purge, &now, sizeof(now));
			if (certdb_clean_expired_certs(xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
			if (certdb_clean_expired_bootstraps(xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
		}

		// TODO: need a CRL regen task

		return;
	}

	/*
	 * Non-authority tasks only from this point on.
	 */
	//if (now.tv_sec < last_cert_check.tv_sec + 600)
	if (now.tv_sec < last_cert_check.tv_sec + 30)
		return;
	memcpy(&last_cert_check, &now, sizeof(now));

	if (cert_is_selfsigned(cert)) {
		if (agent_bootstrap(xerrz(&e)) == -1)
			xlog(LOG_ERR, &e, "%s", __func__);
	} else {
		if (agent_cert_renew_inquiry(xerrz(&e)) == -1)
			xlog(LOG_ERR, &e, "%s", __func__);
	}

	// TODO: need a CRL refresh task
}

static int
agent_run(int lsock, struct xerr *e)
{
	struct pollfd *fds;
	int            ready, i;
	int            fd, nfds, fds_sz = 32;
	struct client *c, needle;
	ssize_t        r;
	struct umdr    um;
	uint64_t       um_sz;
	void          *tmp;

	if ((fds = malloc(sizeof(struct pollfd) * fds_sz)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	for (;;) {
		fds[0].fd = lsock;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		nfds = 1;
		SPLAY_FOREACH(c, client_tree, &clients) {
			fds[nfds].fd = c->fd;
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}

		if ((ready = poll(fds, nfds, 1000)) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "poll");
			goto fail;
		}

		if (ready == 0) {
			if (getppid() == 1) {
				xlog(LOG_NOTICE, NULL, "%s: parent exited, so "
				    "we will too", __func__);
				return 0;
			}

			/* Run background tasks when we're idle */
			agent_tasks();
			continue;
		}

		for (i = 0; i < nfds; i++) {
			if (fds[i].revents == 0)
				continue;

			if (fds[i].revents & POLLERR) {
				xlog(LOG_ERR, NULL, "%s: fd %d error", __func__,
				    fds[i].fd);
				close(fds[i].fd);
				if (fds[i].fd == lsock) {
					xlog(LOG_ERR, NULL, "%s: lsock %d "
					    "closed unexpectedly", __func__,
					    lsock);
					_exit(1);
				}

				needle.fd = fds[i].fd;
				c = SPLAY_FIND(client_tree, &clients, &needle);
				if (c != NULL) {
					SPLAY_REMOVE(client_tree, &clients, c);
					client_free(c);
				}

				continue;
			}

			/* Handle our listening socket for new clients. */
			if (fds[i].fd == lsock &&
			    fds[i].revents & POLLIN) {
				if (client_tree_sz >= fds_sz) {
					tmp = realloc(fds, client_tree_sz + 32);
					if (tmp == NULL) {
						xlog_strerror(LOG_ERR, errno,
						    "%s: realloc", __func__);
						continue;
					}
					fds = tmp;
					fds_sz = client_tree_sz + 32;
				}

				fd = accept(lsock, NULL, 0);
				if (fd == -1) {
					if (errno != EAGAIN && errno != EINTR)
						xlog_strerror(LOG_ERR, errno,
						    "%s: accept", __func__);
					continue;
				}
				c = malloc(sizeof(struct client));
				if (c == NULL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: malloc", __func__);
					continue;
				}
				c->fd = fd;
				c->in_buf_sz = 4096;
				c->out_buf_sz = 4096;
				c->in_buf_used = 0;
				c->out_buf_used = 0;
				c->in_buf = malloc(c->in_buf_sz);
				if (c->in_buf == NULL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: malloc", __func__);
					free(c);
					continue;
				}
				c->out_buf = malloc(c->out_buf_sz);
				if (c->out_buf == NULL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: malloc", __func__);
					free(c->in_buf);
					free(c);
					continue;
				}
				SPLAY_INSERT(client_tree, &clients, c);
				client_tree_sz++;
				continue;
			}

			/* Any other event is communication from clients. */
			needle.fd = fds[i].fd;
			c = SPLAY_FIND(client_tree, &clients, &needle);
			if (c == NULL) {
				close(fds[i].fd);
				xlog(LOG_ERR, NULL, "%s: client fd %d not "
				    "found; closing", __func__, fds[i].fd);
				continue;
			}

			r = read(c->fd, c->in_buf + c->in_buf_used,
			    c->in_buf_sz - c->in_buf_used);
			if (r <= 0) {
				if (r == -1)
					xlog(LOG_ERR, NULL, "%s: fd %d read "
					    "error; closing", __func__, c->fd);
				close(c->fd);
				SPLAY_REMOVE(client_tree, &clients, c);
				client_free(c);
				continue;
			}
			c->in_buf_used += r;

			if (umdr_init(&um, c->in_buf, c->in_buf_used,
			    MDR_FNONE) == MDR_FAIL) {
				if (errno == EAGAIN)
					continue;
				xlog_strerror(LOG_ERR, errno,
				    "%s: umdr_init failed on fd %d; "
				    "closing", __func__, c->fd);
				close(c->fd);
				SPLAY_REMOVE(client_tree, &clients, c);
				client_free(c);
				continue;
			}

			if (umdr_size(&um) > c->in_buf_sz) {
				tmp = realloc(c->in_buf, umdr_size(&um));
				if (tmp == NULL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: realloc failed on fd %d; "
					    "closing", __func__, c->fd);
					close(c->fd);
					SPLAY_REMOVE(client_tree, &clients, c);
					client_free(c);
					continue;
				}
				c->in_buf = tmp;
				c->in_buf_sz = umdr_size(&um);
			}

			if (umdr_pending(&um) > 0)
				continue;

			switch (umdr_dcv(&um)) {
			case MDR_DCV_MDR_ERROR:
				if (agent_error(&um, xerrz(e)) == MDR_FAIL)
					xlog(LOG_ERR, e, "%s", __func__);
				break;
			case MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK:
				if (agent_bootstrap_dialback(&um, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e, "%s", __func__);
				break;
			case MDR_DCV_CERTALATOR_CERT_RENEW_DIALBACK:
				if (agent_cert_renew_dialback(&um, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e, "%s", __func__);
				break;
			default:
				xlog(LOG_ERR, NULL, "%s: unknown message %lu",
				    __func__, umdr_dcv(&um));
			}

			um_sz = umdr_size(&um);
			memmove(c->in_buf, c->in_buf + um_sz,
			    c->in_buf_used - um_sz);
			c->in_buf_used -= um_sz;
		}
	}
	free(fds);
	return 0;
fail:
	SPLAY_FOREACH(c, client_tree, &clients) {
		SPLAY_REMOVE(client_tree, &clients, c);
		client_free(c);
	}
	free(fds);
	return -1;
}

static struct authop *
authop_new(enum authop_type type, struct xerr *e)
{
	char            host[302];
	int             fd;
	struct timeval  timeout;
	SSL            *ssl = NULL;
	struct authop  *op;
	int             authority, caproxy;
	X509           *peer_crt;

	if ((op = malloc(sizeof(struct authop))) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "malloc");
		return NULL;
	}
	bzero(op, sizeof(*op));

	if (certalator_conf.authority_fqdn[0] == '\0') {
		XERRF(e, XLOG_APP, XLOG_EDESTADDRREQ,
		    "no destination address was specified");
		goto fail;
	}

	if (snprintf(host, sizeof(host), "%s:%llu",
	    certalator_conf.authority_fqdn,
	    certalator_conf.authority_port) >= sizeof(host)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "resulting host:port is too long");
		goto fail;
	}

	if ((op->bio = BIO_new_ssl_connect(ssl_ctx)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new_ssl_connect");
		goto fail;
	}

	BIO_get_ssl(op->bio, &ssl);
	if (ssl == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_get_ssl");
		goto fail;
	}

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	BIO_set_conn_hostname(op->bio, host);

	if (BIO_do_connect(op->bio) <= 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_do_connect");
		goto fail;
	}

	timeout.tv_sec = certalator_conf.agent_send_timeout_ms / 1000;
	timeout.tv_usec = certalator_conf.agent_send_timeout_ms % 1000;
	fd = BIO_get_fd(op->bio, NULL);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto fail;
	}

	timeout.tv_sec = certalator_conf.agent_recv_timeout_ms / 1000;
	timeout.tv_usec = certalator_conf.agent_recv_timeout_ms % 1000;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto fail;
	}

	if (BIO_do_handshake(op->bio) <= 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_do_handshake");
		goto fail;
	}

#ifdef __OpenBSD__
	peer_crt = SSL_get_peer_certificate(ssl);
#else
	peer_crt = SSL_get1_peer_certificate(ssl);
#endif
	if (peer_crt == NULL) {
		XERRF(e, XLOG_APP, XLOG_FAIL, "no peer cert");
		goto fail;
	}
	authority = cert_has_role(peer_crt, ROLE_AUTHORITY, xerrz(e));
	if (authority == -1) {
		X509_free(peer_crt);
		XERR_PREPENDFN(e);
		goto fail;
	}
	caproxy = cert_has_role(peer_crt, ROLE_CAPROXY, xerrz(e));
	if (caproxy == -1) {
		X509_free(peer_crt);
		XERR_PREPENDFN(e);
		goto fail;
	}
	X509_free(peer_crt);
	if (!authority && !caproxy) {
		XERRF(e, XLOG_APP, XLOG_ACCES,
		    "peer is neither a caproxy or valid authority");
		goto fail;
	}

	op->type = type;
	clock_gettime(CLOCK_MONOTONIC, &op->created_at);
	if (snprintf(op->id, sizeof(op->id), "%llu-%lld.%lu",
	    next_authop_id, op->created_at.tv_sec, op->created_at.tv_nsec)
	    >= sizeof(op->id)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "resulting authop id too long; this is a bug");
		goto fail;
	}
	next_authop_id++;

	SPLAY_INSERT(authop_tree, &authops, op);

	return op;
fail:
	BIO_free(op->bio);
	free(op);
	return NULL;
}

static void
authop_free(struct authop *op)
{
	SPLAY_REMOVE(authop_tree, &authops, op);
	if (op->type == AUTHOP_BOOTSTRAP || op->type == AUTHOP_CERT_RENEW)
		cert_fetch_in_progress = 0;
	BIO_flush(op->bio);
	BIO_free_all(op->bio);
	free(op);
}

static int
authop_send(struct authop *op, const void *buf, size_t sz, struct xerr *e)
{
	int r;
	if ((r = BIO_write(op->bio, buf, sz)) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	else if (r < sz)
		return XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");
	return 0;
}

static int
authop_recv(struct authop *op, char *buf, size_t buf_sz, struct xerr *e)
{
	int  r, ecode;

	errno = 0;
	if ((r = mdr_buf_from_BIO(op->bio, buf, buf_sz)) < 1) {
		ecode = ERR_get_error();
		return XERRF(e, XLOG_SSL,
		    (ecode == 0) ? errno : ecode, "BIO_read");
	}
	return r;
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
	X509_CRL_free(crl);
	return 0;
}

/*
 * Process errors from the authority
 */
static int
agent_error(struct umdr *msg, struct xerr *e)
{
	struct authop   *op;
	struct authop    needle;
	struct umdr_vec  uv[2];

	if (umdr_unpack(msg, msg_error, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");

	strlcpy(needle.id, uv[0].v.s.bytes, sizeof(needle.id));
	op = SPLAY_FIND(authop_tree, &authops, &needle);
	if (op == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOENT,
		    "no such authop found: %s", needle.id);

	xlog(LOG_ERR, NULL, "%s: %s (op type %d)",
	    __func__, uv[1].v.s.bytes, op->type);

	authop_free(op);
	return 0;
}

/*
 * Contact the authority to send our bootstrap key in order to obtain
 * a challenge so we can send our REQ.
 */
static int
agent_bootstrap(struct xerr *e)
{
	struct pmdr          pm;
	struct pmdr_vec      pv[3];
	char                 pbuf[CERTALATOR_MAX_MSG_SIZE];
	uint8_t              bootstrap_key[CERTALATOR_BOOTSTRAP_KEY_LENGTH];
	struct authop       *op;
	unsigned char       *req_buf = NULL;
	int                  req_len;
	int                  sockfd;
	struct sockaddr_in6  addr;
	socklen_t            slen = sizeof(addr);
	char                 ip6[INET6_ADDRSTRLEN];
	struct umdr          um;
	char                 ubuf[256];
	struct umdr_vec      uv[3];
	int                  r;

	if (cert_fetch_in_progress)
		return 0;
	cert_fetch_in_progress = 1;

	if (strlen(certalator_conf.bootstrap_key) !=
	    CERTALATOR_BOOTSTRAP_KEY_LENGTH_B64)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "bad bootstrap key format in configuration; bad length");

	if (b64dec(bootstrap_key, sizeof(bootstrap_key),
	    certalator_conf.bootstrap_key) < sizeof(bootstrap_key))
		return XERRF(e, XLOG_ERRNO, errno, "b64dec");

	if ((op = authop_new(AUTHOP_BOOTSTRAP, xerrz(e))) == NULL) {
		cert_fetch_in_progress = 0;
		return XERR_PREPENDFN(e);
	}

	if (BIO_get_fd(op->bio, &sockfd) <= 0) {
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
	if (inet_ntop(addr.sin6_family, &addr, ip6, slen) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "inet_ntop");
		goto fail;
	}
	if (cert_new_selfreq(key, X509_get_subject_name(cert), ip6, &req_buf,
	    &req_len, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op->id;
	pv[1].type = MDR_B;
	pv[1].v.b.bytes = bootstrap_key;
	pv[1].v.b.sz = sizeof(bootstrap_key);
	pv[2].type = MDR_B; /* REQ bytes */
	pv[2].v.b.bytes = req_buf;
	pv[2].v.b.sz = req_len;
	if (pmdr_pack(&pm,  msg_bootstrap_dialin, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "pmdr_pack/msg_bootstrap_dialin");
		goto fail;
	}

	if (authop_send(op, pmdr_buf(&pm), pmdr_size(&pm), xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if ((r = authop_recv(op, ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}
	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_CERTALATOR_OK:
		break;
	case MDR_DCV_CERTALATOR_ERROR:
		if (umdr_unpack(&um, msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[2].v.s.bytes, uv[1].v.u32);
		goto fail;
	default:
		XERRF(e, XLOG_APP, XLOG_BADMSG, "bad response from authority");
		goto fail;
	}

	xlog(LOG_INFO, NULL, "%s: awaiting challenge for authop id %s",
	    __func__, op->id);
	return 0;
fail:
	authop_free(op);
	return -1;
}

static int
agent_cert_renew_inquiry(struct xerr *e)
{
	struct pmdr          pm;
	struct pmdr_vec      pv[1];
	char                 pbuf[CERTALATOR_MAX_MSG_SIZE];
	struct authop       *op;
	struct umdr          um;
	char                 ubuf[256];
	struct umdr_vec      uv[3];
	int                  r;

	if (cert_fetch_in_progress)
		return 0;
	cert_fetch_in_progress = 1;

	if ((op = authop_new(AUTHOP_CERT_RENEW, xerrz(e))) == NULL) {
		cert_fetch_in_progress = 0;
		return XERR_PREPENDFN(e);
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op->id;
	if (pmdr_pack(&pm,  msg_cert_renewal_inquiry, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "pmdr_pack/msg_cert_renewal_inquiry");
		goto fail;
	}

	if (authop_send(op, pmdr_buf(&pm), pmdr_size(&pm), xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if ((r = authop_recv(op, ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}
	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_CERTALATOR_OK:
		/*
		 * No renewal required, cancel the op.
		 */
		authop_free(op);
		break;
	case MDR_DCV_CERTALATOR_CERT_RENEWAL_REQUIRED:
		break;
	case MDR_DCV_CERTALATOR_ERROR:
		if (umdr_unpack(&um, msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[2].v.s.bytes, uv[1].v.u32);
		goto fail;
	default:
		XERRF(e, XLOG_APP, XLOG_BADMSG, "bad response from authority");
		goto fail;
	}

	return 0;
fail:
	authop_free(op);
	return -1;
}

/*
 * Process a dialback from the authority
 */
static int
agent_bootstrap_dialback(struct umdr *msg, struct xerr *e)
{
	struct umdr_vec  uv[3];
	struct pmdr      pm;
	char             pbuf[CERTALATOR_MAX_MSG_SIZE];
	struct pmdr_vec  pv[2];
	struct authop   *op;
	struct authop    needle;

	if (umdr_unpack(msg, msg_bootstrap_dialback, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno,
		    "umdr_unpack/msg_bootstrap_dialback");

	strlcpy(needle.id, uv[0].v.s.bytes, sizeof(needle.id));
	op = SPLAY_FIND(authop_tree, &authops, &needle);
	if (op == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOENT,
		    "no such authop found: %s", needle.id);

	if (op->type != AUTHOP_BOOTSTRAP)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "authop %s is not a bootstrap request", op->id);

	xlog(LOG_INFO, NULL, "%s: authop id %s received",
	    __func__, op->id);

	/*
	 * Send the REQ+challenge to the authority.
	 */
	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S; /* Operation ID */
	pv[0].v.s = op->id;
	pv[1].type = MDR_B; /* Challenge */
	pv[1].v.b.bytes = uv[1].v.b.bytes;
	pv[1].v.b.sz = uv[1].v.b.sz;
	if (pmdr_pack(&pm, msg_bootstrap_answer, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "mdr_pack/msg_bootstrap_answer");
		goto fail;
	}
	if (authop_send(op, pmdr_buf(&pm), pmdr_size(&pm), xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (agent_recv_cert(op, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	authop_free(op);
	return 0;
fail:
	authop_free(op);
	return -1;
}

static int
agent_recv_cert(struct authop *op, struct xerr *e)
{
	struct umdr      um;
	char             ubuf[CERTALATOR_MAX_MSG_SIZE];
	struct umdr_vec  uv[3];
	int              r;
	X509            *crt = NULL, *icrt;
	FILE            *f = NULL;
	const uint8_t   *der_chain, *dp;
	uint64_t         der_chain_sz;
	uint32_t         der_sz;
	char             tmpfile[PATH_MAX];

	if ((r = authop_recv(op, ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_init");
		goto fail;
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_CERTALATOR_SEND_CERT:
		break;
	case MDR_DCV_CERTALATOR_ERROR:
		if (umdr_unpack(&um, msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[2].v.s.bytes, uv[1].v.u32);
		goto fail;
	default:
		XERRF(e, XLOG_APP, XLOG_BADMSG, "bad response from authority");
		goto fail;
	}

	/*
	 * Finally, we get the cert back.
	 */

	if (umdr_unpack(&um, msg_send_cert, uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");
		goto fail;
	}

	if (uv[0].v.s.bytes == NULL || strcmp(op->id, uv[0].v.s.bytes) != 0) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "expected authop %s, got %s", op->id, uv[0].v.s.bytes);
		goto fail;
	}

	crt = d2i_X509(NULL, (const unsigned char **)&uv[1].v.b.bytes,
	    uv[1].v.b.sz);
	if (crt == NULL) {
		XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap reply did not contain a valid "
		    "DER-encoded X.509, or alloc failed");
		goto fail;
	}

	if (snprintf(tmpfile, sizeof(tmpfile), "%s.new",
	    certalator_conf.cert_file) >= sizeof(tmpfile)) {
		XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
		    "temporary cert file name too long");
		goto fail;
	}

	if ((f = fopen(tmpfile, "w")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s", tmpfile);
		goto fail;
	}

	if (PEM_write_X509(f, crt) == 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
		goto fail;
	}

	der_chain = uv[2].v.b.bytes;
	der_chain_sz = uv[2].v.b.sz;

	for (dp = der_chain; dp - der_chain < der_chain_sz; ) {
		der_sz = *(uint32_t *)dp;
		dp += sizeof(uint32_t);
		icrt = d2i_X509(NULL, &dp, der_sz);
		dp += der_sz;
		if (icrt == NULL) {
			XERRF(e, XLOG_APP, XLOG_BADMSG,
			    "bootstrap reply did not contain a valid "
			    "DER-encoded X.509, or alloc failed");
			goto fail;
		}
		if (PEM_write_X509(f, icrt) == 0) {
			X509_free(icrt);
			XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
			goto fail;
		}
	}

	fclose(f);
	f = NULL;

	if (rename(tmpfile, certalator_conf.cert_file) == -1) {
		unlink(tmpfile);
		XERRF(e, XLOG_ERRNO, errno, "rename");
		goto fail;
	}

	xlog(LOG_INFO, NULL, "%s: new cert written", __func__);

	cert = crt;
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
	    certalator_conf.cert_file) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "SSL_CTX_use_certificate_chain_file");
		goto fail;
	}

	return 0;
fail:
	if (crt != NULL)
		X509_free(crt);
	if (f != NULL) {
		fclose(f);
		unlink(tmpfile);
	}
	return -1;
}

/*
 * Process a dialback from the authority
 */
static int
agent_cert_renew_dialback(struct umdr *msg, struct xerr *e)
{
	struct umdr_vec  uv[3];
	struct pmdr      pm;
	char             pbuf[CERTALATOR_MAX_MSG_SIZE];
	struct pmdr_vec  pv[2];
	struct authop   *op;
	struct authop    needle;

	if (umdr_unpack(msg, msg_cert_renew_dialback, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "umdr_unpack/dialback");

	strlcpy(needle.id, uv[0].v.s.bytes, sizeof(needle.id));
	op = SPLAY_FIND(authop_tree, &authops, &needle);
	if (op == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOENT,
		    "no such authop found: %s", needle.id);

	if (op->type != AUTHOP_CERT_RENEW)
		return XERRF(e, XLOG_APP, XLOG_INVAL,
		    "authop %s is not a bootstrap request", op->id);

	xlog(LOG_INFO, NULL, "%s: authop id %s received",
	    __func__, op->id);

	/*
	 * Send the challenge to the authority.
	 */
	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S; /* Operation ID */
	pv[0].v.s = op->id;
	pv[1].type = MDR_B; /* Challenge */
	pv[1].v.b.bytes = uv[1].v.b.bytes;
	pv[1].v.b.sz = uv[1].v.b.sz;
	if (pmdr_pack(&pm, msg_cert_renew_answer, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "mdr_pack/msg_cert_renew_answer");
		goto fail;
	}
	if (authop_send(op, pmdr_buf(&pm), pmdr_size(&pm), xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (agent_recv_cert(op, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	authop_free(op);
	return 0;
fail:
	authop_free(op);
	return -1;
}

static void
bootstrap_setup_usage()
{
	printf("Usage: %s bootstrap-setup [options]\n",
	    CERTALATOR_PROGNAME);
	printf("\t-help        Prints this help\n");
	printf("\t-timeout     Validity of bootstrap entry in "
	    "seconds (default 600)\n");
	printf("\t-cert_expiry Validity of certificate in "
	    "seconds (default 7*86400)\n");
	printf("\t-san         Adds a Subject Alt Name to this "
	    "bootstrap entry\n");
	printf("\t-role        Adds a role to this bootstrap entry\n");
	printf("\t-cn          Sets de CommonName for the entry\n");
}

void
agent_bootstrap_setup_cli(int argc, char **argv)
{
	int               opt, r;
	uint32_t          timeout = 600;
	uint32_t          flags = 0;
	uint32_t          cert_expiry = 7 * 86400;
	char            **roles = NULL;
	size_t            roles_sz = 0;
	char             *cn = NULL;
	char            **sans = NULL;
	size_t            sans_sz = 0;
	struct pmdr       pm;
	struct pmdr_vec   pv[6];
	char              pbuf[1024];
	struct umdr       um;
	struct umdr_vec   uv[2];
	char              ubuf[1024];
	struct xerr       e;
	struct authop    *op;

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			bootstrap_setup_usage();
			exit(0);
		}

		if (strcmp(argv[opt], "-timeout") == 0) {
			opt++;
			if (opt > argc) {
				bootstrap_setup_usage();
				exit(1);
			}
			timeout = atoi(argv[opt]);
			continue;
		}

		if (strcmp(argv[opt], "-cert_expiry") == 0) {
			opt++;
			if (opt > argc) {
				bootstrap_setup_usage();
				exit(1);
			}
			cert_expiry = atoi(argv[opt]);
			continue;
		}

		if (strcmp(argv[opt], "-san") == 0) {
			opt++;
			if (opt > argc) {
				bootstrap_setup_usage();
				exit(1);
			}
			sans = strlist_add(sans, argv[opt]);
			if (sans == NULL)
				err(1, "strlist_add");
			sans_sz++;
			continue;
		}

		if (strcmp(argv[opt], "-cn") == 0) {
			opt++;
			if (opt > argc) {
				bootstrap_setup_usage();
				exit(1);
			}
			cn = argv[opt];
			flags |= CERTDB_BOOTSTRAP_FLAG_SETCN;
			continue;
		}

		if (strcmp(argv[opt], "-role") == 0) {
			opt++;
			if (opt > argc) {
				bootstrap_setup_usage();
				exit(1);
			}
			roles = strlist_add(roles, argv[opt]);
			if (roles == NULL)
				err(1, "strlist_add");
			roles_sz++;
			continue;
		}
	}

	if (agent_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((op = authop_new(AUTHOP_BOOTSTRAP_SETUP, xerrz(&e))) == NULL) {
		xerr_print(&e);
		exit(1);
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = cn;
	pv[1].type = MDR_AS;
	pv[1].v.as.items = (const char **)sans;
	pv[1].v.as.length = sans_sz;
	pv[2].type = MDR_AS;
	pv[2].v.as.items = (const char **)roles;
	pv[2].v.as.length = roles_sz;
	pv[3].type = MDR_U32;
	pv[3].v.u32 = cert_expiry;
	pv[4].type = MDR_U32;
	pv[4].v.u32 = timeout;
	pv[5].type = MDR_U32;
	pv[5].v.u32 = flags;
	if (pmdr_pack(&pm, msg_bootstrap_setup, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		err(1, "pmdr_pack");

	if (authop_send(op, pmdr_buf(&pm), pmdr_size(&pm), xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((r = authop_recv(op, ubuf, sizeof(ubuf), xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		xerr_print(&e);
		exit(1);
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_MDR_OK:
		break;
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&um, mdr_msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "umdr_unpack");
		errx(1, "bootstrap setup failed: %s (%u)",
		    uv[1].v.s.bytes, uv[0].v.u32);
	default:
		errx(1, "bad response from authority");
	}

	free(sans);
	free(roles);
}

int
agent_load_keys(struct xerr *e)
{
	FILE          *f;
	DIR           *d;
	struct dirent *de;
	int            de_len;
	char           crl_path[PATH_MAX + NAME_MAX + 1];
	X509          *ca_crt;
#ifndef __OpenBSD__
	int            pkey_sz;
#endif
	if ((f = fopen(certalator_conf.key_file, "r")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen");
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
	X509_free(ca_crt);

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
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    certalator_conf.cert_file);
		goto fail;
	}
	if ((cert = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509");
		goto fail;
	}
	fclose(f);

	is_authority = cert_has_role(cert, ROLE_AUTHORITY, xerrz(e));
	if (is_authority == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	/*
	 * Authorities need their own cert to the store, as well as all
	 * other authorities, so they can validate the clients they signed.
	 */
	if (is_authority) {
		// TODO: need to add other authorities too...
		if (!X509_STORE_add_cert(store, cert)) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_STORE_add_cert");
			goto fail;
		}
	}

	if ((ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");
		goto fail;
	}

	SSL_CTX_set_security_level(ssl_ctx, 3);
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_cert_store(ssl_ctx, store);

	if (SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_CTX_use_PrivateKey");
		goto fail;
	}

	if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
	    certalator_conf.cert_file) != 1) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "SSL_CTX_use_certificate_chain_file");
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

int
agent_send(const void *buf, size_t sz, struct xerr *e)
{
	ssize_t r;

	if (agent_fd == -1)
		if (agent_connect(xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

	if ((r = write(agent_fd, buf, sz)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "write on fd %d", agent_fd);
	else if (r < sz)
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "write on fd %d", agent_fd);

	return 0;
}

int
agent_recv(void *buf, size_t buf_sz, struct xerr *e)
{
	if (agent_fd == -1) {
		if (agent_connect(xerrz(e)) == -1)
			xlog(LOG_ERR, e, "%s", __func__);
		/*
		 * If we were disconnected and/or had to restart the
		 * agent, it probably lost state so we'll have to restart
		 * whatever operation we were doing.
		 */
		return XERRF(e, XLOG_ERRNO, EBADF, "agent_fd is -1");
	}

	return mdr_buf_from_fd(agent_fd, buf, buf_sz);
}

int
agent_start(struct xerr *e)
{
	pid_t              pid;
	char               pid_line[32];
	int                lock_fd, null_fd;
	int                lsock, lsock_flags;
	struct sockaddr_un saddr;

	if ((lock_fd = open(certalator_conf.lock_file,
	    O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "open: %s",
		    certalator_conf.lock_file);

	if (flock(lock_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			close(lock_fd);
			return XERRF(e, XLOG_ERRNO, errno,
			    "lock file %s is already locked; "
			    "is another instance running?",
			    certalator_conf.lock_file);
		}
		close(lock_fd);
		return XERRF(e, XLOG_ERRNO, errno, "flock");
	}

	if ((pid = fork()) == -1) {
		close(lock_fd);
		return XERRF(e, XLOG_ERRNO, errno, "fork");
	} else if (pid != 0) {
		close(lock_fd);
		if (agent_init(xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
		xlog(LOG_NOTICE, NULL, "%s: finished initialization; we are "
		    "%san authority", __func__, (is_authority) ? "" : "not ");
		return 0;
	}

	if (agent_init(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	chdir("/");

	if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: open /dev/null", __func__);
		_exit(1);
	}

	dup2(null_fd, STDIN_FILENO);
	dup2(null_fd, STDOUT_FILENO);
	dup2(null_fd, STDERR_FILENO);
	if (null_fd > 2)
		close(null_fd);

	if (xlog_init(CERTALATOR_AGENT_PROGNAME, NULL, NULL, 0) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: xlog_init", __func__);
		_exit(1);
	}

	if (setsid() == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: setsid", __func__);
		_exit(1);
	}

	setproctitle("agent");

	xlog(LOG_NOTICE, NULL, "%s: initialized", __func__);

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(lock_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: write", __func__);
		_exit(1);
	}
	if (fsync(lock_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fsync", __func__);
		_exit(1);
	}

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sock", __func__);
		_exit(1);
	}
	unlink(certalator_conf.agent_sock_path);

	if (fcntl(lsock, F_SETFD, FD_CLOEXEC) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fcntl", __func__);
		_exit(1);
	}
	if ((lsock_flags = fcntl(lsock, F_GETFL, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fcntl", __func__);
		_exit(1);
	}
	if (fcntl(lsock, F_SETFL, lsock_flags | O_NONBLOCK) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fcntl", __func__);
		_exit(1);
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, certalator_conf.agent_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: bind", __func__);
		_exit(1);
	}

	if (listen(lsock, 64) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: listen", __func__);
		_exit(1);
	}

	if (agent_run(lsock, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, "%s", __func__);
		_exit(1);
	}

	_exit(0);
}
