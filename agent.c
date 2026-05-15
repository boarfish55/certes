/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include <mdr/mdr.h>
#include <mdr/xlog.h>
#include <mdr/util.h>
#include "agent.h"
#include "certes.h"
#include "cert.h"
#include "certdb.h"
#include "util.h"

static EVP_PKEY    *key = NULL;
static X509        *cert = NULL;
static int          is_authority = 0;
static X509_STORE  *store = NULL;
static SSL_CTX     *ssl_ctx = NULL;
static uint64_t     next_authop_id = 1;
static uint64_t     crls_gen = 1;

static struct timespec last_authop_purge = {0, 0};
static struct timespec last_certdb_purge = {0, 0};
static struct timespec next_certdb_backup = {0, 0};
static struct timespec last_cert_check = {0, 0};
static struct timespec last_crl_check = {0, 0};
static int             agent_fd = -1;
static int             cert_fetch_in_progress = 0;

extern struct certes_flatconf certes_conf;

static struct loaded_crls loaded_crls = { 0, NULL, NULL, NULL };

enum authop_type {
	AUTHOP_BOOTSTRAP_SETUP = 1,
	AUTHOP_BOOTSTRAP,
	AUTHOP_CERT_RENEW,
	AUTHOP_CERT_REVOKE,
	AUTHOP_REFRESH_CRLS,
	AUTHOP_CERT_GET,
	AUTHOP_CERT_FIND,
	AUTHOP_ROLE_MOD,
	AUTHOP_ROLE_SAN,
	AUTHOP_SIGN_REQ
};

struct authop {
	char              id[CERTES_AUTHOP_ID_LENGTH];
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

static void           free_loaded_crls();
static int            agent_bootstrap(struct xerr *);
static int            agent_cert_renew_inquiry(struct xerr *);
static int            agent_refresh_crls(const char *, struct xerr *);
static int            agent_bootstrap_dialback(struct umdr *, struct xerr *);
static int            agent_cert_renew_dialback(struct umdr *, struct xerr *);
static int            agent_recv_cert(struct authop *, struct xerr *);
static void           purge_authops();
static int            agent_connect(struct xerr *);
static void           agent_tasks();
static int            agent_run(int, struct xerr *);
static struct authop *authop_new(enum authop_type, const char *, struct xerr *);
static void           authop_free(struct authop *);
static int            authop_send(struct authop *, const void *, size_t,
                          struct xerr *);
static int            authop_recv(struct authop *, char *, size_t,
                          struct xerr *);
static X509_CRL      *load_crl(const char *, struct xerr *);
static void           bootstrap_setup_usage();
static int            agent_error(struct umdr *, struct xerr *);
static int            load_crls(struct xerr *);
static int            agent_init_ctx(struct xerr *);
static int            agent_poll_crls_gen(int, struct xerr *);
static int            agent_regen_crl(struct xerr *);

static int
verify_callback(int ok, X509_STORE_CTX *ctx)
{
	int   e;
	X509 *err_cert;
	char  name[256];

	err_cert = X509_STORE_CTX_get_current_cert(ctx);

	if (!ok) {
		X509_NAME_oneline(X509_get_subject_name(err_cert),
		    name, sizeof(name));
		e = X509_STORE_CTX_get_error(ctx);
		xlog(LOG_NOTICE, NULL, "verify error for %s: %s\n",
		    name, X509_verify_cert_error_string(e));
	}
	return ok;
}

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
		strlcpy(saddr.sun_path, certes_conf.agent_sock_path,
		    sizeof(saddr.sun_path));

		if (connect(fd, (struct sockaddr *)&saddr,
		    sizeof(saddr)) == -1) {
			if (errno != ENOENT && errno != ECONNREFUSED) {
				close(fd);
				return XERRF(e, XLOG_ERRNO, errno, "connect");
			}

			if (agent_start(xerrz(e)) == -1) {
				if (errno != EWOULDBLOCK) {
					close(fd);
					return XERR_PREPENDFN(e);
				}
			}
			nanosleep(&tp, NULL);
		} else {
			xlog(LOG_NOTICE, NULL,
			    "%s: connected to backend agent", __func__);
			agent_fd = fd;
			return 0;
		}
	}

	close(fd);
	return XERRF(e, XLOG_APP, XLOG_FAIL,
	    "no agent to connect to after 5 attempts");
}

static void
agent_tasks()
{
	struct timespec now;
	struct xerr     e;
	int             i;

	/*
	 * Tasks must be quick, unless it's one of bootstrap or cert
	 * renewal.
	 */
	purge_authops();

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (is_authority) {
		if (now.tv_sec > last_certdb_purge.tv_sec + 300) {
			xlog(LOG_DEBUG, NULL, "%s: purging expired certs and "
			    "bootstrap entries", __func__);
			memcpy(&last_certdb_purge, &now, sizeof(now));
			if (certdb_clean_expired_certs(
			    certes_conf.cert_expired_retention_seconds,
			    xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
			if (certdb_clean_expired_bootstraps(xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
		}

		/*
		 * We don't run a backup if the interval is 0.
		 * TODO: add a signal handler, or command, to trigger
		 * a backup.
		 */
		if (certes_conf.certdb_backup_interval_seconds &&
		    *certes_conf.certdb_backup_path != '\0' &&
		    now.tv_sec > next_certdb_backup.tv_sec) {
			xlog(LOG_NOTICE, NULL, "backing up cert DB to %s",
			    certes_conf.certdb_backup_path);
			if (certdb_backup(certes_conf.certdb_backup_path,
			    certes_conf.certdb_backup_pages_per_step,
			    xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
			memcpy(&next_certdb_backup, &now, sizeof(now));
			next_certdb_backup.tv_sec +=
			    certes_conf.certdb_backup_interval_seconds;
		}

		if (now.tv_sec < last_crl_check.tv_sec +
		    certes_conf.crl_reload_interval_seconds)
			return;
		memcpy(&last_crl_check, &now, sizeof(now));
		for (i = 0; certes_conf.peer_authorities != NULL &&
		    certes_conf.peer_authorities[i] != NULL; i++) {
			if (agent_refresh_crls(
			    certes_conf.peer_authorities[i], xerrz(&e)) == -1)
				xlog(LOG_ERR, &e, __func__);
		}

		return;
	}

	/*
	 * Non-authority tasks only from this point on.
	 */
	if (now.tv_sec < last_cert_check.tv_sec +
	    certes_conf.cert_check_interval_seconds)
		return;
	memcpy(&last_cert_check, &now, sizeof(now));

	if (cert_is_selfsigned(cert)) {
		if (agent_bootstrap(xerrz(&e)) == -1)
			xlog(LOG_ERR, &e, __func__);
	} else {
		if (agent_cert_renew_inquiry(xerrz(&e)) == -1)
			xlog(LOG_ERR, &e, __func__);

		if (agent_refresh_crls(NULL, xerrz(&e)) == -1)
			xlog(LOG_ERR, &e, __func__);
	}

}

static int
agent_run(int lsock, struct xerr *e)
{
	struct pollfd *fds;
	int            ready, i;
	int            fd, nfds, fds_sz = 32;
	struct client *c, *next, needle;
	ssize_t        r;
	struct umdr    um;
	uint64_t       um_sz;
	void          *tmp;
	int            status = 0;

	if ((fds = calloc(fds_sz, sizeof(struct pollfd))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "calloc");

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
			status = XERRF(e, XLOG_ERRNO, errno, "poll");
			break;
		}

		if (ready == 0) {
			if (getppid() == 1) {
				xlog(LOG_NOTICE, NULL, "%s: parent exited, so "
				    "we will too", __func__);
				break;
			}

			/* Run background tasks when we're idle */
			agent_tasks();
			continue;
		}

		for (i = 0; i < nfds; i++) {
			if (fds[i].revents == 0)
				continue;

			/* Handle our listening socket for new clients. */
			if (fds[i].fd == lsock) {
				if (client_tree_sz >= fds_sz) {
					tmp = reallocarray(fds,
					    (client_tree_sz + 32),
					    sizeof(struct pollfd));
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
			case MDR_DCV_CERTES_BOOTSTRAP_DIALBACK:
				if (agent_bootstrap_dialback(&um, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e, "%s", __func__);
				break;
			case MDR_DCV_CERTES_CERT_RENEW_DIALBACK:
				if (agent_cert_renew_dialback(&um, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e, "%s", __func__);
				break;
			case MDR_DCV_CERTES_RELOAD_CRLS:
				xlog(LOG_INFO, NULL,
				    "%s: received CRLs reload request",
				    __func__);
				if (agent_regen_crl(xerrz(e)) == MDR_FAIL)
					xlog(LOG_ERR, e, "%s", __func__);
				else
					crls_gen++;
				break;
			case MDR_DCV_CERTES_POLL_CRLS_GEN:
				if (agent_poll_crls_gen(c->fd, xerrz(e))
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
	for (c = SPLAY_MIN(client_tree, &clients); c != NULL; c = next) {
		next = SPLAY_NEXT(client_tree, &clients, c);
		SPLAY_REMOVE(client_tree, &clients, c);
		client_free(c);
	}
	free(fds);
	return status;
}

static struct authop *
authop_new(enum authop_type type, const char *peer, struct xerr *e)
{
	char            host[302], *p;
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

	if (peer == NULL) {
		if (certes_conf.authority_fqdn[0] == '\0') {
			XERRF(e, XLOG_APP, XLOG_INVALID,
			    "no destination address was specified");
			goto fail;
		}
		if (snprintf(host, sizeof(host), "%s:%llu",
		    certes_conf.authority_fqdn,
		    certes_conf.authority_port) >= sizeof(host)) {
			XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "resulting host:port is too long");
			goto fail;
		}
	} else if (strstr(peer, ":") == NULL) {
		if (snprintf(host, sizeof(host), "%s:%llu",
		    peer, certes_conf.authority_port) >= sizeof(host)) {
			XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "resulting host:port is too long");
			goto fail;
		}
	} else
		strlcpy(host, peer, sizeof(host));

	BIO_set_conn_hostname(op->bio, host);
	// TODO: eventually add X509_VERIFY_PARAM_set1_ip_asc for IP-literal
	// targets
	if ((p = strrchr(host, ':')) != NULL)
		*p = '\0';

	if (!SSL_set1_host(ssl, host)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_set1_host");
		goto fail;
	}
	if (!SSL_set_tlsext_host_name(ssl, host)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_set_tlsext_host_name");
		goto fail;
	}

	if (BIO_do_connect(op->bio) <= 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_do_connect");
		goto fail;
	}

	timeout.tv_sec = certes_conf.agent_send_timeout_ms / 1000;
	timeout.tv_usec = certes_conf.agent_send_timeout_ms % 1000;
	fd = BIO_get_fd(op->bio, NULL);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
	    &timeout, sizeof(timeout)) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "setsockopt");
		goto fail;
	}

	timeout.tv_sec = certes_conf.agent_recv_timeout_ms / 1000;
	timeout.tv_usec = certes_conf.agent_recv_timeout_ms % 1000;
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
		XERRF(e, XLOG_APP, XLOG_DENIED,
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
	if (op->bio != NULL)
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

static X509_CRL *
load_crl(const char *crl_path, struct xerr *e)
{
	X509_CRL *crl;
	FILE     *f;

	if ((f = fopen(crl_path, "r")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s", crl_path);
		return NULL;
	}
	if ((crl = PEM_read_X509_CRL(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509_CRL");
		return NULL;
	}
	fclose(f);

	if (!X509_STORE_add_crl(store, crl)) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_add_crl");
		return NULL;
	}
	return crl;
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
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
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
	char                 pbuf[CERTES_MAX_MSG_SIZE];
	uint8_t              bootstrap_key[CERTES_BOOTSTRAP_KEY_LENGTH];
	struct authop       *op;
	unsigned char       *req_buf = NULL;
	int                  req_len;
	int                  sockfd;
	struct sockaddr_in6  addr;
	const char          *in;
	socklen_t            slen = sizeof(addr);
	char                 ip6[INET6_ADDRSTRLEN];
	struct umdr          um;
	char                 ubuf[256];
	struct umdr_vec      uv[3];
	int                  r;

	if (cert_fetch_in_progress)
		return 0;
	cert_fetch_in_progress = 1;

	if (strlen(certes_conf.bootstrap_key) !=
	    CERTES_BOOTSTRAP_KEY_LENGTH_B64)
		return XERRF(e, XLOG_APP, XLOG_INVALID,
		    "bad bootstrap key format in configuration; bad length");

	if (b64dec(bootstrap_key, sizeof(bootstrap_key),
	    certes_conf.bootstrap_key) < sizeof(bootstrap_key))
		return XERRF(e, XLOG_ERRNO, errno, "b64dec");

	if ((op = authop_new(AUTHOP_BOOTSTRAP, NULL, xerrz(e))) == NULL) {
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
	if (addr.sin6_family == AF_INET6)
		in = inet_ntop(AF_INET6, &addr.sin6_addr, ip6, sizeof(ip6));
	else
		in = inet_ntop(AF_INET,
		    &((struct sockaddr_in *)&addr)->sin_addr, ip6, sizeof(ip6));

	if (in == NULL) {
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
	case MDR_DCV_CERTES_OK:
		break;
	case MDR_DCV_CERTES_ERROR:
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

	free(req_buf);
	xlog(LOG_INFO, NULL, "%s: awaiting challenge for authop id %s",
	    __func__, op->id);
	return 0;
fail:
	free(req_buf);
	authop_free(op);
	return -1;
}

static int
agent_cert_renew_inquiry(struct xerr *e)
{
	struct pmdr      pm;
	struct pmdr_vec  pv[1];
	char             pbuf[CERTES_MAX_MSG_SIZE];
	struct authop   *op;
	struct umdr      um;
	char             ubuf[256];
	struct umdr_vec  uv[3];
	int              r;

	if (cert_fetch_in_progress)
		return 0;
	cert_fetch_in_progress = 1;

	if ((op = authop_new(AUTHOP_CERT_RENEW, NULL, xerrz(e))) == NULL) {
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
	case MDR_DCV_CERTES_OK:
		/*
		 * No renewal required, cancel the op.
		 */
		authop_free(op);
		break;
	case MDR_DCV_CERTES_CERT_RENEWAL_REQUIRED:
		break;
	case MDR_DCV_CERTES_ERROR:
		if (umdr_unpack(&um, msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[2].v.s.bytes, uv[1].v.u32);
		goto fail;
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&um, mdr_msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[1].v.s.bytes, uv[0].v.u32);
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

static int
agent_poll_crls_gen(int cfd, struct xerr *e)
{
	struct pmdr     pm;
	struct pmdr_vec pv[1];
	char            pbuf[mdr_spec_base_sz(msg_crls_gen, 0)];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U64;
	pv[0].v.u64 = crls_gen;
	if (pmdr_pack(&pm, msg_crls_gen, pv, PMDRVECLEN(pv)) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, __func__);
		abort();
	}

	if (writeall(cfd, pmdr_buf(&pm), pmdr_size(&pm)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "writeall");

	return 0;
}

static int
agent_refresh_crls(const char *peer_fqdn, struct xerr *e)
{
	struct pmdr      pm;
	struct pmdr_vec  pv[3];
	char             pbuf[CERTES_MAX_MSG_SIZE];
	struct authop   *op;
	struct umdr      um;
	char             ubuf[CERTES_MAX_MSG_SIZE];
	struct umdr_vec  uv[3];
	int              r, i;
	uint32_t         crl_count;
	uint32_t        *crl_sizes = NULL;
	const uint8_t   *p;
	X509_CRL        *crl = NULL;
	X509_NAME       *issuer;
	char             issuer_cn[256];
	char             crl_path[PATH_MAX];
	FILE            *f;
	mode_t           save_umask;

	if ((op = authop_new(AUTHOP_REFRESH_CRLS, peer_fqdn, xerrz(e))) == NULL)
		return XERR_PREPENDFN(e);

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = op->id;
	pv[1].type = MDR_AS;
	pv[1].v.as.items = (const char **)loaded_crls.issuers;
	pv[1].v.as.length = loaded_crls.count;
	pv[2].type = MDR_AU64;
	pv[2].v.au64.items = loaded_crls.last_updates;
	pv[2].v.au64.length = loaded_crls.count;
	if (pmdr_pack(&pm, msg_fetch_outdated_crls, pv,
	    PMDRVECLEN(pv)) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno,
		    "pmdr_pack/msg_fetch_outdated_crls");
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
	case MDR_DCV_CERTES_SEND_UPDATED_CRLS:
		/* Success */
		break;
	case MDR_DCV_CERTES_ERROR:
		if (umdr_unpack(&um, msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[2].v.s.bytes, uv[1].v.u32);
		goto fail;
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&um, mdr_msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL) {
			XERR_PREPENDFN(e);
			goto fail;
		}
		XERRF(e, XLOG_APP, XLOG_FAIL, "authop %s failed with %s (%u)",
		    op->id, uv[1].v.s.bytes, uv[0].v.u32);
		goto fail;
	default:
		XERRF(e, XLOG_APP, XLOG_BADMSG, "bad response from authority");
		goto fail;
	}

	if (umdr_unpack(&um, msg_send_updated_crls, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	crl_count = umdr_vec_alen(&uv[1].v.au32);
	if (crl_count == 0) {
		authop_free(op);
		return 0;
	}

	xlog(LOG_NOTICE, NULL, "%s: %u CRLs to update",
	    __func__, crl_count);

	crl_sizes = calloc(crl_count, sizeof(uint32_t));
	if (crl_sizes == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "calloc");
		goto fail;
	}

	if (umdr_vec_au32(&uv[1].v.au32, crl_sizes, crl_count) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_vec_au32");
		goto fail;
	}

	for (i = 0, p = uv[2].v.b.bytes;
	    i < crl_count && (p - (uint8_t *)uv[2].v.b.bytes) < uv[2].v.b.sz;
	    i++) {
		crl = d2i_X509_CRL(NULL, &p, crl_sizes[i]);
		/* p is incremented */
		if (crl == NULL) {
			XERRF(e, XLOG_APP, XLOG_BADMSG,
			    "reply did not contain a valid "
			    "DER-encoded X.509 CRL, or alloc failed");
			goto fail;
		}

		issuer = X509_CRL_get_issuer(crl);
		if (X509_NAME_get_text_by_NID(issuer, NID_commonName,
		    issuer_cn, sizeof(issuer_cn)) < 0) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_NAME_get_text_by_NID");
			goto fail;
		}

		if (!cert_authority_cn_sane(issuer_cn)) {
			XERRF(e, XLOG_APP, XLOG_INVALID, "authority CN "
			    "contains dubious characters: %s", issuer_cn);
			goto fail;
		}

		if (snprintf(crl_path, sizeof(crl_path), "%s/%s.crl",
		    certes_conf.crl_path, issuer_cn) >= sizeof(crl_path)) {
			XERRF(e, XLOG_APP, XLOG_OVERFLOW,
			    "crl path too long");
			goto fail;
		}

		save_umask = umask(022);
		f = fopen(crl_path, "w");
		umask(save_umask);
		if (f == NULL) {
			XERRF(e, XLOG_ERRNO, errno, "fopen: %s", crl_path);
			goto fail;
		}
		if (PEM_write_X509_CRL(f, crl) == 0) {
			fclose(f);
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "PEM_write_X509_CRL");
			goto fail;
		}
		fclose(f);
		X509_CRL_free(crl);
		xlog(LOG_NOTICE, NULL, "%s: wrote updated CRL from %s",
		    __func__, issuer_cn);
	}
	free(crl_sizes);
	authop_free(op);

	if (load_crls(xerrz(e)) == -1)
		xlog(LOG_ERR, e, "%s");
	crls_gen++;

	return 0;
fail:
	if (crl != NULL)
		X509_CRL_free(crl);
	free(crl_sizes);
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
	char             pbuf[CERTES_MAX_MSG_SIZE];
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
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "no such authop found: %s", needle.id);

	if (op->type != AUTHOP_BOOTSTRAP)
		return XERRF(e, XLOG_APP, XLOG_INVALID,
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
	char             ubuf[CERTES_MAX_MSG_SIZE];
	struct umdr_vec  uv[3];
	int              r;
	X509            *crt = NULL, *icrt;
	FILE            *f = NULL;
	const uint8_t   *der_chain, *dp;
	uint64_t         der_chain_sz;
	uint32_t         der_sz;
	char             tmpfile[PATH_MAX];
	mode_t           save_umask;

	if ((r = authop_recv(op, ubuf, sizeof(ubuf), xerrz(e))) == -1) {
		XERR_PREPENDFN(e);
		goto fail;
	}

	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "umdr_init");
		goto fail;
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_CERTES_SEND_CERT:
		break;
	case MDR_DCV_CERTES_ERROR:
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
		XERRF(e, XLOG_APP, XLOG_INVALID,
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
	    certes_conf.cert_file) >= sizeof(tmpfile)) {
		XERRF(e, XLOG_APP, XLOG_OVERFLOW,
		    "temporary cert file name too long");
		goto fail;
	}

	save_umask = umask(022);
	if ((f = fopen(tmpfile, "w")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s", tmpfile);
		goto fail;
	}
	umask(save_umask);

	if (PEM_write_X509(f, crt) == 0) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_write_X509");
		goto fail;
	}

	der_chain = uv[2].v.b.bytes;
	der_chain_sz = uv[2].v.b.sz;

	for (dp = der_chain; dp - der_chain < der_chain_sz; ) {
		if (der_chain_sz - (dp - der_chain) < sizeof(uint32_t)) {
			XERRF(e, XLOG_APP, XLOG_BADMSG, "corrupted DER chain");
			goto fail;
		}
		memcpy(&der_sz, dp, sizeof(uint32_t));
		der_sz = be32toh(der_sz);
		dp += sizeof(uint32_t);
		if (der_chain_sz - (dp - der_chain) < der_sz) {
			XERRF(e, XLOG_APP, XLOG_BADMSG,
			    "DER size exceeds our byte field length");
			goto fail;
		}
		icrt = d2i_X509(NULL, &dp, der_sz);
		/* dp is incremented */
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
		X509_free(icrt);
	}

	fclose(f);
	f = NULL;

	if (rename(tmpfile, certes_conf.cert_file) == -1) {
		unlink(tmpfile);
		XERRF(e, XLOG_ERRNO, errno, "rename");
		goto fail;
	}

	xlog(LOG_INFO, NULL, "%s: new cert written", __func__);

	X509_free(cert);
	cert = crt;
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
	    certes_conf.cert_file) != 1) {
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
	char             pbuf[CERTES_MAX_MSG_SIZE];
	struct pmdr_vec  pv[2];
	struct authop   *op;
	struct authop    needle;

	if (umdr_unpack(msg, msg_cert_renew_dialback, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "umdr_unpack/dialback");

	strlcpy(needle.id, uv[0].v.s.bytes, sizeof(needle.id));
	op = SPLAY_FIND(authop_tree, &authops, &needle);
	if (op == NULL)
		return XERRF(e, XLOG_APP, XLOG_NOTFOUND,
		    "no such authop found: %s", needle.id);

	if (op->type != AUTHOP_CERT_RENEW)
		return XERRF(e, XLOG_APP, XLOG_INVALID,
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

/*
 * Regen CRL after reinitiating our store/ctx
 */
static int
agent_regen_crl(struct xerr *e)
{
	if (cert != NULL) {
		X509_free(cert);
		cert = NULL;
	}
	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}

	if (agent_init_ctx(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (is_authority) {
		if (!certdb_initialized())
			return XERRF(e, XLOG_APP, XLOG_FAIL,
			    "certdb not initialized");
		if (cert_gen_crl(xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
	}

	if (load_crls(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

/*
 * Reload CRLs after reinitiating our store/ctx
 */
int
agent_reload_crls(struct xerr *e)
{
	if (cert != NULL) {
		X509_free(cert);
		cert = NULL;
	}
	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}

	if (agent_init_ctx(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (load_crls(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

static void
bootstrap_setup_usage()
{
	printf("Usage: %s bootstrap-setup [options]\n",
	    CERTES_PROGNAME);
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
agent_cli_bootstrap_setup(int argc, char **argv)
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
	char              bootstrap_key[CERTES_BOOTSTRAP_KEY_LENGTH_B64 + 1];

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
			sans = strarray_add(sans, argv[opt]);
			if (sans == NULL)
				err(1, "strarray_add");
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
			flags |= CERTDB_BOOTSTRAP_FLAG_SETSUBJECT;
			continue;
		}

		if (strcmp(argv[opt], "-role") == 0) {
			opt++;
			if (opt > argc) {
				bootstrap_setup_usage();
				exit(1);
			}
			roles = strarray_add(roles, argv[opt]);
			if (roles == NULL)
				err(1, "strarray_add");
			roles_sz++;
			continue;
		}
	}

	if (cert_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (agent_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((op = authop_new(AUTHOP_BOOTSTRAP_SETUP, NULL, xerrz(&e))) == NULL) {
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
	case MDR_DCV_CERTES_BOOTSTRAP_SETUP_OK:
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

	if (umdr_unpack(&um, msg_bootstrap_setup_ok,
	    uv, UMDRVECLEN(uv)) == MDR_FAIL)
		err(1, "umdr_unpack");

	if (uv[0].v.b.bytes == NULL)
		errx(1, "bootstrap key is NULL");

	if (b64enc(bootstrap_key, sizeof(bootstrap_key),
	    uv[0].v.b.bytes, uv[0].v.b.sz) == -1)
		err(1, "b64enc");

	printf("%s\n", bootstrap_key);

	free(sans);
	free(roles);
}

static void
sign_req_usage()
{
	printf("Usage: %s sign-req [options] -in <REQ> -out <cert>\n",
	    CERTES_PROGNAME);
	printf("\t-help         Prints this help\n");
	printf("\t-in           Input REQ file name\n");
	printf("\t-out          Output file name for the certificate\n");
	printf("\t-cert_expiry  Validity of certificate in "
	    "seconds (default 7*86400)\n");
	printf("\t-role         Adds a role\n");
	printf("\t-server_auth  Adds serverAuth extended usage\n");
	printf("\t-copy_sans    Copy REQ SANs when signing\n");
}

struct append_san_data {
	char   **sans;
	size_t   sz;
};

static int
append_san(const char *san, void *arg)
{
	struct append_san_data *sd = (struct append_san_data *)arg;

	sd->sans = strarray_add(sd->sans, san);
	if (sd->sans == NULL)
		err(1, "strarray_add");
	sd->sz++;
	return 1;
}

void
agent_cli_sign_req(int argc, char **argv)
{
	int               opt, r;
	uint32_t          cert_expiry = 7 * 86400;
	const char       *out = NULL;
	const char       *in = NULL;
	char            **roles = NULL;
	size_t            roles_sz = 0;
	struct pmdr       pm;
	struct pmdr_vec   pv[6];
	char              pbuf[CERTES_MAX_MSG_SIZE];
	struct umdr       um;
	struct umdr_vec   uv[3];
	char              ubuf[CERTES_MAX_MSG_SIZE];
	struct xerr       e;
	struct authop    *op;
	X509             *crt = NULL, *icrt;
	X509_REQ         *req = NULL;
	FILE             *f = NULL;
	uint8_t          *der = NULL;
	int               der_sz;
	const uint8_t    *der_chain = NULL, *dp;
	uint64_t          der_chain_sz;
	uint32_t          req_flags = 0;
	int               i, copy_sans = 0;

	struct append_san_data sd = { NULL, 0 };

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			sign_req_usage();
			exit(0);
		}

		if (strcmp(argv[opt], "-out") == 0) {
			opt++;
			if (opt > argc) {
				sign_req_usage();
				exit(1);
			}
			out = argv[opt];
			continue;
		}

		if (strcmp(argv[opt], "-in") == 0) {
			opt++;
			if (opt > argc) {
				sign_req_usage();
				exit(1);
			}
			in = argv[opt];
			continue;
		}

		if (strcmp(argv[opt], "-cert_expiry") == 0) {
			opt++;
			if (opt > argc) {
				sign_req_usage();
				exit(1);
			}
			cert_expiry = atoi(argv[opt]);
			continue;
		}

		if (strcmp(argv[opt], "-copy_sans") == 0) {
			if (opt > argc) {
				sign_req_usage();
				exit(1);
			}
			copy_sans = 1;
			continue;
		}

		if (strcmp(argv[opt], "-server_auth") == 0) {
			if (opt > argc) {
				sign_req_usage();
				exit(1);
			}
			req_flags |= CERTES_SIGN_REQ_FSERVERAUTH;
			continue;
		}

		if (strcmp(argv[opt], "-role") == 0) {
			opt++;
			if (opt > argc) {
				sign_req_usage();
				exit(1);
			}
			roles = strarray_add(roles, argv[opt]);
			if (roles == NULL)
				err(1, "strarray_add");
			roles_sz++;
			continue;
		}
	}

	if (in == NULL || out == NULL) {
		sign_req_usage();
		exit(1);
	}

	if ((f = fopen(in, "r")) == NULL)
		err(1, "fopen");

	if ((req = PEM_read_X509_REQ(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if (copy_sans) {
		if (cert_req_foreach_san(req, &append_san, &sd,
		    xerrz(&e)) == -1) {
			xerr_print(&e);
			exit(1);
		}
		printf("Copying SANs:\n");
		for (i = 0; i < sd.sz; i++)
			printf("* %s\n", sd.sans[i]);
	}

	if ((der_sz = i2d_X509_REQ(req, &der)) == -1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (cert_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (agent_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((op = authop_new(AUTHOP_SIGN_REQ, NULL, xerrz(&e))) == NULL) {
		xerr_print(&e);
		exit(1);
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;  /* Op ID */
	pv[0].v.s = op->id;
	pv[1].type = MDR_B;  /* DER-encoded REQ */
	pv[1].v.b.bytes = der;
	pv[1].v.b.sz = der_sz;
	pv[2].type = MDR_U32;
	pv[2].v.u32 = cert_expiry;
	pv[3].type = MDR_AS;
	pv[3].v.as.items = (const char **)roles;
	pv[3].v.as.length = roles_sz;
	pv[4].type = MDR_AS;
	pv[4].v.as.items = (const char **)sd.sans;
	pv[4].v.as.length = sd.sz;
	pv[5].type = MDR_U32;
	pv[5].v.u32 = req_flags;
	if (pmdr_pack(&pm, msg_sign_req, pv, PMDRVECLEN(pv)) == MDR_FAIL)
		err(1, "pmdr_pack");
	free(roles);
	X509_REQ_free(req);
	free(der);

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
	case MDR_DCV_CERTES_SEND_CERT:
		break;
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&um, mdr_msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "umdr_unpack");
		errx(1, "failed: %s (%u)", uv[1].v.s.bytes, uv[0].v.u32);
	case MDR_DCV_CERTES_ERROR:
		if (umdr_unpack(&um, msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "umdr_unpack");
		errx(1, "authop %s failed with %s (%u)",
		    op->id, uv[2].v.s.bytes, uv[1].v.u32);
	default:
		errx(1, "bad response from authority");
	}

	/*
	 * Finally, we get the cert back.
	 */

	if (umdr_unpack(&um, msg_send_cert, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		err(1, "umdr_unpack");

	if (uv[0].v.s.bytes == NULL || strcmp(op->id, uv[0].v.s.bytes) != 0)
		errx(1, "expected authop %s, got %s", op->id, uv[0].v.s.bytes);

	crt = d2i_X509(NULL, (const unsigned char **)&uv[1].v.b.bytes,
	    uv[1].v.b.sz);
	if (crt == NULL)
		errx(1, "sign-req reply did not contain a valid "
		    "DER-encoded X.509, or alloc failed");

	if ((f = fopen(out, "w")) == NULL)
		err(1, "fopen: %s", out);

	if (PEM_write_X509(f, crt) == 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	der_chain = uv[2].v.b.bytes;
	der_chain_sz = uv[2].v.b.sz;

	for (dp = der_chain; dp - der_chain < der_chain_sz; ) {
		if (der_chain_sz - (dp - der_chain) < sizeof(uint32_t))
			errx(1, "corrupted DER chain");
		memcpy(&der_sz, dp, sizeof(uint32_t));
		der_sz = be32toh(der_sz);
		dp += sizeof(uint32_t);
		if (der_chain_sz - (dp - der_chain) < der_sz)
			errx(1, "DER size exceeds our byte field length");

		icrt = d2i_X509(NULL, &dp, der_sz);
		/* dp is incremented */
		if (icrt == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		if (PEM_write_X509(f, icrt) == 0) {
			X509_free(icrt);
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	}

	fclose(f);
	X509_free(crt);
}

static void
revoke_usage()
{
	printf("Usage: %s revoke -serial <serial>\n",
	    CERTES_PROGNAME);
	printf("\t-help        Prints this help\n");
	printf("\t-serial      Serial of the certificate to revoke\n");
}

void
agent_cli_revoke(int argc, char **argv)
{
	int               opt, r;
	char             *serial = NULL;
	struct pmdr       pm;
	struct pmdr_vec   pv[1];
	char              pbuf[1024];
	struct umdr       um;
	struct umdr_vec   uv[3];
	char              ubuf[1024];
	struct xerr       e;
	struct authop    *op;

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			revoke_usage();
			exit(0);
		}

		if (strcmp(argv[opt], "-serial") == 0) {
			opt++;
			if (opt > argc) {
				revoke_usage();
				exit(1);
			}
			serial = argv[opt];
			continue;
		}
	}

	if (serial == NULL) {
		warn("no serial provided");
		revoke_usage();
		exit(1);
	}

	if (cert_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (agent_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((op = authop_new(AUTHOP_CERT_REVOKE, NULL, xerrz(&e))) == NULL) {
		xerr_print(&e);
		exit(1);
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = serial;
	if (pmdr_pack(&pm, msg_revoke, pv, PMDRVECLEN(pv)) == MDR_FAIL)
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
			err(1, "failed to unpack response");
		errx(1, "revoke failed: %s (%u)", uv[1].v.s.bytes, uv[0].v.u32);
	case MDR_DCV_CERTES_ERROR:
		if (umdr_unpack(&um, msg_error, uv, UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "failed to unpack response");
		errx(1, "revoke failed: %s (%u)", uv[2].v.s.bytes, uv[1].v.u32);
	default:
		errx(1, "bad response from authority");
	}
}

static void
cli_update_crls_usage()
{
	printf("Usage: %s update-crls\n", CERTES_PROGNAME);
	printf("\t-help        Prints this help\n");
}

void
agent_cli_update_crls(int argc, char **argv)
{
	int         opt;
	struct xerr e;

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			cli_update_crls_usage();
			exit(0);
		}
	}

	if (cert_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (agent_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (agent_refresh_crls(NULL, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}
}

static void
role_san_usage(int role)
{
	printf("Usage: %s %s -serial <serial> [-add <entry>] [-del <entry>]\n",
	    CERTES_PROGNAME, (role) ? "role" : "san");
	printf("\t-help        Prints this help\n");
	printf("\t-serial      Which cert to change\n");
	printf("\t-add         Entry to add\n");
	printf("\t-del         Entry to remove\n");
}

void
agent_cli_role_sans(int role, int argc, char **argv)
{
	int               opt, r;
	char             *serial = NULL;
	char            **add = NULL;
	size_t            add_sz = 0;
	char            **del = NULL;
	size_t            del_sz = 0;
	struct pmdr       pm;
	struct pmdr_vec   pv[3];
	char              pbuf[CERTES_MAX_MSG_SIZE];
	struct umdr       um;
	struct umdr_vec   uv[3];
	char              ubuf[1024];
	struct xerr       e;
	struct authop    *op;

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			role_san_usage(role);
			exit(0);
		}

		if (strcmp(argv[opt], "-add") == 0) {
			opt++;
			if (opt > argc) {
				role_san_usage(role);
				exit(1);
			}
			add = strarray_add(add, argv[opt]);
			if (add == NULL)
				err(1, "strarray_add");
			add_sz++;
			continue;
		}

		if (strcmp(argv[opt], "-del") == 0) {
			opt++;
			if (opt > argc) {
				role_san_usage(role);
				exit(1);
			}
			del = strarray_add(del, argv[opt]);
			if (del == NULL)
				err(1, "strarray_add");
			del_sz++;
			continue;
		}

		if (strcmp(argv[opt], "-serial") == 0) {
			opt++;
			if (opt > argc) {
				role_san_usage(role);
				exit(1);
			}
			serial = argv[opt];
			continue;
		}
	}

	if (serial == NULL) {
		warn("no serial provided");
		role_san_usage(role);
		exit(1);
	}

	if (cert_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (agent_init(xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((op = authop_new((role) ? AUTHOP_ROLE_MOD : AUTHOP_ROLE_SAN,
	    NULL, xerrz(&e))) == NULL) {
		xerr_print(&e);
		exit(1);
	}

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_S;
	pv[0].v.s = serial;
	pv[1].type = MDR_AS;
	pv[1].v.as.items = (const char **)add;
	pv[1].v.as.length = add_sz;
	pv[2].type = MDR_AS;
	pv[2].v.as.items = (const char **)del;
	pv[2].v.as.length = del_sz;
	if (pmdr_pack(&pm, (role) ? msg_cert_mod_roles : msg_cert_mod_sans,
	    pv, PMDRVECLEN(pv)) == MDR_FAIL)
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
			err(1, "failed to unpack response");
		errx(1, "mod failed: %s (%u)", uv[1].v.s.bytes,
		    uv[0].v.u32);
	case MDR_DCV_CERTES_ERROR:
		if (umdr_unpack(&um, msg_error, uv, UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "failed to unpack response");
		errx(1, "mod failed: %s (%u)", uv[2].v.s.bytes,
		    uv[1].v.u32);
	default:
		errx(1, "bad response from authority");
	}
}

static void
cli_cert_usage()
{
	printf("Usage: %s cert [-serial <serial>] [-find <pattern>]\n",
	    CERTES_PROGNAME);
	printf("\t-help             Prints this help\n");
	printf("\t-serial <serial>  Serial of the certificate to display\n");
	printf("\t-find <pattern>   List serials matching pattern\n");
}

static int
print_str_ext(const char *s, void *args)
{
	printf("  - %s\n", s);
	return 1;
}

void
agent_cli_cert(int argc, char **argv)
{
	int               opt, r, i;
	char             *serial = NULL;
	char             *find = NULL;
	struct pmdr       pm;
	struct pmdr_vec   pv[1];
	char              pbuf[CERTES_MAX_MSG_SIZE];
	struct umdr       um;
	struct umdr_vec   uv[3];
	char              ubuf[CERTES_MAX_MSG_SIZE];
	struct xerr       e;
	struct authop    *op;
	X509             *crt = NULL;
	const uint8_t    *der;
	uint32_t          flags;
	time_t            revoked_at_sec;
	char             *subject;
	struct tm         tm;
	struct tm        *ptm;
	char              tstr[80];
	const char      **serials;
	size_t            serials_sz;
	const char      **subjects;
	size_t            subjects_sz;
	uint32_t         *find_flags;
	size_t            find_flags_sz;

	for (opt = 0; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			cli_cert_usage();
			exit(0);
		}

		if (strcmp(argv[opt], "-serial") == 0) {
			opt++;
			if (opt > argc) {
				cli_cert_usage();
				exit(1);
			}
			serial = argv[opt];
			continue;
		}

		if (strcmp(argv[opt], "-find") == 0) {
			opt++;
			if (opt > argc) {
				cli_cert_usage();
				exit(1);
			}
			find = argv[opt];
			continue;
		}
	}

	if (serial == NULL && find == NULL) {
		warn("no serial or pattern provided");
		cli_cert_usage();
		exit(1);
	}

	if (cert_init(xerrz(&e)) == -1)
		goto fail;

	if (agent_init(xerrz(&e)) == -1)
		goto fail;

	if ((op = authop_new(
	    (serial == NULL) ? AUTHOP_CERT_FIND : AUTHOP_CERT_GET,
	    NULL, xerrz(&e))) == NULL)
		goto fail;

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	if (serial == NULL) {
		pv[0].type = MDR_S;
		pv[0].v.s = find;
		if (pmdr_pack(&pm, msg_cert_find, pv,
		    PMDRVECLEN(pv)) == MDR_FAIL)
			err(1, "pmdr_pack");
	} else {
		pv[0].type = MDR_S;
		pv[0].v.s = serial;
		if (pmdr_pack(&pm, msg_cert_get, pv,
		    PMDRVECLEN(pv)) == MDR_FAIL)
			err(1, "pmdr_pack");
	}


	if (authop_send(op, pmdr_buf(&pm), pmdr_size(&pm), xerrz(&e)) == -1)
		goto fail;

	if ((r = authop_recv(op, ubuf, sizeof(ubuf), xerrz(&e))) == -1)
		goto fail;

	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL)
		goto fail;

	switch (umdr_dcv(&um)) {
	case MDR_DCV_CERTES_CERT_FIND_ANSWER:
		if (find == NULL)
			errx(1, "bad response from authority");
		/* Success */
		break;
	case MDR_DCV_CERTES_CERT_GET_ANSWER:
		if (serial == NULL)
			errx(1, "bad response from authority");
		/* Success */
		break;
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&um, mdr_msg_error, uv, 2) == MDR_FAIL)
			err(1, "failed to unpack response");
		errx(1, "revoke failed: %s (%u)", uv[1].v.s.bytes, uv[0].v.u32);
	case MDR_DCV_CERTES_ERROR:
		if (umdr_unpack(&um, msg_error, uv, UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "failed to unpack response");
		errx(1, "revoke failed: %s (%u)", uv[2].v.s.bytes, uv[1].v.u32);
	default:
		errx(1, "bad response from authority");
	}

	if (serial == NULL) {
		if (umdr_unpack(&um, msg_cert_find_answer, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "umdr_unpack/msg_cert_get_answer");
		serials_sz = umdr_vec_alen(&uv[0].v.as);
		subjects_sz = umdr_vec_alen(&uv[1].v.as);
		find_flags_sz = umdr_vec_alen(&uv[2].v.au32);

		if (serials_sz != subjects_sz || serials_sz != find_flags_sz)
			errx(1, "msg_cert_find_answer: not all arrays "
			    "are same length; invalid response");

		serials = calloc(serials_sz + 1, sizeof(char *));
		subjects = calloc(subjects_sz + 1, sizeof(char *));
		find_flags = calloc(find_flags_sz, sizeof(uint32_t));
		if (serials == NULL || subjects == NULL || find_flags == NULL)
			err(1, "calloc");

		if (umdr_vec_as(&uv[0].v.as, serials, serials_sz + 1)
		    == MDR_FAIL)
			err(1, "umdr_vec_as");
		if (umdr_vec_as(&uv[1].v.as, subjects, subjects_sz + 1)
		    == MDR_FAIL)
			err(1, "umdr_vec_as");
		if (umdr_vec_au32(&uv[2].v.au32, find_flags, find_flags_sz + 1)
		    == MDR_FAIL)
			err(1, "umdr_vec_au32");

		for (i = 0; i < serials_sz; i++)
			printf("%s\t%s\t0x%08x\n",
			    serials[i], subjects[i], find_flags[i]);
		free(serials);
		free(subjects);
		free(find_flags);
		return;
	}

	if (umdr_unpack(&um, msg_cert_get_answer, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		err(1, "umdr_unpack/msg_cert_get_answer");

	der = uv[0].v.b.bytes;
	revoked_at_sec = uv[1].v.u64;
	flags = uv[2].v.u32;

	crt = d2i_X509(NULL, &der, uv[0].v.b.sz);
	/* der is incremented */
	if (crt == NULL) {
		XERRF(&e, XLOG_APP, XLOG_BADMSG,
		    "cert_get_answer reply did not contain a valid "
		    "DER-encoded X.509, or alloc failed");
		goto fail;
	}

	if ((serial = cert_serial_to_hex(crt, xerrz(&e))) == NULL)
		goto fail;
	printf("Serial:  %s\n", serial);
	free(serial);

	if ((subject = cert_subject_oneline(crt, xerrz(&e))) == NULL)
		goto fail;
	printf("Subject: %s\n", subject);
	free(subject);

	printf("Roles:\n");
	if (cert_foreach_role(crt, &print_str_ext, NULL, xerrz(&e)) == -1)
		printf(" N/A\n");

	printf("SANs:\n");
	if (cert_foreach_san(crt, &print_str_ext, NULL, xerrz(&e)) == -1)
		printf(" N/A\n");

	if (flags & CERTDB_FLAG_REVOKED) {
		ptm = gmtime(&revoked_at_sec);
		if (strftime(tstr, sizeof(tstr), "%F %H:%M:%S %z", ptm) == 0)
			errx(1, "strftime() result too large");
		printf("Revoked at: %s\n", tstr);
	}

	ASN1_TIME_to_tm(X509_get_notBefore(crt), &tm);
	if (strftime(tstr, sizeof(tstr), "%F %H:%M:%S %z", &tm) == 0)
		errx(1, "strftime() result too large");
	printf("Not before: %s\n", tstr);

	ASN1_TIME_to_tm(X509_get_notAfter(crt), &tm);
	if (strftime(tstr, sizeof(tstr), "%F %H:%M:%S %z", &tm) == 0)
		errx(1, "strftime() result too large");
	printf("Not after:  %s\n", tstr);

	if (PEM_write_X509(stdout, crt) == 0)
		ERR_print_errors_fp(stderr);

	X509_free(crt);
	return;
fail:
	if (crt != NULL)
		X509_free(crt);
	xerr_print(&e);
	exit(1);
}

static int
agent_load_key(struct xerr *e)
{
	FILE          *f;
#ifndef __OpenBSD__
	int            pkey_sz;
#endif
	if ((f = fopen(certes_conf.key_file, "r")) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "fopen");
	if ((key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		fclose(f);
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "PEM_read_PrivateKey");
	}
	fclose(f);
#ifndef __OpenBSD__
	if (!(pkey_sz = EVP_PKEY_size(key))) {
		EVP_PKEY_free(key);
		key = NULL;
		return XERRF(e, XLOG_SSL, ERR_get_error(), "EVP_PKEY_size");
	}

	/* pledge() doesn't allow mlock() */
	if (mlock(key, pkey_sz) == -1) {
		EVP_PKEY_free(key);
		key = NULL;
		return XERRF(e, XLOG_ERRNO, errno, "mlock");
	}
#endif
	return 0;
}

void
agent_cleanup()
{
	free_loaded_crls();
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
agent_get_crl(const char *issuer_cn, const X509_CRL **crl,
    uint64_t *last_update)
{
	int i;
	for (i = 0; i < loaded_crls.count; i++) {
		if (strcmp(issuer_cn, loaded_crls.issuers[i]) == 0) {
			if (last_update != NULL)
				*last_update = loaded_crls.last_updates[i];
			if (crl != NULL)
				*crl = loaded_crls.crls[i];
			return i;
		}
	}
	return -1;
}


const struct loaded_crls *
agent_get_loaded_crls()
{
	return &loaded_crls;
}

static int
agent_init_ctx(struct xerr *e)
{
	FILE          *f = NULL;
	X509          *root_crt;

	if ((store = X509_STORE_new()) == NULL)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_new");

	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL)) {
		XERRF(e, XLOG_SSL, ERR_get_error(),
		    "X509_STORE_set_flags");
		goto fail;
	}

	if ((f = fopen(certes_conf.root_cert_file, "r")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    certes_conf.root_cert_file);
		goto fail;
	}
	if ((root_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509");
		goto fail;
	}
	fclose(f);
	f = NULL;

	if (!X509_STORE_add_cert(store, root_crt)) {
		X509_free(root_crt);
		XERRF(e, XLOG_SSL, ERR_get_error(), "X509_STORE_add_cert");
		goto fail;
	}
	X509_free(root_crt);

	if ((f = fopen(certes_conf.cert_file, "r")) == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "fopen: %s",
		    certes_conf.cert_file);
		goto fail;
	}
	if ((cert = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		XERRF(e, XLOG_SSL, ERR_get_error(), "PEM_read_X509");
		goto fail;
	}
	fclose(f);
	f = NULL;

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
		XERRF(e, XLOG_SSL, ERR_get_error(), "SSL_CTX_new");
		goto fail;
	}

	SSL_CTX_set_security_level(ssl_ctx, 3);
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, &verify_callback);
	SSL_CTX_set_cert_store(ssl_ctx, store);

	/* Ownership of store now passed to ssl_ctx. */

	if (SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1) {
		X509_free(cert);
		cert = NULL;
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "SSL_CTX_use_PrivateKey");
	}

	if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
	    certes_conf.cert_file) != 1) {
		X509_free(cert);
		cert = NULL;
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
		return XERRF(e, XLOG_SSL, ERR_get_error(),
		    "SSL_CTX_use_certificate_chain_file");
	}

	return 0;
fail:
	if (f != NULL)
		fclose(f);
	if (cert != NULL)
		X509_free(cert);
	if (store != NULL)
		X509_STORE_free(store);
	return -1;
}

static void
free_loaded_crls()
{
	int i;

	if (loaded_crls.count > 0) {
		free(loaded_crls.issuers);
		free(loaded_crls.last_updates);
		for (i = 0; i < loaded_crls.count; i++)
			X509_CRL_free(loaded_crls.crls[i]);
		free(loaded_crls.crls);
	}
}

static int
load_crls(struct xerr *e)
{
	DIR              *d = NULL;
	struct dirent    *de;
	size_t            de_len;
	char              crl_path[PATH_MAX];
	uint32_t          count = 0, i;
	char            **issuers = NULL;
	uint64_t         *last_updates = NULL;
	X509_CRL         *crl = NULL, **crls = NULL;
	const ASN1_TIME  *lu;
	struct tm         tm;
	X509_NAME        *issuer;

	if (*certes_conf.crl_path == '\0')
		return 0;

	if (mkdir(certes_conf.crl_path, 0700) == -1 && errno != EEXIST)
		return XERRF(e, XLOG_ERRNO, errno, "mkdir: %s",
		    certes_conf.crl_path);
	if ((d = opendir(certes_conf.crl_path)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "opendir: %s",
		    certes_conf.crl_path);

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

		count++;
	}
	rewinddir(d);

	last_updates = calloc(count, sizeof(time_t));
	if (last_updates == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "calloc");
		goto fail;
	}
	issuers = calloc(count, sizeof(char *) + 256);
	if (issuers == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "calloc");
		goto fail;
	}
	for (i = 0; i < count; i++)
		issuers[i] = ((char *)issuers + (count * sizeof(char *))) +
		    (i * 256);
	crls = calloc(count, sizeof(X509_CRL *));
	if (crls == NULL) {
		XERRF(e, XLOG_ERRNO, errno, "calloc");
		goto fail;
	}

	for (i = 0; i < count;) {
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
		    certes_conf.crl_path, de->d_name);
		if ((crl = load_crl(crl_path, xerrz(e))) == NULL) {
			XERR_PREPENDFN(e);
			goto fail;
		}

		issuer = X509_CRL_get_issuer(crl);
		if (X509_NAME_get_text_by_NID(issuer, NID_commonName,
		    issuers[i], 256) < 0) {
			XERRF(e, XLOG_SSL, ERR_get_error(),
			    "X509_NAME_get_text_by_NID");
			X509_CRL_free(crl);
			goto fail;
		}
		xlog(LOG_INFO, NULL, "loaded CRL with issuer %s", issuers[i]);
		if ((lu = X509_CRL_get0_lastUpdate(crl)) == NULL) {
			xlog(LOG_ERR, NULL, "%s: crl for issuer %s has no "
			    "lastUpdate field; skipping", __func__,
			    issuers[i]);
			X509_CRL_free(crl);
			crl = NULL;
			continue;
		}
		ASN1_TIME_to_tm(lu, &tm);
		last_updates[i] = timegm(&tm);
		crls[i] = crl;
		i++;
	}
	closedir(d);
	d = NULL;

	free_loaded_crls();

	loaded_crls.count = count;
	loaded_crls.issuers = issuers;
	loaded_crls.last_updates = last_updates;
	loaded_crls.crls = crls;

	return 0;
fail:
	if (d != NULL)
		closedir(d);
	if (issuers != NULL)
		free(issuers);
	if (last_updates != NULL)
		free(last_updates);
	if (crls != NULL) {
		count = i;
		for (i = 0; i < count; i++)
			X509_CRL_free(crls[i]);
		free(crls);
	}
	return -1;
}

static int
agent_init2(int gen_crl, struct xerr *e)
{
	clock_gettime(CLOCK_MONOTONIC, &next_certdb_backup);
	next_certdb_backup.tv_sec +=
	    certes_conf.certdb_backup_interval_seconds;

	/*
	 * In order we must:
	 *   1) Load our private key, which is needed to sign a CRL if we
	 *      are an authority
	 *   2.a) Create the store and load the root cert and our own cert,
	 *        which is needed to determine if we are an authority
	 *   2.b) Create our SSL_CTX and transfer ownership of the store to
	 *        it for proper cleanup (not double-freeing the store)
	 *   3) Initialize the certdb if we are an authority
	 *   4) Generate the CRL with the help of the certdb, which also
	 *      needs the private key to sign the CRL
	 *   5) Load any CRLs
	 */
	if (agent_load_key(e) == -1)
		return XERR_PREPENDFN(e);

	if (agent_init_ctx(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	if (is_authority && gen_crl) {
		if (*certes_conf.certdb_path == '\0')
			return XERRF(e, XLOG_APP, XLOG_FAIL,
			    "certdb_path is not set and we are an authority");

		if (certdb_init(certes_conf.certdb_path, xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

		if (cert_gen_crl(xerrz(e)) == -1)
			return XERR_PREPENDFN(e);
	}

	if (load_crls(xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	return 0;
}

int
agent_init(struct xerr *e)
{
	return agent_init2(0, e);
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

	if ((r = writeall(agent_fd, buf, sz)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "write on fd %d", agent_fd);

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

	if (agent_init2(1, xerrz(e)) == -1)
		return XERR_PREPENDFN(e);

	xlog(LOG_NOTICE, NULL, "%s: finished initialization; we are "
	    "%san authority", __func__, (is_authority) ? "" : "not ");

	if ((lock_fd = open(certes_conf.lock_file,
	    O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "open: %s",
		    certes_conf.lock_file);

	if (flock(lock_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			close(lock_fd);
			return XERRF(e, XLOG_ERRNO, errno,
			    "lock file %s is already locked; "
			    "is another instance running?",
			    certes_conf.lock_file);
		}
		close(lock_fd);
		return XERRF(e, XLOG_ERRNO, errno, "flock");
	}

	if ((pid = fork()) == -1) {
		close(lock_fd);
		return XERRF(e, XLOG_ERRNO, errno, "fork");
	} else if (pid != 0) {
		close(lock_fd);
		return 0;
	}

	chdir("/");

	if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: open /dev/null", __func__);
		exit(1);
	}

	dup2(null_fd, STDIN_FILENO);
	dup2(null_fd, STDOUT_FILENO);
	dup2(null_fd, STDERR_FILENO);
	if (null_fd > 2)
		close(null_fd);

	if (xlog_init2(CERTES_AGENT_PROGNAME, LOG_DAEMON,
	    NULL, NULL, 0) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: xlog_init", __func__);
		exit(1);
	}

	if (setsid() == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: setsid", __func__);
		exit(1);
	}

	setproctitle("agent");

	xlog(LOG_NOTICE, NULL, "%s: initialized", __func__);

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(lock_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: write", __func__);
		exit(1);
	}
	if (fsync(lock_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fsync", __func__);
		exit(1);
	}

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sock", __func__);
		exit(1);
	}
	unlink(certes_conf.agent_sock_path);

	if (fcntl(lsock, F_SETFD, FD_CLOEXEC) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fcntl", __func__);
		exit(1);
	}
	if ((lsock_flags = fcntl(lsock, F_GETFL, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fcntl", __func__);
		exit(1);
	}
	if (fcntl(lsock, F_SETFL, lsock_flags | O_NONBLOCK) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: fcntl", __func__);
		exit(1);
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, certes_conf.agent_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: bind", __func__);
		exit(1);
	}

	if (listen(lsock, 64) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: listen", __func__);
		exit(1);
	}

	if (agent_run(lsock, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, "%s", __func__);
		exit(1);
	}

	agent_cleanup();
	certdb_shutdown();
	mdr_registry_clear();
	exit(0);
}
