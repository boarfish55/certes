#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/un.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "coordinator.h"
#include "certalator.h"

extern struct certalator_flatconf certalator_conf;

static int  coordinator_connect(struct xerr *);
static void purge_challenges();
static int  coordinator_rcv_challenge(struct umdr *, struct xerr *);
static int  coordinator_get_challenge(struct umdr *, struct xerr *);

static struct timespec last_challenge_purge = {0, 0};
static int             coordinator_fd = -1;

struct challenge {
	char            req_id[CERTALATOR_REQ_ID_LENGTH];
	char            challenge[CERTALATOR_CHALLENGE_LENGTH];
	struct timespec created_at;
	SPLAY_ENTRY(challenge) entries;
};

static int
challenge_cmp(struct challenge *c1, struct challenge *c2)
{
	return memcmp(c1->req_id, c2->req_id, sizeof(c1->req_id));
}

SPLAY_HEAD(challenge_tree, challenge) challenges = SPLAY_INITIALIZER(&challenges);
SPLAY_PROTOTYPE(challenge_tree, challenge, entries, challenge_cmp);
SPLAY_GENERATE(challenge_tree, challenge, entries, challenge_cmp);

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

static void
purge_challenges()
{
	struct timespec   now;
	struct challenge *chal;

	clock_gettime(CLOCK_REALTIME, &now);

	/* We only purge every minute */
	if (now.tv_sec - last_challenge_purge.tv_sec <= 60)
		return;

	SPLAY_FOREACH(chal, challenge_tree, &challenges) {
		if (now.tv_sec - chal->created_at.tv_sec > 60) {
			SPLAY_REMOVE(challenge_tree, &challenges, chal);
			free(chal);
		}
	}

	clock_gettime(CLOCK_REALTIME, &last_challenge_purge);
}

static int
coordinator_connect(struct xerr *e)
{
	int                fd;
	struct sockaddr_un saddr;
	struct timespec    tp = {1, 0};
	int                try;

	if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "%s: socket", __func__);

	for (try = 0; try < 5 && coordinator_fd == -1; try++) {
		bzero(&saddr, sizeof(saddr));
		saddr.sun_family = AF_LOCAL;
		strlcpy(saddr.sun_path, certalator_conf.coordinator_sock_path,
		    sizeof(saddr.sun_path));

		if (connect(fd, (struct sockaddr *)&saddr,
		    sizeof(saddr)) == -1) {
			if (errno != ENOENT && errno != ECONNREFUSED)
				return XERRF(e, XLOG_ERRNO, errno, "connect");

			if (coordinator_start(xerrz(e)) == -1) {
				if (errno != EWOULDBLOCK)
					return XERR_PREPENDFN(e);
			}
			nanosleep(&tp, NULL);
			continue;
		}

		coordinator_fd = fd;
	}

	xlog(LOG_NOTICE, NULL, "%s: connected to backend agent", __func__);
	return 0;
}

int
coordinator_send(struct pmdr *m, struct xerr *e)
{
	ssize_t r;

	if (coordinator_fd == -1)
		if (coordinator_connect(xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

	if ((r = write(coordinator_fd, pmdr_buf(m), pmdr_size(m))) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "%s: write", __func__);
	else if (r < pmdr_size(m))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "%s: write", __func__);

	return 0;
}

int
coordinator_recv(void *buf, size_t buf_sz, struct xerr *e)
{
	if (coordinator_fd == -1) {
		if (coordinator_connect(xerrz(e)) == -1)
			xlog(LOG_ERR, e, "%s: coordinator_connect", __func__);
		/*
		 * If we were disconnected and/or had to restart the
		 * coordinator, it probably lost state so we'll have to restart
		 * whatever operation we were doing.
		 */
		return XERRF(e, XLOG_ERRNO, EBADF,
		    "%s: coordinator_fd is -1", __func__);
	}

	return mdr_buf_from_fd(coordinator_fd, buf, buf_sz);
}

static int
coordinator_rcv_challenge(struct umdr *m, struct xerr *e)
{
	struct umdr_vec   uv[2];
	struct challenge *chal;

	if ((chal = malloc(sizeof(struct challenge))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	if (umdr_unpack(m, msg_coord_save_cert_challenge,
	    uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		free(chal);
		return XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
	}

	strlcpy(chal->req_id, uv[0].v.s.bytes, sizeof(chal->req_id));
	strlcpy(chal->challenge, uv[1].v.b.bytes,
	    MIN(uv[1].v.b.sz, sizeof(chal->challenge)));
	clock_gettime(CLOCK_REALTIME, &chal->created_at);
	SPLAY_INSERT(challenge_tree, &challenges, chal);

	return 0;
}

static int
coordinator_get_challenge(struct umdr *m, struct xerr *e)
{
	struct challenge needle, *chal;
	struct pmdr      resp;
	struct pmdr_vec  pv[1];
	struct umdr_vec  uv[1];
	char             buf[1024];
	ssize_t          r;

	if (umdr_unpack(m, msg_coord_get_cert_challenge,
	    uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");

	pmdr_init(&resp, buf, sizeof(buf), MDR_FNONE);

	strlcpy(needle.req_id, uv[0].v.s.bytes, sizeof(needle.req_id));
	chal = SPLAY_FIND(challenge_tree, &challenges, &needle);
	if (chal == NULL) {
		if (pmdr_pack(&resp, msg_coord_get_cert_challenge_resp_notfound,
		    NULL, 0) == MDR_FAIL) {
			return XERRF(e, XLOG_ERRNO, errno,
			    "pmdr_pack/msg_coord_get_cert_challenge_notfound");
		}
	} else {
		SPLAY_REMOVE(challenge_tree, &challenges, chal);
		pv[0].type = MDR_B;
		pv[0].v.b.bytes = chal->challenge;
		pv[0].v.b.sz = sizeof(chal->challenge);
		if (pmdr_pack(&resp, msg_coord_get_cert_challenge_resp,
		    pv, PMDRVECLEN(pv)) == MDR_FAIL)
			return XERRF(e, XLOG_ERRNO, errno,
			    "pmdr_pack/msg_coord_get_cert_challenge_resp");
	}

	if ((r = write(coordinator_fd, pmdr_buf(&resp), pmdr_size(&resp))) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "%s: write", __func__);
	else if (r < pmdr_size(&resp))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "%s: write", __func__);

	return 0;
}

int
coordinator_run(int lsock, struct xerr *e)
{
	struct pollfd *fds;
	int            ready;
	int            fd, nfds, fds_sz = 32;
	struct client *c, needle;
	ssize_t        r;
	struct umdr    um;
	void          *tmp;

	if ((fds = malloc(sizeof(struct pollfd) * fds_sz)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	for (;;) {
		nfds = 0;
		fds[0].fd = lsock;
		fds[0].events = POLLIN;
		nfds++;
		SPLAY_FOREACH(c, client_tree, &clients) {
			fds[nfds].fd = c->fd;
			fds[nfds].events = POLLIN;
			nfds++;
		}

		purge_challenges();

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
			continue;
		}

		for (; ready > 0; ready--) {
			if (fds[ready].revents & POLLERR) {
				xlog(LOG_ERR, NULL, "%s: fd %d error", __func__,
				    fds[ready].fd);
				close(fds[ready].fd);
				if (fds[ready].fd == lsock) {
					xlog(LOG_ERR, NULL, "%s: lsock %d "
					    "closed unexpectedly", __func__,
					    lsock);
					_exit(1);
				}

				needle.fd = fds[ready].fd;
				c = SPLAY_FIND(client_tree, &clients, &needle);
				if (c != NULL) {
					SPLAY_REMOVE(client_tree, &clients, c);
					client_free(c);
				}

				continue;
			}

			/* Handle our listening socket for new clients. */
			if (fds[ready].fd == lsock &&
			    fds[ready].revents & POLLIN) {
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
			needle.fd = fds[ready].fd;
			c = SPLAY_FIND(client_tree, &clients, &needle);
			if (c == NULL) {
				xlog(LOG_ERR, NULL, "%s: client fd %d not "
				    "found", __func__, fds[ready].fd);
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
			case MDR_DCV_CERTALATOR_COORD_SAVE_CERT_CHALLENGE:
				if (coordinator_rcv_challenge(&um, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e,
					    "%s: coordinator_rcv_challenge",
					    __func__);
				break;
			case MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE:
				if (coordinator_get_challenge(&um, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e,
					    "%s: coordinator_get_challenge",
					    __func__);
				break;
			default:
				xlog(LOG_ERR, NULL, "%s: unknown message %lu",
				    __func__, umdr_dcv(&um));
			}
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

int
coordinator_start(struct xerr *e)
{
	pid_t              pid;
	char               pid_line[32];
	int                lock_fd, null_fd;
	int                lsock, lsock_flags;
	struct sockaddr_un saddr;

	if ((lock_fd = open(certalator_conf.lock_file,
	    O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: open", __func__);
		return -1;
	}

	if (flock(lock_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: lock file %s is already locked; "
			    "is another instance running?",
			    __func__, certalator_conf.lock_file);
		} else {
			xlog_strerror(LOG_ERR, errno, "%s: flock", __func__);
		}
		return -1;
	}

	if ((pid = fork()) == -1) {
		close(lock_fd);
		xlog_strerror(LOG_ERR, errno, "%s: fork", __func__);
		return -1;
	} else if (pid != 0) {
		close(lock_fd);
		return 0;
	}

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
	unlink(certalator_conf.coordinator_sock_path);

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
	strlcpy(saddr.sun_path, certalator_conf.coordinator_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: bind", __func__);
		_exit(1);
	}

	if (listen(lsock, 64) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: listen", __func__);
		_exit(1);
	}

	if (coordinator_run(lsock, xerrz(e)) == -1) {
		xlog(LOG_ERR, e, "coordinator_run");
		_exit(1);
	}

	_exit(0);
}
