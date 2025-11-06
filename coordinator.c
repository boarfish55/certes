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

static int  coordinator_start();
static int  coordinator_connect(struct xerr *);
static void purge_challenges();
static int  coordinator_rcv_challenge(struct mdr *, struct xerr *);
static int  coordinator_get_challenge(struct mdr *, struct xerr *);

static struct timespec last_challenge_purge = {0, 0};
static int coordinator_fd = -1;

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

SPLAY_HEAD(challenge_tree, challenge);
SPLAY_PROTOTYPE(challenge_tree, challenge, entries, challenge_cmp);
SPLAY_GENERATE(challenge_tree, challenge, entries, challenge_cmp);
struct challenge_tree challenges = SPLAY_INITIALIZER(challenges_list);

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

SPLAY_HEAD(client_tree, client);
SPLAY_PROTOTYPE(client_tree, client, entries, client_cmp);
SPLAY_GENERATE(client_tree, client, entries, client_cmp);
struct client_tree clients = SPLAY_INITIALIZER(client_list);

static void
client_free(struct client *c)
{
	free(c->in_buf);
	free(c->out_buf);
	free(c);
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

			if (coordinator_start() == -1) {
				if (errno != EWOULDBLOCK)
					return XERRF(e, XLOG_ERRNO, errno,
					    "%s: coordinator_start", __func__);
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
coordinator_send(struct mdr *m, struct xerr *e)
{
	ssize_t r;

	if (coordinator_fd == -1)
		if (coordinator_connect(xerrz(e)) == -1)
			return XERR_PREPENDFN(e);

	if ((r = write(coordinator_fd, mdr_buf(m), mdr_size(m))) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "%s: write", __func__);
	else if (r < mdr_size(m))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "%s: write", __func__);

	return 0;
}

int
coordinator_recv(struct mdr *m, char *buf, size_t buf_sz, struct xerr *e)
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

	return mdr_read_from_fd(m, MDR_F_NONE, coordinator_fd, buf, buf_sz);
}

static int
coordinator_rcv_challenge(struct mdr *m, struct xerr *e)
{
	struct mdr_out    m_out[2];
	struct challenge *chal;

	if ((chal = malloc(sizeof(struct challenge))) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	if (mdr_unpack_payload(m, msg_coord_save_cert_challenge,
	    m_out, 2) == MDR_FAIL) {
		free(chal);
		return XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
	}

	strlcpy(chal->req_id, m_out[0].v.s.bytes, sizeof(chal->req_id));
	strlcpy(chal->challenge, m_out[1].v.b.bytes, MIN(m_out[1].v.b.sz, sizeof(chal->challenge)));
	clock_gettime(CLOCK_REALTIME, &chal->created_at);
	SPLAY_INSERT(challenge_tree, &challenges, chal);

	return 0;
}

static int
coordinator_get_challenge(struct mdr *m, struct xerr *e)
{
	struct challenge needle, *chal;
	struct mdr_out   m_out[1];
	struct mdr_in    m_in[1];
	struct mdr       resp;
	char             buf[1024];
	ssize_t          r;

	if (mdr_unpack_payload(m, msg_coord_get_cert_challenge,
	    m_out, 1) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");

	strlcpy(needle.req_id, m_out[0].v.s.bytes, sizeof(needle.req_id));
	chal = SPLAY_FIND(challenge_tree, &challenges, &needle);
	if (chal == NULL) {
		if (mdr_pack(&resp, buf, sizeof(buf),
		    msg_coord_get_cert_challenge_resp_notfound,
		    MDR_F_NONE, NULL, 0) == MDR_FAIL) {
			return XERRF(e, XLOG_ERRNO, errno,
			    "mdr_pack/msg_coord_get_cert_challenge_notfound");
		}
	} else {
		SPLAY_REMOVE(challenge_tree, &challenges, chal);
		m_in[0].type = MDR_B;
		m_in[0].v.b.bytes = chal->challenge;
		m_in[0].v.b.sz = sizeof(chal->challenge);
		if (mdr_pack(&resp, buf, sizeof(buf),
		    msg_coord_get_cert_challenge_resp,
		    MDR_F_NONE, m_in, 1) == MDR_FAIL)
			return XERRF(e, XLOG_ERRNO, errno,
			    "mdr_pack/msg_coord_get_cert_challenge_resp");
	}

	if ((r = write(coordinator_fd, mdr_buf(&resp), mdr_size(&resp))) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "%s: write", __func__);
	else if (r < mdr_size(&resp))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO,
		    "%s: write", __func__);

	return 0;
}

int
coordinator_run(int lsock, struct xerr *e)
{
	struct pollfd *fds;
	int            ready;
	int            nfds = 0, fds_sz = 32, fd;
	struct client *c, needle;
	ssize_t        r;
	struct mdr     m;
	void          *tmp;


	if ((fds = malloc(sizeof(struct pollfd) * fds_sz)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "malloc");

	for (;;) {
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

		if (ready == 0)
			continue;

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
				continue;
			}

			/* Any other event is communication from clients. */
			needle.fd = fds[ready].fd;
			c = SPLAY_FIND(client_tree, &clients, &needle);
			if (c == NULL) {
				xlog(LOG_ERR, NULL, "%s: client fd %d not "
				    "found", fds[ready].fd, __func__);
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

			if (mdr_unpack_hdr(&m, 0, c->in_buf, c->in_buf_used)
			    == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdr_unpack_hdr failed on fd %d; "
				    "closing", __func__, c->fd);
				close(c->fd);
				SPLAY_REMOVE(client_tree, &clients, c);
				client_free(c);
				continue;
			}
			if (mdr_size(&m) > c->in_buf_sz) {
				tmp = realloc(c->in_buf, mdr_size(&m));
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
				c->in_buf_sz = mdr_size(&m);
			}
			if (mdr_pending(&m) > 0)
				continue;

			switch (mdr_dcv(&m)) {
			case MDR_DCV_CERTALATOR_COORD_SAVE_CERT_CHALLENGE:
				if (coordinator_rcv_challenge(&m, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e,
					    "%s: coordinator_rcv_challenge",
					    __func__);
				break;
			case MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE:
				if (coordinator_get_challenge(&m, xerrz(e))
				    == MDR_FAIL)
					xlog(LOG_ERR, e,
					    "%s: coordinator_get_challenge",
					    __func__);
				break;
			default:
				xlog(LOG_ERR, NULL, "%s: unknown message %lu",
				    __func__, mdr_dcv(&m));
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

static int
coordinator_start()
{
	pid_t               pid;
	char                pid_line[32];
	int                 lock_fd, null_fd;
	int                 lsock, lsock_flags;
	struct sockaddr_un  saddr;
	struct xerr         e;

	if ((lock_fd = open(certalator_conf.lock_file,
	    O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1)
		return -1;
	if (flock(lock_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK) {
			warnx("lock file %s is already locked; "
			    "is another instance running?",
			    certalator_conf.lock_file);
		}
		return -1;
	}

	if ((pid = fork()) == -1) {
		close(lock_fd);
		return -1;
	} else if (pid != 0) {
		close(lock_fd);
		return 0;
	}

	chdir("/");

	if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
		warn("open");
		_exit(1);
	}

	dup2(null_fd, STDIN_FILENO);
	dup2(null_fd, STDOUT_FILENO);
	dup2(null_fd, STDERR_FILENO);
	if (null_fd > 2)
		close(null_fd);

	if (xlog_init(CERTALATOR_AGENT_PROGNAME, NULL, NULL, 0) == -1) {
		warn("xlog_init");
		_exit(1);
	}

	if (setsid() == -1) {
		xlog_strerror(LOG_ERR, errno, "setsid");
		_exit(1);
	}

	setproctitle("agent");

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(lock_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "write");
		_exit(1);
	}
	if (fsync(lock_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "fsync");
		_exit(1);
	}

	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "socket");
		_exit(1);
	}
	unlink(certalator_conf.coordinator_sock_path);

	if (fcntl(lsock, F_SETFD, FD_CLOEXEC) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		_exit(1);
	}
	if ((lsock_flags = fcntl(lsock, F_GETFL, 0)) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		_exit(1);
	}
	if (fcntl(lsock, F_SETFL, lsock_flags | O_NONBLOCK) == -1) {
		xlog_strerror(LOG_ERR, errno, "fcntl");
		_exit(1);
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sun_family = AF_LOCAL;
	strlcpy(saddr.sun_path, certalator_conf.coordinator_sock_path,
	    sizeof(saddr.sun_path));

	if (bind(lsock, (struct sockaddr *)&saddr, SUN_LEN(&saddr)) == -1) {
		xlog_strerror(LOG_ERR, errno, "bind");
		_exit(1);
	}

	if (listen(lsock, 64) == -1) {
		xlog_strerror(LOG_ERR, errno, "listen");
		_exit(1);
	}

	if (coordinator_run(lsock, xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, "coordinator_run");
		_exit(1);
	}

	_exit(0);
}
