#include <sys/file.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "util.h"
#include "xlog.h"

int
is_hex_str(const char *str)
{
	const char *p;

	for (p = str; *p; p++) {
		if (!((*p >= '0' && *p <= '9') ||
		    (*p >= 'a' && *p <= 'f') ||
		    (*p >= 'A' && *p <= 'F'))) {
			return 0;
		}
	}
	return 1;
}

int
daemonize(const char *program, const char *pid_path, int nochdir, int noclose, struct xerr *e)
{
	pid_t pid;
	int   pid_fd;
	char  pid_line[32];
	int   null_fd;

	if ((pid_fd = open(pid_path, O_CREAT|O_WRONLY|O_CLOEXEC, 0644)) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "open %s", pid_path);

	if (flock(pid_fd, LOCK_EX|LOCK_NB) == -1) {
		if (errno == EWOULDBLOCK)
			return XERRF(e, XLOG_ERRNO, errno,
			    "pid file %s is already locked; "
			    "is another instance running?", pid_path);
		return XERRF(e, XLOG_ERRNO, errno, "flock %s", pid_path);
	}

	if ((pid = fork()) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "fork");

	if (pid > 0)
		exit(0);

	if (setsid() == -1) {
		xlog_strerror(LOG_ERR, errno, "setsid");
		exit(1);
	}

	xlog_init(program, NULL, NULL, 1);

	if (!nochdir && chdir("/") == -1) {
		xlog_strerror(LOG_ERR, errno, "chdir");
		exit(1);
	}

	if (!noclose) {
		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			xlog_strerror(LOG_ERR, errno, "open /dev/null");
			exit(1);
		}

		dup2(null_fd, STDIN_FILENO);
		dup2(null_fd, STDOUT_FILENO);
		dup2(null_fd, STDERR_FILENO);
		if (null_fd > 2)
			close(null_fd);
	}

	snprintf(pid_line, sizeof(pid_line), "%d\n", getpid());
	if (write(pid_fd, pid_line, strlen(pid_line)) == -1) {
		xlog_strerror(LOG_ERR, errno, "write %s", pid_path);
		exit(1);
	}

	if (fsync(pid_fd) == -1) {
		xlog_strerror(LOG_ERR, errno, "fsync");
		exit(1);
	}

	/* We never close pid_fd, to prevent concurrent executions. */

	return 0;
}

int
drop_privileges(const char *user, const char *group, struct xerr *e)
{
	struct group  *gr;
	struct passwd *pw;

	if (group != NULL) {
		if ((gr = getgrnam(group)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno,
			    "getgrnam %s", group);

		if (setgid(gr->gr_gid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "setgid");
		if (setegid(gr->gr_gid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "setegid");
	}

	if (user != NULL) {
		if ((pw = getpwnam(user)) == NULL)
			return XERRF(e, XLOG_ERRNO, errno, "getpwnam %s", user);

		if (setuid(pw->pw_uid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "setuid");
		if (seteuid(pw->pw_uid) == -1)
			return XERRF(e, XLOG_ERRNO, errno, "seteuid");
	}
	return 0;
}

#define CLOSE_X(fd) close_x(fd, #fd, __func__, __LINE__)
void
close_x(int fd, const char *fd_name, const char *fn, int line)
{
	if (close(fd) == -1)
		xlog_strerror(LOG_ERR, errno, "%s:%d: close(%s)",
		    fn, line, fd_name);
}

ssize_t
writeall(int fd, const void *buf, size_t count)
{
	ssize_t w;
	ssize_t n = 0;

	while (n < count) {
		w = write(fd, buf + n, count - n);
		if (w == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n += w;
	}
	return n;
}

ssize_t
readall(int fd, void *buf, size_t count)
{
	ssize_t r;
	ssize_t n = 0;

	while (n < count) {
		r = read(fd, buf + n, count - n);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if (r == 0) {
			return n;
		}
		n += r;
	}
	return n;
}

int
spawn(char *const argv[], int *stdin, int *stdout, const char *user,
    const char *group, struct xerr *e)
{
	pid_t pid;
	int   p_in[2];
	int   p_out[2];
	int   null_fd;

	if (pipe(p_in) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "pipe");
	*stdin = p_in[1];

	if (pipe(p_out) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "pipe");
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		return -1;
	}
	*stdout = p_out[0];

	if ((pid = fork()) == -1) {
		XERRF(e, XLOG_ERRNO, errno, "fork");
		CLOSE_X(p_in[0]);
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		CLOSE_X(p_out[1]);
		return -1;
	} else if (pid == 0) {
		CLOSE_X(p_in[1]);
		CLOSE_X(p_out[0]);
		if (p_in[0] != STDIN_FILENO) {
			if (dup2(p_in[0], STDIN_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				_exit(1);
			}
			CLOSE_X(p_in[0]);
		}
		if (p_out[1] != STDOUT_FILENO) {
			if (dup2(p_out[1], STDOUT_FILENO) == -1) {
				XERRF(e, XLOG_ERRNO, errno, "dup2");
				_exit(1);
			}
			CLOSE_X(p_out[1]);
		}

		if ((null_fd = open("/dev/null", O_RDWR)) == -1) {
			xlog_strerror(LOG_ERR, errno, "open /dev/null");
			exit(1);
		}
		dup2(null_fd, STDERR_FILENO);
		if (null_fd > 2)
			close(null_fd);

		if (chdir("/") == -1) {
			XERRF(e, XLOG_ERRNO, errno, "chdir");
			_exit(1);
		}

		if (geteuid() == 0) {
			if (drop_privileges(user, group, xerrz(e)) == -1) {
				xlog(LOG_ERR, e, "drop_privileges");
				_exit(1);
			}
		}

		if (execv(argv[0], argv) == -1) {
			XERRF(e, XLOG_ERRNO, errno, "execv: %s", argv[0]);
			_exit(1);
		}
	}

	CLOSE_X(p_in[0]);
	CLOSE_X(p_out[1]);

	return 0;
}

char **
cmdargv(char *command)
{
	char **argv;
	char  *p;
	int    in_arg;
	int    n = 0, i;

	for (in_arg = 0, p = command; *p != '\0'; p++) {
		if (!in_arg && *p != ' ') {
			n++;
			in_arg = 1;
			continue;
		}

		if (*p == ' ') {
			in_arg = 0;
			continue;
		}
	}

	argv = malloc(sizeof(char *) * (n + 1));
	if (argv == NULL)
		return NULL;
	argv[n] = NULL;

	for (in_arg = 0, i = 0, p = command; i < n; p++) {
		if (!in_arg && *p != ' ') {
			argv[i++] = p;
			in_arg = 1;
			continue;
		}

		if (*p == ' ') {
			in_arg = 0;
			*p = '\0';
			continue;
		}
	}
	return argv;
}
