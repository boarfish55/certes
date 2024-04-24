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

	if ((gr = getgrnam(group)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "getgrnam %s", group);

	if (setgid(gr->gr_gid) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "setgid");
	if (setegid(gr->gr_gid) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "setegid");

	if ((pw = getpwnam(user)) == NULL)
		return XERRF(e, XLOG_ERRNO, errno, "getpwnam %s", user);

	if (setuid(pw->pw_uid) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "setuid");
	if (seteuid(pw->pw_uid) == -1)
		return XERRF(e, XLOG_ERRNO, errno, "seteuid");
	return 0;
}
