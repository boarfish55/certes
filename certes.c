/*
 * Copyright (C) 2026 Pascal Lalonde <plalonde@overnet.ca>
 *
 * SPDX-License-Identifier: ISC
 */
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <mdr/flatconf.h>
#include <mdr/mdrd.h>
#include <mdr/util.h>
#include <mdr/xlog.h>
#include "util.h"
#include "agent.h"
#include "authority.h"
#include "cert.h"
#include "certes.h"
#include "certdb.h"
#include "mdr_certes.h"

static int             debug = 0;
static char            config_file_path[PATH_MAX] = "/etc/certes/certes.conf";
static uint64_t        crls_gen = 1;
static struct timespec next_crl_reload;

struct certes_flatconf certes_conf = {
	0,
	CERTES_AGENT_PORT,
	"",
	CERTES_AGENT_PORT,
	"",
	"",
	86400,                  /* certdb_backup_interval_seconds */
	0,                      /* certdb_backup_pages_per_steps */
	60000,
	60000,
	"",
	30,                     /* challenge_timeout */
	"ca.pem",               /* root_cert_file */
	"",
	"key.pem",
	"cert.pem",
	"agent.lock",
	"agent.sock",
	4096,                   /* max_cert_size */
	345600,
	864000,
	600,
	"serial",
	"",
	"",

	"0x0",
	"0x0"
};

struct flatconf certes_config_vars[] = {
	{
		"enable_coredumps",
		FLATCONF_BOOLINT,
		&certes_conf.enable_coredumps,
		sizeof(certes_conf.enable_coredumps)
	},
	{
		"agent_bootstrap_port",
		FLATCONF_ULONG,
		&certes_conf.agent_bootstrap_port,
		sizeof(certes_conf.agent_bootstrap_port)
	},
	{
		"authority_fqdn",
		FLATCONF_STRING,
		certes_conf.authority_fqdn,
		sizeof(certes_conf.authority_fqdn)
	},
	{
		"authority_port",
		FLATCONF_ULONG,
		&certes_conf.authority_port,
		sizeof(certes_conf.authority_port)
	},
	{
		"certdb_path",
		FLATCONF_STRING,
		certes_conf.certdb_path,
		sizeof(certes_conf.certdb_path)
	},
	{
		"certdb_backup_path",
		FLATCONF_STRING,
		certes_conf.certdb_backup_path,
		sizeof(certes_conf.certdb_backup_path)
	},
	{
		"certdb_backup_interval_seconds",
		FLATCONF_ULONG,
		&certes_conf.certdb_backup_interval_seconds,
		sizeof(certes_conf.certdb_backup_interval_seconds)
	},
	{
		"certdb_backup_pages_per_step",
		FLATCONF_ULONG,
		&certes_conf.certdb_backup_pages_per_step,
		sizeof(certes_conf.certdb_backup_pages_per_step)
	},
	{
		"agent_send_timeout_ms",
		FLATCONF_ULONG,
		&certes_conf.agent_send_timeout_ms,
		sizeof(certes_conf.agent_send_timeout_ms)
	},
	{
		"agent_recv_timeout_ms",
		FLATCONF_ULONG,
		&certes_conf.agent_recv_timeout_ms,
		sizeof(certes_conf.agent_recv_timeout_ms)
	},
	{
		"bootstrap_key",
		FLATCONF_STRING,
		certes_conf.bootstrap_key,
		sizeof(certes_conf.bootstrap_key)
	},
	{
		"challenge_timeout_seconds",
		FLATCONF_ULONG,
		&certes_conf.challenge_timeout_seconds,
		sizeof(certes_conf.challenge_timeout_seconds)
	},
	{
		"root_cert_file",
		FLATCONF_STRING,
		certes_conf.root_cert_file,
		sizeof(certes_conf.root_cert_file)
	},
	{
		"crl_path",
		FLATCONF_STRING,
		certes_conf.crl_path,
		sizeof(certes_conf.crl_path)
	},
	{
		"key_file",
		FLATCONF_STRING,
		certes_conf.key_file,
		sizeof(certes_conf.key_file)
	},
	{
		"cert_file",
		FLATCONF_STRING,
		certes_conf.cert_file,
		sizeof(certes_conf.cert_file)
	},
	{
		"lock_file",
		FLATCONF_STRING,
		certes_conf.lock_file,
		sizeof(certes_conf.lock_file)
	},
	{
		"agent_socket_path",
		FLATCONF_STRING,
		certes_conf.agent_sock_path,
		sizeof(certes_conf.agent_sock_path)
	},
	{
		"max_cert_size",
		FLATCONF_ULONG,
		&certes_conf.max_cert_size,
		sizeof(certes_conf.max_cert_size)
	},
	{
		"cert_min_lifetime_seconds",
		FLATCONF_ULONG,
		&certes_conf.cert_min_lifetime_seconds,
		sizeof(certes_conf.cert_min_lifetime_seconds)
	},
	{
		"cert_renew_lifetime_seconds",
		FLATCONF_ULONG,
		&certes_conf.cert_renew_lifetime_seconds,
		sizeof(certes_conf.cert_renew_lifetime_seconds)
	},
	{
		"cert_check_interval_seconds",
		FLATCONF_ULONG,
		&certes_conf.cert_check_interval_seconds,
		sizeof(certes_conf.cert_check_interval_seconds)
	},
	{
		"serial_file",
		FLATCONF_STRING,
		certes_conf.serial_file,
		sizeof(certes_conf.serial_file)
	},
	{
		"cert_org",
		FLATCONF_STRING,
		certes_conf.cert_org,
		sizeof(certes_conf.cert_org)
	},
	{
		"cert_email",
		FLATCONF_STRING,
		certes_conf.cert_email,
		sizeof(certes_conf.cert_email)
	},
	{
		"min_serial",
		FLATCONF_STRING,
		certes_conf.min_serial,
		sizeof(certes_conf.min_serial)
	},
	{
		"max_serial",
		FLATCONF_STRING,
		certes_conf.max_serial,
		sizeof(certes_conf.max_serial)
	},
	FLATCONF_LAST
};

void
usage()
{
	printf("Usage: %s [options] <command>\n", CERTES_PROGNAME);
	printf("\t-help            Prints this help\n");
	printf("\t-debug           Do not fork and print errors to STDERR\n");
	printf("\t-config <conf>   Specify alternate configuration path\n");
	printf("\n");
	printf("  Commands:\n");
	printf("\tmdrd-backend     Run as an mdrd backend\n");
	printf("\tinit             Generate our initial key and "
	    "self-signed cert\n");
	printf("\tinit-db          Create the cert DB then exit\n");
	printf("\tbootstrap-setup  Create a bootstrap entry on the "
	    "authority\n");
	printf("\trevoke           Revoke a certificate\n");
}

static void
free_certes_session(void *data)
{
	struct certes_session *cs = (struct certes_session *)data;

	if (cs->challenge != NULL)
		free(cs->challenge);
	if (cs->bootstrap_key != NULL)
		free(cs->bootstrap_key);
	if (cs->req != NULL)
		X509_REQ_free(cs->req);
	free(data);
}

static char client_name_buf[1024];

char *
certes_client_name(struct mdrd_besession *s, char *dst, size_t sz,
    struct xerr *e)
{
	struct certes_session *cs = (struct certes_session *)s->data;
	char                  *buf = dst;
	char                   namebuf[256];
	char                  *cnbuf;
	int                    r;

	if (buf == NULL) {
		buf = client_name_buf;
		sz = sizeof(client_name_buf);
	}

	if ((r = getnameinfo((struct sockaddr *)&s->peer, s->peer_len, namebuf,
	    sizeof(namebuf), NULL, 0, NI_NUMERICHOST)) != 0)
		XERRF(e, XLOG_EAI, r, "getnameinfo");

	if (s->cert == NULL) {
		snprintf(buf, sz, "peer=%s (no certificate)", namebuf);
		return buf;
	}

	cnbuf = cert_subject_oneline(s->cert, NULL);

	snprintf(buf, sz, "peer=%s, subject=%s, verified=%s",
	    namebuf, (cnbuf == NULL) ? "???" : cnbuf,
	    (cs->verified) ? "verified" : "unverified");
	free(cnbuf);

	return buf;
}

static void
task_reload_crls()
{
	struct xerr     e;
	int             r;
	struct pmdr     pm;
	char            pbuf[mdr_spec_base_sz(msg_poll_crls_gen, 0)];
	struct umdr     um;
	struct umdr_vec uv[1];
	char            ubuf[mdr_spec_base_sz(msg_crls_gen, 0)];
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec < next_crl_reload.tv_sec)
		return;
	memcpy(&next_crl_reload, &now, sizeof(next_crl_reload));
	next_crl_reload.tv_sec += 300;

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	if (pmdr_pack(&pm, msg_poll_crls_gen, NULL, 0) == MDR_FAIL)
		abort();

	if (agent_send(pmdr_buf(&pm), pmdr_size(&pm), &e) == -1) {
		xlog(LOG_ERR, &e, "%s: agent_send", __func__);
		return;
	}
	if ((r = agent_recv(ubuf, sizeof(ubuf), &e)) == -1) {
		xlog(LOG_ERR, &e, "%s: agent_recv", __func__);
		return;
	}

	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: umdr_init", __func__);
		return;
	}

	if (umdr_dcv(&um) != MDR_DCV_CERTES_CRLS_GEN) {
		xlog(LOG_ERR, NULL, "%s: unexpected response from agent (%llu)",
		    __func__, umdr_dcv(&um));
		return;
	}

	if (umdr_unpack(&um, msg_crls_gen, uv, UMDRVECLEN(uv)) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: umdr_unpack/msg_crls_gen", __func__);
		return;
	}

	if (uv[0].v.u64 <= crls_gen)
		return;

	xlog(LOG_NOTICE, NULL, "reloading CRLs");
	if (agent_reload_crls(xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		return;
	}

	crls_gen = uv[0].v.u64;
}

int
mdrd_backend()
{
	struct pmdr            pm;
	char                   pbuf[CERTES_MAX_MSG_SIZE * 2];
	X509_STORE_CTX        *ctx;
	struct sigaction       act;
	struct xerr            e;
	struct certes_session *cs;
	ptrdiff_t              r;
	struct mdrd_recvhdl    mrh;
	char                   msgbuf[mdr_spec_base_sz(mdr_msg_mdrd_bein,
	    CERTES_MAX_MSG_SIZE + certes_conf.max_cert_size +
	    sizeof(struct sockaddr_in6))];

	xlog_init(CERTES_PROGNAME, NULL, NULL, 1);

	setproctitle("backend");

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGPIPE, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sigaction", __func__);
		return 1;
	}

	if (cert_init(xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		return 1;
	}

	/* Agent might already be running, don't die if that's the case */
	if (agent_start(xerrz(&e)) == -1 &&
	    !xerr_is(&e, XLOG_ERRNO, EWOULDBLOCK)) {
		xlog(LOG_ERR, &e, __func__);
		return 1;
	}

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	clock_gettime(CLOCK_MONOTONIC, &next_crl_reload);
	next_crl_reload.tv_sec += 300;

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	bzero(&mrh, sizeof(mrh));
	mrh.buf = msgbuf;
	mrh.bufsz = sizeof(msgbuf);
	while ((r = mdrd_recv(&mrh, 1000))) {
		if (r == MDR_FAIL) {
			if (errno == ETIMEDOUT) {
				if ((r = mdrd_purge_sessions(
				    certes_conf.agent_recv_timeout_ms / 1000))
				    > 0)
					xlog(LOG_NOTICE, NULL,
					    "purged %d idle sessions", r);
				task_reload_crls();
				continue;
			}
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdrd_recv", __func__);
			X509_STORE_CTX_free(ctx);
			return 1;
		}

		/*
		 * Verify the client's cert
		 */
		if (mrh.session->is_new) {
			cs = malloc(sizeof(struct certes_session));
			if (cs == NULL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: malloc", __func__);
				mdrd_beout_error(mrh.session, MDRD_BEOUT_FCLOSE,
				    MDR_ERR_BEFAIL, "backend failed");
				continue;
			}
			bzero(cs, sizeof(struct certes_session));
			mdrd_besession_set_data(mrh.session, cs,
			    free_certes_session);

			if (cert_verify(ctx, mrh.session->cert) == 0)
				cs->verified = 1;
		} else
			cs = (struct certes_session *)mrh.session->data;

		/*
		 * The only message we can accept with an invalid cert
		 * is a bootstrap dialin or bootstrap req request.
		 */
		if (!cs->verified &&
		    umdr_dcv(mrh.msg) != MDR_DCV_CERTES_BOOTSTRAP_DIALIN &&
		    umdr_dcv(mrh.msg) != MDR_DCV_CERTES_BOOTSTRAP_ANSWER) {
			xlog(LOG_NOTICE, NULL, "%s: no certificate "
			    "provided, or verification failed",
			    __func__);
			mdrd_beout_error(mrh.session, MDRD_BEOUT_FCLOSE,
			    MDR_ERR_CERTFAIL, "no certificate provided,"
			    " or verification failed");
			continue;
		}

		/*
		 * Client is now verified; let's process their request.
		 */
		switch (umdr_dcv(mrh.msg)) {
		case MDR_DCV_CERTES_BOOTSTRAP_DIALIN:
			if (authority_bootstrap_dialin(mrh.session, mrh.msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_BOOTSTRAP_SETUP:
			if (authority_bootstrap_setup(mrh.session, mrh.msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_REVOKE:
			if (authority_revoke(mrh.session, mrh.msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_BOOTSTRAP_ANSWER:
			if (authority_bootstrap_answer(mrh.session, mrh.msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_CERT_RENEW_ANSWER:
			if (authority_cert_renew_answer(mrh.session, mrh.msg,
			    &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_CERT_RENEWAL_INQUIRY:
			if (authority_cert_renewal_inquiry(mrh.session, mrh.msg,
			    &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_FETCH_OUTDATED_CRLS:
			if (authority_fetch_outdated_crls(mrh.session, mrh.msg,
			    &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTES_BOOTSTRAP_DIALBACK:
		case MDR_DCV_CERTES_CERT_RENEW_DIALBACK:
			/*
			 * For these messages we only need to forward to
			 * the agent, if they come from an authority.
			 */
			if (!cert_has_role(mrh.session->cert, ROLE_AUTHORITY,
			    xerrz(&e))) {
				mdrd_beout_error(mrh.session, MDRD_BEOUT_FNONE,
				    MDR_ERR_DENIED,
				    ROLE_AUTHORITY " role required");
				continue;
			}
			/* Fallthrough */
		case MDR_DCV_CERTES_ERROR:
		case MDR_DCV_MDR_ERROR:
			if (agent_send(umdr_buf(mrh.msg), umdr_size(mrh.msg),
			    &e) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		default:
			xlog(LOG_ERR, NULL, "%s: message not supported (%x)",
			    __func__, umdr_dcv(mrh.msg));
			if (agent_is_authority())
				mdrd_beout_error(mrh.session, MDRD_BEOUT_FNONE,
				    MDR_ERR_NOTSUPP, "not supported");
		}
		task_reload_crls();
	}
	if ((r = mdrd_purge_sessions(0)) > 0)
		xlog(LOG_NOTICE, NULL, "purging %d sessions before exit", r);
	X509_STORE_CTX_free(ctx);
	return 0;
}

void
cleanup()
{
	flatconf_free(certes_config_vars);
	agent_cleanup();
        mdr_registry_clear();
}

int
main(int argc, char **argv)
{
	int             opt, status = 0;
	char           *command;
	size_t          sz;
	struct xerr     e;

	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] != '-')
			break;

		if (strcmp(argv[opt], "-help") == 0) {
			usage();
			exit(0);
		}
		if (strcmp(argv[opt], "-config") == 0) {
			opt++;
			if (opt > argc) {
				usage();
				exit(1);
			}
			strlcpy(config_file_path, argv[opt],
			    sizeof(config_file_path));
			continue;
		}
		if (strcmp(argv[opt], "-debug") == 0) {
			debug = 1;
			continue;
		}
	}

	if (opt >= argc) {
		usage();
		exit(1);
	}

	umask(077);

	if (flatconf_read(config_file_path, certes_config_vars, NULL) == -1)
		err(1, "config_vars_read");

	if (certes_conf.authority_port > 65535 ||
	    certes_conf.authority_port == 0)
		errx(1, "authority_port must be non-zero and <= 65535");

	if (strncmp(certes_conf.min_serial, "0x", 2) != 0)
		errx(1, "min_serial does not begin with \"0x\"");
	sz = strlen(certes_conf.min_serial) - 2;
	memmove(certes_conf.min_serial,
	    certes_conf.min_serial + 2, sz);
	certes_conf.min_serial[sz] = '\0';
	if (!is_hex_str(certes_conf.min_serial))
		errx(1, "min_serial is not a valid hex integer");

	if (strncmp(certes_conf.max_serial, "0x", 2) != 0)
		errx(1, "max_serial does not begin with \"0x\"");
	sz = strlen(certes_conf.max_serial) - 2;
	memmove(certes_conf.max_serial,
	    certes_conf.max_serial + 2, sz);
	certes_conf.max_serial[sz] = '\0';
	if (!is_hex_str(certes_conf.max_serial))
		errx(1, "max_serial is not a valid hexadecimal integer");

	command = argv[opt++];

	load_mdr_defs();

	if (strcmp(command, "mdrd-backend") == 0) {
		status = mdrd_backend();
	} else if (strcmp(command, "bootstrap-setup") == 0) {
		agent_cli_bootstrap_setup(argc - opt, argv + opt);
	} else if (strcmp(command, "revoke") == 0) {
		agent_cli_revoke(argc - opt, argv + opt);
	} else if (strcmp(command, "init") == 0) {
		/*
		 * Do a standalone run to get our initial key/cert,
		 * without mdrd.
		 */
		if (cert_new_privkey(xerrz(&e))) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		if (mkdir(certes_conf.crl_path, 0755) == -1)
			if (errno != EEXIST)
				err(1, "mkdir: %s", certes_conf.crl_path);
	} else if (strcmp(command, "init-db") == 0) {
		if (*certes_conf.certdb_path == '\0')
			errx(1, "certdb_path is unset");
		if (certdb_init(certes_conf.certdb_path, &e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		certdb_shutdown();
	} else {
		usage();
		status = 1;
	}
	cleanup();
	return status;
}
