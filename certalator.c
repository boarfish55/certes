#include <openssl/err.h>
#include <openssl/ssl.h>
#include <err.h>
#include <signal.h>
#include <sys/tree.h>
#include <unistd.h>
#include "agent.h"
#include "authority.h"
#include "cert.h"
#include "certalator.h"
#include "certdb.h"
#include "flatconf.h"
#include "mdr_certalator.h"
#include "mdrd.h"
#include "util.h"
#include "xlog.h"

int  debug = 0;
char config_file_path[PATH_MAX] = "/etc/certalator.conf";

struct certalator_flatconf certalator_conf = {
	0,
	CERTALATOR_AGENT_PORT,
	"",
	CERTALATOR_AGENT_PORT,
	"",
	60000,
	60000,
	"",
	30,                       /* challenge_timeout */
	"ca.pem",
	"",
	"",
	"key.pem",
	"cert.pem",
	"agent.lock",
	"agent.sock",
	4096,
	"serial",
	"",
	"",

	"0x0",
	"0x0"
};

struct flatconf certalator_config_vars[] = {
	{
		"enable_coredumps",
		FLATCONF_BOOLINT,
		&certalator_conf.enable_coredumps,
		sizeof(certalator_conf.enable_coredumps)
	},
	{
		"agent_bootstrap_port",
		FLATCONF_ULONG,
		&certalator_conf.agent_bootstrap_port,
		sizeof(certalator_conf.agent_bootstrap_port)
	},
	{
		"authority_fqdn",
		FLATCONF_STRING,
		certalator_conf.authority_fqdn,
		sizeof(certalator_conf.authority_fqdn)
	},
	{
		"authority_port",
		FLATCONF_ULONG,
		&certalator_conf.authority_port,
		sizeof(certalator_conf.authority_port)
	},
	{
		"certdb_path",
		FLATCONF_STRING,
		certalator_conf.certdb_path,
		sizeof(certalator_conf.certdb_path)
	},
	{
		"agent_send_timeout_ms",
		FLATCONF_ULONG,
		&certalator_conf.agent_send_timeout_ms,
		sizeof(certalator_conf.agent_send_timeout_ms)
	},
	{
		"agent_recv_timeout_ms",
		FLATCONF_ULONG,
		&certalator_conf.agent_recv_timeout_ms,
		sizeof(certalator_conf.agent_recv_timeout_ms)
	},
	{
		"bootstrap_key",
		FLATCONF_STRING,
		certalator_conf.bootstrap_key,
		sizeof(certalator_conf.bootstrap_key)
	},
	{
		"challenge_timeout_seconds",
		FLATCONF_ULONG,
		&certalator_conf.challenge_timeout_seconds,
		sizeof(certalator_conf.challenge_timeout_seconds)
	},
	{
		"ca_file",
		FLATCONF_STRING,
		certalator_conf.ca_file,
		sizeof(certalator_conf.ca_file)
	},
	{
		"crl_file",
		FLATCONF_STRING,
		certalator_conf.crl_file,
		sizeof(certalator_conf.crl_file)
	},
	{
		"crl_path",
		FLATCONF_STRING,
		certalator_conf.crl_path,
		sizeof(certalator_conf.crl_path)
	},
	{
		"key_file",
		FLATCONF_STRING,
		certalator_conf.key_file,
		sizeof(certalator_conf.key_file)
	},
	{
		"cert_file",
		FLATCONF_STRING,
		certalator_conf.cert_file,
		sizeof(certalator_conf.cert_file)
	},
	{
		"lock_file",
		FLATCONF_STRING,
		certalator_conf.lock_file,
		sizeof(certalator_conf.lock_file)
	},
	{
		"agent_socket_path",
		FLATCONF_STRING,
		certalator_conf.agent_sock_path,
		sizeof(certalator_conf.agent_sock_path)
	},
	{
		"max_cert_size",
		FLATCONF_ULONG,
		&certalator_conf.max_cert_size,
		sizeof(certalator_conf.max_cert_size)
	},
	{
		"serial_file",
		FLATCONF_STRING,
		certalator_conf.serial_file,
		sizeof(certalator_conf.serial_file)
	},
	{
		"cert_org",
		FLATCONF_STRING,
		certalator_conf.cert_org,
		sizeof(certalator_conf.cert_org)
	},
	{
		"cert_email",
		FLATCONF_STRING,
		certalator_conf.cert_email,
		sizeof(certalator_conf.cert_email)
	},
	{
		"min_serial",
		FLATCONF_STRING,
		certalator_conf.min_serial,
		sizeof(certalator_conf.min_serial)
	},
	{
		"max_serial",
		FLATCONF_STRING,
		certalator_conf.max_serial,
		sizeof(certalator_conf.max_serial)
	},
	FLATCONF_LAST
};

void
usage()
{
	printf("Usage: %s [options] <command>\n", CERTALATOR_PROGNAME);
	printf("\t-help            Prints this help\n");
	printf("\t-debug           Do not fork and print errors to STDERR\n");
	printf("\t-config <conf>   Specify alternate configuration path\n");
	printf("\n");
	printf("  Commands:\n");
	printf("\tverify           Ensures the certificate is signed by our "
	    "authority\n");
	printf("\tsign             Re-signs the certificate\n");
	printf("\tmdrd-backend     Run as an mdrd backend\n");
	printf("\tinit             Generate our initial key and "
	    "self-signed cert\n");
	printf("\tinit-db          Create the cert DB then exit\n");
	printf("\tbootstrap-setup  Create a bootstrap entry on the "
	    "authority\n");
}

int
mdrd_backend()
{
	struct pmdr             pm;
	char                    pbuf[32768];
	struct umdr             msg;
	char                    msgbuf[16384];
	X509_STORE_CTX         *ctx;
	struct sigaction        act;
	struct xerr             e;
	struct mdrd_besession  *sess;

	xlog_init(CERTALATOR_PROGNAME, NULL, NULL, 1);

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sigaction", __func__);
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

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	while (mdrd_recv(&msg, msgbuf, sizeof(msgbuf),
	    certalator_conf.max_cert_size, MDR_DOMAIN_CERTALATOR, MDR_FNONE,
	    &sess) > 0) {
		/*
		 * Verify the client's cert
		 */
		if (cert_verify(ctx, sess->cert, 0) != 0) {
			/*
			 * We can still accept a bootstrap if the cert is not
			 * valid.
			 */
			if (umdr_dcv(&msg) ==
			    MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN) {
				if (authority_bootstrap_dialin(sess, &msg, &e)
				    == MDR_FAIL)
					xlog(LOG_ERR, &e, "%s", __func__);
				continue;
			}

			xlog(LOG_NOTICE, NULL, "%s: no certificate provided, "
			    "or verification failed", __func__);
			mdrd_beresp_error(sess, MDRD_BERESP_FCLOSE,
			    MDR_ERR_CERTFAIL, "no certificate provided, "
			    "or verification failed");
			continue;
		}

		/*
		 * Client is now verified; let's process their request.
		 */
		switch (umdr_dcv(&msg)) {
		case MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN:
			if (authority_bootstrap_dialin(sess, &msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP:
			if (authority_bootstrap_setup(sess, &msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTALATOR_BOOTSTRAP_REQ:
			if (authority_bootstrap_req(sess, &msg, &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		case MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK:
		case MDR_DCV_CERTALATOR_BOOTSTRAP_SEND_CERT:
			/*
			 * For these messages we only need to forward to
			 * the agent, if they come from an authority.
			 */
			if (!cert_has_role(sess->cert, ROLE_AUTHORITY,
			    xerrz(&e))) {
				mdrd_beresp_error(sess, MDRD_BERESP_FNONE,
				    MDR_ERR_DENIED,
				    ROLE_AUTHORITY " role required");
				continue;
			}
			if (agent_send(umdr_buf(&msg), umdr_size(&msg),
			    &e) == -1)
				xlog(LOG_ERR, &e, "%s", __func__);
			break;
		default:
			mdrd_beresp_error(sess, MDRD_BERESP_FNONE,
			    MDR_ERR_NOTSUPP, "not supported");
		}
	}
	X509_STORE_CTX_free(ctx);
	return 0;
}

void
cleanup()
{
	flatconf_free(certalator_config_vars);
	agent_cleanup();
}

int
main(int argc, char **argv)
{
	int             opt, status;
	char           *command;
	size_t          sz;
	FILE           *f;
	X509           *crt, *newcrt;
	X509_STORE_CTX *ctx;
	struct xerr     e;
	char            crtpath[PATH_MAX];

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

	if (flatconf_read(config_file_path, certalator_config_vars, NULL) == -1)
		err(1, "config_vars_read");

	if (certalator_conf.authority_port > 65535 ||
	    certalator_conf.authority_port == 0)
		errx(1, "authority_port must be non-zero and <= 65535");

	if (strncmp(certalator_conf.min_serial, "0x", 2) != 0)
		errx(1, "min_serial does not begin with \"0x\"");
	sz = strlen(certalator_conf.min_serial) - 2;
	memmove(certalator_conf.min_serial,
	    certalator_conf.min_serial + 2, sz);
	certalator_conf.min_serial[sz] = '\0';
	if (!is_hex_str(certalator_conf.min_serial))
		errx(1, "min_serial is not a valid hex integer");

	if (strncmp(certalator_conf.max_serial, "0x", 2) != 0)
		errx(1, "max_serial does not begin with \"0x\"");
	sz = strlen(certalator_conf.max_serial) - 2;
	memmove(certalator_conf.max_serial,
	    certalator_conf.max_serial + 2, sz);
	certalator_conf.max_serial[sz] = '\0';
	if (!is_hex_str(certalator_conf.max_serial))
		errx(1, "max_serial is not a valid hexadecimal integer");

	command = argv[opt++];

	load_mdr_defs();

	if (strcmp(command, "verify") == 0) {
		if (opt >= argc)
			errx(1, "no certificate file provided");
		if ((f = fopen(argv[opt], "r")) == NULL)
			err(1, "fopen");
		if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);
		if (agent_init(&e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		if ((ctx = X509_STORE_CTX_new()) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		status = cert_verify(ctx, crt, 0);
		X509_STORE_CTX_free(ctx);
	} else if (strcmp(command, "sign") == 0) {
		if (opt >= argc)
			errx(1, "no certificate file provided");

		if (agent_init(&e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}

		if ((f = fopen(argv[opt], "r")) == NULL)
			err(1, "fopen: %s", argv[opt]);
		if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);

		newcrt = cert_sign(crt, agent_cert(), agent_key(),
		    (const char **)argv + opt + 1);
		if (newcrt == NULL) {
			xlog(LOG_ERR, &e, "cert_sign");
			exit(1);
		}

		snprintf(crtpath, sizeof(crtpath), "%s.new", argv[opt]);
		if ((f = fopen(crtpath, "w")) == NULL)
			err(1, "fopen: %s", crtpath);
		if (!PEM_write_X509(f, newcrt)) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);
	} else if (strcmp(command, "mdrd-backend") == 0) {
		if (*certalator_conf.certdb_path != '\0' &&
		    certdb_init(certalator_conf.certdb_path, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		status = mdrd_backend();
	} else if (strcmp(command, "bootstrap-setup") == 0) {
		agent_bootstrap_setup_cli(argc - opt, argv + opt);
	} else if (strcmp(command, "init") == 0) {
		/*
		 * Do a standalone run to get our initial key/cert,
		 * without mdrd.
		 */
		if (*certalator_conf.certdb_path != '\0' &&
		    certdb_init(certalator_conf.certdb_path, xerrz(&e)) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
		if (cert_new_privkey(xerrz(&e))) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
	} else if (strcmp(command, "init-db") == 0) {
		if (*certalator_conf.certdb_path == '\0')
			errx(1, "certdb_path is unset");
		if (certdb_init(certalator_conf.certdb_path, &e) == -1) {
			xlog(LOG_ERR, &e, __func__);
			exit(1);
		}
	} else {
		usage();
		status = 1;
	}
	cleanup();
	return status;
}
