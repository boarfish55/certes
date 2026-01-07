#include <openssl/err.h>
#include <openssl/ssl.h>
#include <err.h>
#include <signal.h>
#include <sys/tree.h>
#include <unistd.h>
#include "agent.h"
#include "authority.h"
#include "coordinator.h"
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
	"",
	9790,
	"certdb.sqlite",
	"",
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
		"bootstrap_key",
		FLATCONF_STRING,
		certalator_conf.bootstrap_key,
		sizeof(certalator_conf.bootstrap_key)
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
		"coordinator_socket_path",
		FLATCONF_STRING,
		certalator_conf.coordinator_sock_path,
		sizeof(certalator_conf.coordinator_sock_path)
	},
	{
		"key_bits",
		FLATCONF_ULONG,
		&certalator_conf.key_bits,
		sizeof(certalator_conf.key_bits)
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
	printf("\tbootstrap-setup  Create a bootstrap entry on the "
	    "authority\n");
}

void
bootstrap_setup_usage()
{
	printf("Usage: %s bootstrap-setup [options] <cn> <roles...>\n",
	    CERTALATOR_PROGNAME);
	printf("\t--help        Prints this help\n");
	printf("\t--timeout     Validity of bootstrap entry in "
	    "seconds (default 600)\n");
	printf("\t--cert_expiry Validity of certificate in "
	    "seconds (default 7*86400)\n");
	printf("\t--san         Adds a Subject Alt Name to this "
	    "bootstrap entry\n");
	printf("\t--role        Adds a role to this bootstrap entry\n");
}

struct cl_session
{
	uint64_t                 id;
	X509                    *cert;
	SPLAY_ENTRY(cl_session)  entries;
};

static int
cl_session_cmp(struct cl_session *c1, struct cl_session *c2)
{
	return (c1->id < c2->id) ? -1 : c1->id > c2->id;
}

SPLAY_HEAD(cl_session_tree, cl_session) cl_sessions = SPLAY_INITIALIZER(&cl_sessions);
SPLAY_PROTOTYPE(cl_session_tree, cl_session, entries, cl_session_cmp);
SPLAY_GENERATE(cl_session_tree, cl_session, entries, cl_session_cmp);

void
cl_session_free(struct cl_session *cs)
{
	if (cs == NULL)
		return;

	SPLAY_REMOVE(cl_session_tree, &cl_sessions, cs);
	if (cs->cert != NULL)
		X509_free(cs->cert);
	free(cs);
}

static int
mdrd_error_resp(uint64_t id, int fd, uint32_t status, uint32_t flags)
{
	struct pmdr     pm;
	struct pmdr_vec pv[4];
	char            pbuf[128];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U64;
	pv[0].v.u64 = id;
	pv[1].type = MDR_I32;
	pv[1].v.i32 = fd;
	pv[2].type = MDR_U32;
	pv[2].v.u32 = status;
	pv[3].type = MDR_U32;
	pv[3].v.u32 = flags;
	if (pmdr_pack(&pm, mdr_msg_mdrd_beresp, pv, PMDRVECLEN(pv)) ==
	    MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: pmdr_pack", __func__);
		return -1;
	}
	if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm)) {
		xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
		return -1;
	}
	return 0;
}

int
mdrd_beresp_wmsg(uint64_t id, int fd, struct pmdr *msg)
{
	struct pmdr     pm;
	struct pmdr_vec pv[5];
	char            pbuf[16384];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U64;
	pv[0].v.u64 = id;
	pv[1].type = MDR_I32;
	pv[1].v.i32 = fd;
	pv[2].type = MDR_U32;
	pv[2].v.u32 = MDRD_BERESP_OK;
	pv[3].type = MDR_U32;
	pv[3].v.u32 = MDRD_BERESP_FNONE;
	pv[4].type = MDR_M;
	pv[4].v.pmdr = msg;
	if (pmdr_pack(&pm, mdr_msg_mdrd_beresp_wmsg, pv, PMDRVECLEN(pv)) ==
	    MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: pmdr_pack", __func__);
		return -1;
	}
	if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm)) {
		xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
		return -1;
	}
	return 0;
}

int
mdrd_backend()
{
	int                  r, fd;
	struct pmdr          pm;
	struct umdr          um, msg;
	struct pmdr_vec      pv[5];
	char                 ubuf[32768];
	char                 pbuf[32768];
	char                 msgbuf[16384];
	uint64_t             id;
	X509                *peer_cert = NULL;
	X509_STORE_CTX      *ctx;
	struct sigaction     act;
	struct xerr          e;
	struct sockaddr_in6  peer;
	socklen_t            slen = sizeof(peer);
	struct cl_session   *csess = NULL, needle;

	xlog_init(CERTALATOR_PROGNAME, NULL, NULL, 1);

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sigaction", __func__);
		return 1;
	}

	if (agent_init(xerrz(&e)) == -1) {
		xlog(LOG_ERR, &e, __func__);
		exit(1);
	}

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	// TODO: we'll end up polling here between stdin and the agent's
	// unix socket in case we get a control message of some sort.
	while ((r = mdr_buf_from_fd(0, ubuf, sizeof(ubuf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_read_from_fd", __func__);
			goto fail;
		}

		if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: umdr_init", __func__);
			pv[0].type = MDR_U32;
			pv[0].v.u32 = MDRD_ERROR_OS;
			pv[1].type = MDR_S;
			pv[1].v.s = strerror(errno);
			if (pmdr_pack(&pm, mdr_msg_mdrd_error, pv, 2) == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno, "%s: pmdr_pack", __func__);
				return -1;
			}
			if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm)) {
				xlog_strerror(LOG_ERR, errno, "%s: writeall", __func__);
				return -1;
			}
			continue;
		}

		if (!umdr_dcv_match(&um, MDR_DOMAIN_MDRD, MDR_MASK_D)) {
			xlog(LOG_ERR, NULL, "invalid mdr domain %u",
			    umdr_domain(&um));
			mdrd_error_resp(id, fd,
			    MDRD_BERESP_BADMSG, MDRD_BERESP_FNONE);
			continue;
		}

		if (umdr_dcv(&um) == MDR_DCV_MDRD_BECLOSE) {
			if (mdrd_unpack_beclose(&um, &id) == MDR_FAIL) {
				if (errno == EAGAIN)
					xlog(LOG_ERR, NULL,
					    "%s: mdrd_unpack_beclose: "
					    "missing bytes in payload",
					    __func__);
				else
					xlog_strerror(LOG_ERR, errno,
					    "%s: mdrd_unpack_beclose",
					    __func__);
				mdrd_error_resp(id, fd, MDRD_BERESP_BEFAIL,
				    MDRD_BERESP_FNONE);
				continue;
			}
			needle.id = id;
			csess = SPLAY_FIND(cl_session_tree, &cl_sessions,
			    &needle);
			if (csess == NULL)
				continue;

			xlog(LOG_NOTICE, NULL,
			    "cleaning up client session for id %lu", id);
			cl_session_free(csess);
			/*
			 * No response is expected on BECLOSE.
			 */
			continue;
		}

		if (umdr_dcv(&um) != MDR_DCV_MDRD_BEREQ) {
			xlog(LOG_NOTICE, NULL,
			    "%s: unexpected message DCV received: %x",
			    __func__, umdr_dcv(&um));
			mdrd_error_resp(id, fd, MDRD_BERESP_BADMSG,
			    MDRD_BERESP_FNONE);
			continue;
		}

		umdr_init0(&msg, msgbuf, sizeof(msgbuf), MDR_FNONE);
		if (mdrd_unpack_bereq(&um, &id, &fd, (struct sockaddr *)&peer,
		    &slen, &msg, &peer_cert) == MDR_FAIL) {
			if (errno == EAGAIN)
				xlog(LOG_ERR, NULL,
				    "%s: mdrd_unpack_bereq: missing bytes "
				    "in payload", __func__);
			else
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdrd_unpack_bereq", __func__);
			mdrd_error_resp(id, fd, MDRD_BERESP_BEFAIL,
			    MDRD_BERESP_FNONE);
			continue;
		}

		if (!umdr_dcv_match(&msg, MDR_DOMAIN_CERTALATOR, MDR_MASK_D)) {
			xlog(LOG_NOTICE, NULL,
			    "%s: expected a certalator message (domain=%x) "
			    "but got %x", __func__, MDR_DOMAIN_CERTALATOR,
			    umdr_domain(&msg));
			mdrd_error_resp(id, fd, MDRD_BERESP_BADMSG,
			    MDRD_BERESP_FNONE);
			continue;
		}

		needle.id = id;
		csess = SPLAY_FIND(cl_session_tree, &cl_sessions, &needle);
		if (csess == NULL) {
			csess = malloc(sizeof(struct cl_session));
			if (csess == NULL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: malloc", __func__);
				mdrd_error_resp(id, fd, MDRD_BERESP_BEFAIL,
				    MDRD_BERESP_FNONE);
				continue;
			}
			csess->id = id;
			csess->cert = peer_cert;
			SPLAY_INSERT(cl_session_tree, &cl_sessions, csess);
		}

		/*
		 * If the client has no cert, then the only option is
		 * to issue a new cert, if we are an authority.
		 */
		if (csess->cert == NULL) {
			if (umdr_dcv(&msg) !=
			    MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN) {
				xlog(LOG_NOTICE, NULL,
				    "%s: client did not provide a cert; only "
				    "a bootstrap setup message (id=%x) can be "
				    "processed but got %x", __func__,
				    MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP,
				    umdr_dcv(&msg));
				mdrd_error_resp(id, fd, MDRD_BERESP_BADMSG,
				    MDRD_BERESP_FNONE);
				continue;
			}

			if (!agent_is_authority()) {
				xlog(LOG_ERR, NULL, "%s: we are not an "
				    "authority and client has no certificate",
				    __func__);
				mdrd_error_resp(id, fd, MDRD_BERESP_NOCERT,
				    MDRD_BERESP_FNONE);
				cl_session_free(csess);
				continue;
			}

			if (authority_bootstrap_dialin(&msg, &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);
			continue;
		}

		/*
		 * Verify the client's cert
		 */
		if (cert_verify(ctx, csess->cert, agent_cert_store(), 0) != 0) {
			xlog(LOG_NOTICE, NULL, "%s: cert_verify failed for "
			    "client on fd %d", __func__, fd);
			mdrd_error_resp(id, fd, MDRD_BERESP_CERTFAIL,
			    MDRD_BERESP_FCLOSE);
			cl_session_free(csess);
			continue;
		}

		/*
		 * Client is now verified; let's process their request.
		 */
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		switch (umdr_dcv(&msg)) {
		case MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP:
			if (!cert_has_role(csess->cert, "bootstrap",
			    xerrz(&e))) {
				mdrd_error_resp(id, fd, MDRD_BERESP_DENIED,
				    MDRD_BERESP_FNONE);
				continue;
			}

			if (authority_bootstrap_setup_msg(&msg, &e) ==
			    MDR_FAIL) {
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);
				mdrd_error_resp(id, fd, MDRD_BERESP_BEFAIL,
				    MDRD_BERESP_FCLOSE);
				continue;
			}

			if (pmdr_pack(&pm, msg_bootstrap_setup_resp_ok, NULL, 0)
			    == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: pmdr_pack", __func__);
				mdrd_error_resp(id, fd, MDRD_BERESP_BEFAIL,
				    MDRD_BERESP_FCLOSE);
				continue;
			}
			mdrd_beresp_wmsg(id, fd, &pm);
			break;
		case MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK:
			// TODO: needs to have role "agent", and the client
			// needs to have the "authority" role
			mdrd_error_resp(id, fd, MDRD_BERESP_BADMSG,
			    MDRD_BERESP_FNONE);
			break;
		default:
			mdrd_error_resp(id, fd, MDRD_BERESP_BADMSG,
			    MDRD_BERESP_FNONE);
		}
	}
	X509_STORE_CTX_free(ctx);
	return 0;
fail:
	X509_STORE_CTX_free(ctx);
	return 1;
}

void
bootstrap_setup_cli(int argc, char **argv)
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
	struct umdr_vec   uv[1];
	char              ubuf[1024];
	struct xerr       e;

	if (agent_init(&e) == -1) {
		xlog(LOG_ERR, &e, __func__);
		exit(1);
	}

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

	if (agent_send(&pm, xerrz(&e)) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if ((r = agent_recv(ubuf, sizeof(ubuf), xerrz(&e))) == -1) {
		xerr_print(&e);
		exit(1);
	}

	if (umdr_init(&um, ubuf, r, MDR_FNONE) == MDR_FAIL) {
		xerr_print(&e);
		exit(1);
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP_RESP_OK:
		break;
	case MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP_RESP_ERR:
		if (umdr_unpack(&um, msg_bootstrap_setup_resp_err, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "umdr_unpack");
		errx(1, "bootstrap setup failed: %s", uv[0].v.s.bytes);
	case MDR_DCV_MDR_ERROR:
		if (umdr_unpack(&um, mdr_msg_error, uv,
		    UMDRVECLEN(uv)) == MDR_FAIL)
			err(1, "umdr_unpack");
		errx(1, "bootstrap setup failed: %s", uv[0].v.s.bytes);
	default:
		errx(1, "bad response from authority");
	}

	free(sans);
	free(roles);
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

	if (certdb_init(certalator_conf.certdb_path, &e) == -1) {
		xlog(LOG_ERR, &e, __func__);
		return -1;
	}

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
		status = cert_verify(ctx, crt, agent_cert_store(), 0);
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
		status = mdrd_backend();
	} else if (strcmp(command, "bootstrap-setup") == 0) {
		bootstrap_setup_cli(argc - opt, argv + opt);
	} else {
		usage();
		status = 1;
	}
	cleanup();
	return status;
}
