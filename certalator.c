#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "authority.h"
#include "coordinator.h"
#include "cert.h"
#include "certalator.h"
#include "certdb.h"
#include "flatconf.h"
#include "mdr_certalator.h"
#include "mdr_mdrd.h"
#include "util.h"
#include "xlog.h"

extern X509_STORE *store;

EVP_PKEY    *agent_key = NULL;
X509        *agent_cert = NULL;
X509        *ca_crt = NULL;
X509_CRL    *ca_crl = NULL;
int          debug = 0;
char         config_file_path[PATH_MAX] = "/etc/certalator.conf";
SSL_CTX     *agent_ssl_ctx = NULL;
SSL         *agent_ssl = NULL;
BIO         *agent_bio = NULL;
int          agent_connected = 0;
int          agent_is_authority = 0;
const char **agent_roles = NULL;

struct certalator_flatconf certalator_conf = {
	0,
	"",
	9790,
	"ca/certdb.sqlite",
	"",
	"ca/overnet.pem",
	"ca/overnet.crl",
	"overnet_key.pem",
	"overnet_crt.pem",
	".lock",
	"agent.sock",
	4096,
	"ca/serial",
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

void load_keys();

int
agent_connect(struct xerr *e)
{
	char host[302];

	if (certalator_conf.authority_fqdn[0] == '\0')
		return XERRF(e, XLOG_APP, XLOG_EDESTADDRREQ,
		    "no destination address was specified");

	if (agent_ssl_ctx == NULL) {
		if ((agent_ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_new");

		SSL_CTX_set_verify(agent_ssl_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_cert_store(agent_ssl_ctx, store);

		if (SSL_CTX_use_PrivateKey(agent_ssl_ctx, agent_key) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_PrivateKey");
		if (SSL_CTX_use_certificate(agent_ssl_ctx, agent_cert) != 1)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "SSL_CTX_use_certificate");
	}

	if (agent_bio == NULL) {
		if (snprintf(host, sizeof(host), "%s:%lu",
		    certalator_conf.authority_fqdn,
		    certalator_conf.authority_port) >= sizeof(host))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "resulting host:port is too long");

		if ((agent_bio = BIO_new_ssl_connect(agent_ssl_ctx)) == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_new_ssl_connect");

		BIO_get_ssl(agent_bio, &agent_ssl);
		if (agent_ssl == NULL)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_get_ssl");

		SSL_set_mode(agent_ssl, SSL_MODE_AUTO_RETRY);
		BIO_set_conn_hostname(agent_bio, host);
	}

	if (!agent_connected) {
		if (BIO_do_connect(agent_bio) <= 0)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_do_connect");

		if (BIO_do_handshake(agent_bio) <= 0)
			return XERRF(e, XLOG_SSL, ERR_get_error(),
			    "BIO_do_handshake");
		agent_connected = 1;
	}

	return 0;
}

int
agent_send(struct mdr *m, struct xerr *e)
{
	int r;

	if (agent_connect(e) == -1)
		return -1;

	if ((r = BIO_write(agent_bio, mdr_buf(m), mdr_size(m))) == -1)
		return XERRF(e, XLOG_SSL, ERR_get_error(), "BIO_write");
	else if (r < mdr_size(m))
		return XERRF(e, XLOG_APP, XLOG_SHORTIO, "BIO_write");

	return 0;

}

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

int
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

	if (!X509_REQ_set_pubkey(req, agent_key)) {
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

	if (BIO_get_fd(agent_bio, &sockfd) <= 0) {
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
	if (asprintf(&sans, "iPAddress:%s", taddr) == -1) {
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

	if (!X509_REQ_sign(req, agent_key, EVP_sha256())) {
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

/*
 * Contact the authority to send our bootstrap key in order to obtain
 * our certificate parameters and create our key and REQ.
 */
FILE *
agent_bootstrap_dialin(struct xerr *e)
{
	struct mdr       m;
	char             buf[1024];
	char            *subject = NULL;
	char             req_id[CERTALATOR_REQ_ID_LENGTH];
	struct mdr_in    m_in[2];
	struct mdr_out   m_out[1];
	struct timespec  now;
	int              try;
	unsigned char   *req_buf;
	size_t           req_len;

	if (strlen(certalator_conf.bootstrap_key) !=
	    CERTALATOR_BOOTSTRAP_KEY_LENGTH_B64) {
		XERRF(e, XLOG_APP, XLOG_INVAL,
		    "bad bootstrap key format in configuration; bad length");
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

	m_in[0].type = MDR_S;
	m_in[0].v.s.bytes = req_id;
	m_in[1].type = MDR_S;
	m_in[1].v.s.bytes = certalator_conf.bootstrap_key;
	if (mdr_pack(&m, buf, sizeof(buf), msg_bootstrap_dialin,
	    MDR_F_NONE, m_in, 2) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_pack/msg_bootstrap_dialin");
		return NULL;
	}

	if (agent_send(&m, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	/*
	 * The coordinator should be receiving a challenge from the authority,
	 * so let's poll for a bit to see if we got it.
	 */
	for (try = 0; try < 10; try++) {
		m_in[0].type = MDR_S;
		m_in[0].v.s.bytes = req_id;
		if (mdr_pack(&m, buf, sizeof(buf), msg_coord_get_cert_challenge,
		    MDR_F_NONE, m_in, 1) == MDR_FAIL) {
			XERRF(e, XLOG_ERRNO, errno,
			    "mdr_pack/msg_coord_get_cert_challenge");
			return NULL;
		}

		if (coordinator_send(&m, xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		if (coordinator_recv(&m, buf, sizeof(buf), xerrz(e)) == -1) {
			XERR_PREPENDFN(e);
			return NULL;
		}

		if (mdr_dcv(&m) ==
		    MDR_DCV_CERTALATOR_COORD_GET_CERT_CHALLENGE_RESP)
			break;

		/* Retry for any other answer */
	}
	if (try == 10) {
		XERRF(e, XLOG_APP, XLOG_TIMEOUT, "challenge timed out");
		return NULL;
	}

	if (mdr_unpack_payload(&m, msg_coord_get_cert_challenge_resp,
	    m_out, 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_unpack_payload");
		return NULL;
	}

	/*
	 * Send the challenge back to the authority.
	 */
	m_in[0].type = MDR_B;
	m_in[0].v.s.bytes = m_out[1].v.s.bytes;
	m_in[0].v.s.sz = m_out[1].v.s.sz;
	if (mdr_pack(&m, buf, sizeof(buf), msg_bootstrap_answer_challenge,
	    MDR_F_NONE, m_in, 1) == MDR_FAIL) {
		XERRF(e, XLOG_ERRNO, errno, "mdr_pack/msg_bootstrap_dialin");
		return NULL;
	}
	if (agent_send(&m, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	// TODO: Receive DIALIN_RESP, see if we succeeded the challenge

	if (agent_new_req(subject, &req_buf, &req_len, xerrz(e)) == -1) {
		XERR_PREPENDFN(e);
		return NULL;
	}

	// TODO: we send MDR_DCV_CERTALATOR_BOOTSTRAP_REQ

	return NULL;
}

void
load_keys()
{
	FILE        *f;
#ifndef __OpenBSD__
	int          pkey_sz;
#endif
	struct xerr  e;

	if ((f = fopen(certalator_conf.key_file, "r")) == NULL) {
		if (errno == ENOENT) {
			warnx("no private key found, generating one");
			f = cert_new_privkey();
		} else
			err(1, "fopen");
	}
	if ((agent_key = PEM_read_PrivateKey(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

#ifndef __OpenBSD__
	if (!(pkey_sz = EVP_PKEY_size(agent_key))) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/* pledge() doesn't allow mlock() */
	if (mlock(agent_key, pkey_sz) == -1)
		err(1, "mlock");
#endif
	if (!X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT|
	    X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((f = fopen(certalator_conf.ca_file, "r")) == NULL)
		err(1, "fopen: %s", certalator_conf.ca_file);
	if ((ca_crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);
	if (!X509_STORE_add_cert(store, ca_crt)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((f = fopen(certalator_conf.crl_file, "r")) == NULL)
		err(1, "fopen: %s", certalator_conf.crl_file);
	if ((ca_crl = PEM_read_X509_CRL(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);
	if (!X509_STORE_add_crl(store, ca_crl)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if ((f = fopen(certalator_conf.cert_file, "r")) == NULL) {
		if (errno != ENOENT)
			err(1, "fopen: %s", certalator_conf.cert_file);
		f = agent_bootstrap_dialin(&e);
	}
	if ((agent_cert = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose(f);

	if (!X509_STORE_add_cert(store, agent_cert)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	agent_is_authority = cert_has_role(agent_cert,
	    ROLE_AUTHORITY, xerrz(&e));

	if (agent_is_authority == -1) {
		xlog(LOG_ERR, &e, "%s: cert_has_role", __func__);
		exit(1);
	}

	/*
	 * We're not calling X509_LOOKUP_free() as this causes a segfault
	 * if we try reusing X509_LOOKUP_file().
	 */
}

int
mdrd_backend()
{
	int               r, fd;
	struct mdr        m, msg;
	char              buf[32768];
	uint64_t          id;
	X509             *peer_cert = NULL;
	X509_STORE_CTX   *ctx;
	struct sigaction  act;
	struct xerr       e;
	struct mdr_in     m_in[5];

	xlog_init(CERTALATOR_PROGNAME, NULL, NULL, 1);

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) == -1 ||
	    sigaction(SIGTERM, &act, NULL) == -1) {
		xlog_strerror(LOG_ERR, errno, "%s: sigaction", __func__);
		return 1;
	}

	load_keys();

	if ((ctx = X509_STORE_CTX_new()) == NULL) {
		xlog(LOG_ERR, NULL, "X509_STORE_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	// TODO: we'll end up polling here between stdin and the agent's
	// unix socket in case we get a control message of some sort.
	while ((r = mdr_read_from_fd(&m, MDR_F_NONE,
	    0, buf, sizeof(buf))) > 0) {
		if (r == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_read_from_fd", __func__);
			goto fail;
		}

		if (mdr_dcv(&m) != MDR_DCV_MDRD_BEREQ) {
			xlog(LOG_NOTICE, NULL,
			    "%s: unexpected message DCV received: %x",
			    __func__, mdr_dcv(&m));
			continue;
		}

		if (mdrd_unpack_bereq(&m, &id, &fd, &msg,
		    &peer_cert) == MDR_FAIL) {
			if (errno == EAGAIN)
				xlog(LOG_ERR, NULL,
				    "%s: mdrd_unpack_bereq: missing bytes "
				    "in payload", __func__);
			else
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdrd_unpack_bereq", __func__);
			continue;
		}

		if (mdr_domain(&msg) != MDR_DOMAIN_CERTALATOR) {
			xlog(LOG_NOTICE, NULL,
			    "%s: expected a certalator message (domain=%x) "
			    "but got %x", __func__, mdr_domain(&msg));
			continue;
		}

		if (peer_cert == NULL) {
			if (mdr_dcv(&msg) !=
			    MDR_DCV_CERTALATOR_BOOTSTRAP_DIALIN) {
				xlog(LOG_NOTICE, NULL,
				    "%s: client did not provide a cert; only "
				    "a bootstrap setup message (id=%x) can be "
				    "processed but got %x", __func__,
				    MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP,
				    mdr_dcv(&msg));
				continue;
			}

			if (!agent_is_authority) {
				xlog(LOG_ERR, NULL, "%s: we are not an "
				    "authority and client has no certificate",
				    __func__);
				m_in[0].type = MDR_U32;
				m_in[0].v.u32 = id;
				m_in[1].type = MDR_I32;
				m_in[1].v.i32 = fd;
				m_in[2].type = MDR_U32;
				m_in[2].v.u32 = MDRD_ST_NOCERT;
				m_in[3].type = MDR_U32;
				m_in[3].v.u32 = MDRD_BERESP_F_CLOSE;
				if (mdr_pack(&m, buf, sizeof(buf),
				    msg_pack_beresp, MDR_F_NONE, m_in, 4)
				    == MDR_FAIL) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: mdr_pack", __func__);
					goto fail;
				}
				if (write(1, mdr_buf(&m), mdr_size(&m))
				    < mdr_size(&m)) {
					xlog_strerror(LOG_ERR, errno,
					    "%s: writeall", __func__);
					goto fail;
				}
				continue;
			}

			if (authority_bootstrap_dialin(&m, &msg, &e)
			    == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);
			continue;
		}

		if (cert_verify(ctx, peer_cert, 0) != 0) {
			xlog(LOG_NOTICE, NULL, "%s: cert_verify failed for "
			    "client on fd %d", __func__, fd);
			if (peer_cert != NULL)
				X509_free(peer_cert);
			m_in[0].type = MDR_U32;
			m_in[0].v.u32 = id;
			m_in[1].type = MDR_I32;
			m_in[1].v.i32 = fd;
			m_in[2].type = MDR_U32;
			m_in[2].v.u32 = MDRD_ST_CERTFAIL;
			m_in[3].type = MDR_U32;
			m_in[3].v.u32 = MDRD_BERESP_F_CLOSE;
			if (mdr_pack(&m, buf, sizeof(buf), msg_pack_beresp,
			    MDR_F_NONE, m_in, 4) == MDR_FAIL) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: mdr_pack", __func__);
				goto fail;
			}
			if (write(1, mdr_buf(&m), mdr_size(&m))
			    < mdr_size(&m)) {
				xlog_strerror(LOG_ERR, errno,
				    "%s: writeall", __func__);
				goto fail;
			}
			continue;
		}

		switch (mdr_dcv(&msg)) {
		case MDR_DCV_CERTALATOR_BOOTSTRAP_SETUP:
			// TODO: client needs to have the "bootstrap" role
			if (authority_bootstrap_setup_msg(&msg, &e) == MDR_FAIL)
				xlog(LOG_ERR, &e, "%s: bootstrap", __func__);
			break;
		case MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK:
			// TODO: needs to have role "agent", and the client
			// needs to have the "authority" role
			break;
		default:
			// TODO: fail
		}

		// TODO: currently this only echoes back
		X509_free(peer_cert);

		m_in[0].type = MDR_U32;
		m_in[0].v.u32 = id;
		m_in[1].type = MDR_I32;
		m_in[1].v.i32 = fd;
		m_in[2].type = MDR_U32;
		m_in[2].v.u32 = MDRD_ST_OK;
		m_in[3].type = MDR_U32;
		m_in[3].v.u32 = 0;
		m_in[4].type = MDR_M;
		// TODO: send meaningful response
		m_in[4].v.m = &msg;
		if (mdr_pack(&m, buf, sizeof(buf), msg_pack_beresp_wmsg,
		    MDR_F_NONE, m_in, 5) == MDR_FAIL) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: mdr_pack", __func__);
			goto fail;
		}
		if (write(1, mdr_buf(&m), mdr_size(&m)) < mdr_size(&m)) {
			xlog_strerror(LOG_ERR, errno,
			    "%s: writeall", __func__);
			goto fail;
		}
	}
	X509_STORE_CTX_free(ctx);
	return 0;
fail:
	X509_STORE_CTX_free(ctx);
	return 1;
}

void
cleanup()
{
	flatconf_free(certalator_config_vars);
	if (ca_crt != NULL) {
		X509_free(ca_crt);
		ca_crt = NULL;
	}
	if (ca_crl != NULL) {
		X509_CRL_free(ca_crl);
		ca_crl = NULL;
	}
	if (agent_cert != NULL) {
		X509_free(agent_cert);
		agent_cert = NULL;
	}
	if (agent_key != NULL) {
		EVP_PKEY_free(agent_key);
		agent_key = NULL;
	}
	if (store != NULL) {
		X509_STORE_free(store);
		store = NULL;
	}
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
				authority_bootstrap_usage();
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

	cert_init();

	command = argv[opt++];

	if (certdb_init(certalator_conf.certdb_path, &e) == -1) {
		xlog(LOG_ERR, &e, "certdb_init");
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
		if ((ctx = X509_STORE_CTX_new()) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		status = cert_verify(ctx, crt, 0);
		X509_STORE_CTX_free(ctx);
	} else if (strcmp(command, "sign") == 0) {
		if (opt >= argc)
			errx(1, "no certificate file provided");

		load_keys();

		if ((f = fopen(argv[opt], "r")) == NULL)
			err(1, "fopen: %s", argv[opt]);
		if ((crt = PEM_read_X509(f, NULL, NULL, NULL)) == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		fclose(f);

		newcrt = cert_sign(crt, agent_cert, agent_key,
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
		if (authority_bootstrap_setup_cli(argc - opt,
		    argv + opt, &e) == -1) {
			xlog(LOG_ERR, &e, "bootstrap");
			return -1;
		}
	} else {
		usage();
		status = 1;
	}
	cleanup();
	return status;
}
