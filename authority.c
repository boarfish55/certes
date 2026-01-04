#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "authority.h"
#include "util.h"

extern struct certalator_flatconf certalator_conf;

// TODO: for boostrapping from the certalator server; this will generate a timed
// challenge and can tie roles to the challenge. Boostrapping can also invoke a
// shell command to perform a action to bring up the server (i.e. DHCP
// reservation & reboot, cloud calls, etc.) The server must remember the
// challenge until it expires.  Active challenges can be kept in an sqlite DB,
// alongside available serial ranges and next allocatable serial.
// When a client sends a successful response to this challenge, along with an
// X509 REQ, the server can sign it if the commonName and subjectAltNames
// match.
/*
 * Create a bootstrap entry with certificate parameters and a challenge key
 * to be used when an agent connects with a DIALIN call.
 * This will populate and save a bootstrap_entry in the certdb.
 */
int
authority_bootstrap_setup(const char *cn, const char **sans,
    size_t sans_sz, const char **roles, size_t roles_sz, uint32_t cert_expiry,
    uint32_t timeout, uint32_t flags, struct xerr *e)
{
	int                     i;
	uint8_t                 buf[CERTALATOR_BOOTSTRAP_KEY_LENGTH];
	char                    subject[CERTALATOR_MAX_SUBJET_LENGTH] = "";
	struct bootstrap_entry  be;
	struct timespec         tp;

	if (flags & CERTDB_BOOTSTRAP_FLAG_SETCN) {
		if (snprintf(subject, sizeof(subject),
		    "/O=%s/CN=%s/emailAddress=%s", certalator_conf.cert_org,
		    cn, certalator_conf.cert_email) >= sizeof(subject))
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "resulting subject name is too long "
			    "for commonName %s", cn);
	}

	arc4random_buf(buf, sizeof(buf));

	if (b64enc(be.bootstrap_key, sizeof(be.bootstrap_key),
	    buf, sizeof(buf)) == -1) {
		// TODO: handle openssl error
		return -1;
	}

	clock_gettime(CLOCK_REALTIME, &tp);

	be.valid_until_sec = tp.tv_sec + timeout;
	be.not_before_sec = tp.tv_sec;
	be.not_after_sec = tp.tv_sec + cert_expiry;
	be.subject = subject;

	for (i = 0; i < roles_sz; i++)
		if (strlen(roles[i]) > CERTALATOR_MAX_ROLE_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "role name %s longer than limit of %d",
			    roles[i], CERTALATOR_MAX_ROLE_LENGTH);

	for (i = 0; i < sans_sz; i++)
		if (strlen(sans[i]) > CERTALATOR_MAX_SAN_LENGTH)
			return XERRF(e, XLOG_APP, XLOG_NAMETOOLONG,
			    "SAN name %s longer than limit of %d",
			    sans[i], CERTALATOR_MAX_SAN_LENGTH);

	be.roles = (char **)roles;
	be.roles_sz = roles_sz;
	be.sans = (char **)sans;
	be.sans_sz = sans_sz;

	return certdb_put_bootstrap(&be, e);
}

int
authority_bootstrap_setup_msg(struct umdr *m, struct xerr *e)
{
	const char       *subject;
	const char      **roles = NULL;
	int32_t           roles_sz;
	const char      **sans = NULL;
	int32_t           sans_sz;
	uint32_t          cert_expiry, timeout, flags;
	struct umdr_vec   uv[4];

	if (umdr_unpack(m, msg_bootstrap_setup, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return -1;

	subject = uv[0].v.s.bytes;
	sans_sz = umdr_vec_alen(&uv[1].v.as);
	roles_sz = umdr_vec_alen(&uv[2].v.as);
	cert_expiry = uv[3].v.u32;
	timeout = uv[4].v.u32;
	flags = uv[5].v.u32;

	if ((sans = malloc(sizeof(char *) * (sans_sz + 1))) == NULL)
		goto fail;
	if ((roles = malloc(sizeof(char *) * (roles_sz + 1))) == NULL)
		goto fail;

	if (umdr_vec_as(&uv[1].v.as, sans, sans_sz) == MDR_FAIL)
		goto fail;
	if (umdr_vec_as(&uv[2].v.as, roles, roles_sz) == MDR_FAIL)
		goto fail;

	if (authority_bootstrap_setup(subject, sans, sans_sz, roles,
	    roles_sz, cert_expiry, timeout, flags, e) == -1)
		goto fail;

	free(sans);
	free(roles);
	return 0;
fail:
	free(sans);
	free(roles);
	return -1;
}

int
authority_challenge(struct bootstrap_entry *be, const char *req_id,
    struct xerr *e)
{
	// TODO:

	// We connect to the subject, with a 
	// MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK message.
	//

	// Save the challenge in our shared tasks

	//for (i = 0; i < MAX_ACTIVE_CHALLENGES; i++) {
	//	if (!authority_challenge.challenges[i].in_use)
	//		break;
	//}

	// TODO: couldn't find a challenge slot
	//if (i == MAX_ACTIVE_CHALLENGES)
	//	return -1;

	// arc5random_buf ...
	// b64enc ..
	//authority_challenge.challenges[i].in_use = 1;
	//strlcpy(authority_challenge.challenges[i].secret, yo,
	//    sizeof(authority_challenge.challenges[i].secret));
	return 0;
}

int
authority_bootstrap_dialin(struct umdr *msg, struct xerr *e)
{
	// TODO: we receive the one-time-key from a client then
	// need to contact it over its CommonName to confirm
	// they are who they claim to be.
	// msg should have the one time key.

	struct bootstrap_entry be;
	struct umdr_vec        uv[2];
	struct timespec        now;

	// TODO: we need the REQ to know the subjectAltName sent to us
	// to contact back for the challenge.
	// Or the egress IP addr to reach back...

	if (umdr_unpack(msg, msg_bootstrap_dialin, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return XERRF(e, XLOG_ERRNO, errno, "umdr_unpack");

	if (uv[1].v.s.sz != CERTALATOR_BOOTSTRAP_KEY_LENGTH)
		return XERRF(e, XLOG_APP, XLOG_BADMSG,
		    "bootstrap key received from client has incorrect length");

	if (certdb_get_bootstrap(&be, uv[1].v.s.bytes, e) == -1)
		return XERR_PREPENDFN(e);

	clock_gettime(CLOCK_REALTIME, &now);
	if (now.tv_sec > be.valid_until_sec)
		return XERRF(e, XLOG_APP, XLOG_TIMEOUT,
		    "bootstrap key is expired");

	// Then we challenge the client by connecting to its CommonName
	// as per our DB
	if (authority_challenge(&be, uv[0].v.s.bytes, e) == -1)
		return -1;

	// TODO: Then send a quick MDR_DCV_CERTALATOR_BOOTSTRAP_DIALBACK_RESP
	// to inform the challenge is out.

	return 0;
}

