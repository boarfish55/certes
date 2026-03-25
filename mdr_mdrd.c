#include <sys/tree.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "mdr.h"
#include "mdrd.h"

static int
session_cmp(struct mdrd_besession *s1, struct mdrd_besession *s2)
{
	return (s1->id < s2->id) ? -1 : s1->id > s2->id;
}

SPLAY_HEAD(session_tree, mdrd_besession) sessions = SPLAY_INITIALIZER(&sessions);
SPLAY_PROTOTYPE(session_tree, mdrd_besession, entries, session_cmp);
SPLAY_GENERATE(session_tree, mdrd_besession, entries, session_cmp);

static void
session_free(struct mdrd_besession *s)
{
	if (s == NULL)
		return;

	SPLAY_REMOVE(session_tree, &sessions, s);
	if (s->cert != NULL)
		X509_free(s->cert);
	if (s->data != NULL && s->free_data != NULL)
		s->free_data(s->data);
	free(s);
}

/*
 * We don't call the umdr/pmdr_init() functions here,
 * we leave the choice of buffer and flags to the caller.
 */
int
mdrd_unpack_beclose(struct umdr *m, uint64_t *id)
{
	struct umdr_vec uv[1];

	if (umdr_unpack(m, mdr_msg_mdrd_beclose, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;
	*id = uv[0].v.u64;

	return 0;
}

int
mdrd_unpack_bein(struct umdr *m, uint64_t *id, int *fd, struct sockaddr *peer,
    socklen_t *slen, struct umdr *msg, X509 **peer_cert)
{
	uint64_t             cert_len;
	const unsigned char *p;
	const uint8_t       *peer_addr;
	size_t               peer_addr_sz;
	uint16_t             port;
	struct sockaddr_in6 *peer6;
	struct sockaddr_in  *peer4;
	struct umdr_vec      uv[6];

	if (id == NULL || fd == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (umdr_unpack(m, mdr_msg_mdrd_bein, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;

	*id = uv[0].v.u64;
	*fd = uv[1].v.i32;
	peer_addr = uv[2].v.b.bytes;
	peer_addr_sz = uv[2].v.b.sz;
	port = uv[3].v.u16;
	if (msg != NULL)
		umdr_copy(msg, &uv[4].v.m);
	p = uv[5].v.b.bytes;
	cert_len = uv[5].v.b.sz;

	if (peer != NULL && slen != NULL) {
		if (peer_addr_sz == 16) {
			peer6 = (struct sockaddr_in6 *)peer;
			if (*slen >= sizeof(struct sockaddr_in6)) {
				*slen = sizeof(struct sockaddr_in6);
				peer6->sin6_family = AF_INET6;
				peer6->sin6_port = htons(port);
				memcpy(peer6->sin6_addr.s6_addr, peer_addr,
				    sizeof(peer6->sin6_addr.s6_addr));
				/* We don't carry the following info */
				peer6->sin6_flowinfo = 0;
				peer6->sin6_scope_id = 0;
			}
		} else {
			peer4 = (struct sockaddr_in *)peer;
			if (*slen >= sizeof(struct sockaddr_in)) {
				*slen = sizeof(struct sockaddr_in);
				peer4->sin_family = AF_INET;
				peer4->sin_port = htons(port);
				memcpy(&peer4->sin_addr.s_addr, peer_addr,
				    sizeof(peer4->sin_addr.s_addr));
			}
		}
	}

	if (peer_cert != NULL) {
		if (cert_len == 0) {
			*peer_cert = NULL;
			return 0;
		}
		*peer_cert = d2i_X509(NULL, &p, cert_len);
		if (*peer_cert == NULL) {
			errno = EBADMSG;
			return MDR_FAIL;
		}
	}

	return 0;
}

int
mdrd_unpack_besesserr(struct umdr *m, uint64_t *id)
{
	struct umdr_vec uv[1];

	if (umdr_unpack(m, mdr_msg_mdrd_besesserr, uv,
	    UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;
	*id = uv[0].v.u64;

	return 0;
}

int
mdrd_beout_error(struct mdrd_besession *sess, uint32_t beout_flags,
    uint32_t errcode, const char *errdesc)
{
	struct pmdr     pm;
	char            pbuf[mdr_hdr_size(MDR_FNONE) + 4 + 8 + strlen(errdesc)];
	struct pmdr_vec pv[2];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U32;
	pv[0].v.u32 = errcode;
	pv[1].type = MDR_S;
	pv[1].v.s = errdesc;
	if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
		return -1;

	return mdrd_beout(sess, beout_flags, &pm);
}

int
mdrd_beout_ok(struct mdrd_besession *sess, uint32_t beout_flags)
{
	struct pmdr pm;
	char        pbuf[mdr_hdr_size(MDR_FNONE)];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	if (pmdr_pack(&pm, mdr_msg_ok, NULL, 0) == MDR_FAIL)
		return -1;
	return mdrd_beout(sess, beout_flags, &pm);
}

int
mdrd_beout(struct mdrd_besession *sess, uint32_t beout_flags,
    const struct pmdr *msg)
{
	struct pmdr     pm;
	struct pmdr_vec pv[4];
	char            pbuf[pmdr_size(msg) + mdr_hdr_size(MDR_FNONE) + 16];

	pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
	pv[0].type = MDR_U64;
	pv[0].v.u64 = sess->id;
	pv[1].type = MDR_I32;
	pv[1].v.i32 = sess->fd;
	pv[2].type = MDR_U32;
	pv[2].v.u32 = beout_flags;

	if (msg != NULL) {
		pv[3].type = MDR_M;
		pv[3].v.pmdr = msg;
		if (pmdr_pack(&pm, mdr_msg_mdrd_beout, pv,
		    PMDRVECLEN(pv)) == MDR_FAIL)
			return -1;
	} else {
		if (pmdr_pack(&pm, mdr_msg_mdrd_beout_empty, pv,
		    PMDRVECLEN(pv) - 1) == MDR_FAIL)
			return -1;
	}

	if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
		return -1;
	if (beout_flags & MDRD_BEOUT_FCLOSE)
		session_free(sess);
	return 0;
}

ptrdiff_t
mdrd_recv(struct umdr *msg, void *buf, size_t sz, size_t cert_sz,
    uint64_t domain, uint32_t features, struct mdrd_besession **session)
{
	int                    r;
	ptrdiff_t              c;
	struct pmdr            pm;
	char                   pbuf[64];
	struct pmdr_vec        pv[2];
	char                   errmsg[64];
	uint64_t               id;
	int                    fd;
	struct mdrd_besession *sess = NULL, needle, tmpsess;
	struct umdr            um;
	char                   ubuf[14 + sizeof(struct sockaddr_in6)
	    + sz + cert_sz];
	struct sockaddr_in6    peer;
	socklen_t              slen = sizeof(peer);
	X509                  *peer_cert;

again:
	if ((c = mdr_buf_from_fd(0, ubuf, sizeof(ubuf))) == MDR_FAIL)
		return MDR_FAIL;

	if (umdr_init(&um, ubuf, c, MDR_FNONE) == MDR_FAIL) {
		snprintf(errmsg, sizeof(errmsg), "failed on umdr_init (%d)",
		    errno);
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_BEFAIL;
		pv[1].type = MDR_S;
		pv[1].v.s = errmsg;
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
	}

	if (!umdr_dcv_match(&um, MDR_DOMAIN_MDRD, MDR_MASK_D)) {
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_NOTSUPP;
		pv[1].type = MDR_S;
		pv[1].v.s = "message is not MDR_DOMAIN_MDRD";
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
		goto again;
	}

	switch (umdr_dcv(&um)) {
	case MDR_DCV_MDRD_BECLOSE:
		r = mdrd_unpack_beclose(&um, &id);
		break;
	case MDR_DCV_MDRD_BESESSERR:
		r = mdrd_unpack_besesserr(&um, &id);
		break;
	case MDR_DCV_MDRD_BEIN:
		umdr_init0(msg, buf, sz, features);
		r = mdrd_unpack_bein(&um, &id, &fd,
		    (struct sockaddr *)&peer, &slen, msg, &peer_cert);
		break;
	default:
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_NOTSUPP;
		pv[1].type = MDR_S;
		pv[1].v.s = "expected MDR_DCV_MDRD_BEREQ";
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
		goto again;
	}

	if (r == MDR_FAIL) {
		pmdr_init(&pm, pbuf, sizeof(pbuf), MDR_FNONE);
		pv[0].type = MDR_U32;
		pv[0].v.u32 = MDR_ERR_BADMSG;
		pv[1].type = MDR_S;
		pv[1].v.s = "unsupported message, or bad format";
		if (pmdr_pack(&pm, mdr_msg_error, pv, 2) == MDR_FAIL)
			return MDR_FAIL;
		if (write(1, pmdr_buf(&pm), pmdr_size(&pm)) < pmdr_size(&pm))
			return MDR_FAIL;
		goto again;
	}

	needle.id = id;
	sess = SPLAY_FIND(session_tree, &sessions, &needle);

	if (umdr_dcv(&um) == MDR_DCV_MDRD_BECLOSE ||
	    umdr_dcv(&um) == MDR_DCV_MDRD_BESESSERR) {
		if (sess != NULL)
			session_free(sess);
		/*
		 * No response is expected on BECLOSE/BESESSERR.
		 */
		goto again;
	}

	if (sess == NULL) {
		sess = malloc(sizeof(struct mdrd_besession));
		if (sess == NULL) {
			/*
			 * We only use the session for id/fd in beout,
			 * so just use static storage for that purpose.
			 */
			bzero(&tmpsess, sizeof(tmpsess));
			tmpsess.id = id;
			tmpsess.fd = fd;
			mdrd_beout_error(&tmpsess, MDRD_BEOUT_FNONE,
			    MDR_ERR_BEFAIL, "mdrd session creation failed");
			goto again;
		}
		sess->id = id;
		sess->fd = fd;
		sess->is_new = 1;
		memcpy(&sess->peer, &peer, sizeof(sess->peer));
		sess->peer_len = slen;
		sess->cert = peer_cert;
		sess->data = NULL;
		sess->free_data = NULL;
		SPLAY_INSERT(session_tree, &sessions, sess);
	} else {
		sess->is_new = 0;
	}

	if (domain != 0 && !umdr_dcv_match(msg, domain, MDR_MASK_D)) {
		mdrd_beout_error(sess, MDRD_BEOUT_FNONE,
		    MDR_ERR_NOTSUPP, "unsupported message domain");
		goto again;
	}

	if (session != NULL)
		*session = sess;
	return c;
}

void
mdrd_besession_set_data(struct mdrd_besession *s, void *data,
    void(*free_data)(void *))
{
	s->data = data;
	s->free_data = free_data;
}
