#include <errno.h>
#include <stdlib.h>
#include "mdr.h"
#include "mdrd.h"

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
mdrd_unpack_bereq(struct umdr *m, uint64_t *id, int *fd, struct sockaddr *peer,
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

	if (umdr_unpack(m, mdr_msg_mdrd_bereq, uv, UMDRVECLEN(uv)) == MDR_FAIL)
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
mdrd_unpack_error(struct umdr *m, uint32_t *status, const char **reason,
    uint64_t *reason_sz)
{
	struct umdr_vec uv[2];

	if (umdr_unpack(m, mdr_msg_mdrd_error, uv, UMDRVECLEN(uv)) == MDR_FAIL)
		return MDR_FAIL;
	*status = uv[0].v.u32;
	*reason = uv[1].v.s.bytes;
	*reason_sz = uv[1].v.s.sz;

	return 0;
}
