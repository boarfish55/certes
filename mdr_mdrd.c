#include <errno.h>
#include <stdlib.h>
#include "mdr.h"
#include "mdr_mdrd.h"

int
mdrd_unpack_bereq(struct mdr *m, uint64_t *id, int *fd, struct mdr *msg,
    char *msg_buf, uint64_t *msg_sz, X509 **peer_cert)
{
	uint64_t             cert_len;
	const unsigned char *p;
	ptrdiff_t            pos;

	if (mdr_unpack_uint64(m, id) == MDR_FAIL ||
	    mdr_unpack_int32(m, fd) == MDR_FAIL ||
	    mdr_unpack_mdr(m, msg, msg_buf, msg_sz) == MDR_FAIL)
		return MDR_FAIL;

	if ((pos = mdr_unpack_tail_bytes(m, &cert_len)) == MDR_FAIL) {
		if (errno != ENOENT) {
			return MDR_FAIL;
		} else {
			*peer_cert = NULL;
			return 0;
		}
	}

	if (cert_len == 0) {
		*peer_cert = NULL;
		return 0;
	}

	p = mdr_buf(m) + pos;
	*peer_cert = d2i_X509(NULL, &p, cert_len);
	if (*peer_cert == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	return 0;
}

int
mdrd_pack_beresp(struct mdr *m, char *buf, size_t sz, uint64_t id, int fd,
    uint32_t status, uint32_t flags, struct mdr *msg)
{
	if (mdr_pack_hdr(m, 0, MDR_NS_MDRD, MDR_ID_MDRD_BERESP, 0,
	    buf, sz) == MDR_FAIL ||
	    mdr_pack_uint64(m, id) == MDR_FAIL ||
	    mdr_pack_int32(m, fd) == MDR_FAIL ||
	    mdr_pack_uint32(m, status) == MDR_FAIL ||
	    mdr_pack_uint32(m, flags) == MDR_FAIL)
		return MDR_FAIL;

	if (flags & MDRD_BERESP_F_MSG &&
	    mdr_pack_mdr(m, msg) == MDR_FAIL)
		return MDR_FAIL;

	return 0;
}

int
mdrd_pack_error(struct mdr *m, char *buf, size_t sz, uint32_t status,
    const char *reason)
{
	if (mdr_pack_hdr(m, 0, MDR_NS_MDRD, MDR_ID_MDRD_ERROR, 0,
	    buf, sz) == MDR_FAIL ||
	    mdr_pack_uint32(m, status) == MDR_FAIL ||
	    mdr_pack_string(m, reason) == MDR_FAIL)
		return MDR_FAIL;

	return 0;
}

int
mdrd_unpack_error(struct mdr *m, uint32_t *status, char *reason,
    uint64_t *reason_sz)
{
	if (mdr_unpack_uint32(m, status) == MDR_FAIL ||
	    mdr_unpack_string(m, reason, reason_sz) == MDR_FAIL)
		return MDR_FAIL;

	return 0;
}
