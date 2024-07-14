#include <errno.h>
#include <stdlib.h>
#include "mdr.h"
#include "mdr_mdrd.h"

int
mdr_unpack_bemsg(struct mdr *m, uint64_t *id, int *fd, struct mdr *msg,
    char *msg_buf, uint64_t *msg_sz, X509 **peer_cert)
{
	uint64_t             cert_len;
	const unsigned char *p;
	ptrdiff_t            pos;

	if (mdr_unpack_uint64(m, id) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_unpack_int32(m, fd) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_unpack_mdr(m, msg, msg_buf, msg_sz) == MDR_FAIL)
		return MDR_FAIL;

	if ((pos = mdr_unpack_tail_bytes(m, &cert_len)) == MDR_FAIL)
		return MDR_FAIL;

	p = mdr_buf(m) + pos;
	*peer_cert = d2i_X509(NULL, &p, cert_len);
	if (*peer_cert == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	return 0;
}
