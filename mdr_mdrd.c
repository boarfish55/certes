#include <errno.h>
#include <stdlib.h>
#include "mdr.h"
#include "mdr_mdrd.h"

int
mdrd_unpack_beclose(struct mdr *m, uint64_t *id)
{
	if (mdr_unpack_u64(m, id) == MDR_FAIL)
		return MDR_FAIL;
	return 0;
}

int
mdrd_unpack_bereq(struct mdr *m, uint64_t *id, int *fd, struct mdr *msg,
    X509 **peer_cert)
{
	uint64_t             cert_len;
	const unsigned char *p;

	if (mdr_unpack_u64(m, id) == MDR_FAIL ||
	    mdr_unpack_i32(m, fd) == MDR_FAIL ||
	    mdr_unpack_mdr(m, msg) == MDR_FAIL ||
	    mdr_unpack_bytes(m, (const void **)&p, &cert_len) == MDR_FAIL)
		return MDR_FAIL;

	if (cert_len == 0) {
		*peer_cert = NULL;
		return 0;
	}

	*peer_cert = d2i_X509(NULL, &p, cert_len);
	if (*peer_cert == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	return 0;
}

int
mdrd_unpack_error(struct mdr *m, uint32_t *status, const char **reason,
    uint64_t *reason_sz)
{
	if (mdr_unpack_u32(m, status) == MDR_FAIL ||
	    mdr_unpack_str(m, reason, reason_sz) == MDR_FAIL)
		return MDR_FAIL;

	return 0;
}
