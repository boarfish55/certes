#include <errno.h>
#include <openssl/x509.h>
#include "mdr_certainty.h"
#include "xlog.h"

int
pack_bemsg(struct mdr *m, uint64_t id, int fd, struct mdr *msg, X509 *peer_cert)
{
	size_t                    cert_len;
	unsigned char            *cert_buf;

	cert_len = i2d_X509(peer_cert, NULL);
	if (cert_len < 0) {
		xlog(LOG_ERR, NULL, "%s: i2d_X509() < 0", __func__);
		return -1;
	}

	if (mdr_pack_hdr(m, MDR_F_TAIL_BYTES, MDR_NS_CERTAINTY,
	    MDR_ID_CERTAINTY_BEMSG, 0, NULL, 4096) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr_pack_hdr", __func__);
		return -1;
	}

	if (mdr_pack_uint64(m, id) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr_pack_uint64", __func__);
		return -1;
	}

	if (mdr_pack_int32(m, fd) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr_pack_int32", __func__);
		return -1;
	}

	if (mdr_pack_mdr(m, msg) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno, "%s: mdr_pack_mdr", __func__);
		return -1;
	}

	if (mdr_pack_tail_bytes(m, cert_len) == MDR_FAIL) {
		xlog_strerror(LOG_ERR, errno,
		    "%s: mdr_pack_tail_bytes", __func__);
		return -1;
	}
	cert_buf = mdr_buf(m) + mdr_tell(m);
	i2d_X509(peer_cert, &cert_buf);

	return 0;
}
