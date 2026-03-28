#include <sys/param.h>
#include <sys/tree.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mdr.h"

union mdr_num_v {
	uint8_t  u8;
	int8_t   i8;

	uint16_t u16;
	int16_t  i16;

	uint32_t u32;
	int32_t  i32;

	uint64_t u64;
	int64_t  i64;

	float    f32;
	double   f64;
};

static struct mdr_def mdr_null = {
	MDR_DCV_MDR_NULL,
	"mdr.null",
	{
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_null;
static struct mdr_def mdr_ping = {
	MDR_DCV_MDR_PING,
	"mdr.ping",
	{
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_ping;
static struct mdr_def mdr_pong = {
	MDR_DCV_MDR_PONG,
	"mdr.pong",
	{
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_pong;
static struct mdr_def mdr_ok = {
	MDR_DCV_MDR_OK,
	"mdr.ok",
	{
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_ok;
static struct mdr_def mdr_error = {
	MDR_DCV_MDR_ERROR,
	"mdr.error",
	{
		MDR_U32, /* Error code */
		MDR_S,   /* Error description */
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_error;

static struct mdr_def mdrd_bein = {
	MDR_DCV_MDRD_BEIN,
	"mdrd.bein",
	{
		MDR_U64, /* id */
		MDR_I32, /* fd */
		MDR_B,   /* peer IP address */
		MDR_U16, /* peer port */
		MDR_M,   /* msg */
		MDR_B,   /* peer cert */
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_mdrd_bein;
static struct mdr_def mdrd_beout = {
	MDR_DCV_MDRD_BEOUT,
	"mdrd.beout",
	{
		MDR_U64, /* id */
		MDR_I32, /* fd */
		MDR_U32, /* flags */
		MDR_M,   /* msg */
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_mdrd_beout;
static struct mdr_def mdrd_beout_empty = {
	MDR_DCV_MDRD_BEOUT_EMPTY,
	"mdrd.beout_empty",
	{
		MDR_U64, /* id */
		MDR_I32, /* fd */
		MDR_U32, /* flags */
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_mdrd_beout_empty;
static struct mdr_def mdrd_beclose = {
	MDR_DCV_MDRD_BECLOSE,
	"mdrd.beclose",
	{
		MDR_U64, /* id */
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_mdrd_beclose;
static struct mdr_def mdrd_besesserr = {
	MDR_DCV_MDRD_BESESSERR,
	"mdrd.besesserr",
	{
		MDR_U64, /* id */
		MDR_LAST
	}
};
const struct mdr_spec *mdr_msg_mdrd_besesserr;

static int
speccmp(struct mdr_spec *s1, struct mdr_spec *s2)
{
	if (s1->dcv < s2->dcv)
		return -1;
	if (s1->dcv > s2->dcv)
		return 1;
	return 0;
}

static struct {
	RB_HEAD(mdr_registry_tree, mdr_spec) head;
	size_t                               count;
} mdr_registry = { RB_INITIALIZER(&mdr_registry.head), 0 };

RB_PROTOTYPE(mdr_registry_tree, mdr_spec, entry, speccmp);
RB_GENERATE(mdr_registry_tree, mdr_spec, entry, speccmp);


static ssize_t
readall(int fd, void *buf, size_t count)
{
        ssize_t r;
        ssize_t n = 0;

        while (n < count) {
                r = read(fd, buf + n, count - n);
                if (r == -1) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                } else if (r == 0) {
                        return n;
                }
                n += r;
        }
        return n;
}

static uint64_t
mdr_size(const struct mdr *m)
{
	return be64toh(*m->size);
}

static ptrdiff_t
mdr_tell(const struct mdr *m)
{
	return m->pos - m->buf;
}

static uint32_t
mdr_features(const struct mdr *m)
{
	return be32toh(*m->features);
}

static int
mdr_can_fit(struct mdr *m, size_t n)
{
	uint8_t *tmp;

	if ((PTRDIFF_MAX - mdr_tell(m)) < n) {
		errno = EOVERFLOW;
		return 0;
	}

	if (m->buf_sz >= mdr_tell(m) + n)
		return 1;

	if (!m->dyn) {
		errno = EOVERFLOW;
		return 0;
	}

	if ((tmp = realloc(m->buf, mdr_tell(m) + n)) == NULL)
		return 0;

	m->buf_sz = mdr_tell(m) + n;
	if (tmp != m->buf) {
		m->pos = tmp + mdr_tell(m);

		m->size = (uint64_t *)(tmp +
		    ((uint8_t *)m->size - (uint8_t *)m->buf));
		m->features = (uint32_t *)(tmp +
		    ((uint8_t *)m->features - (uint8_t *)m->buf));
		m->dcv = (uint64_t *)(tmp +
		    ((uint8_t *)m->dcv - (uint8_t *)m->buf));

		if (mdr_features(m) & MDR_FTAILBYTES)
			m->tail_bytes = (uint64_t *)(tmp +
			    ((uint8_t *)m->tail_bytes - (uint8_t *)m->buf));

		if (mdr_features(m) & MDR_FSTREAMID)
			m->stream_id = (uint64_t *)(tmp +
			    ((uint8_t *)m->stream_id - (uint8_t *)m->buf));

		if (mdr_features(m) & MDR_FACCTID)
			m->acct_id = (uint64_t *)(tmp +
			    ((uint8_t *)m->acct_id - (uint8_t *)m->buf));

		if (mdr_features(m) & MDR_FTRACEID)
			m->trace_id = (uint8_t *)(tmp +
			    ((uint8_t *)m->trace_id - (uint8_t *)m->buf));

		m->buf = tmp;
	}

	return 1;
}

static ptrdiff_t
mdr_update_size(struct mdr *m)
{
	*m->size = htobe64(mdr_tell(m));
	/*
	 * We return the size without trailing bytes to make
	 * it easy for callers to know where to start appending bytes
	 * in a buffer.
	 */
	return mdr_tell(m);
}

static ptrdiff_t
mdr_pack_num_nochk(struct mdr *m, uint8_t type, union mdr_num_v v)
{
	switch (type) {
	case MDR_U8:
	case MDR_I8:
		*(uint8_t *)m->pos = v.u8;
		m->pos += sizeof(uint8_t);
		break;
	case MDR_U16:
	case MDR_I16:
		*(uint16_t *)m->pos = htobe16(v.u16);
		m->pos += sizeof(uint16_t);
		break;
	case MDR_U32:
	case MDR_I32:
	case MDR_F32:
		*(uint32_t *)m->pos = htobe32(v.u32);
		m->pos += sizeof(uint32_t);
		break;
	case MDR_U64:
	case MDR_I64:
	case MDR_F64:
		*(uint64_t *)m->pos = htobe64(v.u64);
		m->pos += sizeof(uint64_t);
		break;
	default:
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_update_size(m);
}

static ptrdiff_t
mdr_pack_bytes_nochk(struct mdr *m, const void *bytes, uint64_t bytes_sz)
{
	if (bytes_sz & 0x8000000000000000) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (bytes == NULL && bytes_sz != 0) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, bytes_sz +
	    ((bytes_sz <= 0x7f) ? sizeof(uint8_t) : sizeof(uint64_t))))
		return MDR_FAIL;

	/*
	 * Only store the byte string length as a single byte if the leading
	 * bit is zero. Otherwise use the full 8 bytes. This should prevent
	 * wasting 7 bytes for large numbers of small strings.
	 */
	if (bytes_sz <= 0x7f) {
		*(uint8_t *)m->pos = (uint8_t)bytes_sz;
		m->pos += sizeof(uint8_t);
	} else {
		*(uint64_t *)m->pos = htobe64(bytes_sz | 0x8000000000000000);
		m->pos += sizeof(uint64_t);
	}

	memcpy(m->pos, bytes, bytes_sz);
	m->pos += bytes_sz;

	return mdr_update_size(m);
}

static ptrdiff_t
mdr_pack_str_nochk(struct mdr *m, const char *bytes)
{
	if (bytes == NULL)
		return mdr_pack_bytes_nochk(m, "", 1);
	else
		return mdr_pack_bytes_nochk(m, bytes, strlen(bytes) + 1);
}

static ptrdiff_t
mdr_pack_mdr(struct mdr *m, const struct mdr *src)
{
	if (src == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, mdr_size(src)))
		return MDR_FAIL;

	memcpy(m->pos, src->buf, mdr_size(src));
	m->pos += mdr_size(src);

	return mdr_update_size(m);
}

static ptrdiff_t
mdr_unpack_num_nochk(struct mdr *m, uint8_t type, union mdr_num_v *v)
{
	switch (type) {
	case MDR_U8:
	case MDR_I8:
		v->u8 = *(uint8_t *)m->pos;
		m->pos += sizeof(uint8_t);
		break;
	case MDR_U16:
	case MDR_I16:
		v->u16 = be16toh(*(uint16_t *)m->pos);
		m->pos += sizeof(uint16_t);
		break;
	case MDR_U32:
	case MDR_I32:
	case MDR_F32:
		v->u32 = be32toh(*(uint32_t *)m->pos);
		m->pos += sizeof(uint32_t);
		break;
	case MDR_U64:
	case MDR_I64:
	case MDR_F64:
		v->u64 = be64toh(*(uint64_t *)m->pos);
		m->pos += sizeof(uint64_t);
		break;
	default:
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_tell(m);
}

static ptrdiff_t
mdr_unpack_bytes_nochk(struct mdr *m, const void **ref, uint64_t *bytes_sz)
{
	if (m->buf_sz - mdr_tell(m) < sizeof(uint8_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*bytes_sz = *(uint8_t *)m->pos;
	if (*bytes_sz & 0x80) {
		if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		*bytes_sz = be64toh(*(uint64_t *)m->pos) & 0x7fffffffffffffff;

		if (m->buf_sz - (mdr_tell(m) + sizeof(uint64_t)) < *bytes_sz) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint64_t);
	} else {
		if (m->buf_sz - (mdr_tell(m) + sizeof(uint8_t)) < *bytes_sz) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint8_t);
	}

	if (ref != NULL) {
		if (*bytes_sz == 0)
			*ref = NULL;
		else
			*ref = m->pos;
	}
	m->pos += *bytes_sz;

	return mdr_tell(m);
}

static ptrdiff_t
mdr_unpack_str_nochk(struct mdr *m, const char **ref, uint64_t *len)
{
	uint64_t bytes_sz;

	if (mdr_unpack_bytes_nochk(m, (const void **)ref, &bytes_sz)
	    == MDR_FAIL)
		return MDR_FAIL;

	if (len != NULL)
		*len = bytes_sz - 1;

	if ((*ref)[*len] != '\0') {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	return mdr_tell(m);
}

static ptrdiff_t
mdr_unpack_mdr(struct mdr *m, struct umdr *dst)
{
	uint64_t sz;
	uint32_t features;

	if (m->buf_sz - mdr_tell(m) < (sizeof(uint64_t) + sizeof(uint32_t))) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	/*
	 * A message always starts with the size
	 */
	sz = be64toh(*(uint64_t *)m->pos);
	features = be32toh(*(uint32_t *)(m->pos + sizeof(uint64_t)));

	if (m->buf_sz - mdr_tell(m) < sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	if (dst != NULL)
		if (umdr_init((struct umdr *)dst, m->pos, sz,
		    features) == MDR_FAIL)
			return MDR_FAIL;
	m->pos += sz;

	return mdr_tell(m);
}

static int
mdr_check_next_type(struct mdr *m, uint8_t type)
{
	if (m->spec == NULL) {
		errno = EINVAL;
		return 0;
	}

	if (m->spec_fld_idx >= m->spec->types_count) {
		errno = ERANGE;
		return 0;
	}

	if (m->spec->types[m->spec_fld_idx] != type) {
		errno = EINVAL;
		return 0;
	}
	m->spec_fld_idx++;
	return 1;
}

static int32_t
umdr_vec_anum(struct umdr_vec_ah *h, uint8_t type, void *dst,
    int32_t maxlen)
{
	const void *pos;
	int         i;

	if (h == NULL || dst == NULL || maxlen < 1) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	pos = h->p;

	for (i = 0; i < MIN(maxlen, h->length); i++) {
		switch (type) {
		case MDR_U8:
		case MDR_I8:
			((uint8_t *)dst)[i] = *(uint8_t *)pos;
			pos += sizeof(uint8_t);
			break;
		case MDR_U16:
		case MDR_I16:
			((uint16_t *)dst)[i] = be16toh(*(uint16_t *)pos);
			pos += sizeof(uint16_t);
			break;
		case MDR_U32:
		case MDR_I32:
		case MDR_F32:
			((uint32_t *)dst)[i] = be32toh(*(uint32_t *)pos);
			pos += sizeof(uint32_t);
			break;
		case MDR_U64:
		case MDR_I64:
		case MDR_F64:
			((uint64_t *)dst)[i] = be64toh(*(uint64_t *)pos);
			pos += sizeof(uint64_t);
			break;
		default:
			errno = EINVAL;
			return MDR_FAIL;
		}
	}

	/*
	 * For string arrays, fill out a NULL pointer at the end if there's
	 * enough space for it.
	 */
	return MIN(maxlen, h->length);
}

static int32_t
umdr_vec_asm(struct umdr_vec_ah *h, uint8_t type, void *dst,
    int32_t maxlen)
{
	int          i;
	uint64_t     sz;
	uint32_t     features;
	const void  *pos;

	if (h == NULL || dst == NULL || maxlen < 1) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	pos = h->p;
	/* We can skip the packed size, we don't need it here. */
	pos += sizeof(uint64_t);

	for (i = 0; i < MIN(maxlen, h->length); i++) {
		if (type == MDR_S) {
			sz = *(uint8_t *)pos;
			if (sz & 0x80) {
				sz = be64toh(*(uint64_t *)pos) &
				    0x7fffffffffffffff;
				pos += sizeof(uint64_t);
			} else
				pos += sizeof(uint8_t);

			((const char **)dst)[i] = (const char *)pos;
			pos += sz;
		} else if (type == MDR_M) {
			sz = be64toh(*(uint64_t *)pos);
			features = be32toh(*(uint32_t *)(pos +
			    sizeof(uint64_t)));
			if (umdr_init(((struct umdr *)dst) + i,
			    pos, sz, features) == MDR_FAIL)
				return MDR_FAIL;
			pos += sz;
		}
	}

	/*
	 * For convience, if there is still room in the string array for
	 * a NULL pointer, add it.
	 */
	if (type == MDR_S && i < maxlen)
		((const char **)dst)[i] = NULL;

	return MIN(maxlen, h->length);
}

static ptrdiff_t
mdr_pack_num(struct mdr *m, uint8_t type, union mdr_num_v nv, size_t sz)
{
	if (!mdr_can_fit(m, sz))
		return MDR_FAIL;

	if (!mdr_check_next_type(m, type))
		return MDR_FAIL;

	return mdr_pack_num_nochk(m, type, nv);
}

static ptrdiff_t
mdr_unpack_num(struct mdr *m, uint8_t type, union mdr_num_v *nv, size_t sz)
{
	if (m->buf_sz - mdr_tell(m) < sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, type))
		return MDR_FAIL;

	return mdr_unpack_num_nochk(m, type, nv);
}

static ptrdiff_t
mdr_unpack_array(struct mdr *m, uint8_t type, struct umdr_vec_ah *ah)
{
	uint32_t packed_n;
	uint64_t asize;

	if (!mdr_check_next_type(m, type))
		return MDR_FAIL;

	if (*(uint8_t *)m->pos & 0x80) {
		packed_n = be32toh(*(uint32_t *)m->pos) & 0x7fffffff;
		m->pos += sizeof(uint32_t);
		if (packed_n > INT32_MAX) {
			errno = EOVERFLOW;
			return MDR_FAIL;
		}
	} else {
		packed_n = *(uint8_t *)m->pos;
		m->pos += sizeof(uint8_t);
	}

	ah->type = type;
	ah->length = packed_n;
	ah->p = m->pos;

	switch (type) {
	case MDR_AU8:
	case MDR_AI8:
		if (m->buf_sz - mdr_tell(m) < (sizeof(uint8_t) * packed_n)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint8_t) * packed_n;
		return mdr_tell(m);
	case MDR_AU16:
	case MDR_AI16:
		if (m->buf_sz - mdr_tell(m) < (sizeof(uint16_t) * packed_n)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint16_t) * packed_n;
		return mdr_tell(m);
	case MDR_AU32:
	case MDR_AI32:
	case MDR_AF32:
		if (m->buf_sz - mdr_tell(m) < (sizeof(uint32_t) * packed_n)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint32_t) * packed_n;
		return mdr_tell(m);
	case MDR_AU64:
	case MDR_AI64:
	case MDR_AF64:
		if (m->buf_sz - mdr_tell(m) < (sizeof(uint64_t) * packed_n)) {
			errno = EAGAIN;
			return MDR_FAIL;
		}
		m->pos += sizeof(uint64_t) * packed_n;
		return mdr_tell(m);
	case MDR_AS:
	case MDR_AM:
		/* Size is item-specific, we handle it below. */
		break;
	default:
		errno = EAGAIN;
		return MDR_FAIL;
	}

	asize = be64toh(*(uint64_t *)m->pos);
	m->pos += asize + sizeof(uint64_t);

	return mdr_tell(m);
}

static uint64_t
mdr_dcv(const struct mdr *m)
{
	return be64toh(*m->dcv);
}

static ptrdiff_t
mdr_pack_rsvb(struct mdr *m, void **dst, uint64_t bytes_sz)
{
	if (bytes_sz & 0x8000000000000000) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_B))
		return MDR_FAIL;

	if (!mdr_can_fit(m, bytes_sz +
	    ((bytes_sz <= 0x7f) ? sizeof(uint8_t) : sizeof(uint64_t))))
		return MDR_FAIL;

	/*
	 * Only store the byte string length as a single byte if the leading
	 * bit is zero. Otherwise use the full 8 bytes. This should prevent
	 * wasting 7 bytes for large numbers of small strings.
	 */
	if (bytes_sz <= 0x7f) {
		*(uint8_t *)m->pos = (uint8_t)bytes_sz;
		m->pos += sizeof(uint8_t);
	} else {
		*(uint64_t *)m->pos = htobe64(bytes_sz | 0x8000000000000000);
		m->pos += sizeof(uint64_t);
	}

	*dst = m->pos;
	m->pos += bytes_sz;

	return mdr_update_size(m);
}

static ptrdiff_t
mdr_pack_array(struct mdr *m, uint8_t type, int32_t n, void *a)
{
	int              i;
	ptrdiff_t        r;
	union mdr_num_v  nv;
	void            *start;

	if (!mdr_check_next_type(m, type))
		return MDR_FAIL;

	if (type == MDR_AS || type == MDR_AM) {
		if (n < 0)
			n = 0x7fffffff;
		for (i = 0; i < n; i++) {
			if (((void **)a)[i] == NULL) {
				n = i;
				break;
			}
		}
	}

	if (n <= 0x7f) {
		if (!mdr_can_fit(m, sizeof(uint8_t)))
			return MDR_FAIL;
		*(uint8_t *)m->pos = n;
		m->pos += sizeof(uint8_t);
	} else {
		if (!mdr_can_fit(m, sizeof(uint32_t)))
			return MDR_FAIL;
		*(uint32_t *)m->pos = htobe32(n | 0x80000000);
		m->pos += sizeof(uint32_t);
	}

	if (type == MDR_AS || type == MDR_AM) {
		/*
		 * We pack the total size of the array data for those types so
		 * we can easily skip when unpacking. To be filled later.
		 */
		if (!mdr_can_fit(m, sizeof(uint64_t)))
			return MDR_FAIL;
		*(uint64_t *)m->pos = 0;
		m->pos += sizeof(uint64_t);
		start = m->pos;
	}

	switch (type) {
	case MDR_AU8:
	case MDR_AI8:
		if (!mdr_can_fit(m, sizeof(uint8_t) * n))
			return MDR_FAIL;
		break;
	case MDR_AU16:
	case MDR_AI16:
		if (!mdr_can_fit(m, sizeof(uint16_t) * n))
			return MDR_FAIL;
		break;
	case MDR_AU32:
	case MDR_AI32:
	case MDR_AF32:
		if (!mdr_can_fit(m, sizeof(uint32_t) * n))
			return MDR_FAIL;
		break;
	case MDR_AU64:
	case MDR_AI64:
	case MDR_AF64:
		if (!mdr_can_fit(m, sizeof(uint64_t) * n))
			return MDR_FAIL;
		break;
	default:
		/* Nothing, other types will check for available buffer */
	}

	for (i = 0; i < n; i++) {
		switch (type) {
		case MDR_AU8:
			nv.u8 = ((uint8_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_U8, nv);
			break;
		case MDR_AU16:
			nv.u16 = ((uint16_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_U16, nv);
			break;
		case MDR_AU32:
			nv.u32 = ((uint32_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_U32, nv);
			break;
		case MDR_AU64:
			nv.u64 = ((uint64_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_U64, nv);
			break;
		case MDR_AI8:
			nv.i8 = ((int8_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_I8, nv);
			break;
		case MDR_AI16:
			nv.i16 = ((int16_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_I16, nv);
			break;
		case MDR_AI32:
			nv.i32 = ((int32_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_I32, nv);
			break;
		case MDR_AI64:
			nv.i64 = ((int64_t *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_I64, nv);
			break;
		case MDR_AF32:
			nv.f32 = ((float *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_F32, nv);
			break;
		case MDR_AF64:
			nv.f64 = ((double *)a)[i];
			r = mdr_pack_num_nochk(m, MDR_F64, nv);
			break;
		case MDR_AS:
			r = mdr_pack_str_nochk(m, ((char **)a)[i]);
			break;
		case MDR_AM:
			r = mdr_pack_mdr(m, (struct mdr *)a + i);
			break;
		default:
			errno = EINVAL;
			return MDR_FAIL;
		}
		if (r == MDR_FAIL)
			return MDR_FAIL;
	}

	if (type == MDR_AS || type == MDR_AM) {
		/*
		 * We know the total bytes used by the array now, store it.
		 */

		*((uint64_t *)(start - sizeof(uint64_t))) =
		    htobe64((char *)m->pos - (char *)start);
	}

	return mdr_tell(m);
}

static uint64_t
mdr_tail_bytes(const struct mdr *m, void **dst)
{
	if (!(mdr_features(m) & MDR_FTAILBYTES))
		return 0;
	if (dst != NULL)
		*dst = (uint8_t *)m->buf + mdr_size(m);
	return be64toh(*m->tail_bytes);
}

static ptrdiff_t
mdr_unpack_bytes(struct mdr *m, const void **ref, uint64_t *bytes_sz)
{
	if (!mdr_check_next_type(m, MDR_B))
		return MDR_FAIL;

	return mdr_unpack_bytes_nochk(m, ref, bytes_sz);
}

static ptrdiff_t
mdr_unpack_str(struct mdr *m, const char **ref, uint64_t *len)
{
	if (!mdr_check_next_type(m, MDR_S))
		return MDR_FAIL;

	return mdr_unpack_str_nochk(m, ref, len);
}

static uint32_t
mdr_domain(const struct mdr *m)
{
	return (uint32_t)(be64toh(*m->dcv) >> 32);
}

static uint16_t
mdr_code(const struct mdr *m)
{
	return (uint16_t)((be64toh(*m->dcv) & 0x00000000ffff0000) >> 16);
}

static uint16_t
mdr_variant(const struct mdr *m)
{
	return (uint16_t)(be64toh(*m->dcv) & 0x000000000000ffff);
}

static uint64_t
mdr_stream_id(const struct mdr *m)
{
	if (!(mdr_features(m) & MDR_FSTREAMID))
		return 0;
	return be64toh(*m->stream_id);
}

static uint64_t
mdr_acct_id(const struct mdr *m)
{
	if (!(mdr_features(m) & MDR_FACCTID))
		return 0;
	return be64toh(*m->acct_id);
}

static const uint8_t *
mdr_trace_id(const struct mdr *m)
{
	if (!(mdr_features(m) & MDR_FTRACEID))
		return NULL;
	return m->trace_id;
}

static int
mdr_print(FILE *out, const struct mdr *m)
{
	const char    *b;
	int            i;
	const uint8_t *trace_id, *t;

	fprintf(out, "  size:        %llu\n", mdr_size(m));
	fprintf(out, "  domain:      %u\n", mdr_domain(m));
	fprintf(out, "  code:        %u\n", mdr_code(m));
	fprintf(out, "  variant:     %u\n", mdr_variant(m));
	if (mdr_features(m) & MDR_FTAILBYTES)
		fprintf(out, "  tail bytes:  %llu\n", mdr_tail_bytes(m, NULL));
	if (mdr_features(m) & MDR_FSTREAMID)
		fprintf(out, "  stream ID:  %llu\n", mdr_stream_id(m));
	if (mdr_features(m) & MDR_FACCTID)
		fprintf(out, "  accounting ID:  %llu\n", mdr_acct_id(m));
	if (mdr_features(m) & MDR_FTRACEID) {
		fprintf(out, "  trace ID:  ");
		trace_id = mdr_trace_id(m);
		for (i = 0, t = trace_id; i < 16; i++, t++)
			fprintf(out, "  trace ID: %x", *t);
		fprintf(out, "\n");
	}
	fprintf(out, "\n");
	fprintf(out, "  payload (%llu bytes):\n",
	    mdr_size(m) - mdr_hdr_size(mdr_features(m)));

	for (b = m->buf + mdr_hdr_size(mdr_features(m)), i = 0;
	    b - (char *)m->buf < mdr_size(m);
	    b++, i++) {
		if (i % 8 == 0)
			fprintf(out, "\n   ");
		else if (i % 4 == 0)
			fprintf(out, " ");
		fprintf(out, " %02x", (unsigned char)*b);
	}
	fprintf(out, "\n");
	return 0;
}

int
mdr_register_builtin_specs()
{
	if ((mdr_msg_null = mdr_register_spec(&mdr_null)) == NULL ||
	    (mdr_msg_ping = mdr_register_spec(&mdr_ping)) == NULL ||
	    (mdr_msg_pong = mdr_register_spec(&mdr_pong)) == NULL ||
	    (mdr_msg_ok = mdr_register_spec(&mdr_ok)) == NULL ||
	    (mdr_msg_error = mdr_register_spec(&mdr_error)) == NULL ||
	    (mdr_msg_mdrd_bein = mdr_register_spec(&mdrd_bein)) == NULL ||
	    (mdr_msg_mdrd_beout = mdr_register_spec(&mdrd_beout)) == NULL ||
	    (mdr_msg_mdrd_beout_empty =
	     mdr_register_spec(&mdrd_beout_empty)) == NULL ||
	    (mdr_msg_mdrd_beclose = mdr_register_spec(&mdrd_beclose)) == NULL ||
	    (mdr_msg_mdrd_besesserr =
	     mdr_register_spec(&mdrd_besesserr)) == NULL)
		return MDR_FAIL;

	return 0;
}

const struct mdr_spec *
mdr_register_spec(struct mdr_def *def)
{
	int              n;
	struct mdr_spec *spec;
	size_t           label_sz;

	if (def == NULL) {
		errno = EINVAL;
		return NULL;
	}

	for (n = 0; def->types[n] != MDR_LAST; n++)
		/* Nothing */;

	label_sz = strlen(def->label);

	spec = malloc(sizeof(struct mdr_spec) + (n * sizeof(uint8_t)) +
	    label_sz);
	if (spec == NULL)
		return NULL;

	spec->dcv = def->dcv;
	spec->types_count = n;
	memcpy(spec->types, def->types, n * sizeof(uint8_t));
	spec->label = (char *)spec->types + (n * sizeof(uint8_t));
	memcpy(spec->label, def->label, label_sz);

	if (RB_INSERT(mdr_registry_tree, &mdr_registry.head, spec) != NULL) {
		free(spec);
		errno = EEXIST;
		return NULL;
	}

	mdr_registry.count++;

	return spec;
}

const struct mdr_spec *
mdr_registry_get(uint64_t dcv)
{
	struct mdr_spec  key;
	struct mdr_spec *r;

	key.dcv = dcv;
	r = RB_FIND(mdr_registry_tree, &mdr_registry.head, &key);
	if (r == NULL)
		errno = ENOENT;
	return r;
}

void
mdr_registry_clear()
{
	struct mdr_spec *s, *next;

	for (s = RB_MIN(mdr_registry_tree, &mdr_registry.head);
	    s != NULL; s = next) {
		next = RB_NEXT(mdr_registry_tree, &mdr_registry.head, s);
		RB_REMOVE(mdr_registry_tree, &mdr_registry.head, s);
		free(s);
	}
}

size_t
mdr_spec_base_sz(const struct mdr_spec *spec)
{
	int    i;
	size_t sz = 0;

	for (i = 0; i < spec->types_count; i++) {
		switch (spec->types[i]) {
		case MDR_U8:
		case MDR_I8:
			sz += sizeof(uint8_t);
			break;
		case MDR_U16:
		case MDR_I16:
			sz += sizeof(uint16_t);
			break;
		case MDR_U32:
		case MDR_I32:
		case MDR_F32:
			sz += sizeof(uint32_t);
			break;
		case MDR_U64:
		case MDR_I64:
		case MDR_F64:
		case MDR_S:
		case MDR_B:
			/*
			 * We don't know how big the S/B payload may be,
			 * but we can at least assume the size prefix is
			 * up to uint64_t.
			 */
			sz += sizeof(uint64_t);
			break;
		case MDR_M:
			/*
			 * We can only know the maximum size of the MDR header.
			 * Let's assume the worst.
			 */
			sz += mdr_hdr_size(MDR_FALL);
			break;
		case MDR_AU8:
		case MDR_AU16:
		case MDR_AU32:
		case MDR_AU64:
		case MDR_AI8:
		case MDR_AI16:
		case MDR_AI32:
		case MDR_AI64:
		case MDR_AF32:
		case MDR_AF64:
		case MDR_AS:
		case MDR_AM:
		default:
			/*
			 * We don't know how big the array, or each element
			 * will be. All we can know is that there is the
			 * array size prefix.
			 */
			sz += sizeof(uint64_t);
			break;
		}
	}
	return sz;
}

void *
pmdr_buf(struct pmdr *m)
{
	return m->m.buf;
}

const void *
umdr_buf(const struct umdr *m)
{
	return m->m.buf;
}

ptrdiff_t
pmdr_tell(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	return mdr_tell(&m->m);
}

ptrdiff_t
umdr_tell(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	return mdr_tell(&m->m);
}

uint64_t
pmdr_size(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	return mdr_size(&m->m);
}

uint64_t
umdr_size(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	return mdr_size(&m->m);
}

uint32_t
pmdr_features(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_features(&m->m);
}

uint32_t
umdr_features(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_features(&m->m);
}

uint64_t
mdr_mkdcv(uint32_t domain, uint16_t code, uint16_t variant)
{
	uint64_t dcv = 0;
	dcv |= (uint64_t)domain << 32;
	dcv |= (uint64_t)code << 16;
	dcv |= (uint64_t)variant;
	return dcv;
}

int
pmdr_print(FILE *out, const struct pmdr *pm)
{
	if (out == NULL || pm == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_print(out, &pm->m);
}

int
umdr_print(FILE *out, const struct umdr *pm)
{
	if (out == NULL || pm == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_print(out, &pm->m);
}

uint64_t
pmdr_dcv(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_dcv(&m->m);
}

uint64_t
umdr_dcv(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_dcv(&m->m);
}

uint32_t
pmdr_domain(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_domain(&m->m);
}

uint32_t
umdr_domain(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_domain(&m->m);
}

uint16_t
pmdr_code(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_code(&m->m);
}

uint16_t
umdr_code(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_code(&m->m);
}

uint16_t
pmdr_variant(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_variant(&m->m);
}

uint16_t
umdr_variant(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_variant(&m->m);
}

uint64_t
pmdr_stream_id(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_stream_id(&m->m);
}

uint64_t
umdr_stream_id(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_stream_id(&m->m);
}

uint64_t
pmdr_acct_id(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_acct_id(&m->m);
}

uint64_t
umdr_acct_id(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_acct_id(&m->m);
}

const uint8_t *
pmdr_trace_id(const struct pmdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return mdr_trace_id(&m->m);
}

const uint8_t *
umdr_trace_id(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return mdr_trace_id(&m->m);
}

int
pmdr_dcv_match(const struct pmdr *m, uint64_t dcv, uint64_t mask)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (be64toh(*m->m.dcv) & mask) == (dcv & mask);
}

int
umdr_dcv_match(const struct umdr *m, uint64_t dcv, uint64_t mask)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (be64toh(*m->m.dcv) & mask) == (dcv & mask);
}

void
pmdr_free(struct pmdr *m)
{
	if (m == NULL)
		return;
	if (m->m.dyn)
		free(m->m.buf);
	bzero(m, sizeof(struct pmdr));
}

size_t
mdr_hdr_size(uint32_t features)
{
	size_t n;
	/*
	 * Header format is as follows, all integers in big-endian:
	 *  - size:       uint64_t
	 *  - features:   uint32_t
	 *  - domain:     uint32_t
	 *  - code:       uint16_t
	 *  - variant:    uint16_t
	 *  - tail_bytes: uint64_t           (optional)
	 *  - stream_id:  uint64_t           (optional)
	 *  - acct_id:    uint64_t           (optional)
	 *  - trace_id:   union mdr_trace_id (optional)
	 */
	n = sizeof(uint64_t) +
	    (2 * sizeof(uint32_t)) +
	    (2 * sizeof(uint16_t));
	if (features & MDR_FTAILBYTES)
		n += sizeof(uint64_t);
	if (features & MDR_FSTREAMID)
		n += sizeof(uint64_t);
	if (features & MDR_FACCTID)
		n += sizeof(uint64_t);
	if (features & MDR_FTRACEID)
		n += sizeof(union mdr_trace_id);
	return n;
}

uint64_t
umdr_pending(const struct umdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	if (m->m.buf_sz >= umdr_size(m))
		return 0;
	return umdr_size(m) - m->m.buf_sz;
}

uint64_t
pmdr_tail_bytes(const struct pmdr *m, void **dst)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_tail_bytes(&m->m, dst);
}

uint64_t
umdr_tail_bytes(const struct umdr *m, void **dst)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return mdr_tail_bytes(&m->m, dst);
}

/*
 * When 'pm' and 'buf' is not NULL and buf_sz is large enough to contain
 * the MDR header, this never fails.
 */
ptrdiff_t
pmdr_init(struct pmdr *pm, void *buf, size_t buf_sz, uint32_t features)
{
	struct mdr *m;

	if (pm == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	m = &pm->m;

	if (buf != NULL) {
		if (buf_sz < mdr_hdr_size(features)) {
			errno = EOVERFLOW;
			return MDR_FAIL;
		}
		m->buf = buf;
		m->buf_sz = buf_sz;
		m->dyn = 0;
	} else {
		if ((m->buf = malloc(mdr_hdr_size(features) + buf_sz)) == NULL)
			return MDR_FAIL;
		m->buf_sz = mdr_hdr_size(features) + buf_sz;
		m->dyn = 1;
	}

	m->spec = NULL;
	m->spec_fld_idx = 0;
	m->pos = m->buf;
	m->accept_features = features;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	m->features = (uint32_t *)m->pos;
	m->pos += sizeof(*m->features);

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	if (features & MDR_FTAILBYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
		*m->tail_bytes = 0;
	} else
		m->tail_bytes = NULL;

	if (features & MDR_FSTREAMID) {
		m->stream_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->stream_id);
		*m->stream_id = 0;
	} else
		m->stream_id = NULL;

	if (features & MDR_FACCTID) {
		m->acct_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->acct_id);
		*m->acct_id = 0;
	} else
		m->acct_id = NULL;

	if (features & MDR_FTRACEID) {
		m->trace_id = (uint8_t *)m->pos;
		m->pos += sizeof(union mdr_trace_id);
		bzero(m->trace_id, sizeof(union mdr_trace_id));
	} else
		m->trace_id = NULL;

	*m->features = htobe32(features);
	*m->dcv = 0;

	return mdr_update_size(m);
}

ptrdiff_t
pmdr_pack(struct pmdr *pm, const struct mdr_spec *spec, struct pmdr_vec *pvec,
    size_t pvec_sz)
{
	ptrdiff_t   r;
	int         i;
	struct mdr *m;

	if (pm == NULL || (pvec == NULL && pvec_sz > 0)) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	m = &pm->m;

	m->pos = m->buf + mdr_hdr_size(mdr_features(m));
	m->spec = spec;
	m->spec_fld_idx = 0;
	*m->dcv = htobe64(spec->dcv);

	for (i = 0; i < pvec_sz && i < m->spec->types_count; i++) {
		if (pvec[i].type == MDR_RSVB) {
			if (m->spec->types[i] != MDR_B) {
				errno = EINVAL;
				goto fail;
			}
		} else if (pvec[i].type != m->spec->types[i]) {
			errno = EINVAL;
			goto fail;
		}

		union mdr_num_v nv;
		switch (pvec[i].type) {
		case MDR_U8:
			nv.u8 = pvec[i].v.u8;
			r = mdr_pack_num(m, MDR_U8, nv, sizeof(uint8_t));
			break;
		case MDR_U16:
			nv.u16 = pvec[i].v.u16;
			r = mdr_pack_num(m, MDR_U16, nv, sizeof(uint16_t));
			break;
		case MDR_U32:
			nv.u32 = pvec[i].v.u32;
			r = mdr_pack_num(m, MDR_U32, nv, sizeof(uint32_t));
			break;
		case MDR_U64:
			nv.u64 = pvec[i].v.u64;
			r = mdr_pack_num(m, MDR_U64, nv, sizeof(uint64_t));
			break;
		case MDR_I8:
			nv.i8 = pvec[i].v.i8;
			r = mdr_pack_num(m, MDR_I8, nv, sizeof(int8_t));
			break;
		case MDR_I16:
			nv.i16 = pvec[i].v.i16;
			r = mdr_pack_num(m, MDR_I16, nv, sizeof(int16_t));
			break;
		case MDR_I32:
			nv.i32 = pvec[i].v.i32;
			r = mdr_pack_num(m, MDR_I32, nv, sizeof(int32_t));
			break;
		case MDR_I64:
			nv.i64 = pvec[i].v.i64;
			r = mdr_pack_num(m, MDR_I64, nv, sizeof(int64_t));
			break;
		case MDR_F32:
			nv.f32 = pvec[i].v.f32;
			r = mdr_pack_num(m, MDR_F32, nv, sizeof(float));
			break;
		case MDR_F64:
			nv.f64 = pvec[i].v.f64;
			r = mdr_pack_num(m, MDR_F64, nv, sizeof(double));
			break;
		case MDR_B:
			if (!mdr_check_next_type(m, MDR_B))
				goto fail;
			r = mdr_pack_bytes_nochk(m, pvec[i].v.b.bytes,
			    pvec[i].v.b.sz);
			break;
		case MDR_S:
			if (!mdr_check_next_type(m, MDR_S))
				goto fail;
			r = mdr_pack_str_nochk(m, pvec[i].v.s);
			break;
		case MDR_RSVB:
			r = mdr_pack_rsvb(m, pvec[i].v.rsvb.dst,
			    pvec[i].v.rsvb.sz);
			break;
		case MDR_M:
			if (!mdr_check_next_type(m, MDR_M))
				goto fail;
			r = mdr_pack_mdr(m, &pvec[i].v.pmdr->m);
			break;
		case MDR_AU8:
			r = mdr_pack_array(m, MDR_AU8,
			    pvec[i].v.au8.length,
			    pvec[i].v.au8.items);
			break;
		case MDR_AU16:
			r = mdr_pack_array(m, MDR_AU16,
			    pvec[i].v.au16.length,
			    pvec[i].v.au16.items);
			break;
		case MDR_AU32:
			r = mdr_pack_array(m, MDR_AU32,
			    pvec[i].v.au32.length,
			    pvec[i].v.au32.items);
			break;
		case MDR_AU64:
			r = mdr_pack_array(m, MDR_AU64,
			    pvec[i].v.au64.length,
			    pvec[i].v.au64.items);
			break;
		case MDR_AI8:
			r = mdr_pack_array(m, MDR_AI8,
			    pvec[i].v.ai8.length,
			    pvec[i].v.ai8.items);
			break;
		case MDR_AI16:
			r = mdr_pack_array(m, MDR_AI16,
			    pvec[i].v.ai16.length,
			    pvec[i].v.ai16.items);
			break;
		case MDR_AI32:
			r = mdr_pack_array(m, MDR_AI32,
			    pvec[i].v.ai32.length,
			    pvec[i].v.ai32.items);
			break;
		case MDR_AI64:
			r = mdr_pack_array(m, MDR_AI64,
			    pvec[i].v.ai64.length,
			    pvec[i].v.ai64.items);
			break;
		case MDR_AF32:
			r = mdr_pack_array(m, MDR_AF32,
			    pvec[i].v.af32.length,
			    pvec[i].v.af32.items);
			break;
		case MDR_AF64:
			r = mdr_pack_array(m, MDR_AF64,
			    pvec[i].v.af64.length,
			    pvec[i].v.af64.items);
			break;
		case MDR_AS:
			r = mdr_pack_array(m, MDR_AS,
			    pvec[i].v.as.length,
			    pvec[i].v.as.items);
			break;
		case MDR_AM:
			r = mdr_pack_array(m, MDR_AM,
			    pvec[i].v.am.length,
			    (void *)pvec[i].v.am.items);
			break;
		default:
			errno = EINVAL;
			goto fail;
		}
		if (r == MDR_FAIL)
			goto fail;
	}

	return mdr_tell(m);
fail:
	m->spec = NULL;
	return MDR_FAIL;
}

/*
 * umdr_init0 must be called first on umdst.
 */
ptrdiff_t
umdr_copy(struct umdr *umdst, const struct umdr *umsrc)
{
	struct mdr       *dst;
	const struct mdr *src;

	if (umdst == NULL || umsrc == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	dst = &umdst->m;
	src = &umsrc->m;

	if ((mdr_features(src) | dst->accept_features)
	    != dst->accept_features) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	if (src->buf_sz > dst->buf_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}
	memcpy(dst->buf, src->buf, src->buf_sz);

	dst->spec = src->spec;
	dst->spec_fld_idx = 0;
	dst->pos = dst->buf;

	dst->size = (uint64_t *)dst->pos;
	dst->pos += sizeof(*dst->size);

	dst->features = (uint32_t *)dst->pos;
	dst->pos += sizeof(*dst->features);

	dst->dcv = (uint64_t *)dst->pos;
	dst->pos += sizeof(*dst->dcv);

	if (mdr_features(dst) & MDR_FTAILBYTES) {
		dst->tail_bytes = (uint64_t *)dst->pos;
		dst->pos += sizeof(*dst->tail_bytes);
	} else
		dst->tail_bytes = NULL;

	if (mdr_features(dst) & MDR_FSTREAMID) {
		dst->stream_id = (uint64_t *)dst->pos;
		dst->pos += sizeof(*dst->stream_id);
	} else
		dst->stream_id = NULL;

	if (mdr_features(dst) & MDR_FACCTID) {
		dst->acct_id = (uint64_t *)dst->pos;
		dst->pos += sizeof(*dst->acct_id);
	} else
		dst->acct_id = NULL;

	if (mdr_features(dst) & MDR_FTRACEID) {
		dst->trace_id = (uint8_t *)dst->pos;
		dst->pos += sizeof(union mdr_trace_id);
	} else
		dst->trace_id = NULL;

	return mdr_tell(dst);
}

ptrdiff_t
pmdr_add_tail_bytes(struct pmdr *m, uint64_t bytes_sz)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_features(&m->m) & MDR_FTAILBYTES)) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	if (m->m.spec == NULL) {
		/*
		 * We shouldn't allow adding tail bytes until we've
		 * packed our regular payload.
		 */
		errno = EAGAIN;
		return MDR_FAIL;
	}

	if (UINT64_MAX - pmdr_tail_bytes(m, NULL) < bytes_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	*m->m.tail_bytes = htobe64(pmdr_tail_bytes(m, NULL) + bytes_sz);

	return mdr_update_size(&m->m);
}

ptrdiff_t
pmdr_set_stream_id(struct pmdr *m, uint64_t id)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_features(&m->m) & MDR_FSTREAMID)) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	*m->m.stream_id = htobe64(id);
	return mdr_update_size(&m->m);
}

ptrdiff_t
pmdr_set_acct_id(struct pmdr *m, uint64_t id)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_features(&m->m) & MDR_FACCTID)) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	*m->m.acct_id = htobe64(id);
	return mdr_update_size(&m->m);
}

ptrdiff_t
pmdr_set_trace_id(struct pmdr *m, const union mdr_trace_id *id)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_features(&m->m) & MDR_FTRACEID)) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	memcpy(m->m.trace_id, id, sizeof(union mdr_trace_id));
	return mdr_update_size(&m->m);
}

/*
 * fd must be blocking.
 */
// TODO: should we provide a generic function with a read callback?
ptrdiff_t
mdr_buf_from_fd(int fd, void *buf, size_t buf_sz)
{
	int       r;
	uint64_t  sz;
	ptrdiff_t count = 0;

	if (fd < 0 || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	r = readall(fd, buf, sizeof(uint64_t));
	if (r == -1)
		return MDR_FAIL;
	else if (r == 0)
		return 0;
	count = r;

	sz = be64toh(*(uint64_t *)buf);
	if (sz > buf_sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	r = readall(fd, buf + r, sz - r);
	if (r == -1) {
		return -1;
	} else if (r == 0) {
		/*
		 * If we tried to read again we'd get EPIPE, so let's
		 * just return that here.
		 */
		errno = EPIPE;
		return MDR_FAIL;
	}
	count += r;

	return count;
}

ptrdiff_t
mdr_buf_from_BIO(BIO *bio, void *buf, size_t buf_sz)
{
	int       r;
	uint64_t  sz;
	ptrdiff_t count = 0;

	if (bio == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	while (count < sizeof(uint64_t)) {
		if ((r = BIO_read(bio, buf + count,
		    sizeof(uint64_t) - count)) < 1)
			return -1;
		count += r;
	}

	sz = be64toh(*(uint64_t *)buf);
	if (sz > buf_sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	while (count < sz) {
		if ((r = BIO_read(bio, buf + count, sz - count)) < 1)
			return -1;
		count += r;
	}

	return count;
}

ptrdiff_t
umdr_init(struct umdr *um, const void *buf, size_t buf_sz,
    uint32_t accept_features)
{
	struct mdr *m;

	if (um == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	m = &um->m;

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->buf = (void *)buf;
	m->buf_sz = buf_sz;
	m->pos = m->buf;
	m->tail_bytes = 0;
	m->dyn = 0;
	m->spec = NULL;
	m->spec_fld_idx = 0;
	m->accept_features = accept_features;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	if (mdr_size(m) > PTRDIFF_MAX) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	/*
	 * Make sure we never try to unpack bytes past
	 * the end of our message.
	 */
	if (m->buf_sz > mdr_size(m))
		m->buf_sz = mdr_size(m);

	m->features = (uint32_t *)m->pos;
	m->pos += sizeof(*m->features);

	/*
	 * Return an error if we're trying to support feature bits that
	 * have no definition in this implementation.
	 */
	if ((accept_features | MDR_FALL) != MDR_FALL) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	/*
	 * Return an error if we don't want, or cannot handle some of the
	 * features in the unpacked MDR.
	 */
	if ((mdr_features(m) | accept_features) != accept_features) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(accept_features)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	if (mdr_features(m) & MDR_FTAILBYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
	} else
		m->tail_bytes = NULL;

	if (mdr_features(m) & MDR_FSTREAMID) {
		m->stream_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->stream_id);
	} else
		m->stream_id = NULL;

	if (mdr_features(m) & MDR_FACCTID) {
		m->acct_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->acct_id);
	} else
		m->acct_id = NULL;

	if (mdr_features(m) & MDR_FTRACEID) {
		m->trace_id = (uint8_t *)m->pos;
		m->pos += sizeof(union mdr_trace_id);
	} else
		m->trace_id = NULL;

	return mdr_tell(m);
}

/*
 * Only unpacks the mdr header without looking past standard fields (not
 * extra features). Useful when we only wish to initialize the buffer
 * to receive data, such as when using umdr_copy (the destination must
 * be initialized with umdr_init0).
 */
ptrdiff_t
umdr_init0(struct umdr *um, const void *buf, size_t buf_sz,
    uint32_t accept_features)
{
	struct mdr *m;

	if (um == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	/*
	 * Return an error if we're trying to support feature bits that
	 * have no definition in this implementation.
	 */
	if ((accept_features | MDR_FALL) != MDR_FALL) {
		errno = ENOTSUP;
		return MDR_FAIL;
	}

	m = &um->m;

	if (buf_sz < mdr_hdr_size(accept_features)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->buf = (void *)buf;
	m->buf_sz = buf_sz;
	m->pos = m->buf;
	m->tail_bytes = 0;
	m->dyn = 0;
	m->spec = NULL;
	m->spec_fld_idx = 0;
	m->accept_features = accept_features;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	m->features = (uint32_t *)m->pos;
	m->pos += sizeof(*m->features);

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	*m->size = 0;
	*m->features = 0;
	*m->dcv = 0;

	return mdr_tell(m);
}

ptrdiff_t
umdr_unpack(struct umdr *um, const struct mdr_spec *spec, struct umdr_vec *uvec,
    size_t uvec_sz)
{
	ptrdiff_t   r;
	int         i;
	struct mdr *m;

	if (um == NULL || (uvec == NULL && uvec_sz > 0)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	m = &um->m;
	m->pos = m->buf + mdr_hdr_size(mdr_features(m));

	if (spec == NULL) {
		if ((m->spec = mdr_registry_get(mdr_dcv(m))) == NULL) {
			if (errno == ENOENT)
				errno = ENOTSUP;
			return MDR_FAIL;
		}
	} else
		m->spec = spec;

	for (i = 0; i < uvec_sz && i < m->spec->types_count; i++) {
		uvec[i].type = m->spec->types[i];

		union mdr_num_v nv;
		switch (m->spec->types[i]) {
		case MDR_U8:
			r = mdr_unpack_num(m, MDR_U8, &nv, sizeof(uint8_t));
			if (r != MDR_FAIL)
				uvec[i].v.u8 = nv.u8;
			break;
		case MDR_U16:
			r = mdr_unpack_num(m, MDR_U16, &nv, sizeof(uint16_t));
			if (r != MDR_FAIL)
				uvec[i].v.u16 = nv.u16;
			break;
		case MDR_U32:
			r = mdr_unpack_num(m, MDR_U32, &nv, sizeof(uint32_t));
			if (r != MDR_FAIL)
				uvec[i].v.u32 = nv.u32;
			break;
		case MDR_U64:
			r = mdr_unpack_num(m, MDR_U64, &nv, sizeof(uint64_t));
			if (r != MDR_FAIL)
				uvec[i].v.u64 = nv.u64;
			break;
		case MDR_I8:
			r = mdr_unpack_num(m, MDR_I8, &nv, sizeof(int8_t));
			if (r != MDR_FAIL)
				uvec[i].v.i8 = nv.i8;
			break;
		case MDR_I16:
			r = mdr_unpack_num(m, MDR_I16, &nv, sizeof(int16_t));
			if (r != MDR_FAIL)
				uvec[i].v.i16 = nv.i16;
			break;
		case MDR_I32:
			r = mdr_unpack_num(m, MDR_I32, &nv, sizeof(int32_t));
			if (r != MDR_FAIL)
				uvec[i].v.i32 = nv.i32;
			break;
		case MDR_I64:
			r = mdr_unpack_num(m, MDR_I64, &nv, sizeof(int64_t));
			if (r != MDR_FAIL)
				uvec[i].v.i64 = nv.i64;
			break;
		case MDR_F32:
			r = mdr_unpack_num(m, MDR_F32, &nv, sizeof(float));
			if (r != MDR_FAIL)
				uvec[i].v.f32 = nv.f32;
			break;
		case MDR_F64:
			r = mdr_unpack_num(m, MDR_F64, &nv, sizeof(double));
			if (r != MDR_FAIL)
				uvec[i].v.f64 = nv.f64;
			break;
		case MDR_B:
			r = mdr_unpack_bytes(m, &uvec[i].v.b.bytes,
			    &uvec[i].v.b.sz);
			break;
		case MDR_S:
			r = mdr_unpack_str(m, &uvec[i].v.s.bytes,
			    &uvec[i].v.s.sz);
			break;
		case MDR_M:
			if (!mdr_check_next_type(m, MDR_M))
				return MDR_FAIL;
			r =  mdr_unpack_mdr(m, &uvec[i].v.m);
			break;
		case MDR_AU8:
			r = mdr_unpack_array(m, MDR_AU8, &uvec[i].v.au8);
			break;
		case MDR_AU16:
			r = mdr_unpack_array(m, MDR_AU16, &uvec[i].v.au16);
			break;
		case MDR_AU32:
			r = mdr_unpack_array(m, MDR_AU32, &uvec[i].v.au32);
			break;
		case MDR_AU64:
			r = mdr_unpack_array(m, MDR_AU64, &uvec[i].v.au64);
			break;
		case MDR_AI8:
			r = mdr_unpack_array(m, MDR_AI8, &uvec[i].v.ai8);
			break;
		case MDR_AI16:
			r = mdr_unpack_array(m, MDR_AI16, &uvec[i].v.ai16);
			break;
		case MDR_AI32:
			r = mdr_unpack_array(m, MDR_AI32, &uvec[i].v.ai32);
			break;
		case MDR_AI64:
			r = mdr_unpack_array(m, MDR_AI64, &uvec[i].v.ai64);
			break;
		case MDR_AF32:
			r = mdr_unpack_array(m, MDR_AF32, &uvec[i].v.af32);
			break;
		case MDR_AF64:
			r = mdr_unpack_array(m, MDR_AF64, &uvec[i].v.af64);
			break;
		case MDR_AS:
			r = mdr_unpack_array(m, MDR_AS, &uvec[i].v.as);
			break;
		case MDR_AM:
			r = mdr_unpack_array(m, MDR_AM, &uvec[i].v.am);
			break;
		default:
			errno = EINVAL;
			return MDR_FAIL;
		}
		if (r == MDR_FAIL)
			return MDR_FAIL;
	}

	return mdr_tell(m);
}

uint8_t
umdr_vec_atype(struct umdr_vec_ah *h)
{
	/*
	 * Exceptionally use abort() here since we don't provide
	 * another way to communicate the error.
	 */
	if (h == NULL)
		abort();
	return h->type;
}

uint32_t
umdr_vec_alen(struct umdr_vec_ah *h)
{
	/*
	 * Exceptionally use abort() here since we don't provide
	 * another way to communicate the error.
	 */
	if (h == NULL)
		abort();
	return h->length;
}

int32_t
umdr_vec_au8(struct umdr_vec_ah *h, uint8_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_U8, dst, maxlen);
}

int32_t
umdr_vec_au16(struct umdr_vec_ah *h, uint16_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_U16, dst, maxlen);
}

int32_t
umdr_vec_au32(struct umdr_vec_ah *h, uint32_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_U32, dst, maxlen);
}

int32_t
umdr_vec_au64(struct umdr_vec_ah *h, uint64_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_U64, dst, maxlen);
}

int32_t
umdr_vec_ai8(struct umdr_vec_ah *h, int8_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_I8, dst, maxlen);
}

int32_t
umdr_vec_ai16(struct umdr_vec_ah *h, int16_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_I16, dst, maxlen);
}

int32_t
umdr_vec_ai32(struct umdr_vec_ah *h, int32_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_I32, dst, maxlen);
}

int32_t
umdr_vec_ai64(struct umdr_vec_ah *h, int64_t *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_I64, dst, maxlen);
}

int32_t
umdr_vec_af32(struct umdr_vec_ah *h, float *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_F32, dst, maxlen);
}

int32_t
umdr_vec_af64(struct umdr_vec_ah *h, double *dst, int32_t maxlen)
{
	return umdr_vec_anum(h, MDR_F64, dst, maxlen);
}

int32_t
umdr_vec_as(struct umdr_vec_ah *h, const char **dst,
    int32_t maxlen)
{
	return umdr_vec_asm(h, MDR_S, dst, maxlen);
}

int32_t
umdr_vec_am(struct umdr_vec_ah *h, struct mdr *dst, int32_t maxlen)
{
	return umdr_vec_asm(h, MDR_M, dst, maxlen);
}
