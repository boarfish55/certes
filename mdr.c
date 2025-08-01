#include <sys/param.h>
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

static struct mdr_def mdr_ping = {
	MDR_DCV_MDR_PING,
	"mdr.ping",
	{
		MDR_LAST
	}
};
static struct mdr_def mdr_pong = {
	MDR_DCV_MDR_PONG,
	"mdr.pong",
	{
		MDR_LAST
	}
};
static struct mdr_def mdr_echo = {
	MDR_DCV_MDR_ECHO,
	"mdr.echo",
	{
		MDR_S,
		MDR_LAST
	}
};

static struct mdr_def mdrd_error = {
	MDR_DCV_MDRD_ERROR,
	"mdrd.error",
	{
		MDR_LAST
	}
};
static struct mdr_def mdrd_bereq = {
	MDR_DCV_MDRD_BEREQ,
	"mdrd.bereq",
	{
		MDR_U64,
		MDR_I32,
		MDR_M,
		MDR_B,
		MDR_LAST
	}
};
static struct mdr_def mdrd_beresp = {
	MDR_DCV_MDRD_BERESP,
	"mdrd.beresp",
	{
		MDR_U64,
		MDR_I32,
		MDR_U32,
		MDR_U32,
		MDR_LAST
	}
};
static struct mdr_def mdrd_beresp_wmsg = {
	MDR_DCV_MDRD_BERESP_WMSG,
	"mdrd.beresp_wmsg",
	{
		MDR_U64,
		MDR_I32,
		MDR_U32,
		MDR_U32,
		MDR_M,
		MDR_LAST
	}
};
static struct mdr_def mdrd_beclose = {
	MDR_DCV_MDRD_BECLOSE,
	"mdrd.beclose",
	{
		MDR_U64,
		MDR_LAST
	}
};

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
		m->flags = (uint32_t *)(tmp +
		    ((uint8_t *)m->flags - (uint8_t *)m->buf));
		m->dcv = (uint64_t *)(tmp +
		    ((uint8_t *)m->dcv - (uint8_t *)m->buf));

		if (mdr_flags(m) & MDR_F_TAIL_BYTES)
			m->tail_bytes = (uint64_t *)(tmp +
			    ((uint8_t *)m->tail_bytes - (uint8_t *)m->buf));

		if (mdr_flags(m) & MDR_F_STREAM_ID)
			m->stream_id = (uint64_t *)(tmp +
			    ((uint8_t *)m->stream_id - (uint8_t *)m->buf));

		if (mdr_flags(m) & MDR_F_ACCT_ID)
			m->acct_id = (uint64_t *)(tmp +
			    ((uint8_t *)m->acct_id - (uint8_t *)m->buf));

		if (mdr_flags(m) & MDR_F_TRACE_ID)
			m->trace_id = (uint8_t *)(tmp +
			    ((uint8_t *)m->trace_id - (uint8_t *)m->buf));

		m->buf = tmp;
	}

	return 1;
}

static ptrdiff_t
mdr_update_size(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
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
mdr_pack_bytes_nochk(struct mdr *m, const uint8_t *bytes, uint64_t bytes_sz)
{
	if (bytes_sz & 0x8000000000000000) {
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
mdr_pack_str_nochk(struct mdr *m, const char *bytes, int64_t maxlen)
{
	size_t len = strlen(bytes) + 1;

	if (maxlen < 0)
		maxlen = INT64_MAX;

	if (len > maxlen) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	return mdr_pack_bytes_nochk(m, (uint8_t *)bytes, MIN(len, maxlen));
}

ptrdiff_t
mdr_pack_mdr_nochk(struct mdr *m, const struct mdr *src)
{
	if (!mdr_can_fit(m, mdr_size(src)))
		return MDR_FAIL;

	memcpy(m->pos, mdr_buf(src), mdr_size(src));
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

	if (ref != NULL)
		*ref = m->pos;
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

	return mdr_tell(m);
}

static ptrdiff_t
mdr_unpack_mdr_nochk(struct mdr *m, struct mdr *dst)
{
	uint64_t sz;

	if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}
	sz = be64toh(*(uint64_t *)m->pos);

	if (m->buf_sz - mdr_tell(m) < sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	if (dst != NULL)
		if (mdr_unpack_hdr(dst, MDR_F_NONE, m->pos, sz) == MDR_FAIL)
			return MDR_FAIL;
	m->pos += sz;

	return mdr_tell(m);
}

static int
mdr_check_next_type(struct mdr *m, uint8_t type)
{
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
mdr_out_array_num(struct mdr_out_array_handle *h, uint8_t type, void *dst,
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
mdr_out_array_sm(struct mdr_out_array_handle *h, uint8_t type, void *dst,
    int32_t maxlen)
{
	int          i;
	uint64_t     sz;
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
				sz = be64toh(*(uint64_t *)pos) & 0x7fffffffffffffff;
				pos += sizeof(uint64_t);
			} else
				pos += sizeof(uint8_t);

			((const char **)dst)[i] = (const char *)pos;
			pos += sz;
		} else if (type == MDR_M) {
			sz = be64toh(*(uint64_t *)pos);
			if (mdr_unpack_hdr(((struct mdr *)dst) + i, MDR_F_NONE,
			    (uint8_t *)pos, sz) == MDR_FAIL)
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

int
mdr_register_builtin_specs()
{
	if (mdr_register_spec(&mdr_ping) == NULL ||
	    mdr_register_spec(&mdr_pong) == NULL ||
	    mdr_register_spec(&mdr_echo) == NULL ||
	    mdr_register_spec(&mdrd_error) == NULL ||
	    mdr_register_spec(&mdrd_bereq) == NULL ||
	    mdr_register_spec(&mdrd_beresp) == NULL ||
	    mdr_register_spec(&mdrd_beresp_wmsg) == NULL ||
	    mdr_register_spec(&mdrd_beclose) == NULL)
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
		;

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

uint64_t
mdr_mkdcv(uint32_t domain, uint16_t code, uint16_t variant)
{
	uint64_t dcv = 0;
	dcv |= (uint64_t)domain << 32;
	dcv |= (uint64_t)code << 16;
	dcv |= (uint64_t)variant;
	return dcv;
}

uint64_t
mdr_dcv(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return be64toh(*m->dcv);
}

int
mdr_dcv_match(const struct mdr *m, uint64_t dcv, uint64_t mask)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (be64toh(*m->dcv) & mask) == (dcv & mask);
}

ptrdiff_t
mdr_copy(struct mdr *dst, void *buf, size_t buf_sz, const struct mdr *src,
    const struct mdr_spec *spec)
{
	ptrdiff_t r;

	if ((r = mdr_pack_hdr(dst, buf, buf_sz, spec,
	    mdr_flags(src))) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_size(src) > buf_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	memcpy(dst->pos, mdr_buf(src) + mdr_hdr_size(mdr_flags(src)),
	    mdr_size(src) - mdr_hdr_size(mdr_flags(src)));

	*dst->size = htobe64(mdr_size(dst) +
	    (mdr_size(src) - mdr_hdr_size(mdr_flags(src))));

	return 0;
}

void
mdr_free(struct mdr *m)
{
	if (m == NULL)
		return;
	if (m->dyn)
		free(m->buf);
	bzero(m, sizeof(struct mdr));
}

size_t
mdr_hdr_size(uint32_t flags)
{
	size_t n;
	/*
	 * Header format is as follows, all integers in big-endian:
	 *  - size:       uint64_t
	 *  - flags:      uint32_t
	 *  - domain:     uint32_t
	 *  - code:       uint16_t
	 *  - variant:    uint16_t
	 *  - tail_bytes: uint64_t    (optional)
	 *  - stream_id:  uint64_t    (optional)
	 *  - acct_id:    uint64_t    (optional)
	 *  - trace_id:   uint8_t[16] (optional)
	 */
	n = sizeof(uint64_t) +
	    (2 * sizeof(uint32_t)) +
	    (2 * sizeof(uint16_t));
	if (flags & MDR_F_TAIL_BYTES)
		n += sizeof(uint64_t);
	if (flags & MDR_F_STREAM_ID)
		n += sizeof(uint64_t);
	if (flags & MDR_F_ACCT_ID)
		n += sizeof(uint64_t);
	if (flags & MDR_F_TRACE_ID)
		n += sizeof(uint8_t[16]);
	return n;
}

uint64_t
mdr_size(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	return be64toh(*m->size);
}

ptrdiff_t
mdr_tell(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	return m->pos - m->buf;
}

uint64_t
mdr_pending(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	if (m->buf_sz >= mdr_size(m))
		return 0;
	return mdr_size(m) - m->buf_sz;
}

int
mdr_rewind(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	m->pos = m->buf + mdr_hdr_size(mdr_flags(m));
	m->spec_fld_idx = 0;
	return 0;
}

uint32_t
mdr_flags(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return be32toh(*m->flags);
}

uint32_t
mdr_domain(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	return (uint32_t)(be64toh(*m->dcv) >> 32);
}

uint16_t
mdr_code(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (uint16_t)((be64toh(*m->dcv) & 0x00000000ffff0000) >> 16);
}

uint16_t
mdr_variant(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	return (uint16_t)(be64toh(*m->dcv) & 0x000000000000ffff);
}

uint64_t
mdr_tail_bytes(const struct mdr *m, void **dst)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	if (!(mdr_flags(m) & MDR_F_TAIL_BYTES))
		return 0;
	if (dst != NULL)
		*dst = (uint8_t *)mdr_buf(m) + mdr_size(m);
	return be64toh(*m->tail_bytes);
}

uint64_t
mdr_stream_id(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	if (!(mdr_flags(m) & MDR_F_STREAM_ID))
		return 0;
	return be64toh(*m->stream_id);
}

uint64_t
mdr_acct_id(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	if (!(mdr_flags(m) & MDR_F_ACCT_ID))
		return 0;
	return be64toh(*m->acct_id);
}

const uint8_t *
mdr_trace_id(const struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (!(mdr_flags(m) & MDR_F_TRACE_ID))
		return NULL;
	return m->trace_id;
}

const void *
mdr_buf(const struct mdr *m)
{
	return m->buf;
}

ptrdiff_t
mdr_pack(struct mdr *m, char *buf, size_t buf_sz, const struct mdr_spec *spec,
    uint32_t flags, struct mdr_in *in, size_t in_sz)
{
	ptrdiff_t r;
	int       i;

	if (mdr_pack_hdr(m, buf, buf_sz, spec, flags) == MDR_FAIL)
		return MDR_FAIL;

	for (i = 0; i < in_sz && i < m->spec->types_count; i++) {
		if (in[i].type == MDR_RSVB) {
			if (m->spec->types[i] != MDR_B) {
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else if (in[i].type != m->spec->types[i]) {
			errno = EINVAL;
			return MDR_FAIL;
		}

		switch (in[i].type) {
		case MDR_U8:
			r = mdr_pack_u8(m, in[i].v.u8);
			break;
		case MDR_U16:
			r = mdr_pack_u16(m, in[i].v.u16);
			break;
		case MDR_U32:
			r = mdr_pack_u32(m, in[i].v.u32);
			break;
		case MDR_U64:
			r = mdr_pack_u64(m, in[i].v.u64);
			break;
		case MDR_I8:
			r = mdr_pack_i8(m, in[i].v.i8);
			break;
		case MDR_I16:
			r = mdr_pack_i16(m, in[i].v.i16);
			break;
		case MDR_I32:
			r = mdr_pack_i32(m, in[i].v.i32);
			break;
		case MDR_I64:
			r = mdr_pack_i64(m, in[i].v.i64);
			break;
		case MDR_F32:
			r = mdr_pack_f32(m, in[i].v.f32);
			break;
		case MDR_F64:
			r = mdr_pack_f64(m, in[i].v.f64);
			break;
		case MDR_B:
			r = mdr_pack_bytes(m, in[i].v.b.bytes,
			    in[i].v.b.sz);
			break;
		case MDR_S:
			r = mdr_pack_str(m, in[i].v.s.bytes,
			    in[i].v.s.sz);
			break;
		case MDR_RSVB:
			r = mdr_pack_rsvb(m, in[i].v.rsvb.dst,
			    in[i].v.rsvb.sz);
			break;
		case MDR_M:
			r = mdr_pack_mdr(m, in[i].v.m);
			break;
		case MDR_AU8:
			r = mdr_pack_array(m, MDR_AU8,
			    in[i].v.au8.length,
			    in[i].v.au8.items);
			break;
		case MDR_AU16:
			r = mdr_pack_array(m, MDR_AU16,
			    in[i].v.au16.length,
			    in[i].v.au16.items);
			break;
		case MDR_AU32:
			r = mdr_pack_array(m, MDR_AU32,
			    in[i].v.au32.length,
			    in[i].v.au32.items);
			break;
		case MDR_AU64:
			r = mdr_pack_array(m, MDR_AU64,
			    in[i].v.au64.length,
			    in[i].v.au64.items);
			break;
		case MDR_AI8:
			r = mdr_pack_array(m, MDR_AI8,
			    in[i].v.ai8.length,
			    in[i].v.ai8.items);
			break;
		case MDR_AI16:
			r = mdr_pack_array(m, MDR_AI16,
			    in[i].v.ai16.length,
			    in[i].v.ai16.items);
			break;
		case MDR_AI32:
			r = mdr_pack_array(m, MDR_AI32,
			    in[i].v.ai32.length,
			    in[i].v.ai32.items);
			break;
		case MDR_AI64:
			r = mdr_pack_array(m, MDR_AI64,
			    in[i].v.ai64.length,
			    in[i].v.ai64.items);
			break;
		case MDR_AF32:
			r = mdr_pack_array(m, MDR_AF32,
			    in[i].v.af32.length,
			    in[i].v.af32.items);
			break;
		case MDR_AF64:
			r = mdr_pack_array(m, MDR_AF64,
			    in[i].v.af64.length,
			    in[i].v.af64.items);
			break;
		case MDR_AS:
			r = mdr_pack_array(m, MDR_AS,
			    in[i].v.as.length,
			    in[i].v.as.items);
			break;
		case MDR_AM:
			r = mdr_pack_array(m, MDR_AM,
			    in[i].v.am.length,
			    (void *)in[i].v.am.items);
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

ptrdiff_t
mdr_pack_hdr(struct mdr *m, char *buf, size_t buf_sz,
    const struct mdr_spec *spec, uint32_t flags)
{
	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf != NULL) {
		if (buf_sz < mdr_hdr_size(flags)) {
			errno = EOVERFLOW;
			return MDR_FAIL;
		}
		m->buf = buf;
		m->buf_sz = buf_sz;
		m->dyn = 0;
	} else {
		if ((m->buf = malloc(mdr_hdr_size(flags) + buf_sz)) == NULL)
			return MDR_FAIL;
		m->buf_sz = mdr_hdr_size(flags) + buf_sz;
		m->dyn = 1;
	}

	m->spec = spec;
	m->spec_fld_idx = 0;
	m->pos = m->buf;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	m->flags = (uint32_t *)m->pos;
	m->pos += sizeof(*m->flags);

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	if (flags & MDR_F_TAIL_BYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
		*m->tail_bytes = 0;

	} else
		m->tail_bytes = NULL;

	if (flags & MDR_F_STREAM_ID) {
		m->stream_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->stream_id);
		*m->stream_id = 0;

	} else
		m->stream_id = NULL;

	if (flags & MDR_F_ACCT_ID) {
		m->acct_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->acct_id);
		*m->acct_id = 0;

	} else
		m->acct_id = NULL;

	if (flags & MDR_F_TRACE_ID) {
		m->trace_id = (uint8_t *)m->pos;
		m->pos += sizeof(uint8_t) * 16;
		bzero(m->trace_id, sizeof(uint8_t) * 16);
	} else
		m->trace_id = NULL;

	*m->flags = htobe32(flags);
	*m->dcv = htobe64(spec->dcv);

	return mdr_update_size(m);
}

static ptrdiff_t
mdr_pack_num(struct mdr *m, uint8_t type, union mdr_num_v nv, size_t sz)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sz))
		return MDR_FAIL;

	if (!mdr_check_next_type(m, type))
		return MDR_FAIL;

	return mdr_pack_num_nochk(m, type, nv);
}

ptrdiff_t
mdr_pack_u8(struct mdr *m, uint8_t v)
{
	union mdr_num_v nv;

	nv.u8 = v;
	return mdr_pack_num(m, MDR_U8, nv, sizeof(uint8_t));
}

ptrdiff_t
mdr_pack_u16(struct mdr *m, uint16_t v)
{
	union mdr_num_v nv;

	nv.u16 = v;
	return mdr_pack_num(m, MDR_U16, nv, sizeof(uint16_t));
}

ptrdiff_t
mdr_pack_u32(struct mdr *m, uint32_t v)
{
	union mdr_num_v nv;

	nv.u32 = v;
	return mdr_pack_num(m, MDR_U32, nv, sizeof(uint32_t));
}

ptrdiff_t
mdr_pack_u64(struct mdr *m, uint64_t v)
{
	union mdr_num_v nv;

	nv.u64 = v;
	return mdr_pack_num(m, MDR_U64, nv, sizeof(uint64_t));
}

ptrdiff_t
mdr_pack_i8(struct mdr *m, int8_t v)
{
	union mdr_num_v nv;

	nv.i8 = v;
	return mdr_pack_num(m, MDR_I8, nv, sizeof(int8_t));
}

ptrdiff_t
mdr_pack_i16(struct mdr *m, int16_t v)
{
	union mdr_num_v nv;

	nv.i16 = v;
	return mdr_pack_num(m, MDR_I16, nv, sizeof(int16_t));
}

ptrdiff_t
mdr_pack_i32(struct mdr *m, int32_t v)
{
	union mdr_num_v nv;

	nv.i32 = v;
	return mdr_pack_num(m, MDR_I32, nv, sizeof(int32_t));
}

ptrdiff_t
mdr_pack_i64(struct mdr *m, int64_t v)
{
	union mdr_num_v nv;

	nv.i64 = v;
	return mdr_pack_num(m, MDR_I64, nv, sizeof(int64_t));
}

ptrdiff_t
mdr_pack_f32(struct mdr *m, float v)
{
	union mdr_num_v nv;

	nv.f32 = v;
	return mdr_pack_num(m, MDR_F32, nv, sizeof(float));
}

ptrdiff_t
mdr_pack_f64(struct mdr *m, double v)
{
	union mdr_num_v nv;

	nv.f64 = v;
	return mdr_pack_num(m, MDR_F64, nv, sizeof(double));
}

ptrdiff_t
mdr_pack_bytes(struct mdr *m, const void *bytes, uint64_t bytes_sz)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_B))
		return MDR_FAIL;

	return mdr_pack_bytes_nochk(m, bytes, bytes_sz);
}

ptrdiff_t
mdr_pack_rsvb(struct mdr *m, void **dst, uint64_t bytes_sz)
{
	if (m == NULL || bytes_sz & 0X8000000000000000) {
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

ptrdiff_t
mdr_add_tail_bytes(struct mdr *m, uint64_t bytes_sz)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_flags(m) & MDR_F_TAIL_BYTES)) {
		errno = EPERM;
		return MDR_FAIL;
	}

	if (UINT64_MAX - mdr_tail_bytes(m, NULL) < bytes_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	*m->tail_bytes = htobe64(mdr_tail_bytes(m, NULL) + bytes_sz);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_set_stream_id(struct mdr *m, uint64_t id)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_flags(m) & MDR_F_STREAM_ID)) {
		errno = EPERM;
		return MDR_FAIL;
	}

	*m->stream_id = htobe64(id);
	return mdr_update_size(m);
}

ptrdiff_t
mdr_set_acct_id(struct mdr *m, uint64_t id)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_flags(m) & MDR_F_ACCT_ID)) {
		errno = EPERM;
		return MDR_FAIL;
	}

	*m->acct_id = htobe64(id);
	return mdr_update_size(m);
}

ptrdiff_t
mdr_set_trace_id(struct mdr *m, const uint8_t *id)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!(mdr_flags(m) & MDR_F_TRACE_ID)) {
		errno = EPERM;
		return MDR_FAIL;
	}

	memcpy(m->trace_id, id, sizeof(uint8_t) * 16);
	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_str(struct mdr *m, const char *bytes, int64_t maxlen)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_S))
		return MDR_FAIL;

	return mdr_pack_str_nochk(m, bytes, maxlen);
}

ptrdiff_t
mdr_pack_mdr(struct mdr *m, const struct mdr *src)
{
	if (m == NULL || src == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_M))
		return MDR_FAIL;

	return mdr_pack_mdr_nochk(m, src);
}

ptrdiff_t
mdr_pack_array(struct mdr *m, uint8_t type, int32_t n, void *a)
{
	int              i;
	ptrdiff_t        r;
	union mdr_num_v  nv;
	void            *start;

	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

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
			r = mdr_pack_str_nochk(m, ((char **)a)[i], -1);
			break;
		case MDR_AM:
			r = mdr_pack_mdr_nochk(m, (struct mdr *)a + i);
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

/*
 * fd must be blocking.
 */
// TODO: should we provide a generic function with a read callback?
ptrdiff_t
mdr_read_from_fd(struct mdr *m, uint32_t accept_flags, int fd,
    void *buf, size_t buf_sz)
{
	int r;

	if (m == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	r = readall(fd, buf, mdr_hdr_size(0));
	if (r == -1)
		return -1;
	else if (r == 0)
		return 0;

	if (mdr_unpack_hdr(m, accept_flags, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_size(m) > buf_sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	r = readall(fd, buf + r, mdr_size(m) - r);
	if (r == -1) {
		return -1;
	} else if (r == 0) {
		/*
		 * If we tried to read again we'd get EPIPE, so let's
		 * just return that here.
		 */
		errno = EPIPE;
		return -1;
	}

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_hdr(struct mdr *m, uint32_t accept_flags, void *buf, size_t buf_sz)
{
	if (m == NULL || buf == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(0)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->buf = buf;
	m->buf_sz = buf_sz;
	m->pos = m->buf;
	m->tail_bytes = 0;
	m->dyn = 0;
	m->spec = NULL;
	m->spec_fld_idx = 0;

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

	m->flags = (uint32_t *)m->pos;
	m->pos += sizeof(*m->flags);

	/*
	 * Some flags (MDR_F_TAIL_BYTES) could have
	 * security implications and therefore refuse
	 * to unpack an mdr unless we explicitly allow
	 * specified flags.
	 */
	if ((mdr_flags(m) & ~accept_flags) != 0) {
		errno = EACCES;
		return MDR_FAIL;
	}

	if (buf_sz < mdr_hdr_size(mdr_flags(m))) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->dcv = (uint64_t *)m->pos;
	m->pos += sizeof(*m->dcv);

	if (mdr_flags(m) & MDR_F_TAIL_BYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
	} else
		m->tail_bytes = NULL;

	if (mdr_flags(m) & MDR_F_STREAM_ID) {
		m->stream_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->stream_id);
	} else
		m->stream_id = NULL;

	if (mdr_flags(m) & MDR_F_ACCT_ID) {
		m->acct_id = (uint64_t *)m->pos;
		m->pos += sizeof(*m->acct_id);
	} else
		m->acct_id = NULL;

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_payload(struct mdr *m, const struct mdr_spec *spec,
    struct mdr_out *out, size_t out_sz)
{
	ptrdiff_t r;
	int       i;

	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (spec == NULL) {
		if ((m->spec = mdr_registry_get(mdr_dcv(m))) == NULL) {
			if (errno == ENOENT)
				errno = ENOTSUP;
			return MDR_FAIL;
		}
	} else
		m->spec = spec;

	for (i = 0; i < out_sz && i < m->spec->types_count; i++) {
		out[i].type = m->spec->types[i];

		switch (m->spec->types[i]) {
		case MDR_U8:
			r = mdr_unpack_u8(m, &out[i].v.u8);
			break;
		case MDR_U16:
			r = mdr_unpack_u16(m, &out[i].v.u16);
			break;
		case MDR_U32:
			r = mdr_unpack_u32(m, &out[i].v.u32);
			break;
		case MDR_U64:
			r = mdr_unpack_u64(m, &out[i].v.u64);
			break;
		case MDR_I8:
			r = mdr_unpack_i8(m, &out[i].v.i8);
			break;
		case MDR_I16:
			r = mdr_unpack_i16(m, &out[i].v.i16);
			break;
		case MDR_I32:
			r = mdr_unpack_i32(m, &out[i].v.i32);
			break;
		case MDR_I64:
			r = mdr_unpack_i64(m, &out[i].v.i64);
			break;
		case MDR_F32:
			r = mdr_unpack_f32(m, &out[i].v.f32);
			break;
		case MDR_F64:
			r = mdr_unpack_f64(m, &out[i].v.f64);
			break;
		case MDR_B:
			r = mdr_unpack_bytes(m, &out[i].v.b.bytes,
			    &out[i].v.b.sz);
			break;
		case MDR_S:
			r = mdr_unpack_str(m, &out[i].v.s.bytes,
			    &out[i].v.s.sz);
			break;
		case MDR_M:
			r = mdr_unpack_mdr(m, &out[i].v.m);
			break;
		case MDR_AU8:
			r = mdr_unpack_array(m, MDR_AU8, &out[i].v.au8);
			break;
		case MDR_AU16:
			r = mdr_unpack_array(m, MDR_AU16, &out[i].v.au16);
			break;
		case MDR_AU32:
			r = mdr_unpack_array(m, MDR_AU32, &out[i].v.au32);
			break;
		case MDR_AU64:
			r = mdr_unpack_array(m, MDR_AU64, &out[i].v.au64);
			break;
		case MDR_AI8:
			r = mdr_unpack_array(m, MDR_AI8, &out[i].v.ai8);
			break;
		case MDR_AI16:
			r = mdr_unpack_array(m, MDR_AI16, &out[i].v.ai16);
			break;
		case MDR_AI32:
			r = mdr_unpack_array(m, MDR_AI32, &out[i].v.ai32);
			break;
		case MDR_AI64:
			r = mdr_unpack_array(m, MDR_AI64, &out[i].v.ai64);
			break;
		case MDR_AF32:
			r = mdr_unpack_array(m, MDR_AF32, &out[i].v.af32);
			break;
		case MDR_AF64:
			r = mdr_unpack_array(m, MDR_AF64, &out[i].v.af64);
			break;
		case MDR_AS:
			r = mdr_unpack_array(m, MDR_AS, &out[i].v.as);
			break;
		case MDR_AM:
			r = mdr_unpack_array(m, MDR_AM, &out[i].v.am);
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

ptrdiff_t
mdr_unpack(struct mdr *m, char *buf, size_t buf_sz, const struct mdr_spec *spec,
    uint32_t accept_flags, struct mdr_out *out, size_t out_sz)
{
	if (mdr_unpack_hdr(m, accept_flags, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;
	return mdr_unpack_payload(m, spec, out, out_sz);
}

static ptrdiff_t
mdr_unpack_num(struct mdr *m, uint8_t type, union mdr_num_v *nv, size_t sz)
{
	if (m == NULL || nv == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sz) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, type))
		return MDR_FAIL;

	return mdr_unpack_num_nochk(m, type, nv);
}

ptrdiff_t
mdr_unpack_u8(struct mdr *m, uint8_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_U8, &nv, sizeof(uint8_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.u8;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_u16(struct mdr *m, uint16_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_U16, &nv, sizeof(uint16_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.u16;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_u32(struct mdr *m, uint32_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_U32, &nv, sizeof(uint32_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.u32;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_u64(struct mdr *m, uint64_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_U64, &nv, sizeof(uint64_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.u64;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_i8(struct mdr *m, int8_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_I8, &nv, sizeof(int8_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.i8;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_i16(struct mdr *m, int16_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_I16, &nv, sizeof(int16_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.i16;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_i32(struct mdr *m, int32_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_I32, &nv, sizeof(int32_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.i32;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_i64(struct mdr *m, int64_t *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_I64, &nv, sizeof(int64_t)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.i64;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_f32(struct mdr *m, float *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_F32, &nv, sizeof(float)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.f32;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_f64(struct mdr *m, double *v)
{
	union mdr_num_v nv;

	if (mdr_unpack_num(m, MDR_F64, &nv, sizeof(double)) == MDR_FAIL)
		return MDR_FAIL;
	*v = nv.f64;
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_str(struct mdr *m, const char **ref, uint64_t *len)
{
	if (m == NULL || len == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_S))
		return MDR_FAIL;

	return mdr_unpack_str_nochk(m, ref, len);
}

ptrdiff_t
mdr_unpack_bytes(struct mdr *m, const void **ref, uint64_t *bytes_sz)
{
	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_B))
		return MDR_FAIL;

	return mdr_unpack_bytes_nochk(m, ref, bytes_sz);
}

ptrdiff_t
mdr_unpack_mdr(struct mdr *m, struct mdr *dst)
{
	if (m == NULL || dst == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_check_next_type(m, MDR_M))
		return MDR_FAIL;

	return mdr_unpack_mdr_nochk(m, dst);
}

ptrdiff_t
mdr_unpack_array(struct mdr *m, uint8_t type, struct mdr_out_array_handle *ah)
{
	uint32_t packed_n;
	uint64_t asize;

	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

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

uint8_t
mdr_out_array_type(struct mdr_out_array_handle *h)
{
	return h->type;
}

uint32_t
mdr_out_array_length(struct mdr_out_array_handle *h)
{
	return h->length;
}

int32_t
mdr_out_array_u8(struct mdr_out_array_handle *h, uint8_t *dst, int32_t maxlen)
{
	return mdr_out_array_num(h, MDR_U8, dst, maxlen);
}

int32_t
mdr_out_array_u16(struct mdr_out_array_handle *h, uint16_t *dst, int32_t maxlen)
{
	return mdr_out_array_num(h, MDR_U16, dst, maxlen);
}

int32_t
mdr_out_array_u32(struct mdr_out_array_handle *h, uint32_t *dst, int32_t maxlen)
{
	return mdr_out_array_num(h, MDR_U32, dst, maxlen);
}

int32_t
mdr_out_array_s(struct mdr_out_array_handle *h, const char **dst,
    int32_t maxlen)
{
	return mdr_out_array_sm(h, MDR_S, dst, maxlen);
}

int32_t
mdr_out_array_m(struct mdr_out_array_handle *h, struct mdr *dst, int32_t maxlen)
{
	return mdr_out_array_sm(h, MDR_M, dst, maxlen);
}

void
mdr_print(FILE *out, const struct mdr *m)
{
	const char *b;
	int         i;

	if (m == NULL)
		return;

	fprintf(out, "  size:        %lu\n", mdr_size(m));
	fprintf(out, "  domain:      %u\n", mdr_domain(m));
	fprintf(out, "  code:        %u\n", mdr_code(m));
	fprintf(out, "  variant:     %u\n", mdr_variant(m));
	if (mdr_flags(m) & MDR_F_TAIL_BYTES)
		fprintf(out, "  tail bytes:  %lu\n", mdr_tail_bytes(m, NULL));
	if (mdr_flags(m) & MDR_F_STREAM_ID)
		fprintf(out, "  stream ID:  %lu\n", mdr_tail_bytes(m, NULL));
	if (mdr_flags(m) & MDR_F_ACCT_ID)
		fprintf(out, "  accounting ID:  %lu\n", mdr_tail_bytes(m, NULL));
	fprintf(out, "\n");
	fprintf(out, "  payload (%lu bytes):\n",
	    mdr_size(m) - mdr_hdr_size(mdr_flags(m)));

	for (b = mdr_buf(m) + mdr_hdr_size(mdr_flags(m)), i = 0;
	    b - (char *)mdr_buf(m) < mdr_size(m);
	    b++, i++) {
		if (i % 8 == 0)
			fprintf(out, "\n   ");
		else if (i % 4 == 0)
			fprintf(out, " ");
		fprintf(out, " %02x", (unsigned char)*b);
	}
	fprintf(out, "\n");
}
