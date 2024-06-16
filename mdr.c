#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mdr.h"

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
	char *tmp;

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

		m->size = (uint64_t *)(tmp + ((char *)m->size - m->buf));
		m->flags = (uint32_t *)(tmp + ((char *)m->flags - m->buf));
		m->namespace = (uint32_t *)(tmp + ((char *)m->namespace -
		    m->buf));
		m->id = (uint16_t *)(tmp + ((char *)m->id - m->buf));
		m->version = (uint16_t *)(tmp + ((char *)m->version - m->buf));

		if (mdr_flags(m) & MDR_F_TAIL_BYTES)
			m->tail_bytes = (uint64_t *)
			    (tmp + ((char *)m->tail_bytes - m->buf));

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
	*m->size = htobe64(mdr_tell(m) + mdr_tail_bytes(m));

	/*
	 * We return the size without trailing bytes to make
	 * it easy for callers to know where to start appending bytes
	 * in a buffer.
	 */
	return mdr_tell(m);
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
	 *  - namespace:  uint32_t
	 *  - id:         uint16_t
	 *  - version:    uint16_t
	 *  - tail_bytes: uint64_t (optional)
	 */
	n = sizeof(uint64_t) +
	    (2 * sizeof(uint32_t)) +
	    (2 * sizeof(uint16_t));
	if (flags & MDR_F_TAIL_BYTES)
		n += sizeof(uint64_t);
	return n;
}

uint64_t
mdr_size(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	return be64toh(*m->size);
}

ptrdiff_t
mdr_tell(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	return m->pos - m->buf;
}

uint64_t
mdr_pending(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return UINT64_MAX;
	}
	if (m->buf_sz >= (mdr_size(m) - mdr_tail_bytes(m)))
		return 0;
	return mdr_size(m) - mdr_tail_bytes(m) - m->buf_sz;
}

int
mdr_reset(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	m->pos = m->buf + mdr_hdr_size(mdr_flags(m));
	return 0;
}

uint32_t
mdr_namespace(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	return be32toh(*m->namespace);
}

uint32_t
mdr_flags(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	return be32toh(*m->flags);
}

uint16_t
mdr_id(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	return be16toh(*m->id);
}

uint16_t
mdr_version(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	return be16toh(*m->version);
}

uint64_t
mdr_tail_bytes(struct mdr *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (!(mdr_flags(m) & MDR_F_TAIL_BYTES))
		return 0;
	return be64toh(*m->tail_bytes);
}

void *
mdr_buf(struct mdr *m)
{
	return m->buf;
}

ptrdiff_t
mdr_pack_hdr(struct mdr *m, uint32_t flags, uint16_t namespace, uint16_t id,
    uint16_t version, char *buf, size_t buf_sz)
{
	if (m == NULL) {
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

	m->pos = m->buf;

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	m->flags = (uint32_t *)m->pos;
	m->pos += sizeof(*m->flags);

	m->namespace = (uint32_t *)m->pos;
	m->pos += sizeof(*m->namespace);

	m->id = (uint16_t *)m->pos;
	m->pos += sizeof(*m->id);

	m->version = (uint16_t *)m->pos;
	m->pos += sizeof(*m->version);

	if (flags & MDR_F_TAIL_BYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
		*m->tail_bytes = 0;

	} else {
		m->tail_bytes = NULL;
	}

	*m->flags = htobe32(flags);
	*m->namespace = htobe32(namespace);
	*m->id = htobe16(id);
	*m->version = htobe16(version);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_int64(struct mdr *m, int64_t v)
{
	return mdr_pack_uint64(m, (uint64_t)v);
}

ptrdiff_t
mdr_pack_int32(struct mdr *m, int32_t v)
{
	return mdr_pack_uint32(m, (uint32_t)v);
}

ptrdiff_t
mdr_pack_int16(struct mdr *m, int16_t v)
{
	return mdr_pack_uint16(m, (uint16_t)v);
}

ptrdiff_t
mdr_pack_int8(struct mdr *m, int8_t v)
{
	return mdr_pack_uint8(m, (uint8_t)v);
}

ptrdiff_t
mdr_pack_uint64(struct mdr *m, uint64_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint64_t)))
		return MDR_FAIL;

	*(uint64_t *)m->pos = htobe64(v);
	m->pos += sizeof(uint64_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_uint32(struct mdr *m, uint32_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint32_t)))
		return MDR_FAIL;

	*(uint32_t *)m->pos = htobe32(v);
	m->pos += sizeof(uint32_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_uint16(struct mdr *m, uint16_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint16_t)))
		return MDR_FAIL;

	*(uint16_t *)m->pos = htobe16(v);
	m->pos += sizeof(uint16_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_uint8(struct mdr *m, uint8_t v)
{
	if (m == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint8_t)))
		return MDR_FAIL;

	*(uint8_t *)m->pos = v;
	m->pos += sizeof(uint8_t);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_bytes(struct mdr *m, const char *bytes, uint64_t bytes_sz)
{
	if (m == NULL || bytes_sz & 0x8000000000000000) {
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

ptrdiff_t
mdr_pack_tail_bytes(struct mdr *m, uint64_t bytes_sz)
{
	if (m == NULL || !(mdr_flags(m) & MDR_F_TAIL_BYTES)) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (!mdr_can_fit(m, sizeof(uint64_t) + bytes_sz))
		return MDR_FAIL;

	if ((UINT64_MAX - (mdr_tell(m) + mdr_tail_bytes(m) +
	    sizeof(uint64_t) + 1)) < bytes_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	*(uint64_t *)m->pos = htobe64(bytes_sz);
	m->pos += sizeof(uint64_t);

	*m->tail_bytes = htobe64(mdr_tail_bytes(m) + bytes_sz);

	return mdr_update_size(m);
}

ptrdiff_t
mdr_pack_string(struct mdr *m, const char *bytes)
{
	return mdr_pack_bytes(m, bytes, strlen(bytes));
}

ptrdiff_t
mdr_pack_mdr(struct mdr *m, struct mdr *src)
{
	return mdr_pack_bytes(m, mdr_buf(src), mdr_size(src));
}

ptrdiff_t
mdr_packf(struct mdr *m, const char *spec, ...)
{
	va_list     ap;
	int         finish = 0;
	const char *p, *prev;
	const char *bytes;
	char       *end;
	uint64_t    bytes_sz;
	uint64_t    bits;
	/*
	 * A uint64 can render up to 20 digits, plus one for the 'b'
	 * prefix and the terminating NUL byte.
	 */
	char        spbuf[22];

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	/*
	 * Possible types in spec:
	 *   u8, u16, u32, u64
	 *   i8, i16, i32, i64
	 *   b, s
	 */
	va_start(ap, spec);
	for (p = spec, prev = spec; !finish; p++) {
		if (*p == '\0')
			finish = 1;

		if (*p != ':' && *p != '\0')
			continue;

		if (strlcpy(spbuf, prev,
		    (((p - prev) + 1) < sizeof(spbuf))
		    ? ((p - prev) + 1)
		    : sizeof(spbuf)) >= sizeof(spbuf)) {
			errno = EINVAL;
			return MDR_FAIL;
		}

		if (strcmp(spbuf, "b") == 0) {
			bytes = va_arg(ap, char *);
			bytes_sz = va_arg(ap, uint64_t);
			if (mdr_pack_bytes(m, bytes, bytes_sz) == MDR_FAIL) {
				errno = EOVERFLOW;
				return MDR_FAIL;
			}
		} else if (strcmp(spbuf, "s") == 0) {
			if (mdr_pack_string(m, va_arg(ap, char *))
			    == MDR_FAIL) {
				errno = EOVERFLOW;
				return MDR_FAIL;
			}
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2) {
				errno = EINVAL;
				return MDR_FAIL;
			}

			if ((bits = strtoull(spbuf + 1, &end, 10))
			    == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}

			switch (bits) {
			case 8:
				if (mdr_pack_uint8(m,
				    va_arg(ap, int)) == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 16:
				if (mdr_pack_uint16(m,
				    va_arg(ap, int)) == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 32:
				if (mdr_pack_uint32(m,
				    va_arg(ap, uint32_t)) == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			case 64:
				if (mdr_pack_uint64(m,
				    va_arg(ap, uint64_t)) == MDR_FAIL) {
					errno = EOVERFLOW;
					return MDR_FAIL;
				}
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else {
			/* Unknown type specifier */
			errno = EINVAL;
			return MDR_FAIL;
		}
		prev = p + 1;
	}
	va_end(ap);

	return mdr_tell(m);
}

/*
 * fd must be blocking.
 */
ptrdiff_t
mdr_unpack_from_fd(struct mdr *m, int fd, char *buf, size_t buf_sz)
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
	if (r == -1) {
		return -1;
	} else if (r == 0) {
		errno = EPIPE;
		return -1;
	}

	if (mdr_unpack_hdr(m, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;

	if (mdr_size(m) > buf_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	r = readall(fd, buf + r, mdr_size(m) - r);
	if (r == -1) {
		return -1;
	} else if (r == 0) {
		errno = EPIPE;
		return -1;
	}

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_all(struct mdr *m, char *buf, size_t buf_sz, size_t max_sz)
{
	if (mdr_unpack_hdr(m, buf, buf_sz) == MDR_FAIL)
		return MDR_FAIL;

	if (max_sz > 0 && mdr_size(m) > max_sz) {
		errno = EOVERFLOW;
		return MDR_FAIL;
	}

	if (mdr_pending(m) > 0) {
		errno = EAGAIN;
		return MDR_FAIL;
	}
	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_hdr(struct mdr *m, char *buf, size_t buf_sz)
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

	m->size = (uint64_t *)m->pos;
	m->pos += sizeof(*m->size);

	if (mdr_size(m) == UINT64_MAX) {
		errno = ERANGE;
		return MDR_FAIL;
	}

	m->flags = (uint32_t *)m->pos;
	m->pos += sizeof(*m->flags);

	if (buf_sz < mdr_hdr_size(mdr_flags(m))) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	m->namespace = (uint32_t *)m->pos;
	m->pos += sizeof(*m->namespace);

	m->id = (uint16_t *)m->pos;
	m->pos += sizeof(*m->id);

	m->version = (uint16_t *)m->pos;
	m->pos += sizeof(*m->version);

	if (mdr_flags(m) & MDR_F_TAIL_BYTES) {
		m->tail_bytes = (uint64_t *)m->pos;
		m->pos += sizeof(*m->tail_bytes);
	} else {
		m->tail_bytes = NULL;
	}

	return mdr_tell(m);
}

void
mdr_print(struct mdr *m)
{
	char *b;
	int   i;

	if (m == NULL)
		return;

	printf("  size:        %lu\n", mdr_size(m));
	printf("  namespace:   %u\n", mdr_namespace(m));
	printf("  id:          %u\n", mdr_id(m));
	printf("  version:     %u\n", mdr_version(m));
	if (mdr_flags(m) & MDR_F_TAIL_BYTES)
		printf("  tail bytes:  %lu\n", mdr_tail_bytes(m));
	printf("\n");
	printf("  payload (%lu bytes):\n",
	    mdr_size(m) - mdr_hdr_size(mdr_flags(m)) - mdr_tail_bytes(m));

	for (b = mdr_buf(m) + mdr_hdr_size(mdr_flags(m)), i = 0;
	    b - (char *)mdr_buf(m) < mdr_size(m) - mdr_tail_bytes(m);
	    b++, i++) {
		if (i % 8 == 0)
			printf("\n   ");
		else if (i % 4 == 0)
			printf(" ");
		printf(" %02x", (unsigned char)*b);
	}
	printf("\n");
}

ptrdiff_t
mdr_unpack_int8(struct mdr *m, int8_t *v)
{
	return mdr_unpack_uint8(m, (uint8_t *)v);
}

ptrdiff_t
mdr_unpack_int16(struct mdr *m, int16_t *v)
{
	return mdr_unpack_uint16(m, (uint16_t *)v);
}

ptrdiff_t
mdr_unpack_int32(struct mdr *m, int32_t *v)
{
	return mdr_unpack_uint32(m, (uint32_t *)v);
}

ptrdiff_t
mdr_unpack_int64(struct mdr *m, int64_t *v)
{
	return mdr_unpack_uint64(m, (uint64_t *)v);
}

ptrdiff_t
mdr_unpack_uint8(struct mdr *m, uint8_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint8_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = *(uint8_t *)m->pos;
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_uint16(struct mdr *m, uint16_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint16_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = be16toh(*(uint16_t *)m->pos);
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_uint32(struct mdr *m, uint32_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint32_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = be32toh(*(uint32_t *)m->pos);
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_uint64(struct mdr *m, uint64_t *v)
{
	if (m == NULL || v == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	*v = be64toh(*(uint64_t *)m->pos);
	m->pos += sizeof(*v);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_bytes(struct mdr *m, char *bytes, uint64_t *bytes_sz)
{
	uint64_t avail;

	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}
	avail = *bytes_sz;

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

	memcpy(bytes, m->pos, (avail < *bytes_sz) ? avail : *bytes_sz);
	m->pos += *bytes_sz;

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_tail_bytes(struct mdr *m, uint64_t *bytes_sz)
{
	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (m->buf_sz - mdr_tell(m) < sizeof(uint64_t)) {
		errno = ERANGE;
		return MDR_FAIL;
	}
	*bytes_sz = be64toh(*(uint64_t *)m->pos);
	m->pos += sizeof(uint64_t);

	*m->tail_bytes = htobe64(mdr_tail_bytes(m) + *bytes_sz);

	return mdr_tell(m);
}

ptrdiff_t
mdr_unpack_string(struct mdr *m, char *bytes, uint64_t *bytes_sz)
{
	uint64_t b, r;

	if (m == NULL || bytes_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	if (*bytes_sz < 1) {
		errno = EAGAIN;
		return MDR_FAIL;
	}

	b = *bytes_sz - 1;
	if ((r = mdr_unpack_bytes(m, bytes, &b)) == MDR_FAIL)
		return MDR_FAIL;

	bytes[(*bytes_sz < b) ? *bytes_sz : b] = '\0';
	*bytes_sz = b + 1;
	return r;
}

ptrdiff_t
mdr_unpack_mdr(struct mdr *m, struct mdr *msg, char *buf, uint64_t *buf_sz)
{
	uint64_t r, sz;

	if (m == NULL || msg == NULL || buf == NULL || buf_sz == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	sz = *buf_sz;
	if ((r = mdr_unpack_bytes(m, buf, buf_sz)) == MDR_FAIL)
		return MDR_FAIL;

	return mdr_unpack_hdr(msg, buf, sz);
}

ptrdiff_t
mdr_unpackf(struct mdr *m, const char *spec, ...)
{
	va_list     ap;
	int         finish = 0;
	const char *p, *prev;
	char       *bytes, *end;
	uint64_t   *bytes_sz;
	uint64_t    bits;
	/*
	 * A uint64 can render up to 20 digits, plus one for the 'b'
	 * prefix and the terminating NUL byte.
	 */
	char        spbuf[22];

	if (m == NULL || spec == NULL) {
		errno = EINVAL;
		return MDR_FAIL;
	}

	/*
	 * Possible types in spec:
	 *   u8, u16, u32, u64
	 *   i8, i16, i32, i64
	 *   b, s
	 */
	va_start(ap, spec);
	for (p = spec, prev = spec; !finish; p++) {
		if (*p == '\0')
			finish = 1;

		if (*p != ':' && *p != '\0')
			continue;

		if (strlcpy(spbuf, prev,
		    (((p - prev) + 1) < sizeof(spbuf))
		    ? ((p - prev) + 1)
		    : sizeof(spbuf)) >= sizeof(spbuf)) {
			errno = EINVAL;
			return MDR_FAIL;
		}

		if (strcmp(spbuf, "b") == 0) {
			bytes = va_arg(ap, char *);
			bytes_sz = va_arg(ap, uint64_t *);
			if (mdr_unpack_bytes(m, bytes, bytes_sz)
			    == MDR_FAIL)
				return MDR_FAIL;
		} else if (strcmp(spbuf, "s") == 0) {
			bytes = va_arg(ap, char *);
			bytes_sz = va_arg(ap, uint64_t *);
			if (mdr_unpack_string(m, bytes, bytes_sz) == MDR_FAIL)
				return MDR_FAIL;
		} else if (spbuf[0] == 'u' || spbuf[0] == 'i') {
			if (strlen(spbuf) < 2) {
				errno = EINVAL;
				return MDR_FAIL;
			}

			if ((bits = strtoull(spbuf + 1, &end, 10))
			    == ULLONG_MAX || *end != '\0') {
				errno = EINVAL;
				return MDR_FAIL;
			}

			switch (bits) {
			case 8:
				if (mdr_unpack_uint8(m,
				    va_arg(ap, uint8_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 16:
				if (mdr_unpack_uint16(m,
				    va_arg(ap, uint16_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 32:
				if (mdr_unpack_uint32(m,
				    va_arg(ap, uint32_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			case 64:
				if (mdr_unpack_uint64(m,
				    va_arg(ap, uint64_t *)) == MDR_FAIL)
					return MDR_FAIL;
				break;
			default:
				errno = EINVAL;
				return MDR_FAIL;
			}
		} else {
			/* Unknown type specifier */
			errno = EINVAL;
			return MDR_FAIL;
		}
		prev = p + 1;
	}
	va_end(ap);

	return mdr_tell(m);
}

ptrdiff_t
mdr_echo_encode(struct mdr_echo *m)
{
	uint64_t r;

	if ((r = mdr_pack_hdr(&m->m, 0, MDR_NS_ECHO, MDR_ID_ECHO, 0,
	    NULL, 0)) == MDR_FAIL)
		return MDR_FAIL;
	return mdr_pack_string(&m->m, m->echo);
}

ptrdiff_t
mdr_echo_decode(struct mdr_echo *m, char *buf, uint64_t sz)
{
	uint64_t r, len = sizeof(m->echo);

	if ((r = mdr_unpack_hdr(&m->m, buf, sz)) == MDR_FAIL)
		return MDR_FAIL;
	return mdr_unpack_string(&m->m, m->echo, &len);
}
