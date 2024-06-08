#ifndef MDR_H
#define MDR_H

#include <stdint.h>
#include <stddef.h>

/*
 * Minimal Data Representation
 *
 * An mdr message can contain at most (UINT64_MAX - 1) bytes.
 * Total bytes excluding tail bytes is PTRDIFF_MAX.
 */
struct mdr {
	/*
	 * Big-endian over the wire. Minimum size is thus 20 bytes.
	 */
	uint64_t *size;

	/* Reserved for future use */
	uint32_t *flags;
#define MDR_F_TAIL_BYTES 0x00000001

	/*
	 * Namespace, id and version is used to identify
	 * the data structure globally across many services.
	 *
	 * For instance, namespace may be used as a service identifier,
	 * while id can identify the type of request and version can
	 * allow defining multiple revisions or variants of this requests,
	 * like adding new fields.
	 */
	uint32_t *namespace;
	uint16_t *id;
	uint16_t *version;
	uint64_t *tail_bytes;

	/*
	 * Internal only; not part of wire payload.
	 */
	char     *buf;
	size_t    buf_sz;
	char     *pos;
	int       dyn;
};


/*
 * Namespaces are 32 bits. The most significant bit is reserved for
 * future use, which in effect means the highest namespace is 0x7FFFFFFF.
 */
#define MDR_NS_ECHO     0x00000001
#define MDR_NS_RESERVED 0x80000000

/* IDs are 16 bits */
#define MDR_ID_ECHO 0x0001

struct mdr_echo {
	struct mdr m;
	char       echo[1024];
};

#define MDR_FAIL UINT64_MAX

void      *mdr_buf(struct mdr *);
void       mdr_free(struct mdr *);
uint64_t   mdr_size(struct mdr *);
size_t     mdr_hdr_size(uint32_t);

int        mdr_reset(struct mdr *);
ptrdiff_t  mdr_tell(struct mdr *);
uint64_t   mdr_pending(struct mdr *);

uint32_t mdr_flags(struct mdr *);
uint32_t mdr_namespace(struct mdr *);
uint16_t mdr_id(struct mdr *);
uint16_t mdr_version(struct mdr *);
uint64_t mdr_tail_bytes(struct mdr *);

uint64_t mdr_pack_hdr(struct mdr *, uint32_t, uint16_t, uint16_t, uint16_t,
             char *, size_t);
uint64_t mdr_pack_int8(struct mdr *, int8_t);
uint64_t mdr_pack_int16(struct mdr *, int16_t);
uint64_t mdr_pack_int32(struct mdr *, int32_t);
uint64_t mdr_pack_int64(struct mdr *, int64_t);
uint64_t mdr_pack_uint8(struct mdr *, uint8_t);
uint64_t mdr_pack_uint16(struct mdr *, uint16_t);
uint64_t mdr_pack_uint32(struct mdr *, uint32_t);
uint64_t mdr_pack_uint64(struct mdr *, uint64_t);
uint64_t mdr_pack_bytes(struct mdr *, const char *, uint64_t);
uint64_t mdr_pack_tail_bytes(struct mdr *, uint64_t);
uint64_t mdr_pack_string(struct mdr *, const char *);
uint64_t mdr_pack_mdr(struct mdr *, struct mdr *);
uint64_t mdr_packf(struct mdr *, const char *, ...);

uint64_t mdr_unpack_from_fd(struct mdr *, int, char *, size_t);
uint64_t mdr_unpack_all(struct mdr *, char *, size_t, size_t);
uint64_t mdr_unpack_hdr(struct mdr *, char *, size_t);
uint64_t mdr_unpack_int8(struct mdr *, int8_t *);
uint64_t mdr_unpack_int16(struct mdr *, int16_t *);
uint64_t mdr_unpack_int32(struct mdr *, int32_t *);
uint64_t mdr_unpack_int64(struct mdr *, int64_t *);
uint64_t mdr_unpack_uint8(struct mdr *, uint8_t *);
uint64_t mdr_unpack_uint16(struct mdr *, uint16_t *);
uint64_t mdr_unpack_uint32(struct mdr *, uint32_t *);
uint64_t mdr_unpack_uint64(struct mdr *, uint64_t *);
uint64_t mdr_unpack_bytes(struct mdr *, char *, uint64_t *);
uint64_t mdr_unpack_tail_bytes(struct mdr *, uint64_t *);
uint64_t mdr_unpack_string(struct mdr *, char *, uint64_t *);
uint64_t mdr_unpackf(struct mdr *, const char *, ...);
void     mdr_print(struct mdr *);

uint64_t mdr_echo_encode(struct mdr_echo *);
uint64_t mdr_echo_decode(struct mdr_echo *, char *, uint64_t);

#endif
