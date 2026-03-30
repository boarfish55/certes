#ifndef MDR_H
#define MDR_H

#include <sys/tree.h>
#include <openssl/bio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

__BEGIN_DECLS

struct mdr_def {
	uint64_t    dcv;     /* domain/code/variant */
	const char *label;
	uint8_t     types[];
};

enum mdr_type {
	MDR_U8 = 1,
	MDR_U16,
	MDR_U32,
	MDR_U64,

	MDR_I8,
	MDR_I16,
	MDR_I32,
	MDR_I64,

	MDR_F32,
	MDR_F64,

	MDR_S,
	MDR_B,
	MDR_M,
	MDR_RSVB,

	MDR_AU8,
	MDR_AU16,
	MDR_AU32,
	MDR_AU64,

	MDR_AI8,
	MDR_AI16,
	MDR_AI32,
	MDR_AI64,

	MDR_AF32,
	MDR_AF64,

	MDR_AS,
	MDR_AM,

	MDR_LAST = 255
};

struct mdr_spec {
	RB_ENTRY(mdr_spec)  entry;
	char               *label;
	uint64_t            dcv;
	size_t              types_count;
	uint8_t             types[];
};

union mdr_trace_id {
	uint8_t  u8[16];
	uint16_t u16[8];
	uint32_t u32[4];
	uint64_t u64[2];
};

/*
 * Minimal Data Representation
 *
 * An mdr message can contain at most PTRDIFF_MAX bytes.
 */
struct mdr {
	/*
	 * Big-endian over the wire.
	 */
	uint64_t *size;

	/*
	 * Features can be used to signal receiving implementations that the
	 * base structure of the message contains additional information
	 * that the receiver must support, or reject.
	 */
	uint32_t *features;
#define MDR_FNONE      0x00000000
#define MDR_FTAILBYTES 0x00000001 /* Arbitrary bytes follow the strucutred
				     payload. Useful for large data that
				     we don't want to load in memory all at
				     once. */
#define MDR_FSTREAMID  0x00000002 /* A field with stream ID is present */
#define MDR_FACCTID    0x00000004 /* A field with a generic accounting ID
				     is present */
#define MDR_FTRACEID   0x00000008 /* A field with a trace ID (e.g. UUID)
				     is present */
#define MDR_FRESERVED  0x80000000 /* The first bit flag is reserved for
				     a possible extension of more flag
				     fields.  */
#define MDR_FALL       0x0000000F /* Sum of all the above, except reserved. */

	/*
	 * Domain, code and variant is used to identify the data structure
	 * globally across many services.
	 *
	 * For instance, domain may be used as a service identifier,
	 * while code can identify the type of request and variant can
	 * allow defining multiple revisions or variantions of this requests,
	 * like adding new fields, optional fields, etc.
	 */
	uint64_t *dcv;         /* domain/code/variant */
	uint64_t *tail_bytes;  /* tail bytes are NOT accounted for in size */
	uint64_t *stream_id;
	uint64_t *acct_id;
	uint8_t  *trace_id;

	/*
	 * Internal only; not part of wire payload.
	 */
	const struct mdr_spec *spec;
	int                    spec_fld_idx;
	void                  *buf;
	size_t                 buf_sz;
	void                  *pos;
	int                    dyn;
	/*
	 * Used by umdr, when running umdr_init0() and we don't have
	 * actual flags in the buffer yet.
	 */
	uint32_t               accept_features;
};

/*
 * We create new types based on the struct mdr above:
 *   - pmdr should be used for packing MDRs.
 *   - umdr should be used for unpacking MDRs.
 *
 * Using those types ensures we are not using pack/unpack functions on
 * the same instance, which would be a mistake.
 */
struct pmdr {
	struct mdr m;
};
struct umdr {
	struct mdr m;
};

/* Packing MDR vector */
struct pmdr_vec {
	uint8_t type;
	union {
		uint8_t u8;
		struct {
			int32_t  length;
			uint8_t *items;
		} au8;

		uint16_t u16;
		struct {
			int32_t   length;
			uint16_t *items;
		} au16;

		uint32_t u32;
		struct {
			int32_t   length;
			uint32_t *items;
		} au32;

		uint64_t u64;
		struct {
			int32_t   length;
			uint64_t *items;
		} au64;

		int8_t i8;
		struct {
			int32_t  length;
			int8_t  *items;
		} ai8;

		int16_t i16;
		struct {
			int32_t  length;
			int16_t *items;
		} ai16;

		int32_t i32;
		struct {
			int32_t  length;
			int32_t *items;
		} ai32;

		int64_t i64;
		struct {
			int32_t  length;
			int64_t *items;
		} ai64;

		float f32;
		struct {
			int32_t  length;
			float   *items;
		} af32;

		double f64;
		struct {
			int32_t  length;
			double  *items;
		} af64;

		const struct pmdr *pmdr;
		const struct umdr *umdr;

		struct {
			int32_t            length;
			const struct pmdr *items;
		} am;

		const char *s;

		struct {
			const void *bytes;
			uint64_t    sz;
		} b;

		struct {
			int32_t      length;
			const char **items;
		} as;

		struct {
			void     **dst;
			uint64_t   sz;
		} rsvb;
	} v;
};
#define PMDRVECLEN(v) (sizeof(v) / sizeof(struct pmdr_vec))

/* Unpacking MDR vector array handle */
struct umdr_vec_ah
{
	uint8_t     type;
	uint32_t    length;
	const void *p;
};

/* Unpacking MDR vector */
struct umdr_vec {
	uint8_t type;
	union {
		uint8_t  u8;
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
		int8_t   i8;
		int16_t  i16;
		int32_t  i32;
		int64_t  i64;
		float    f32;
		double   f64;

		struct umdr m;

		struct {
			const char *bytes;
			uint64_t    sz;
		} s;

		struct {
			const void *bytes;
			uint64_t    sz;
		} b;

		struct umdr_vec_ah au8, au16, au32, au64;
		struct umdr_vec_ah ai8, ai16, ai32, ai64;
		struct umdr_vec_ah af32, af64;
		struct umdr_vec_ah as, am;
	} v;
};
#define UMDRVECLEN(v) (sizeof(v) / sizeof(struct umdr_vec))

uint8_t  umdr_vec_atype(struct umdr_vec_ah *);
uint32_t umdr_vec_alen(struct umdr_vec_ah *);
int32_t  umdr_vec_au8(struct umdr_vec_ah *, uint8_t *, int32_t);
int32_t  umdr_vec_au16(struct umdr_vec_ah *, uint16_t *, int32_t);
int32_t  umdr_vec_au32(struct umdr_vec_ah *, uint32_t *, int32_t);
int32_t  umdr_vec_au64(struct umdr_vec_ah *, uint64_t *, int32_t);
int32_t  umdr_vec_ai8(struct umdr_vec_ah *, int8_t *, int32_t);
int32_t  umdr_vec_ai16(struct umdr_vec_ah *, int16_t *, int32_t);
int32_t  umdr_vec_ai32(struct umdr_vec_ah *, int32_t *, int32_t);
int32_t  umdr_vec_ai64(struct umdr_vec_ah *, int64_t *, int32_t);
int32_t  umdr_vec_af32(struct umdr_vec_ah *, float *, int32_t);
int32_t  umdr_vec_af64(struct umdr_vec_ah *, double *, int32_t);
int32_t  umdr_vec_as(struct umdr_vec_ah *, const char **, int32_t);
int32_t  umdr_vec_am(struct umdr_vec_ah *, struct mdr *, int32_t);

#define MDR_FAIL -1

size_t         mdr_hdr_size(uint32_t);
uint64_t       mdr_mkdcv(uint32_t, uint16_t, uint16_t);
ptrdiff_t      mdr_buf_from_fd(int, void *, size_t);
ptrdiff_t      mdr_buf_from_BIO(BIO *, void *, size_t);

ptrdiff_t      pmdr_init(struct pmdr *, void *, size_t, uint32_t);
void           pmdr_free(struct pmdr *);
ptrdiff_t      pmdr_pack(struct pmdr *, const struct mdr_spec *, struct pmdr_vec *,
                   size_t);
ptrdiff_t      pmdr_add_tail_bytes(struct pmdr *, uint64_t);
ptrdiff_t      pmdr_set_stream_id(struct pmdr *, uint64_t);
ptrdiff_t      pmdr_set_acct_id(struct pmdr *, uint64_t);
ptrdiff_t      pmdr_set_trace_id(struct pmdr *, const union mdr_trace_id *);
void          *pmdr_buf(struct pmdr *);
uint64_t       pmdr_size(const struct pmdr *);
ptrdiff_t      pmdr_tell(const struct pmdr *);
uint32_t       pmdr_features(const struct pmdr *);
uint32_t       pmdr_domain(const struct pmdr *);
uint16_t       pmdr_code(const struct pmdr *);
uint16_t       pmdr_variant(const struct pmdr *);
uint64_t       pmdr_dcv(const struct pmdr *);
uint64_t       pmdr_tail_bytes(const struct pmdr *, void **dst);
int            pmdr_print(FILE *, const struct pmdr *);

ptrdiff_t      umdr_init(struct umdr *, const void *, size_t, uint32_t);
ptrdiff_t      umdr_init0(struct umdr *, const void *, size_t, uint32_t);
ptrdiff_t      umdr_unpack(struct umdr *, const struct mdr_spec *, struct umdr_vec *,
                   size_t);
const void    *umdr_buf(const struct umdr *);
uint64_t       umdr_size(const struct umdr *);
ptrdiff_t      umdr_tell(const struct umdr *);
ptrdiff_t      umdr_copy(struct umdr *, const struct umdr *);
uint64_t       umdr_pending(const struct umdr *);
uint32_t       umdr_features(const struct umdr *);
uint32_t       umdr_domain(const struct umdr *);
uint16_t       umdr_code(const struct umdr *);
uint16_t       umdr_variant(const struct umdr *);
uint64_t       umdr_dcv(const struct umdr *);
uint64_t       umdr_tail_bytes(const struct umdr *, void **dst);
uint64_t       umdr_stream_id(const struct umdr *);
uint64_t       umdr_acct_id(const struct umdr *);
const uint8_t *umdr_trace_id(const struct umdr *);
int            umdr_dcv_match(const struct umdr *, uint64_t, uint64_t);
int            umdr_print(FILE *, const struct umdr *);

int                    mdr_register_builtin_specs();
const struct mdr_spec *mdr_register_spec(struct mdr_def *);
const struct mdr_spec *mdr_registry_get(uint64_t);
void                   mdr_registry_clear();

size_t                 mdr_spec_base_sz(const struct mdr_spec *, uint64_t);

#define MDR_DCV(domain, code, variant) \
    ((uint64_t)domain << 32 | (uint64_t)code << 16 | (uint64_t)variant)

#define MDR_MASK_D   0xffffffff00000000
#define MDR_MASK_DC  0xffffffffffff0000
#define MDR_MASK_DCV 0xffffffffffffffff
#define MDR_MAKE_VARIANT(dcv, variant) \
    (((uint64_t)dcv & MDR_MASK_DC) | (uint64_t)variant)

/*
 * Built-in DCVs (Domain/Code/Variant). Domains are 32 bits, code and
 * variant are 16 bits.
 */

/*
 * Messages exchanged between mdrd and its clients; clients must support
 * MDR_DCV_MDR_ERROR responses.
 */
#define MDR_DOMAIN_MDR             MDR_DCV(0x00000000, 0, 0)
#define MDR_DCV_MDR_NULL           MDR_DCV(0x00000000, 0x0000, 0x0000)
#define MDR_DCV_MDR_PING           MDR_DCV(0x00000000, 0x0001, 0x0000)
#define MDR_DCV_MDR_PONG           MDR_DCV(0x00000000, 0x0001, 0x0001)
#define MDR_DCV_MDR_OK             MDR_DCV(0x00000000, 0x0002, 0x0000)
                                   /* Generic response to signify success,
                                      with nothing else to return to client */
#define MDR_DCV_MDR_ERROR          MDR_DCV(0x00000000, 0x0003, 0x0000)
enum mdr_err_code {
	MDR_ERR_FAIL = 1,   /* Generic failure */
	MDR_ERR_BEFAIL,     /* Failure on backend */
	MDR_ERR_BADMSG,     /* Bad message format */
	MDR_ERR_SZEX,       /* MDR size exceeded */
	MDR_ERR_NOTSUPP,    /* Message not supported */
	MDR_ERR_CERTFAIL,   /* Cerfificate validation failure */
	MDR_ERR_DENIED,     /* Client is not authorized for this operation */

	MDR_ERR_LAST,

	/*
	 * Applications can define their own errors
	 * starting at this index.
	 */
	MDR_ERR_LOCAL = 1073741824,
};
#define MDR_DCV_MDR_TEST           MDR_DCV(0x00000000, 0x0004, 0x0000)
extern const struct mdr_spec *mdr_msg_ping;
extern const struct mdr_spec *mdr_msg_pong;
extern const struct mdr_spec *mdr_msg_ok;
extern const struct mdr_spec *mdr_msg_error;
extern const struct mdr_spec *mdr_msg_test;

/* Messages exchanged between mdrd and its backend */
#define MDR_DOMAIN_MDRD          MDR_DCV(0x00000001, 0, 0)
#define MDR_DCV_MDRD_BEIN        MDR_DCV(0x00000001, 0x0001, 0x0000)
#define MDR_DCV_MDRD_BEOUT       MDR_DCV(0x00000001, 0x0002, 0x0000)
#define MDR_DCV_MDRD_BEOUT_EMPTY MDR_DCV(0x00000001, 0x0002, 0x0001)
#define MDR_DCV_MDRD_BECLOSE     MDR_DCV(0x00000001, 0x0003, 0x0000)
#define MDR_DCV_MDRD_BESESSERR   MDR_DCV(0x00000001, 0x0004, 0x0000)
                                 /* Backend tried to send a response but
                                    mdrd could not find an active session */
extern const struct mdr_spec *mdr_msg_mdrd_bein;
extern const struct mdr_spec *mdr_msg_mdrd_beout;
extern const struct mdr_spec *mdr_msg_mdrd_beout_empty;
extern const struct mdr_spec *mdr_msg_mdrd_beclose;
extern const struct mdr_spec *mdr_msg_mdrd_besesserr;

#define MDR_DOMAIN_CERTALATOR    MDR_DCV(0x00000002, 0, 0)

__END_DECLS

#endif
