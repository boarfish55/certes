#ifndef MDR_H
#define MDR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/tree.h>

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

/*
 * Minimal Data Representation
 *
 * An mdr message can contain at most PTRDIFF_MAX bytes.
 */
struct mdr {
	/*
	 * Big-endian over the wire. Minimum size is thus 20 bytes.
	 */
	uint64_t *size;

	/*
	 * Flags can be used to provide generic information to implementations
	 * that are otherwise unaware of the specific structure of the data.
	 */
	uint32_t *flags;
#define MDR_F_NONE       0x00000000
#define MDR_F_TAIL_BYTES 0x00000001 /* Arbitrary bytes follow
				       the strucutred payload */
#define MDR_F_STREAM_ID  0x00000002 /* A field with stream ID is present */
#define MDR_F_ACCT_ID    0x00000004 /* A field with a generic accounting ID
				       is present */
#define MDR_F_TRACE_ID   0x00000008 /* A field with a trace ID (e.g. UUID)
				       is present */

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
};

struct mdr_in {
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

		const struct mdr *m;
		struct {
			int32_t           length;
			const struct mdr *items;
		} am;

		struct {
			const char *bytes;
			uint64_t    sz;
		} s;

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

struct mdr_out_array_handle
{
	uint8_t     type;
	uint32_t    length;
	const void *p;
};

struct mdr_out {
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

		struct mdr m;

		struct {
			const char *bytes;
			uint64_t    sz;
		} s;

		struct {
			const void *bytes;
			uint64_t    sz;
		} b;

		struct mdr_out_array_handle au8, au16, au32, au64;
		struct mdr_out_array_handle ai8, ai16, ai32, ai64;
		struct mdr_out_array_handle af32, af64;
		struct mdr_out_array_handle as, am;
	} v;
};

uint8_t  mdr_out_array_type(struct mdr_out_array_handle *);
uint32_t mdr_out_array_length(struct mdr_out_array_handle *);
int32_t  mdr_out_array_u8(struct mdr_out_array_handle *, uint8_t *, int32_t);
int32_t  mdr_out_array_u16(struct mdr_out_array_handle *, uint16_t *, int32_t);
int32_t  mdr_out_array_u32(struct mdr_out_array_handle *, uint32_t *, int32_t);
int32_t  mdr_out_array_u64(struct mdr_out_array_handle *, uint64_t *, int32_t);
int32_t  mdr_out_array_i8(struct mdr_out_array_handle *, int8_t *, int32_t);
int32_t  mdr_out_array_i16(struct mdr_out_array_handle *, int16_t *, int32_t);
int32_t  mdr_out_array_i32(struct mdr_out_array_handle *, int32_t *, int32_t);
int32_t  mdr_out_array_i64(struct mdr_out_array_handle *, int64_t *, int32_t);
int32_t  mdr_out_array_f32(struct mdr_out_array_handle *, float *, int32_t);
int32_t  mdr_out_array_f64(struct mdr_out_array_handle *, double *, int32_t);
int32_t  mdr_out_array_s(struct mdr_out_array_handle *, const char **, int32_t);
int32_t  mdr_out_array_m(struct mdr_out_array_handle *, struct mdr *, int32_t);

#define MDR_FAIL -1

const void *mdr_buf(const struct mdr *);
void        mdr_free(struct mdr *);
uint64_t    mdr_size(const struct mdr *);
size_t      mdr_hdr_size(uint32_t);
int         mdr_rewind(struct mdr *);
ptrdiff_t   mdr_tell(const struct mdr *);
uint64_t    mdr_pending(const struct mdr *);
ptrdiff_t   mdr_copy(struct mdr *, void *, size_t, const struct mdr *,
                const struct mdr_spec *);
uint64_t    mdr_mkdcv(uint32_t, uint16_t, uint16_t);

uint32_t       mdr_flags(const struct mdr *);
uint32_t       mdr_domain(const struct mdr *);
uint16_t       mdr_code(const struct mdr *);
uint16_t       mdr_variant(const struct mdr *);
uint64_t       mdr_dcv(const struct mdr *);
uint64_t       mdr_tail_bytes(const struct mdr *, void **dst);
uint64_t       mdr_stream_id(const struct mdr *);
uint64_t       mdr_acct_id(const struct mdr *);
const uint8_t *mdr_trace_id(const struct mdr *);
int            mdr_dcv_match(const struct mdr *, uint64_t, uint64_t);

ptrdiff_t mdr_pack_hdr(struct mdr *, char *, size_t, const struct mdr_spec *,
              uint32_t);
ptrdiff_t mdr_pack(struct mdr *, char *, size_t, const struct mdr_spec *,
              uint32_t, struct mdr_in *, size_t);
ptrdiff_t mdr_pack_i8(struct mdr *, int8_t);
ptrdiff_t mdr_pack_i16(struct mdr *, int16_t);
ptrdiff_t mdr_pack_i32(struct mdr *, int32_t);
ptrdiff_t mdr_pack_i64(struct mdr *, int64_t);
ptrdiff_t mdr_pack_u8(struct mdr *, uint8_t);
ptrdiff_t mdr_pack_u16(struct mdr *, uint16_t);
ptrdiff_t mdr_pack_u32(struct mdr *, uint32_t);
ptrdiff_t mdr_pack_u64(struct mdr *, uint64_t);
ptrdiff_t mdr_pack_f32(struct mdr *, float);
ptrdiff_t mdr_pack_f64(struct mdr *, double);
ptrdiff_t mdr_pack_bytes(struct mdr *, const void *, uint64_t);
ptrdiff_t mdr_pack_rsvb(struct mdr *, void **, uint64_t);
ptrdiff_t mdr_pack_str(struct mdr *, const char *, int64_t);
ptrdiff_t mdr_pack_mdr(struct mdr *, const struct mdr *);
ptrdiff_t mdr_pack_array(struct mdr *, uint8_t, int32_t, void *);
ptrdiff_t mdr_add_tail_bytes(struct mdr *, uint64_t);
ptrdiff_t mdr_set_stream_id(struct mdr *, uint64_t);
ptrdiff_t mdr_set_acct_id(struct mdr *, uint64_t);
ptrdiff_t mdr_set_trace_id(struct mdr *, const uint8_t *);

ptrdiff_t mdr_read_from_fd(struct mdr *, uint32_t, int, void *, size_t);
ptrdiff_t mdr_unpack_hdr(struct mdr *, uint32_t, void *, size_t);
ptrdiff_t mdr_unpack_payload(struct mdr *, const struct mdr_spec *,
              struct mdr_out *, size_t);
ptrdiff_t mdr_unpack(struct mdr *, char *, size_t, const struct mdr_spec *,
              uint32_t, struct mdr_out *, size_t);
ptrdiff_t mdr_unpack_i8(struct mdr *, int8_t *);
ptrdiff_t mdr_unpack_i16(struct mdr *, int16_t *);
ptrdiff_t mdr_unpack_i32(struct mdr *, int32_t *);
ptrdiff_t mdr_unpack_i64(struct mdr *, int64_t *);
ptrdiff_t mdr_unpack_u8(struct mdr *, uint8_t *);
ptrdiff_t mdr_unpack_u16(struct mdr *, uint16_t *);
ptrdiff_t mdr_unpack_u32(struct mdr *, uint32_t *);
ptrdiff_t mdr_unpack_u64(struct mdr *, uint64_t *);
ptrdiff_t mdr_unpack_f32(struct mdr *, float *);
ptrdiff_t mdr_unpack_f64(struct mdr *, double *);
ptrdiff_t mdr_unpack_bytes(struct mdr *, const void **, uint64_t *);
ptrdiff_t mdr_unpack_str(struct mdr *, const char **, uint64_t *);
ptrdiff_t mdr_unpack_mdr(struct mdr *, struct mdr *);
ptrdiff_t mdr_unpack_array(struct mdr *, uint8_t,
              struct mdr_out_array_handle *);
void      mdr_print(FILE *, const struct mdr *);

int                    mdr_register_builtin_specs();
const struct mdr_spec *mdr_register_spec(struct mdr_def *);
const struct mdr_spec *mdr_registry_get(uint64_t);

#define MDR_DCV(domain, code, variant) \
    ((uint64_t)domain << 32 | (uint64_t)code << 16 | (uint64_t)variant)

#define MDR_MASK_D   0xffffffff00000000
#define MDR_MASK_DC  0xffffffffffff0000
#define MDR_MASK_DCV 0xffffffffffffffff

/*
 * Built-in DCVs (Domain/Code/Variant). Domains are 32 bits, code and
 * variant are 16 bits.
 */

#define MDR_DOMAIN_MDR           0x00000000
#define MDR_DCV_MDR_PING         MDR_DCV(0x00000000, 0x0001, 0x0000)
#define MDR_DCV_MDR_PONG         MDR_DCV(0x00000000, 0x0002, 0x0000)
#define MDR_DCV_MDR_ECHO         MDR_DCV(0x00000000, 0x0003, 0x0000)
#define MDR_DCV_MDR_TEST         MDR_DCV(0x00000000, 0x0004, 0x0000)

#define MDR_DOMAIN_MDRD          0x00000001
#define MDR_DCV_MDRD_ERROR       MDR_DCV(0x00000001, 0x0001, 0x0000)
#define MDR_DCV_MDRD_BEREQ       MDR_DCV(0x00000001, 0x0002, 0x0000)
#define MDR_DCV_MDRD_BERESP      MDR_DCV(0x00000001, 0x0003, 0x0000)
#define MDR_DCV_MDRD_BERESP_WMSG MDR_DCV(0x00000001, 0x0003, 0x0001)
#define MDR_DCV_MDRD_BECLOSE     MDR_DCV(0x00000001, 0x0004, 0x0000)

#define MDR_DOMAIN_CERTALATOR    0x00000002

#endif
