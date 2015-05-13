#ifndef MP_MODEXP
#define MP_MODEXP

#include <stdint.h>

#include <openssl/bn.h>

#include <cuda_runtime.h>
#include <cutil_inline.h>

#define MAX_STREAMS		16
#define MP_MAX_NUM_PAIRS	1024

#if MP_USE_64BIT == 1

#define BITS_PER_WORD 64
typedef uint64_t WORD;

// the maximum number of WORDS in a mp number
#define MAX_S	32
#define S_256	4
#define S_512	8
#define S_1024	16
#define S_2048	32

#define MP_MSGS_PER_BLOCK (16 / (S / S_256))

#elif MP_USE_64BIT == 0

#define BITS_PER_WORD 32
typedef uint32_t WORD;

// the maximum number of WORDS in a mp number
#define MAX_S	64
#define S_256	8
#define S_512	16
#define S_1024	32
#define S_2048	64

#define MP_MSGS_PER_BLOCK (8 / (S / S_256))

#else

#error MP_USE_64BIT is not defined

#endif

/* CRT postprocessing offloading */
#define MP_MODEXP_OFFLOAD_POST 1

/* these two are only valid for test code */
#define MONTMUL_FAST_CPU 1
#define MONTMUL_FAST_GPU 1

#ifdef __GPU__
#define sync_if_needed()	do { if (S > 32) __syncthreads(); } while(0)
#else
#define sync_if_needed()
#endif

/* c: carry (may increment by 1)
   s: partial sum
   x, y: operands */
#define ADD_CARRY(c, s, x, y) \
		do { \
			WORD _t = (x) + (y); \
			(c) += (_t < (x)); \
			sync_if_needed(); \
			(s) = _t; \
			sync_if_needed(); \
		} while (0)

/* Same with ADD_CARRY, but sets y to 0 */
#define ADD_CARRY_CLEAR(c, s, x, y) \
		do { \
			WORD _t = (x) + (y); \
			(y) = 0; \
			sync_if_needed(); \
			(c) += (_t < (x)); \
			(s) = _t; \
			sync_if_needed(); \
		} while (0)

/* b: borrow (may increment by 1)
   d: partial difference
   x, y: operands (a - b) */
#define SUB_BORROW(b, d, x, y) \
		do { \
			WORD _t = (x) - (y); \
			(b) += (_t > (x)); \
			sync_if_needed(); \
			(d) = _t; \
			sync_if_needed(); \
		} while (0)

/* Same with SUB_BORROW, but sets y to 0 */
#define SUB_BORROW_CLEAR(b, d, x, y) \
		do { \
			WORD _t = (x) - (y); \
			(y) = 0; \
			sync_if_needed(); \
			(b) += (_t > (x)); \
			(d) = _t; \
			sync_if_needed(); \
		} while (0)

#define MP_USE_CLNW 1
#define MP_USE_VLNW 0

#if MP_USE_CLNW + MP_USE_VLNW != 1
#error Use one and only one sliding window technique
#endif

#define MP_SW_MAX_NUM_FRAGS 512
#define MP_SW_MAX_FRAGMENT 128

/* for sliding algorithms (both CLNW and VLNW) */
struct mp_sw {
	uint16_t fragment[MP_SW_MAX_NUM_FRAGS];
	uint16_t length[MP_SW_MAX_NUM_FRAGS];
	int num_fragments;
	int max_fragment;
};

void mp_print(const char *name, const WORD *a, int word_len = MAX_S);
void mp_bn2mp(WORD *a, const BIGNUM *bn, int word_len = MAX_S);
void mp_mp2bn(BIGNUM *bn, const WORD *a, int word_len = MAX_S);
void mp_copy(WORD *dst, const WORD *org, int word_len = MAX_S);
void mp_get_sw(struct mp_sw *ret, const WORD *a, int word_len = MAX_S);

void mp_modexp_crt(WORD *a,
		int cnt, int S,
		WORD *ret_d, WORD *ar_d,
		struct mp_sw *sw_d,
		WORD *n_d, WORD *np_d, WORD *r_sqr_d,
		cudaStream_t stream,
		unsigned int stream_id,
		uint8_t *checkbits = 0);

int mp_modexp_crt_sync(WORD *ret, WORD *ret_d,
		WORD *n_d, WORD *np_d, WORD *r_sqr_d, WORD *iqmp_d,
		int cnt, int S,
		bool block, cudaStream_t stream,
		uint8_t *checkbits = 0);

int mp_modexp_crt_post_kernel(WORD *ret, WORD *ret_d, WORD *n_d, WORD *np_d, WORD *r_sqr_d, WORD *iqmp_d,
			      int cnt, int S,
			      bool block, cudaStream_t stream,
			      uint8_t *checkbits = 0);



void mp_test_cpu();
void mp_test_gpu();

/* all mp_*_cpu() and mp_*_gpu() functions are single-threaded */
void mp_mul_cpu(WORD *ret, const WORD *a, const WORD *b);
int mp_add_cpu(WORD *ret, const WORD *x, const WORD *y);
int mp_add1_cpu(WORD *ret, const WORD *x);
int mp_sub_cpu(WORD *ret, const WORD *x, const WORD *y);
void mp_montmul_cpu(WORD *ret, const WORD *a, const WORD *b,
		const WORD *n, const WORD *np);
void mp_modexp_cpu(WORD *ret, const WORD *ar, const WORD *e,
		const WORD *n, const WORD *np);

void mp_mul_gpu(WORD *ret, const WORD *x, const WORD *y);
void mp_add_gpu(WORD *ret, const WORD *x, const WORD *y);
void mp_add1_gpu(WORD *ret, const WORD *x);
void mp_sub_gpu(WORD *ret, const WORD *x, const WORD *y);
void mp_montmul_gpu(WORD *ret, const WORD *a, const WORD *b,
		const WORD *n, const WORD *np);
void mp_modexp_gpu(WORD *ret, const WORD *ar, const WORD *e,
		const WORD *n, const WORD *np);

#endif
