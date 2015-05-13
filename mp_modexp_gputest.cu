#include <cassert>

#include <sys/time.h>

#include <cuda_runtime.h>
#include <cutil_inline.h>

#include "mp_modexp.h"

static __device__ WORD mp_umul_hi(WORD a, WORD b)
{
#if MP_USE_64BIT
	return __umul64hi(a, b);
#else
	return __umulhi(a, b);
#endif
}

static __device__ WORD mp_umul_lo(WORD a, WORD b)
{
	return a * b;
}

static __device__ void mp_mul_dev(volatile WORD *ret, 
		volatile const WORD *a, volatile const WORD *b, int S)
{
	volatile __shared__ WORD t[MAX_S * 2];	// in case that ret == a or ret == b
	volatile __shared__ WORD c[MAX_S * 2];	// carry

	const int idx = threadIdx.x;

	c[idx] = 0;
	c[idx + S] = 0;
	t[idx] = 0;
	t[idx + S] = 0;

	for (int i = 0; i < S; i++) {
		WORD hi = mp_umul_hi(a[i], b[idx]);
		WORD lo = mp_umul_lo(a[i], b[idx]);

		ADD_CARRY(c[i + idx + 2], t[i + idx + 1], t[i + idx + 1], hi);
		ADD_CARRY(c[i + idx + 1], t[i + idx], t[i + idx], lo);
	}

	while (__any(c[idx] != 0 || c[idx + S] != 0)) {
		ADD_CARRY_CLEAR(c[idx + S + 1], t[idx + S], t[idx + S], c[idx + S]);
		ADD_CARRY_CLEAR(c[idx + 1], t[idx], t[idx], c[idx]);
	}

	ret[idx] = t[idx];
	ret[idx + S] = t[idx + S];
}

/* returns 1 for the most significant carry. 0 otherwise */
static __device__ int mp_add_dev(volatile WORD *ret, 
		volatile const WORD *x, volatile const WORD *y, int S)
{
	volatile __shared__ WORD c[MAX_S];	// carry. c[i] is set by a[i] and b[i]

	const int idx = threadIdx.x;

	c[idx] = 0;
	ADD_CARRY(c[idx], ret[idx], x[idx], y[idx]);

	if (idx < S - 1) {
		while (__any(c[idx] != 0))
			ADD_CARRY_CLEAR(c[idx + 1], ret[idx + 1], 
					ret[idx + 1], c[idx]);
	}

	return c[S - 1];
}

/* returns 1 for the most significant carry (very unlikely). 0 otherwise */
static __device__ int mp_add1_dev(volatile WORD *ret, 
		volatile const WORD *x, int S)
{
	volatile __shared__ WORD c[MAX_S];	// carry. c[i] is set by a[i] and b[i]

	const int idx = threadIdx.x;

	c[idx] = 0;
	ADD_CARRY(c[idx], ret[idx], x[idx], (idx == 0) ? 1 : 0);

	if (idx < S - 1) {
		while (__any(c[idx] != 0))
			ADD_CARRY_CLEAR(c[idx + 1], ret[idx + 1], 
					ret[idx + 1], c[idx]);
	}

	return c[S - 1];
}

/* returns 1 for the most significant borrow. 0 otherwise */
static __device__ int mp_sub_dev(volatile WORD *ret, 
		volatile const WORD *x, volatile const WORD *y, int S)
{
	volatile __shared__ WORD b[MAX_S]; // borrow

	const int idx = threadIdx.x;

	b[idx] = 0;
	SUB_BORROW(b[idx], ret[idx], x[idx], y[idx]);

	if (idx < S - 1) {
		while (__any(b[idx] != 0))
			SUB_BORROW_CLEAR(b[idx + 1], ret[idx + 1], 
					ret[idx + 1], b[idx]);
	}

	return b[S - 1];
}

#if !MONTMUL_FAST_GPU

/* assumes a and b are 'montgomeritized' */
static __device__ void mp_montmul_dev(WORD *ret, const WORD *a, const WORD *b, 
		const WORD *n, const WORD *np, int S)
{
	volatile __shared__ WORD t[MAX_S * 2];
	volatile __shared__ WORD m[MAX_S * 2];
	volatile __shared__ WORD mn[MAX_S * 2];
	__shared__ WORD u[MAX_S];

	const int idx = threadIdx.x;
	
	int c = 0;

	mp_mul_dev(t, a, b, S);
	mp_mul_dev(m, t, np, S);
	mp_mul_dev(mn, m, n, S);
	c = mp_add_dev(u, t + S, mn + S, S);

	if (__any(t[idx] != 0))
		c |= mp_add1_dev(u, u, S);

	// c may be 0 or 1, but not 2
	if (c)	
		goto u_is_bigger;

	/* Ugly, but practical. 
	 * Can we do this much better with Fermi's ballot()? */
	for (int i = S - 1; i >= 0; i--) {
		if (u[i] > n[i])
			goto u_is_bigger;
		if (u[i] < n[i])
			goto n_is_bigger;
	}

u_is_bigger:
	mp_sub_dev(ret, u, n, S);
	return;

n_is_bigger:
	ret[idx] = u[idx];
	return;
}

#else 

/* fast version */
static __device__ void mp_montmul_dev(WORD *ret, const WORD *a, const WORD *b, 
		const WORD *n, const WORD *np, int S)
{
	volatile __shared__ WORD t[MAX_S * 2];
	volatile __shared__ WORD c[MAX_S * 2];

	const int idx = threadIdx.x;

	c[idx] = 0;
	c[idx + S] = 0;

	/* step 1: calculate t = ab */
	mp_mul_dev(t, a, b, S);

	/* step 2: calculate t + mn */
	for (int j = 0; j < S; j++) {
		WORD m = mp_umul_lo(t[j], np[0]);
		WORD hi = mp_umul_hi(m, n[idx]);
		WORD lo = mp_umul_lo(m, n[idx]);

		ADD_CARRY(c[idx + j + 1], t[idx + j + 1], t[idx + j + 1], hi);
		ADD_CARRY(c[idx + j], t[idx + j], t[idx + j], lo);

		ADD_CARRY_CLEAR(c[idx + 1], t[idx + 1], t[idx + 1], c[idx]);
	}

	/* here all t[0] ~ t[MAX_S - 1] should be zero */

	while (__any(c[idx + S - 1] != 0))
		ADD_CARRY_CLEAR(c[idx + S], t[idx + S], t[idx + S], c[idx + S - 1]);

	/* step 3: return t or t - n */

	// c may be 0 or 1, but not 2
	if (c[S * 2 - 1])	
		goto u_is_bigger;

	/* Ugly, but practical. 
	 * Can we do this much better with Fermi's ballot()? */
	for (int i = S - 1; i >= 0; i--) {
		if (t[i + S] > n[i])
			goto u_is_bigger;
		if (t[i + S] < n[i])
			goto n_is_bigger;
	}

u_is_bigger:
	mp_sub_dev(ret, t + S, n, S);
	return;

n_is_bigger:
	ret[idx] = t[idx + S];
	return;
}

#endif

static __device__ WORD ar_pow[MP_SW_MAX_FRAGMENT / 2][MAX_S];

/* assumes ar is 'montgomeritized' */
static __device__ void mp_modexp_dev(WORD *ret, const WORD *ar, const struct mp_sw *sw, 
		const WORD *n, const WORD *np, int S)
{
	const int idx = threadIdx.x;

	__shared__ WORD tmp[MAX_S];

	ar_pow[0][idx] = ar[idx];
	mp_montmul_dev(ret, ar, ar, n, np, S);

	for (int i = 3; i <= sw->max_fragment; i += 2) {
		tmp[idx] = ar_pow[(i >> 1) - 1][idx];
		mp_montmul_dev(tmp, tmp, ret, n, np, S);
		ar_pow[i >> 1][idx] = tmp[idx];
	}

	ret[idx] = ar_pow[sw->fragment[sw->num_fragments - 1] >> 1][idx];

	for (int i = sw->num_fragments - 2; i >= 0; i--) {
		for (int k = 0; k < sw->length[i]; k++)
			mp_montmul_dev(ret, ret, ret, n, np, S);

		if (sw->fragment[i]) {
			tmp[idx] = ar_pow[sw->fragment[i] >> 1][idx];
			mp_montmul_dev(ret, ret, tmp, n, np, S);
		}
	}
}

static __global__ void mp_mul_kernel(int num_words, WORD *RET, WORD *X, WORD *Y)
{
	__shared__ WORD x[MAX_S];
	__shared__ WORD y[MAX_S];
	__shared__ WORD ret[MAX_S * 2];
	
	const int idx = threadIdx.x;

	x[idx] = X[idx];
	y[idx] = Y[idx];

	mp_mul_dev(ret, x, y, num_words);

	RET[idx] = ret[idx];
	RET[idx + num_words] = ret[idx + num_words];
}

static __global__ void mp_add_kernel(int num_words, WORD *RET, WORD *X, WORD *Y)
{
	__shared__ WORD x[MAX_S];
	__shared__ WORD y[MAX_S];
	__shared__ WORD ret[MAX_S];
	
	const int idx = threadIdx.x;

	x[idx] = X[idx];
	y[idx] = Y[idx];

	mp_add_dev(ret, x, y, num_words);

	RET[idx] = ret[idx];
}

static __global__ void mp_add1_kernel(int num_words, WORD *RET, WORD *X)
{
	__shared__ WORD x[MAX_S];
	__shared__ WORD ret[MAX_S];
	
	const int idx = threadIdx.x;

	x[idx] = X[idx];

	mp_add1_dev(ret, x, num_words);

	RET[idx] = ret[idx];
}

static __global__ void mp_sub_kernel(int num_words, WORD *RET, WORD *X, WORD *Y)
{
	__shared__ WORD x[MAX_S];
	__shared__ WORD y[MAX_S];
	__shared__ WORD ret[MAX_S];
	
	const int idx = threadIdx.x;

	x[idx] = X[idx];
	y[idx] = Y[idx];

	mp_sub_dev(ret, x, y, num_words);

	RET[idx] = ret[idx];
}

static __global__ void mp_montmul_kernel(int num_words, WORD *RET, WORD *A, WORD *B, WORD *N, WORD *NP)
{
	__shared__ WORD a[MAX_S];
	__shared__ WORD b[MAX_S];
	__shared__ WORD n[MAX_S];
	__shared__ WORD np[MAX_S];
	__shared__ WORD ret[MAX_S];
	
	const int idx = threadIdx.x;

	a[idx] = A[idx];
	b[idx] = B[idx];
	n[idx] = N[idx];
	np[idx] = NP[idx];

	mp_montmul_dev(ret, a, b, n, np, num_words);

	RET[idx] = ret[idx];
}

static __global__ void mp_modexp_kernel(int num_words, WORD *RET, WORD *A, struct mp_sw *sw, WORD *N, WORD *NP)
{
	__shared__ WORD a[MAX_S];
	__shared__ WORD n[MAX_S];
	__shared__ WORD np[MAX_S];
	__shared__ WORD ret[MAX_S];
	
	const int idx = threadIdx.x;

	a[idx] = A[idx];
	n[idx] = N[idx];
	np[idx] = NP[idx];

	mp_modexp_dev(ret, a, sw, n, np, num_words);

	RET[idx] = ret[idx];
}

void mp_mul_gpu(WORD *ret, const WORD *x, const WORD *y)
{
	WORD *x_d;
	WORD *y_d;
	WORD *ret_d;

	cutilSafeCall(cudaMalloc(&x_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&y_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&ret_d, sizeof(WORD) * 2 * MAX_S));

	cutilSafeCall(cudaMemcpy(x_d, x, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(y_d, y, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));

	mp_mul_kernel<<<1, MAX_S>>>(MAX_S, ret_d, x_d, y_d);
	assert(cudaGetLastError() == cudaSuccess);

	cutilSafeCall(cudaMemcpy(ret, ret_d, sizeof(WORD) * 2 * MAX_S, cudaMemcpyDeviceToHost));

	cutilSafeCall(cudaFree(x_d));
	cutilSafeCall(cudaFree(y_d));
	cutilSafeCall(cudaFree(ret_d));
}

void mp_add_gpu(WORD *ret, const WORD *x, const WORD *y)
{
	WORD *x_d;
	WORD *y_d;
	WORD *ret_d;

	cutilSafeCall(cudaMalloc(&x_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&y_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&ret_d, sizeof(WORD) * MAX_S));

	cutilSafeCall(cudaMemcpy(x_d, x, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(y_d, y, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));

	mp_add_kernel<<<1, MAX_S>>>(MAX_S, ret_d, x_d, y_d);
	assert(cudaGetLastError() == cudaSuccess);

	cutilSafeCall(cudaMemcpy(ret, ret_d, sizeof(WORD) * MAX_S, cudaMemcpyDeviceToHost));

	cutilSafeCall(cudaFree(x_d));
	cutilSafeCall(cudaFree(y_d));
	cutilSafeCall(cudaFree(ret_d));
}

void mp_add1_gpu(WORD *ret, const WORD *x)
{
	WORD *x_d;
	WORD *ret_d;

	cutilSafeCall(cudaMalloc(&x_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&ret_d, sizeof(WORD) * MAX_S));

	cutilSafeCall(cudaMemcpy(x_d, x, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));

	mp_add1_kernel<<<1, MAX_S>>>(MAX_S, ret_d, x_d);
	assert(cudaGetLastError() == cudaSuccess);

	cutilSafeCall(cudaMemcpy(ret, ret_d, sizeof(WORD) * MAX_S, cudaMemcpyDeviceToHost));

	cutilSafeCall(cudaFree(x_d));
	cutilSafeCall(cudaFree(ret_d));
}

void mp_sub_gpu(WORD *ret, const WORD *x, const WORD *y)
{
	WORD *x_d;
	WORD *y_d;
	WORD *ret_d;

	cutilSafeCall(cudaMalloc(&x_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&y_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&ret_d, sizeof(WORD) * MAX_S));

	cutilSafeCall(cudaMemcpy(x_d, x, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(y_d, y, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));

	mp_sub_kernel<<<1, MAX_S>>>(MAX_S, ret_d, x_d, y_d);
	assert(cudaGetLastError() == cudaSuccess);

	cutilSafeCall(cudaMemcpy(ret, ret_d, sizeof(WORD) * MAX_S, cudaMemcpyDeviceToHost));

	cutilSafeCall(cudaFree(x_d));
	cutilSafeCall(cudaFree(y_d));
	cutilSafeCall(cudaFree(ret_d));
}

void mp_montmul_gpu(WORD *ret, const WORD *a, const WORD *b, 
		const WORD *n, const WORD *np)
{
	WORD *a_d;
	WORD *b_d;
	WORD *n_d;
	WORD *np_d;
	WORD *ret_d;

	cutilSafeCall(cudaMalloc(&a_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&b_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&n_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&np_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&ret_d, sizeof(WORD) * MAX_S));

	cutilSafeCall(cudaMemcpy(a_d, a, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(b_d, b, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(n_d, n, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(np_d, np, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));

	mp_montmul_kernel<<<1, MAX_S>>>(MAX_S, ret_d, a_d, b_d, n_d, np_d);
	assert(cudaGetLastError() == cudaSuccess);

	cutilSafeCall(cudaMemcpy(ret, ret_d, sizeof(WORD) * MAX_S, cudaMemcpyDeviceToHost));

	cutilSafeCall(cudaFree(a_d));
	cutilSafeCall(cudaFree(b_d));
	cutilSafeCall(cudaFree(n_d));
	cutilSafeCall(cudaFree(np_d));
	cutilSafeCall(cudaFree(ret_d));
}

void mp_modexp_gpu(WORD *ret, const WORD *ar, const WORD *e, 
		const WORD *n, const WORD *np)
{
	struct mp_sw sw;
	struct mp_sw *sw_d;
	mp_get_sw(&sw, e);

	WORD *ar_d;
	WORD *n_d;
	WORD *np_d;
	WORD *ret_d;

	cutilSafeCall(cudaMalloc(&sw_d, sizeof(sw)));
	cutilSafeCall(cudaMalloc(&ar_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&n_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&np_d, sizeof(WORD) * MAX_S));
	cutilSafeCall(cudaMalloc(&ret_d, sizeof(WORD) * MAX_S));

	cutilSafeCall(cudaMemcpy(sw_d, &sw, sizeof(sw), cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(ar_d, ar, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(n_d, n, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));
	cutilSafeCall(cudaMemcpy(np_d, np, sizeof(WORD) * MAX_S, cudaMemcpyHostToDevice));

	mp_modexp_kernel<<<1, MAX_S>>>(MAX_S, ret_d, ar_d, sw_d, n_d, np_d);
	assert(cudaGetLastError() == cudaSuccess);

	cutilSafeCall(cudaMemcpy(ret, ret_d, sizeof(WORD) * MAX_S, cudaMemcpyDeviceToHost));

	cutilSafeCall(cudaFree(sw_d));
	cutilSafeCall(cudaFree(ar_d));
	cutilSafeCall(cudaFree(n_d));
	cutilSafeCall(cudaFree(np_d));
	cutilSafeCall(cudaFree(ret_d));
}
