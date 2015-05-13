#include <cassert>
#include <cstdio>
#include <cstdlib>

#include "mp_modexp.h"

static WORD umulhi(WORD a, WORD b)
{
#if MP_USE_64BIT
#define UMUL_HI_ASM(a,b)   ({      \
	register BN_ULONG ret,discard;  \
	asm ("mulq      %3"             \
		      : "=a"(discard),"=d"(ret)  \
		      : "a"(a), "g"(b)           \
		      : "cc");                   \
	ret;})

	return UMUL_HI_ASM(a, b);
#else
	uint64_t t;

	t = (uint64_t)a * (uint64_t)b;
	return (WORD)(t >> BITS_PER_WORD);
#endif
}

static WORD umullo(WORD a, WORD b)
{
	return a * b;
}

void mp_mul_cpu(WORD *ret, const WORD *a, const WORD *b)
{
	WORD t[MAX_S * 2];
	WORD c[MAX_S * 2];	// carry

	for (int i = 0; i < MAX_S; i++) {
		c[i] = 0;
		c[i + MAX_S] = 0;
		t[i] = 0;
		t[i + MAX_S] = 0;
	}

	for (int j = 0; j < MAX_S; j++) {
		for (int i = 0; i < MAX_S; i++) {
			WORD hi = umulhi(a[i], b[j]);
			WORD lo = umullo(a[i], b[j]);
		
			ADD_CARRY(c[i + j + 2], t[i + j + 1], t[i + j + 1], hi);
			ADD_CARRY(c[i + j + 1], t[i + j], t[i + j], lo);
		}

		//printf("j = %d\n", j);
		//mp_print(c + MAX_S); mp_print(c); printf("\n");
		//mp_print(t + MAX_S); mp_print(t); printf("\n");
	}

	while (1) {
		bool all_zero = true;
		for (int j = 0; j < MAX_S; j++) {
			if (c[j])
				all_zero = false;
			if (c[j + MAX_S])
				all_zero = false;
		}
		if (all_zero)
			break;

		for (int j = 2 * MAX_S - 1; j >= 1; j--)
			ADD_CARRY_CLEAR(c[j + 1], t[j], t[j], c[j]);
	}

	for (int i = 0; i < MAX_S; i++) {
		ret[i] = t[i];
		ret[i + MAX_S] = t[i + MAX_S];
	}
}

/* returns 1 for the most significant carry. 0 otherwise */
int mp_add_cpu(WORD *ret, const WORD *x, const WORD *y)
{
	WORD c[MAX_S];	// carry. c[i] is set by a[i] and b[i]

	for (int i = 0; i < MAX_S; i++) {
		c[i] = 0;
		ADD_CARRY(c[i], ret[i], x[i], y[i]);
	}

	while (1) {
		bool all_zero = true;
		/* NOTE MAX_S - 1, not just MAX_S */ 
		for (int j = 0; j < MAX_S - 1; j++) { 
			if (c[j])
				all_zero = false;
		}

		if (all_zero)
			break;

		for (int j = MAX_S - 2; j >= 0; j--)
			ADD_CARRY_CLEAR(c[j + 1], ret[j + 1], ret[j + 1], c[j]);
	}

	return c[MAX_S - 1];
}

/* returns 1 for the most significant carry. 0 otherwise */
int mp_add1_cpu(WORD *ret, const WORD *x)
{
	WORD c[MAX_S];	// carry. c[i] is set by a[i]

	for (int i = 0; i < MAX_S; i++) {
		c[i] = 0;
		ADD_CARRY(c[i], ret[i], x[i], (i == 0) ? 1 : 0);
	}

	while (1) {
		bool all_zero = true;
		/* NOTE MAX_S - 1, not just MAX_S */ 
		for (int j = 0; j < MAX_S - 1; j++) { 
			if (c[j])
				all_zero = false;
		}

		if (all_zero)
			break;

		for (int j = MAX_S - 2; j >= 0; j--)
			ADD_CARRY_CLEAR(c[j + 1], ret[j + 1], ret[j + 1], c[j]);
	}

	return c[MAX_S - 1];
}

/* returns 1 for the most significant borrow. 0 otherwise */
int mp_sub_cpu(WORD *ret, const WORD *x, const WORD *y)
{
	WORD b[MAX_S]; // borrow

	for (int i = 0; i < MAX_S; i++) {
		b[i] = 0;
		SUB_BORROW(b[i], ret[i], x[i], y[i]);
	}

	while (1) {
		bool all_zero = true;
		/* NOTE MAX_S - 1, not just MAX_S */ 
		for (int j = 0; j < MAX_S - 1; j++) { 
			if (b[j])
				all_zero = false;
		}

		if (all_zero)
			break;

		for (int j = MAX_S - 2; j >= 0; j--)
			SUB_BORROW_CLEAR(b[j + 1], ret[j + 1], ret[j + 1], b[j]);
	}

	return b[MAX_S - 1];
}

#if !MONTMUL_FAST_CPU

/* assumes a and b are 'montgomeritized' */
void mp_montmul_cpu(WORD *ret, const WORD *a, const WORD *b, 
		const WORD *n, const WORD *np)
{
	WORD t[MAX_S * 2];
	WORD m[MAX_S * 2];
	WORD mn[MAX_S * 2];
	WORD u[MAX_S];
	int c = 0;

	mp_mul_cpu(t, a, b);
	mp_mul_cpu(m, t, np);
	mp_mul_cpu(mn, m, n);
	c = mp_add_cpu(u, t + MAX_S, mn + MAX_S);

	bool half_zero = true;
	for (int i = 0; i < MAX_S; i++) {
		if (t[i])
			half_zero = false;
	}
	if (!half_zero)
		c |= mp_add1_cpu(u, u);

	// c may be 0 or 1, but not 2
	if (c)	
		goto u_is_bigger;

	/* Ugly, but practical. 
	 * Can we do this much better with Fermi's ballot()? */
	for (int i = MAX_S - 1; i >= 0; i--) {
		if (u[i] > n[i])
			goto u_is_bigger;
		if (u[i] < n[i])
			goto n_is_bigger;
	}

u_is_bigger:
	mp_sub_cpu(ret, u, n);
	return;

n_is_bigger:
	for (int i = 0; i < MAX_S; i++)
		ret[i] = u[i];
	return;
}

#else

/* fast version */
void mp_montmul_cpu(WORD *ret, const WORD *a, const WORD *b, 
		const WORD *n, const WORD *np)
{
	WORD t[MAX_S * 2];
	WORD c[MAX_S * 2];
	WORD u[MAX_S];
	int carry = 0;
	
	for (int i = 0; i < MAX_S; i++) {
		c[i] = 0;
		c[i + MAX_S] = 0;
	}

	mp_mul_cpu(t, a, b);
		
	for (int j = 0; j < MAX_S; j++) {
		WORD m = t[j] * np[0];
		for (int i = 0; i < MAX_S; i++) {
			WORD hi = umulhi(m, n[i]);
			WORD lo = umullo(m, n[i]);

			ADD_CARRY(c[i + j + 1], t[i + j + 1], t[i + j + 1], hi);
			ADD_CARRY(c[i + j], t[i + j], t[i + j], lo);
		}
//		printf("j = %d, m = %X\n", j, m);
//		mp_print(c, MAX_S * 2); printf("\n");
//		mp_print(t, MAX_S * 2); printf("\n");
		
		while (1) {
			bool all_zero = true;
			for (int j = 0; j < MAX_S; j++) {
				if (c[j])
					all_zero = false;
				if (j < MAX_S - 1 && c[j + MAX_S])
					all_zero = false;
			}
			if (all_zero)
				break;

			for (int j = 2 * MAX_S - 1; j >= 1; j--)
				ADD_CARRY_CLEAR(c[j], t[j], t[j], c[j - 1]);
		}
	}

	for (int i = 0; i < MAX_S; i++)
		u[i] = t[i + MAX_S];

	//carry = mp_add_cpu(u, t + MAX_S, mn + MAX_S);
	carry = c[2 * MAX_S - 1];

	// c may be 0 or 1, but not 2
	if (carry)	
		goto u_is_bigger;

	/* Ugly, but practical. 
	 * Can we do this much better with Fermi's ballot()? */
	for (int i = MAX_S - 1; i >= 0; i--) {
		if (u[i] > n[i])
			goto u_is_bigger;
		if (u[i] < n[i])
			goto n_is_bigger;
	}

u_is_bigger:
	mp_sub_cpu(ret, u, n);
	return;

n_is_bigger:
	for (int i = 0; i < MAX_S; i++)
		ret[i] = u[i];
	return;
}

#endif

void mp_modexp_cpu_org(WORD *ret, const WORD *ar, const WORD *e, 
		const WORD *n, const WORD *np)
{
	int t = MAX_S * BITS_PER_WORD - 1;

	while (((e[t / BITS_PER_WORD] >> (t % BITS_PER_WORD)) & 1) == 0 && t > 0)
		t--;

	for (int i = 0; i < MAX_S; i++)
		ret[i] = ar[i];

	t--;

	while (t >= 0) {
		mp_montmul_cpu(ret, ret, ret, n, np);
		if (((e[t / BITS_PER_WORD] >> (t % BITS_PER_WORD)) & 1) == 1)
			mp_montmul_cpu(ret, ret, ar, n, np);

		t--;
	}
}

/* assumes ar is 'montgomeritized' */
void mp_modexp_cpu(WORD *ret, const WORD *ar, const WORD *e, 
		const WORD *n, const WORD *np)
{
	struct mp_sw sw;
	WORD ar_sqr[MAX_S];

	mp_get_sw(&sw, e);

	/* odd powers of ar (ar, (ar)^3, (ar)^5, ... ) */
	WORD ar_pow[MP_SW_MAX_FRAGMENT / 2][MAX_S];

	for (int i = 0; i < MAX_S; i++)
		ar_pow[0][i] = ar[i];

	mp_montmul_cpu(ar_sqr, ar_pow[0], ar_pow[0], n, np);

	for (int i = 3; i <= sw.max_fragment; i += 2)
		mp_montmul_cpu(ar_pow[i >> 1], ar_pow[(i >> 1) - 1], ar_sqr, n, np);

	for (int i = 0; i < MAX_S; i++)
		ret[i] = ar_pow[sw.fragment[sw.num_fragments - 1] >> 1][i];

	for (int k = sw.num_fragments - 2; k >= 0; k--) {
		for (int i = 0; i < sw.length[k]; i++)
			mp_montmul_cpu(ret, ret, ret, n, np);

		if (sw.fragment[k])
			mp_montmul_cpu(ret, ret, ar_pow[sw.fragment[k] >> 1], n, np);
	}
}
