#include <cassert>

#include "rsa_context_rns.hh"

rsa_context_rns::rsa_context_rns(int keylen)
	: rsa_context(keylen)
{
	gpu_setup();
}

rsa_context_rns::rsa_context_rns(const std::string &filename, 
		const std::string &passwd)
	: rsa_context(filename, passwd)
{
	gpu_setup();
}

rsa_context_rns::rsa_context_rns(const char *filename, const char *passwd)
	: rsa_context(filename, passwd)
{
	gpu_setup();
}

rsa_context_rns::~rsa_context_rns()
{
	RNS_CTX_free(rns_ctx[0]);
	RNS_CTX_free(rns_ctx[1]);
}

void rsa_context_rns::dump()
{
	for (int i = 0; i < (is_crt_available() ? 2 : 1); i++) {
		RNS_CTX *ctx = rns_ctx[i];

		printf("RNS_CTX %d: # of base elements = %d/%d\n", 
				i, ctx->bs, MAX_BS);

		printf("A = {");
		for (int i = 0; i < ctx->bs; i++) {
			if (i > 0)
				printf(", ");

			printf("%d", ctx->a[i]);
		}
		printf("}\n");

		printf("B = {");
		for (int i = 0; i < ctx->bs; i++) {
			if (i > 0)
				printf(", ");

			printf("%d", ctx->b[i]);
		}
		printf("}\n");
	}

	rsa_context::dump();
}

void rsa_context_rns::priv_decrypt(unsigned char *out, int *out_len, 
		const unsigned char *in, int in_len)
{
	priv_decrypt_batch(&out, out_len, &in, &in_len, 1);
}

void rsa_context_rns::priv_decrypt_batch(unsigned char **out, int *out_len,
		const unsigned char **in, const int *in_len, 
		int n)
{
	assert(0 < n && n <= max_batch);

	if (is_crt_available()) {
		BIGNUM *in_bn[max_batch * 2];
		BIGNUM *out_bn[max_batch * 2];
		RNS_CTX *ctx[max_batch * 2];
		BIGNUM *t = BN_new();

		for (int i = 0; i < n; i++) {
			int p = i;
			int q = n + i;

			in_bn[p] = BN_bin2bn(in[i], in_len[i], NULL);
			in_bn[q] = BN_bin2bn(in[i], in_len[i], NULL);
			out_bn[p] = BN_new();
			out_bn[q] = BN_new();
			ctx[p] = rns_ctx[0];
			ctx[q] = rns_ctx[1];

			assert(in_bn[p] != NULL);
			assert(in_bn[q] != NULL);
			assert(out_bn[p] != NULL);
			assert(out_bn[q] != NULL);
			assert(BN_cmp(in_bn[p], rsa->n) == -1);

			BN_nnmod(in_bn[p], in_bn[p], rsa->p, bn_ctx);
			BN_nnmod(in_bn[q], in_bn[q], rsa->q, bn_ctx);
		}

		BN_mod_exp_mont_batch_cu(out_bn, in_bn, n * 2, ctx);

		int p_bits = BN_num_bits(rsa->p);
		int q_bits = BN_num_bits(rsa->q);

		for (int i = 0; i < n; i++) {
			int p = i;
			int q = n + i;

			if (BN_num_bits(out_bn[p]) > p_bits ||
					BN_num_bits(out_bn[q]) > q_bits) {
				fprintf(stderr, "failed: %.3fms\n", 
						elapsed_ms_kernel);
				// fallback. necessary?
				assert(false);
				rsa_context::priv_decrypt(out[i], &out_len[i], 
						in[i], in_len[i]);
			} else {
				BN_sub(t, out_bn[p], out_bn[q]);
				BN_mod_mul(t, t, rsa->iqmp, rsa->p, bn_ctx);
				BN_mul(t, t, rsa->q, bn_ctx);
				BN_add(t, out_bn[q], t);

				int ret = remove_padding(out[i], &out_len[i], t);
				assert(ret != -1);
				
				BN_free(in_bn[p]);
				BN_free(in_bn[q]);
				BN_free(out_bn[p]);
				BN_free(out_bn[q]);
			}
		}

		BN_free(t);
	} else {
		BIGNUM *in_bn[max_batch];
		BIGNUM *out_bn[max_batch];
		RNS_CTX *ctx[max_batch];

		for (int i = 0; i < n; i++) {
			in_bn[i] = BN_bin2bn(in[i], in_len[i], NULL);
			out_bn[i] = BN_new();
			ctx[i] = rns_ctx[0];

			assert(in_bn[i] != NULL);
			assert(out_bn[i] != NULL);
			assert(BN_cmp(in_bn[i], rsa->n) == -1);
		}

		BN_mod_exp_mont_batch_cu(out_bn, in_bn, n, ctx);

		int n_bits = BN_num_bits(rsa->n);

		for (int i = 0; i < n; i++) {
			if (BN_num_bits(out_bn[i]) > n_bits) {
				fprintf(stderr, "failed: %.3fms\n", 
						elapsed_ms_kernel);
				// fallback. necessary?
				assert(false);
				rsa_context::priv_decrypt(out[i], &out_len[i], 
						in[i], in_len[i]);
			} else {
				int ret = remove_padding(out[i], &out_len[i], out_bn[i]);
				assert(ret != -1);

				BN_free(in_bn[i]);
				BN_free(out_bn[i]);
			}
		}
	}
}

void rsa_context_rns::gpu_setup()
{
	if (is_crt_available()) {
		rns_ctx[0] = RNS_CTX_new(rsa->p, rsa->dmp1);
		rns_ctx[1] = RNS_CTX_new(rsa->q, rsa->dmq1);
	} else {
		rns_ctx[0] = RNS_CTX_new(rsa->n, rsa->d);
		rns_ctx[1] = NULL;
	}

	cpyRNSCTX2Dev();
}
