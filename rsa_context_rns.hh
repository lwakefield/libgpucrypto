#ifndef RSA_CONTEXT_RNS_HH
#define RSA_CONTEXT_RNS_HH

#include "rsa_context.hh"

#include "rsa_cuda.h"

class rsa_context_rns : public rsa_context
{
public:
	// generates a random key
	rsa_context_rns(int keylen);

	// currently supports PEM format only
	rsa_context_rns(const std::string &filename, const std::string &passwd);
	rsa_context_rns(const char *filename, const char *passwd);

	virtual ~rsa_context_rns();

	virtual void dump();

	// All encryption/decryption methods assume RSA_PKCS1_PADDING
	// out_len is an input+output variable
	virtual void priv_decrypt(unsigned char *out, int *out_len,
			const unsigned char *in, int in_len);
	virtual void priv_decrypt_batch(unsigned char **out, int *out_len,
			const unsigned char **in, const int *in_len, 
			int n);
protected:

private:
	void gpu_setup();

	RNS_CTX *rns_ctx[2];
};

#endif
