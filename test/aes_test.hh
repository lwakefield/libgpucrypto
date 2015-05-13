#ifndef __AES_TEST_HH__
#define __AES_TEST_HH__


#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16

typedef struct aes_enc_param
{
	uint8_t         *memory_start;
	unsigned long   in_pos;
	unsigned long   key_pos;
	unsigned long   ivs_pos;
	unsigned long   pkt_offset_pos;
	unsigned long   tot_in_len;
	unsigned long   tot_out_len;
	uint8_t         *out;
	unsigned        num_flows;
} aes_enc_param_t;

typedef struct aes_dec_param
{
	uint8_t         *memory_start;
	unsigned long   in_pos;
	unsigned long   key_pos;
	unsigned long   ivs_pos;
	unsigned long   pkt_index_pos;
	unsigned long   total_size;
	uint8_t         *out;
	unsigned        num_blks;
	unsigned        num_flows;
} aes_dec_param_t;

void gen_aes_cbc_data(operation_batch_t *ops,
		      unsigned          key_bits,
		      unsigned          num_flows,
		      unsigned          flow_len,
		      bool              encrypt);

//gather data into a contiguous memory region as needed by aes_context api.
void aes_cbc_encrypt_prepare(operation_batch_t *ops,
			     aes_enc_param_t   *param,
			     pinned_mem_pool   *pool);

void aes_cbc_decrypt_prepare(operation_batch_t *ops,
			     aes_dec_param_t   *param,
			     pinned_mem_pool   *pool);

//copy output from pinned page in param to ops's out
void aes_cbc_post(operation_batch_t *ops,
		  aes_enc_param_t   *param);
void aes_cbc_post(operation_batch_t *ops,
		  aes_dec_param_t   *param);

bool aes_cbc_verify_result(operation_batch_t *ops);

#endif /*__AES_TEST_HH__*/
