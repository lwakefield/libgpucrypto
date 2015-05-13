#include <cassert>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include <typeinfo>
#include <stdint.h>
#include <openssl/aes.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#include "aes_kernel.h"
#include "aes_context.hh"
#include "device_context.hh"
#include "pinned_mem_pool.hh"
#include "common.hh"
#include "aes_test.hh"

#define MAX_FLOW_LEN 16384

static bool test_correctness_aes_cbc_encrypt(unsigned key_bits,
					     unsigned num_flows,
					     unsigned flow_len)
{
	device_context dev_ctx;
	pinned_mem_pool *pool;
	aes_enc_param_t param;
	operation_batch_t ops;

	dev_ctx.init(num_flows * flow_len * 3, 0);
	aes_context aes_ctx(&dev_ctx);

	pool = new pinned_mem_pool();
	pool->init(num_flows * flow_len * 3);

	//generate test random test case
	gen_aes_cbc_data(&ops,
			 key_bits,
			 num_flows,
			 flow_len,
			 true);

	//copy input to pinned page and prepare parameter for gpu
	aes_cbc_encrypt_prepare(&ops, &param, pool);

	//gpu execution
	aes_ctx.cbc_encrypt(param.memory_start,
			    param.in_pos,
			    param.key_pos,
			    param.ivs_pos,
			    param.pkt_offset_pos,
			    param.tot_in_len,
			    param.out,
			    param.num_flows,
			    param.tot_out_len,
			    0);

	aes_ctx.sync(0); /* wait for completion */

	//copy output from pinned memory to ops
	aes_cbc_post(&ops, &param);

	delete pool;

	//verify result
	bool result = aes_cbc_verify_result(&ops);
	if (!result) {
		printf("X");
	} else {
		printf(".");
	}

	return result;
}

static bool test_correctness_aes_cbc_decrypt(unsigned key_bits,
					     unsigned num_flows,
					     unsigned flow_len)
{
	device_context dev_ctx;
	aes_dec_param_t param;
	pinned_mem_pool *pool;
	operation_batch_t ops;

	dev_ctx.init(num_flows * flow_len * 3, 0);
	aes_context aes_ctx(&dev_ctx);

	pool = new pinned_mem_pool();
	pool->init(num_flows * flow_len * 3);

	//generate test random test case
	gen_aes_cbc_data(&ops,
			 key_bits,
			 num_flows,
			 flow_len,
			 false);

	//copy input to pinned page and prepare parameter for gpu
	aes_cbc_decrypt_prepare(&ops, &param, pool);

	//gpu execution
	aes_ctx.cbc_decrypt(param.memory_start,
			    param.in_pos,
			    param.key_pos,
			    param.ivs_pos,
			    param.pkt_index_pos,
			    param.total_size,
			    param.out,
			    param.num_blks,
			    param.num_flows,
			    0);

	aes_ctx.sync(0); /* wait for completion */

	//copy output from pinned memory to ops
	aes_cbc_post(&ops, &param);

	//verify result
	bool result = aes_cbc_verify_result(&ops);
	if (!result) {
		printf("X");
	} else {
		printf(".");
	}

	delete pool;
	return result;
}


static void test_latency_aes_cbc_decrypt(unsigned key_bits,
					 unsigned num_flows,
					 unsigned flow_len)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * flow_len * 3, 0);
	aes_context aes_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * flow_len * 3);

	operation_batch_t ops;
	aes_dec_param_t param;

	//generate test random test case
	gen_aes_cbc_data(&ops,
			 key_bits,
			 num_flows,
			 flow_len,
			 false);

	//copy input to pinned page and prepare parameter for gpu
	aes_cbc_decrypt_prepare(&ops, &param, pool);

	//warmup
	aes_ctx.cbc_decrypt(param.memory_start,
			    param.in_pos,
			    param.key_pos,
			    param.ivs_pos,
			    param.pkt_index_pos,
			    param.total_size,
			    param.out,
			    param.num_blks,
			    param.num_flows,
			    0);

	aes_ctx.sync(0);

	//start actual test
	unsigned rounds = 100;
	uint64_t elaplsed_time[100];
	for (unsigned i = 0; i < rounds; i++ ) {
		aes_ctx.cbc_decrypt(param.memory_start,
				    param.in_pos,
				    param.key_pos,
				    param.ivs_pos,
				    param.pkt_index_pos,
				    param.total_size,
				    param.out,
				    param.num_blks,
				    param.num_flows,
				    0);
		aes_ctx.sync(0);
		elaplsed_time[i] = dev_ctx.get_elapsed_time(0);
	}

	uint64_t total = 0, avg = 0;
	for (unsigned i = 0; i <rounds; i++)
		total += elaplsed_time[i];
	avg = total / rounds;

	printf("%4d %13ld %13ld\n",
	       num_flows, avg, num_flows * flow_len * 8 / avg);

	delete pool;
}

static void test_latency_aes_cbc_encrypt(unsigned key_bits,
					 unsigned num_flows,
					 unsigned flow_len)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * flow_len * 3, 0);
	aes_context aes_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * flow_len * 3);

	aes_enc_param_t param;
	operation_batch_t ops;
	//generate test random test case
	gen_aes_cbc_data(&ops,
			 key_bits,
			 num_flows,
			 flow_len,
			 true);

	//copy input to pinned page and prepare parameter for gpu
	aes_cbc_encrypt_prepare(&ops, &param, pool);

	//gpu execution
	aes_ctx.cbc_encrypt(param.memory_start,
			    param.in_pos,
			    param.key_pos,
			    param.ivs_pos,
			    param.pkt_offset_pos,
			    param.tot_in_len,
			    param.out,
			    param.num_flows,
			    param.tot_out_len,
			    0);

	aes_ctx.sync(0);

	unsigned rounds = 100;
	uint64_t elaplsed_time[100];

	for (unsigned i = 0; i < rounds; i++ ) {
		//gpu execution
		aes_ctx.cbc_encrypt(param.memory_start,
				    param.in_pos,
				    param.key_pos,
				    param.ivs_pos,
				    param.pkt_offset_pos,
				    param.tot_in_len,
				    param.out,
				    param.num_flows,
				    param.tot_out_len,
				    0);
		aes_ctx.sync(0);
		elaplsed_time[i] = dev_ctx.get_elapsed_time(0);
	}

	uint64_t total = 0, avg = 0;
	for (unsigned i = 0; i <rounds; i++)
		total += elaplsed_time[i];
	avg = total / rounds;

	printf("%4d %13ld %13ld\n",
	       num_flows, avg, num_flows * flow_len * 8 / avg);

	delete pool;
}

static void test_latency_stream_aes_cbc_encrypt(unsigned key_bits,
						unsigned num_flows,
						unsigned flow_len,
						unsigned num_stream)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * flow_len * 2.2, num_stream);
	aes_context aes_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * flow_len * 2.2 * num_stream);


	operation_batch_t ops[MAX_STREAM + 1];
	aes_enc_param_t   param[MAX_STREAM + 1];

	for (unsigned i = 1; i <= num_stream; i++) {
		gen_aes_cbc_data(&ops[i],
				 key_bits,
				 num_flows,
				 flow_len,
				 true);

		aes_cbc_encrypt_prepare(&ops[i], &param[i], pool);
	}


	unsigned count = 0;
	uint64_t begin_usec = get_usec();
	unsigned rounds = 100;
	do {
		int stream = 0;
		for (unsigned i = 1; i <= num_stream; i++) {
			if (dev_ctx.get_state(i + stream) == READY) {
				stream = i;
				break;
			} else {
				if (aes_ctx.sync(i + stream, false)) {
					count++;
					if (count == num_stream)
						begin_usec = get_usec();
				}
			}
		}
		if (stream != 0) {
			aes_ctx.cbc_encrypt(param[stream].memory_start,
					    param[stream].in_pos,
					    param[stream].key_pos,
					    param[stream].ivs_pos,
					    param[stream].pkt_offset_pos,
					    param[stream].tot_in_len,
					    param[stream].out,
					    param[stream].num_flows,
					    param[stream].tot_out_len,
					    stream);
		} else {
			usleep(0);
		}

	} while (count < rounds);
	uint64_t end_usec = get_usec();

	for (unsigned i = 1; i <= num_stream; i++) {
		aes_ctx.sync(i, true);
	}


	delete pool;

	printf("%4d %7d %13ld %13ld\n",
	       num_flows, num_stream,
	       (end_usec - begin_usec) / rounds,
	       num_flows * flow_len * 8 / ((end_usec - begin_usec) / rounds));
}

static void test_latency_stream_aes_cbc_decrypt(unsigned key_bits,
						unsigned num_flows,
						unsigned flow_len,
						unsigned num_stream)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * flow_len * 2.2, num_stream);
	aes_context aes_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * flow_len * 2.2 * num_stream);


	operation_batch_t ops[MAX_STREAM + 1];
	aes_dec_param_t   param[MAX_STREAM + 1];

	for (unsigned i = 1; i <= num_stream; i++) {
		gen_aes_cbc_data(&ops[i],
				 key_bits,
				 num_flows,
				 flow_len,
				 false);

		aes_cbc_decrypt_prepare(&ops[i], &param[i], pool);
	}


	unsigned count = 0;
	uint64_t begin_usec = get_usec();
	unsigned rounds = 100;
	int active_stream = 0;
	do {
		int stream = 0;
		for (unsigned i = 1; i <= num_stream; i++) {
			if (dev_ctx.get_state(i + stream) == READY) {
				stream = i;
				break;
			} else {
				if (aes_ctx.sync(i + stream, false)) {
					count++;
					active_stream--;
					if (count == num_stream)
						begin_usec = get_usec();

				}
			}
		}
		if (stream != 0) {
			aes_ctx.cbc_decrypt(param[stream].memory_start,
					    param[stream].in_pos,
					    param[stream].key_pos,
					    param[stream].ivs_pos,
					    param[stream].pkt_index_pos,
					    param[stream].total_size,
					    param[stream].out,
					    param[stream].num_blks,
					    param[stream].num_flows,
					    stream);
			active_stream++;
#if 0
			printf("%d", active_stream);
#endif
		} else {
			usleep(0);
		}

	} while (count < rounds);
	uint64_t end_usec = get_usec();

	for (unsigned i = 1; i <= num_stream; i++) {
		aes_ctx.sync(i, true);
	}

	delete pool;

	printf("%4d %7d %13ld %13ld\n",
	       num_flows, num_stream,
	       (end_usec - begin_usec) / rounds,
	       num_flows * flow_len * 8 / ((end_usec - begin_usec) / rounds));
}

void test_aes_enc(int size)
{
	printf("------------------------------------------\n");
	printf("AES-128-CBC ENC, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg latency(usec) thruput(Mbps)\n");
	for (unsigned i = 1; i <= 4096;  i *= 2)
		test_latency_aes_cbc_encrypt(128, i, size);

	bool result = true;
	printf("Correctness check (batch, random): ");
	for (unsigned i = 1; i <= 4096; i *= 2)
		result = result && test_correctness_aes_cbc_encrypt(128, i, size);

	if (!result)
		printf("FAIL\n");
	else
		printf("OK\n");
}

void test_aes_dec(int size)
{
	printf("------------------------------------------\n");
	printf("AES-128-CBC DEC, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg latency(usec) thruput(Mbps)\n");
	for (unsigned i = 1; i <= 4096;  i *= 2)
		test_latency_aes_cbc_decrypt(128, i, size);

	bool result = true;
	printf("Correctness check (batch, random): ");
	for (unsigned i = 1; i <= 4096; i *= 2)
		result = result && test_correctness_aes_cbc_decrypt(128, i, size);

	if (!result)
		printf("FAIL\n");
	else
		printf("OK\n");
}

void test_aes_enc_stream(int size, int num_stream)
{
	printf("------------------------------------------\n");
	printf("AES-128-CBC ENC, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg #stream latency(usec) thruput(Mbps)\n");

	for (unsigned i = 1; i <= 4096;  i *= 2)
		test_latency_stream_aes_cbc_encrypt(128, i, size, num_stream);

}

void test_aes_dec_stream(int size, int num_stream)
{
	printf("------------------------------------------\n");
	printf("AES-128-CBC DEC, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg #stream latency(usec) thruput(Mbps)\n");

	for (unsigned i = 1; i <= 4096;  i *= 2)
		test_latency_stream_aes_cbc_decrypt(128, i, size, num_stream);

}

static char usage[] = "%s -m ENC|DEC "
	"[-s number of stream] "
	"[-l length of message in bytes (multiples of 16)]\n";

int main(int argc, char *argv[])
{
	srand(time(NULL));

	bool enc = false;
	bool dec = false;
	int size = 16384;
	int num_stream = 0;

	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "-m") == 0) {
			i++;
			if (i == argc)
				goto parse_error;
			if (strcmp(argv[i], "ENC") == 0) {
				enc = true;
			} else if (strcmp(argv[i], "DEC") == 0) {
				dec = true;
			} else {
				goto parse_error;
			}
		} else if (strcmp(argv[i], "-s") == 0) {
			i++;
			if (i == argc)
				goto parse_error;
			num_stream = atoi(argv[i]);
			if (num_stream > 16 || num_stream < 0)
				goto parse_error;
		} else if (strcmp(argv[i], "-l") == 0) {
			i++;
			if (i == argc)
				goto parse_error;
			size = atoi(argv[i]);
			if (size <= 0 || size > 16384 || size % 16 != 0)
				goto parse_error;
		} else
			goto parse_error;
		i++;
	}

	if (!(enc || dec))
		goto parse_error;

	if (enc) {
		if (num_stream == 0)
			test_aes_enc(size);
		else
			test_aes_enc_stream(size, num_stream);
	}
	if (dec) {
		if (num_stream == 0)
			test_aes_dec(size);
		else
			test_aes_dec_stream(size, num_stream);
	}

	return 0;

 parse_error:
	printf(usage, argv[0]);
	return -1;
}



void gen_aes_cbc_data(operation_batch_t *ops,
		      unsigned          key_bits,
		      unsigned          num_flows,
		      unsigned          flow_len,
		      bool              encrypt)
{
	assert(flow_len  > 0 && flow_len  <= MAX_FLOW_LEN);
	assert(num_flows > 0 && num_flows <= 4096);
	assert(key_bits == 128);
	assert(ops != NULL);

	//prepare buffer for data generation
	ops->resize(num_flows);

	//generate random data
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		(*i).destroy();

		//input data
		(*i).in_len  = flow_len;
		(*i).in      = (uint8_t*)malloc(flow_len);
		assert((*i).in != NULL);
		set_random((*i).in, flow_len);

		//output data
		(*i).out_len = flow_len;
		(*i).out     = (uint8_t*)malloc(flow_len);
		assert((*i).out != NULL);
		set_random((*i).out, flow_len);

		//key
		(*i).key_len = key_bits / 8;
		(*i).key     = (uint8_t*)malloc(key_bits / 8);
		assert((*i).key != NULL);
		set_random((*i).key, key_bits / 8);

		//iv
		(*i).iv_len  = AES_IV_SIZE;
		(*i).iv      = (uint8_t*)malloc(AES_IV_SIZE);
		assert((*i).iv != NULL);
		set_random((*i).iv, AES_IV_SIZE);

		//set opcode
		if (encrypt)
			(*i).op = AES_ENC;
		else
			(*i).op = AES_DEC;
	}
}

void aes_cbc_encrypt_prepare(operation_batch_t *ops,
			     aes_enc_param_t   *param,
			     pinned_mem_pool   *pool)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);
	assert(pool != NULL);

	uint32_t *pkt_offset;
	uint8_t *in;
	uint8_t *keys;
	uint8_t *ivs;
	uint8_t *out;
	unsigned tot_in_size = 0; /* total size of input text */

	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		assert((*i).in_len % AES_BLOCK_SIZE == 0); /* assume padded */
		tot_in_size += (*i).in_len;
	}

	//key size should be same for every operation
	unsigned long key_size  = ops->begin()->key_len;
	unsigned long num_flows = ops->size();

	//allocate pinned memory from pool
	pkt_offset = (uint32_t *)pool->alloc(sizeof(uint32_t) * (num_flows + 1));
	keys       = (uint8_t  *)pool->alloc(num_flows * key_size);
	ivs        = (uint8_t  *)pool->alloc(num_flows * AES_IV_SIZE);
	in         = (uint8_t  *)pool->alloc(tot_in_size);
	out        = (uint8_t  *)pool->alloc(tot_in_size);

	assert(pkt_offset != NULL);
	assert(keys       != NULL);
	assert(ivs        != NULL);
	assert(in         != NULL);
	assert(out        != NULL);

	//copy data into pinned memory and set metadata
	unsigned cnt = 0;
	unsigned sum_input = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		pkt_offset[cnt] = sum_input;
		memcpy(keys + cnt * key_size,     (*i).key,   key_size);
		memcpy(ivs  + cnt * AES_IV_SIZE,  (*i).iv,    AES_IV_SIZE);
		memcpy(in   + sum_input,          (*i).in,    (*i).in_len);

		sum_input += (*i).in_len;
		cnt++;
	}
	pkt_offset[cnt] = sum_input;
	assert(sum_input == tot_in_size);

	//set param for aes_context api
	param->memory_start   = (uint8_t*)pkt_offset;
	param->pkt_offset_pos = (unsigned long)((uint8_t*)pkt_offset -
						param->memory_start);
	param->in_pos         = (unsigned long)(in   - param->memory_start);
	param->ivs_pos        = (unsigned long)(ivs  - param->memory_start);
	param->key_pos        = (unsigned long)(keys - param->memory_start);
	//tot_in_len is total length of input plus metadata
	param->tot_in_len     = (unsigned long)(out  - param->memory_start);

	// output data will be sams as the input
	param->tot_out_len    = sum_input;
	param->out            = out;
	param->num_flows      = num_flows;
}

void aes_cbc_decrypt_prepare(operation_batch_t *ops,
			     aes_dec_param_t   *param,
			     pinned_mem_pool   *pool)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);
	assert(pool != NULL);

	uint16_t *pkt_index;
	uint8_t *in;
	uint8_t *keys;
	uint8_t *ivs;
	uint8_t *out;
	unsigned tot_in_size = 0; /* total size of input text */

	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		assert((*i).in_len % AES_BLOCK_SIZE == 0);
		assert((*i).op = AES_DEC);
		tot_in_size += (*i).in_len;
	}

	//key size should be same for every operation
	unsigned long key_size  = ops->begin()->key_len;
	unsigned long num_flows = ops->size();
	unsigned long num_blks  = tot_in_size / AES_BLOCK_SIZE;

	//allocate pinned memory from pool
	pkt_index  = (uint16_t *)pool->alloc(num_blks * sizeof(uint16_t));
	keys       = (uint8_t  *)pool->alloc(num_flows * key_size);
	ivs        = (uint8_t  *)pool->alloc(num_flows * AES_IV_SIZE);
	in         = (uint8_t  *)pool->alloc(tot_in_size);
	out        = (uint8_t  *)pool->alloc(tot_in_size);

	assert(pkt_index  != NULL);
	assert(keys       != NULL);
	assert(ivs        != NULL);
	assert(in         != NULL);
	assert(out        != NULL);

	//copy data into pinned memory and set metadata
	unsigned cnt = 0;
	unsigned sum_input = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		for (unsigned j = 0; j < (*i).in_len / AES_BLOCK_SIZE; j++) {
			pkt_index[j + sum_input / AES_BLOCK_SIZE] = cnt;
		}

		memcpy(keys + cnt * key_size,     (*i).key,   key_size);
		memcpy(ivs  + cnt * AES_IV_SIZE,  (*i).iv,    AES_IV_SIZE);
		memcpy(in   + sum_input,          (*i).in,    (*i).in_len);

		sum_input += (*i).in_len;
		cnt++;
	}
	assert(sum_input == tot_in_size);

	//set param for aes_context api
	param->memory_start   = (uint8_t*)pkt_index;
	param->pkt_index_pos  = (unsigned long)((uint8_t*)pkt_index -
						param->memory_start);
	param->in_pos         = (unsigned long)(in   - param->memory_start);
	param->ivs_pos        = (unsigned long)(ivs  - param->memory_start);
	param->key_pos        = (unsigned long)(keys - param->memory_start);
	param->total_size     = (unsigned long)(out  - param->memory_start);

	param->out            = out;
	param->num_flows      = num_flows;
	param->num_blks       = num_blks;

}

void aes_cbc_post(operation_batch_t *ops,
		  aes_enc_param_t   *param)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);

	unsigned sum_outsize = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		memcpy((*i).out,   param->out + sum_outsize,   (*i).out_len);
		sum_outsize += (*i).out_len;
	}
}

void aes_cbc_post(operation_batch_t *ops,
		  aes_dec_param_t   *param)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);

	unsigned sum_outsize = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		memcpy((*i).out,   param->out + sum_outsize,   (*i).out_len);
		sum_outsize += (*i).out_len;
	}
}

bool aes_cbc_verify_result(operation_batch_t *ops)
{
	//verify result by comparing with OpenSSL
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		uint8_t out_temp[MAX_FLOW_LEN];
		AES_KEY key;
		if ((*i).op == AES_ENC) {
			AES_set_encrypt_key((*i).key, (*i).key_len * 8, &key);
			AES_cbc_encrypt((*i).in,
					out_temp,
					(*i).in_len,
					&key,
					(*i).iv,
					AES_ENCRYPT);
		} else if ((*i).op == AES_DEC) {
			AES_set_decrypt_key((*i).key, (*i).key_len * 8, &key);
			AES_cbc_encrypt((*i).in,
					out_temp,
					(*i).in_len,
					&key,
					(*i).iv,
					AES_DECRYPT);
		} else {
			printf("Incorret opcode \n");
			assert(0);
		}

		if (memcmp((*i).out, out_temp, (*i).out_len) != 0) {
			return false;
		}
	}
	return true;
}
