#include <cassert>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include <typeinfo>
#include <stdint.h>
#include <openssl/hmac.h>

#include <time.h>

#include "sha1.hh"
#include "sha_context.hh"
#include "device_context.hh"
#include "pinned_mem_pool.hh"
#include "cuda_mem_pool.hh"
#include "common.hh"

#define HMAC_SHA1_HASH_SIZE 20
#define MAX_FLOW_LEN 16384

#define max(a,b) ((a >= b)?(a):(b))

typedef struct hmac_sha1_param
{
	uint8_t         *memory_start;
	unsigned long   pkt_offset_pos;
	unsigned long   in_pos;
	unsigned long   key_pos;
	unsigned long   length_pos;
	unsigned        total_size;
	unsigned        num_flows;
	uint8_t         *out;
} hmac_sha1_param;


void gen_hmac_sha1_data(operation_batch_t *ops,
			unsigned          num_flows,
			unsigned          flow_len)
{
	assert(flow_len  > 0 && flow_len  <= MAX_FLOW_LEN);
	assert(num_flows > 0 && num_flows <= 4096);
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
		(*i).out_len = HMAC_SHA1_HASH_SIZE;
		(*i).out     = (uint8_t*)malloc(HMAC_SHA1_HASH_SIZE);
		assert((*i).out != NULL);
		set_random((*i).out, HMAC_SHA1_HASH_SIZE);

		//key
		(*i).key_len = MAX_KEY_SIZE;
		(*i).key     = (uint8_t*)malloc(MAX_KEY_SIZE);
		assert((*i).key != NULL);
		set_random((*i).key, MAX_KEY_SIZE);

		(*i).op = HMAC_SHA1;
	}

}

void hmac_sha1_prepare(operation_batch_t *ops,
		       hmac_sha1_param_t *param,
		       pinned_mem_pool   *pool)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);
	assert(pool != NULL);

	uint32_t *pkt_offset;
	uint8_t  *in;
	uint16_t *lengths;
	uint8_t  *keys;
	uint8_t  *out;

	unsigned tot_in_size = 0; /* total size of input text */

	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		tot_in_size += (*i).in_len;
	}

	unsigned long num_flows = ops->size();

	//allocate memory
	pkt_offset = (uint32_t *)pool->alloc(sizeof(uint32_t) * (num_flows));
	keys       = (uint8_t  *)pool->alloc(num_flows * MAX_KEY_SIZE);
	in         = (uint8_t  *)pool->alloc(tot_in_size);
	lengths     = (uint16_t *)pool->alloc(sizeof(uint16_t) * num_flows);
	out        = (uint8_t  *)pool->alloc(HMAC_SHA1_HASH_SIZE * num_flows);

	assert(pkt_offset != NULL);
	assert(keys       != NULL);
	assert(in         != NULL);
	assert(lengths    != NULL);
	assert(out        != NULL);

	//copy data into pinned memory and set metadata
	unsigned cnt = 0;
	unsigned sum_input = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		pkt_offset[cnt] = sum_input;
		lengths[cnt]    = (*i).in_len;

		memcpy(keys + cnt * MAX_KEY_SIZE, (*i).key,  MAX_KEY_SIZE);
		memcpy(in + sum_input,  (*i).in,   (*i).in_len);

		cnt++;
		sum_input += (*i).in_len;
	}

	//set param for sha_context api
	param->memory_start   = (uint8_t*)pkt_offset;
	param->pkt_offset_pos = (unsigned long)((uint8_t *)pkt_offset -
						param->memory_start);
	param->in_pos         = (unsigned long)(in      - param->memory_start);
	param->key_pos        = (unsigned long)(keys    - param->memory_start);
	param->length_pos     = (unsigned long)((uint8_t *)lengths
						- param->memory_start);
	param->total_size     = (unsigned long)(out     - param->memory_start);

	param->out            = out;
	param->num_flows      = num_flows;
}


void hmac_sha1_post(operation_batch_t *ops,
		    hmac_sha1_param_t   *param)
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


bool verify_hmac_sha1(operation_batch_t *ops)
{
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		uint8_t out_temp[HMAC_SHA1_HASH_SIZE];

		unsigned len;
		HMAC(EVP_sha1(),
		     (*i).key,
		     (*i).key_len,
		     (*i).in,
		     (*i).in_len,
		     out_temp,
		     &len);
		assert(len == HMAC_SHA1_HASH_SIZE);

		if (memcmp(out_temp, (*i).out, (*i).out_len) != 0) {
			return false;
		}
	}
	return true;
}


static bool test_correctness_hmac_sha1(unsigned  num_flows, unsigned flow_len)
{
	device_context dev_ctx;
	dev_ctx.init(104857600, 0);
	sha_context sha_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(104857600);

	operation_batch_t ops;
	hmac_sha1_param_t param;

	gen_hmac_sha1_data(&ops, num_flows, flow_len);
	hmac_sha1_prepare(&ops, &param, pool);

	sha_ctx.hmac_sha1((void*)param.memory_start,
			  param.in_pos,
			  param.key_pos,
			  param.pkt_offset_pos,
			  param.length_pos,
			  param.total_size,
			  param.out,
			  param.num_flows,
			  0);

	sha_ctx.sync(0);

	hmac_sha1_post(&ops, &param);

	delete pool;

	return verify_hmac_sha1(&ops);
}

static void test_latency_hmac_sha1(unsigned num_flows, unsigned flow_len)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * max(flow_len, 512) * 2.2, 0);
	sha_context sha_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * max(flow_len, 512) * 2.2);

	operation_batch_t ops;
	hmac_sha1_param_t param;

	gen_hmac_sha1_data(&ops, num_flows, flow_len);
	hmac_sha1_prepare(&ops, &param, pool);

	sha_ctx.hmac_sha1((void*)param.memory_start,
			  param.in_pos,
			  param.key_pos,
			  param.pkt_offset_pos,
			  param.length_pos,
			  param.total_size,
			  param.out,
			  param.num_flows,
			  0);

	sha_ctx.sync(0);

	hmac_sha1_post(&ops, &param);

	unsigned rounds = 100;
	uint64_t begin_usec = get_usec();
	for (unsigned i = 0; i < rounds; i++) {
		sha_ctx.hmac_sha1((void*)param.memory_start,
				  param.in_pos,
				  param.key_pos,
				  param.pkt_offset_pos,
				  param.length_pos,
				  param.total_size,
				  param.out,
				  param.num_flows,
				  0);

		sha_ctx.sync(0);
	}
	uint64_t end_usec = get_usec();
	uint64_t total = end_usec - begin_usec;
	uint64_t avg = total / rounds;

	delete pool;

	printf("%4d %13ld %13ld\n",
	       num_flows, avg, num_flows * flow_len * 8 / avg);
}

static void test_latency_stream_hmac_sha1(unsigned num_flows,
					  unsigned flow_len,
					  unsigned num_stream)
{
	device_context dev_ctx;
	dev_ctx.init(num_flows * max(flow_len, 512) * 2, num_stream);
	sha_context sha_ctx(&dev_ctx);

	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows * max(flow_len, 512) * 2 * num_stream);

	operation_batch_t ops[MAX_STREAM + 1];
	hmac_sha1_param_t param[MAX_STREAM + 1];

	//warmup
	for (unsigned i = 1; i <= num_stream; i++) {
		gen_hmac_sha1_data(&ops[i], num_flows, flow_len);
		hmac_sha1_prepare(&ops[i], &param[i], pool);
		sha_ctx.hmac_sha1((void*)param[i].memory_start,
				  param[i].in_pos,
				  param[i].key_pos,
				  param[i].pkt_offset_pos,
				  param[i].length_pos,
				  param[i].total_size,
				  param[i].out,
				  param[i].num_flows,
				  i);
		sha_ctx.sync(i, true);
	}

	unsigned count = 0;
	unsigned rounds = 100;
	uint64_t begin_usec = get_usec();
	do {
		int stream = 0;
		for (unsigned i = 1; i <= num_stream; i++) {
			if (dev_ctx.get_state(i) == READY) {
				stream = i;
				break;
			} else {
				if (sha_ctx.sync(i, false)) {
					count++;
					if (count == num_stream )
						begin_usec = get_usec();
				}
			}
		}
		if (stream != 0) {
			sha_ctx.hmac_sha1((void*)param[stream].memory_start,
					  param[stream].in_pos,
					  param[stream].key_pos,
					  param[stream].pkt_offset_pos,
					  param[stream].length_pos,
					  param[stream].total_size,
					  param[stream].out,
					  param[stream].num_flows,
					  stream);

		} else {
		}
	} while (count < rounds + num_stream);
	uint64_t end_usec = get_usec();

	for (unsigned i = 1; i < num_stream; i++) {
		sha_ctx.sync(i, true);
	}
	uint64_t total = end_usec - begin_usec;
	uint64_t avg = total / rounds;

	delete pool;
	printf("%4d %7d %13ld %13ld\n",
	       num_flows, num_stream,
	       avg,
	       num_flows * flow_len * 8 / avg);
}

void test_hmac_sha1(int size)
{
	printf("------------------------------------------\n");
	printf("HMAC_SHA1, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg latency(usec) thruput(Mbps)\n");
	for (unsigned i = 1 ; i <= 4096 ;i = i * 2)
		test_latency_hmac_sha1(i, size);

	printf("Correctness check (batch, random): ");
	bool result = true;
	for (unsigned i = 1 ; i <= 4096 ;i = i * 2)
		result = result && test_correctness_hmac_sha1(i, size);

	if (!result)
		printf("FAIL\n");
	else
		printf("OK\n");

}

void test_hmac_sha1_stream(int size, int num_stream)
{
	printf("------------------------------------------\n");
	printf("HMAC_SHA1, Size: %dKB\n", size / 1024);
	printf("------------------------------------------\n");
	printf("#msg #stream latency(usec) thruput(Mbps)\n");
	for (unsigned i = 1 ; i <= 4096 ;i = i * 2)
		test_latency_stream_hmac_sha1(i, size, num_stream);
}


static char usage[] = "%s "
	"[-s number of stream] "
	"[-l length of message in bytes (multiples of 16)]\n";

int main(int argc, char *argv[])
{
	srand(time(NULL));

	int size = 16384;
	int num_stream = 0;

	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "-s") == 0) {
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

	if (num_stream == 0)
		test_hmac_sha1(size);
	else
		test_hmac_sha1_stream(size, num_stream);

	return 0;

 parse_error:
	printf(usage, argv[0]);
	return -1;
}
