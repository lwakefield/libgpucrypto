#include "aes_context.hh"
#include "aes_kernel.h"

#include <assert.h>
#include <cutil_inline.h>

#define AES_BLOCK_SIZE 16
#define THREADS_PER_BLK 256 // in order to load t box into shared memory on parallel

aes_context::aes_context(device_context *dev_ctx)
{
	dev_ctx_ = dev_ctx;
	for (unsigned i = 0; i <= MAX_STREAM; i++) {
		streams[i].out = 0;
		streams[i].out_d = 0;
		streams[i].out_len = 0;
	}
}
aes_context::~aes_context() {

}

void aes_context::cbc_encrypt(const void           *memory_start,
			      const unsigned long  in_pos,
			      const unsigned long  keys_pos,
			      const unsigned long  ivs_pos,
			      const unsigned long  pkt_offset_pos,
			      const unsigned long  tot_in_len,
			      unsigned char        *out,
			      const unsigned long  num_flows,
			      const unsigned long  tot_out_len,
			      const unsigned int   stream_id,
			      const unsigned int   bits)
{
	assert(bits == 128);
	assert(dev_ctx_->get_state(stream_id) == READY);
	dev_ctx_->set_state(stream_id, WAIT_KERNEL);

	/* Allocate memory on device */
	uint8_t *in_d;
	uint8_t *keys_d;
	uint8_t *ivs_d;
	uint32_t *pkt_offset_d;
	void *memory_d;

	//Calculate # of cuda blks required
	unsigned int  threads_per_blk = THREADS_PER_BLK;
	int           num_blks        = (num_flows + threads_per_blk - 1) / threads_per_blk;
	cuda_mem_pool *pool           = dev_ctx_->get_cuda_mem_pool(stream_id);

	memory_d = pool->alloc(tot_in_len);
	cudaMemcpyAsync(memory_d, memory_start, tot_in_len,
			cudaMemcpyHostToDevice, dev_ctx_->get_stream(stream_id));

	dev_ctx_->clear_checkbits(stream_id, num_blks);

	streams[stream_id].out_d = (uint8_t*)pool->alloc(tot_out_len);

	in_d         = (uint8_t *) memory_d + in_pos;
	keys_d       = (uint8_t *) memory_d + keys_pos;
	ivs_d        = (uint8_t *) memory_d + ivs_pos;
	pkt_offset_d = (uint32_t *) ((uint8_t *)memory_d + pkt_offset_pos);

	/* Call cbc kernel function to do encryption */
	if (dev_ctx_->use_stream()) {
		AES_cbc_128_encrypt_gpu(in_d,
					streams[stream_id].out_d,
					pkt_offset_d,
					keys_d,
					ivs_d,
					num_flows,
					dev_ctx_->get_dev_checkbits(stream_id),
					threads_per_blk,
					dev_ctx_->get_stream(stream_id));
	} else {
		AES_cbc_128_encrypt_gpu(in_d,
					streams[stream_id].out_d,
					pkt_offset_d,
					keys_d,
					ivs_d,
					num_flows,
					dev_ctx_->get_dev_checkbits(stream_id),
					threads_per_blk);

	}

	assert(cudaGetLastError() == cudaSuccess);

	streams[stream_id].out     = out;
	streams[stream_id].out_len = tot_out_len;

	/* Copy data back from device to host */
	if (!dev_ctx_->use_stream()) {
		sync(stream_id);
	}
}

bool aes_context::sync(const unsigned int  stream_id,
		       const bool          block,
		       const bool          copy_result)
{
        if (block) {
		dev_ctx_->sync(stream_id, true);
		if (copy_result && dev_ctx_->get_state(stream_id) == WAIT_KERNEL) {
			cutilSafeCall(cudaMemcpyAsync(streams[stream_id].out,
						      streams[stream_id].out_d,
						      streams[stream_id].out_len,
						      cudaMemcpyDeviceToHost,
						      dev_ctx_->get_stream(stream_id)));
			dev_ctx_->set_state(stream_id, WAIT_COPY);
			dev_ctx_->sync(stream_id, true);
			dev_ctx_->set_state(stream_id, READY);
		} else if (dev_ctx_->get_state(stream_id) == WAIT_COPY) {
			dev_ctx_->set_state(stream_id, READY);
		}
		return true;
	} else {
		if (!dev_ctx_->sync(stream_id, false))
			return false;

		if (dev_ctx_->get_state(stream_id) == WAIT_KERNEL) {
			//if no need for data copy
			if (!copy_result) {
				dev_ctx_->set_state(stream_id, READY);
				return true;
			}

			cutilSafeCall(cudaMemcpyAsync(streams[stream_id].out,
						      streams[stream_id].out_d,
						      streams[stream_id].out_len,
						      cudaMemcpyDeviceToHost,
						      dev_ctx_->get_stream(stream_id)));
			dev_ctx_->set_state(stream_id, WAIT_COPY);

		} else if (dev_ctx_->get_state(stream_id) == WAIT_COPY) {
			dev_ctx_->set_state(stream_id, READY);
			return true;
		} else if (dev_ctx_->get_state(stream_id) == READY) {
			return true;
		} else {
			assert(0);
		}
	}
        return false;
}

void aes_context::ecb_128_encrypt(const void           *memory_start,
				  const unsigned long  in_pos,
				  const unsigned long  keys_pos,
				  const unsigned long  pkt_index_pos,
				  const unsigned long  data_size,
				  unsigned char        *out,
				  const unsigned long  block_count,
				  const unsigned long  num_flows,
				  unsigned int         stream_id)
{
	assert(dev_ctx_->get_state(stream_id) == READY);

	unsigned long total_len = block_count * AES_BLOCK_SIZE;
	uint8_t *in_d;
	uint8_t *keys_d;
	uint16_t *pkt_index_d;
	void * memory_d;

	cuda_mem_pool *pool = dev_ctx_->get_cuda_mem_pool(stream_id);
	memory_d = pool->alloc(data_size);
	cudaMemcpyAsync(memory_d, memory_start, data_size,
			cudaMemcpyHostToDevice, dev_ctx_->get_stream(stream_id));

	streams[stream_id].out_d = (uint8_t *) pool->alloc(total_len);

	in_d        = (uint8_t *) memory_d + in_pos;
	keys_d      = (uint8_t *) memory_d + keys_pos;
	pkt_index_d = (uint16_t *) ((uint8_t *) memory_d + pkt_index_pos);

	unsigned int threads_per_blk = THREADS_PER_BLK;

	if (dev_ctx_->use_stream())
		AES_ecb_128_encrypt_gpu(in_d,
					streams[stream_id].out_d,
					keys_d,
					pkt_index_d,
					block_count,
					threads_per_blk,
					dev_ctx_->get_stream(stream_id));
	else
		AES_ecb_128_encrypt_gpu(in_d,
					streams[stream_id].out_d,
					keys_d,
					pkt_index_d,
					block_count,
					threads_per_blk);

	dev_ctx_->set_state(stream_id, WAIT_KERNEL);

	streams[stream_id].out     = out;
	streams[stream_id].out_len = total_len;

	if (!dev_ctx_->use_stream()) {
		sync(stream_id);
	}
}

void aes_context::ecb_128_encrypt_nocopy(const void           *memory_start,
					 const unsigned long  in_pos,
					 const unsigned long  keys_pos,
					 const unsigned long  pkt_index_pos,
					 const unsigned long  data_size,
					 unsigned char        *out,
					 const unsigned long  block_count,
					 const unsigned long  num_flows,
					 unsigned int         stream_id)
{
	assert(dev_ctx_->get_state(stream_id) == READY);

	unsigned long total_len = block_count * AES_BLOCK_SIZE;
	uint8_t *in_d;
	uint8_t *keys_d;
	uint16_t *pkt_index_d;
	void * memory_d;

	cuda_mem_pool *pool = dev_ctx_->get_cuda_mem_pool(stream_id);

	memory_d                 = pool->alloc(data_size);
	streams[stream_id].out_d = (uint8_t*)pool->alloc(total_len);
	in_d                     = (uint8_t *) memory_d + in_pos;
	keys_d                   = (uint8_t *) memory_d + keys_pos;
	pkt_index_d              = (uint16_t *) ((uint8_t *) memory_d + pkt_index_pos);

	unsigned int threads_per_blk = THREADS_PER_BLK;

	if (dev_ctx_->use_stream())
		AES_ecb_128_encrypt_gpu(in_d,
					streams[stream_id].out_d,
					keys_d,
					pkt_index_d,
					block_count,
					threads_per_blk,
					dev_ctx_->get_stream(stream_id));
	else
		AES_ecb_128_encrypt_gpu(in_d,
					streams[stream_id].out_d,
					keys_d, pkt_index_d,
					block_count,
					threads_per_blk);

	assert(cudaGetLastError() == cudaSuccess);
	dev_ctx_->set_state(stream_id, WAIT_KERNEL);

	streams[stream_id].out     = out;
	streams[stream_id].out_len = total_len;

	if (!dev_ctx_->use_stream()) {
		sync(stream_id);
	}
}


void aes_context::cbc_decrypt(const void           *memory_start,
			      const unsigned long  in_pos,
			      const unsigned long  keys_pos,
			      const unsigned long  ivs_pos,
			      const unsigned long  pkt_index_pos,
			      const unsigned long  data_size,
			      unsigned char        *out,
			      const unsigned long  block_count,
			      const unsigned long  num_flows,
			      const unsigned int   stream_id,
			      const unsigned int   bits)
{
	assert(bits==128);
	assert(dev_ctx_->get_state(stream_id) == READY);
	dev_ctx_->set_state(stream_id, WAIT_KERNEL);

	unsigned long total_len = block_count * AES_BLOCK_SIZE;
	uint8_t *in_d;
	uint8_t *keys_d;
	uint8_t *ivs_d;
	uint16_t *pkt_index_d;
	void *memory_d;
	unsigned int threads_per_blk = 512;
	int num_blks = (block_count + threads_per_blk - 1) / threads_per_blk;

	//transfor encrypt key to decrypt key
	//basically it generates round key and take the last
	//CUDA code will generate the round key in reverse order
	for (unsigned i = 0; i < num_flows; i++) {
		uint8_t *key = (uint8_t *)memory_start + keys_pos + i * bits / 8;
		AES_decrypt_key_prepare(key, key, bits);
	}

	dev_ctx_->clear_checkbits(stream_id, num_blks);

	cuda_mem_pool *pool = dev_ctx_->get_cuda_mem_pool(stream_id);
	memory_d = pool->alloc(data_size);
	cudaMemcpyAsync(memory_d,
			memory_start,
			data_size,
			cudaMemcpyHostToDevice,
			dev_ctx_->get_stream(stream_id));

	streams[stream_id].out_d = (uint8_t*)pool->alloc(total_len);

	in_d        = (uint8_t *) memory_d + in_pos;
	keys_d      = (uint8_t *) memory_d + keys_pos;
	ivs_d       = (uint8_t *) memory_d + ivs_pos;
	pkt_index_d = (uint16_t *) ((uint8_t *) memory_d + pkt_index_pos);

	assert(bits == 128);
	if (dev_ctx_->use_stream() && stream_id > 0) {
		AES_cbc_128_decrypt_gpu(in_d,
					streams[stream_id].out_d,
					keys_d,
					ivs_d,
					pkt_index_d,
					block_count,
					dev_ctx_->get_dev_checkbits(stream_id),
					threads_per_blk,
					dev_ctx_->get_stream(stream_id));
	} else if (stream_id == 0) {
		AES_cbc_128_decrypt_gpu(in_d,
					streams[stream_id].out_d,
					keys_d,
					ivs_d,
					pkt_index_d,
					block_count,
					dev_ctx_->get_dev_checkbits(stream_id),
					threads_per_blk);
	} else {
		assert(0);
	}

	assert(cudaGetLastError() == cudaSuccess);

	streams[stream_id].out     = out;
	streams[stream_id].out_len = total_len;

	if (!dev_ctx_->use_stream()) {
		sync(stream_id, true);
	}
}


