#include "sha_context.hh"
#include "sha1.hh"

#include <assert.h>
#include <cuda_runtime.h>
#include <cutil_inline.h>

sha_context::sha_context(device_context *dev_ctx)
{
	for (unsigned i = 0; i <MAX_STREAM; i++) {
		streams[i].out = 0;
		streams[i].out_d = 0;
		streams[i].out_len = 0;
	}
	dev_ctx_ = dev_ctx;
}
sha_context::~sha_context()
{
}


void sha_context::hmac_sha1(const void           *memory_start,
			    const unsigned long  in_pos,
			    const unsigned long  keys_pos,
			    const unsigned long  offsets_pos,
			    const unsigned long  lengths_pos,
			    const unsigned long  data_size,
			    unsigned char        *out,
			    const unsigned long  num_flows,
			    const unsigned int   stream_id)
{
	assert(dev_ctx_->get_state(stream_id) == READY);
	dev_ctx_->set_state(stream_id, WAIT_KERNEL);
	cuda_mem_pool *pool = dev_ctx_->get_cuda_mem_pool(stream_id);
	void *memory_d = pool->alloc(data_size);;

	//copy input data
	cudaMemcpyAsync(memory_d,
			memory_start,
			data_size,
			cudaMemcpyHostToDevice,
			dev_ctx_->get_stream(stream_id));

	//variables need for kernel launch
	int threads_per_blk = SHA1_THREADS_PER_BLK;
	int num_blks = (num_flows+threads_per_blk-1)/threads_per_blk;

	//allocate buffer for output
	uint32_t *out_d = (uint32_t *)pool->alloc(20 * num_flows);

	//initialize input memory offset in device memory
	char     *in_d         = (char *)memory_d + in_pos;
	char     *keys_d       = (char *)memory_d + keys_pos;
	uint32_t *pkt_offset_d = (uint32_t *)((uint8_t *)memory_d + offsets_pos);
	uint16_t *lengths_d    = (uint16_t *)((uint8_t *)memory_d + lengths_pos);

	//clear checkbits before kernel execution
	dev_ctx_->clear_checkbits(stream_id, num_blks);

	if (dev_ctx_->use_stream() && stream_id > 0) {	//with stream
		hmac_sha1_gpu(in_d,
			      keys_d,
			      pkt_offset_d,
			      lengths_d,
			      out_d,
			      num_flows,
			      dev_ctx_->get_dev_checkbits(stream_id),
			      threads_per_blk,
			      dev_ctx_->get_stream(stream_id));
	} else  if (!dev_ctx_->use_stream() && stream_id == 0) {//w/o stream
		hmac_sha1_gpu(in_d,
			      keys_d,
			      pkt_offset_d,
			      lengths_d,
			      out_d,
			      num_flows,
			      dev_ctx_->get_dev_checkbits(stream_id),
			      SHA1_THREADS_PER_BLK);
	} else {
		assert(0);
	}

	assert(cudaGetLastError() == cudaSuccess);

	streams[stream_id].out_d   = (uint8_t*)out_d;
	streams[stream_id].out     = out;
	streams[stream_id].out_len = 20 * num_flows;

	//if stream is not used then sync (assuming blocking mode)
	if (dev_ctx_->use_stream() && stream_id == 0) {
		sync(stream_id);
	}
}

bool sha_context::sync(const unsigned int  stream_id,
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
		}
		if (dev_ctx_->get_state(stream_id) == WAIT_COPY) {
			dev_ctx_->sync(stream_id, true);
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
