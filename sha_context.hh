#ifndef __SHA_CONTEXT__
#define __SHA_CONTEXT__

#include "cuda_mem_pool.hh"
#include "device_context.hh"

/**
 * class sha_context
 *
 * Interface for HMAC-SHA1 in GPU.
 */
class sha_context {
public:
	/**
	 * Constructior.
	 *
	 * @param dev_ctx Device context pointer.
	 * Device context must be initialized before calling this function.
	 */
	sha_context(device_context *dev_ctx);

	~sha_context();

	/**
	 * It executes hmac_sha1 in GPU.
	 * If stream is enabled it will run in non-blocking mode,
	 * if not, it will run in blocking mode and the result
	 * will be written back to out at the end of function call.
	 * This function takes one or more data  and
	 * returns HMAC-SHA1 value for all of them.
	 *
	 * @param memory_start Starting point of input data.
	 * All input data should be be packed in to single continous region
	 * before making call to this function.
	 * @param in_pos Offset of plain texts.
	 * @param keys_pos Offset of region that stores HHAC keys.
	 * @param pkt_offset_pos Offset of region that stores
	 * position of each plain text.
	 * @param lengths_pos Offset of region that stores length of
	 * each plain text.
	 * @param data_size Total amount of input data.
	 * @param out Buffer to store output.
	 * @param num_flows Number of plain texts to be hashed.
	 * @param stream_id Stream index.
	 */
        void hmac_sha1(const void           *memory_start,
		       const unsigned long  in_pos,
		       const unsigned long  keys_pos,
		       const unsigned long  pkt_offset_pos,
		       const unsigned long  lengths_pos,
		       const unsigned long  data_size,
		       unsigned char        *out,
		       const unsigned long  num_flows,
		       unsigned int         stream_id);

	/**
	 * Synchronize/query the execution on the stream.
	 * This function can be used to check whether the current execution
	 * on the stream is finished or also be used to wait until
	 * the execution to be finished.
	 *
	 * @param stream_id Stream index.
	 * @param block Wait for the execution to finish or not. true by default.
	 * @param copy_result If false, it will not copy result back to CPU.
	 *
	 * @return true if the current operation on the stream is finished
	 * otherwise false.
	 */
	bool sync(const unsigned int  stream_id,
		  const bool          block = true,
		  const bool          copy_result = true);

private:
	struct {
		uint8_t        *out;
		uint8_t        *out_d;
		unsigned long  out_len;
	} streams[MAX_STREAM + 1];

	device_context *dev_ctx_;

};
#endif/*__SHA_CONTEXT__*/
