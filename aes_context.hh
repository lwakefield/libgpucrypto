#ifndef __AES_CONTEXT__
#define __AES_CONTEXT__

#include "cuda_mem_pool.hh"
#include "device_context.hh"

/**
 * class aes_context
 *
 * Interface for AES cipher in GPU.
 * It supports 128-bit CBC-mode encryption/decryptiion, ecb 128 bit encryption.
 */
class aes_context {

public:
	/**
	 * Constructior.
	 *
	 * @param dev_ctx Device context pointer.
	 * Device context must be initialized before calling this function.
	 */
	aes_context(device_context *dev_ctx);
        ~aes_context();

	/**
	 * It executes AES-ECB-128 encryption in GPU.
	 * If stream is enabled it will run in non-blocking mode,
	 * if not, it will run in blocking mode and the result
	 * will be written back to out at the end of function call.
	 * This function takes one or more plaintext and
	 * returns ciphertext for all of them.
	 *
	 * @param memory_start Starting point of input data.
	 * @param in_pos Offset of plain texts. All plain texts are
	 * gathered in to one big buffer with 16-byte align which is
	 * AES block size.
	 * @param keys_pos Offset of region that stores keys.
	 * @param pkt_index_pos Offset of region that stores
	 * per plain text index for every block.
	 * @param data_size Total amount of input data.
	 * @param out Buffer to store output.
	 * @param block_count Total number of blocks in all plain texts.
	 * @param num_flows Total number of plain text.
	 * @param stream_id Stream index.
	 */
        void ecb_128_encrypt(const void           *memory_start,
			     const unsigned long  in_pos,
			     const unsigned long  keys_pos,
			     const unsigned long  pkt_index_pos,
			     const unsigned long  data_size,
			     unsigned char        *out,
			     const unsigned long  block_count,
			     const unsigned long  num_flows,
			     unsigned int         stream_id);


	/**
	 * It executes AES-ECB-128 encryption in GPU.
	 * This function differs from ecb_128_encrypt in that
	 * it will not involve any data copy from/to GPU.
	 * This was intended to measure purely AES computation performance
	 * using GPU.
	 *
	 * @param memory_start Starting point of input data.
	 * @param in_pos Offset of plain texts. All plain texts are
	 * gathered in to one big buffer with 16-byte align which is
	 * AES block size.
	 * @param keys_pos Offset of region that stores keys.
	 * @param pkt_index_pos Offset of region that stores
	 * per plain text index for every block.
	 * @param data_size Total amount of input data.
	 * @param out Buffer to store output.
	 * @param block_count Total number of blocks in all plain texts.
	 * @param num_flows Total number of plain text.
	 * @param stream_id Stream index.
	 */
        void ecb_128_encrypt_nocopy(const void           *memory_start,
				    const unsigned long  in_pos,
				    const unsigned long  keys_pos,
				    const unsigned long  pkt_index_pos,
				    const unsigned long  data_size,
				    unsigned char        *out,
				    const unsigned long  block_count,
				    const unsigned long  num_flows,
				    unsigned int         stream_id);

	/**
	 * It executes AES-CBC encryption in GPU.
	 *
	 * It only supports 128-bit key length at the moment.
	 *
	 * If stream is enabled it will run in non-blocking mode,
	 * if not, it will run in blocking mode and the result
	 * will be written back to out at the end of function call.
	 * This function takes one or more plaintext and
	 * returns ciphertext for all of them.
	 *
	 * @param memory_start Starting point of input data.
	 * @param in_pos Offset of plain texts. All plain texts are
	 * gathered in to one big buffer with 16-byte align which is
	 * AES block size.
	 * @param keys_pos Offset of region that stores keys.
	 * @param ivs_pos Offset of region that store IVs.
	 * @param pkt_offset_pos Offset of region that stores
	 * position of the beginning of each plain text.
	 * @param tot_in_len Total amount of input data plus meta data.
	 * @param out Buffer to store output.
	 * @param block_count Total number of blocks in all plain texts.
	 * @param num_flows Total number of plain text.
	 * @param tot_out_len Total amount of output length.
	 * @param stream_id Stream index.
	 * @param bits key length for AES cipher
	 */
        void cbc_encrypt(const void           *memory_start,
			 const unsigned long  in_pos,
			 const unsigned long  keys_pos,
			 const unsigned long  ivs_pos,
			 const unsigned long  pkt_offset_pos,
			 const unsigned long  tot_in_len,
			 unsigned char        *out,
			 const unsigned long  num_flows,
			 const unsigned long  tot_out_len,
			 const unsigned int   stream_id,
			 const unsigned int   bits = 128);

	/**
	 * It executes AES-CBC encryption in GPU.
	 *
	 * It only supports 128-bit key length at the moment.
	 *
	 * If stream is enabled it will run in non-blocking mode,
	 * if not, it will run in blocking mode and the result
	 * will be written back to out at the end of function call.
	 * This function takes one or more plaintext and
	 * returns ciphertext for all of them.
	 *
	 * @param memory_start Starting point of input data.
	 * @param in_pos Offset of plain texts. All plain texts are
	 * gathered in to one big buffer with 16-byte align which is
	 * AES block size.
	 * @param keys_pos Offset of region that stores keys.
	 * @param ivs_pos Offset of region that store IVs.
	 * @param pkt_index_pos Offset of region that stores
	 * per plain text index for every block. It is used to locate key an IV.
	 * @param data_size Total amount of input data.
	 * @param out Buffer to store output.
	 * @param block_count Total number of blocks in all plain texts.
	 * @param num_flows Total number of plain text.
	 * @param stream_id Stream index.
	 * @param bits key length for AES cipher
	 */
        void cbc_decrypt(const void           *memory_start,
			 const unsigned long  in_pos,
			 const unsigned long  keys_pos,
			 const unsigned long  ivs_pos,
			 const unsigned long  pkt_index_pos,
			 const unsigned long  data_size,
			 unsigned char        *out,
			 const unsigned long  block_count,
			 const unsigned long  num_flows,
			 unsigned int         stream_id,
			 const unsigned int   bits = 128);

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
		  const bool          block=true,
		  const bool          copy_result = true);


private:
	struct {
		uint8_t *out;
		uint8_t *out_d;
		unsigned long out_len;
	} streams[MAX_STREAM + 1];

	device_context *dev_ctx_;
};


#endif /*__AES_CONTEXT__*/
