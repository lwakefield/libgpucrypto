#ifndef __SHA1_KERNEL__
#define __SHA1_KERNEL__

#define SHA1_THREADS_PER_BLK 32
#define MAX_KEY_SIZE 64
#define MAX_HASH_SIZE 20

#include <stdint.h>
#include <cuda_runtime.h>

void hmac_sha1_gpu(char* buf, char* keys,  uint32_t *offsets, uint16_t *lengths,
		   uint32_t *outputs, int N, uint8_t * checkbits,
		   unsigned threads_per_blk, cudaStream_t stream=0);


#endif/*__SHA1_KERNEL*/
