#include "cuda_mem_pool.hh"

#include <cuda_runtime.h>
#include <cutil_inline.h>

cuda_mem_pool::~cuda_mem_pool()
{
        if(mem_)
        {
                cutilSafeCall(cudaFree(mem_));
                mem_ = 0;
        }
}

bool cuda_mem_pool::init(unsigned long maxsize)
{
        maxsize_ = maxsize;
        cutilSafeCall(cudaMalloc((void**)&mem_, maxsize));
        return true;
}


void cuda_mem_pool::destroy()
{
	if (mem_) {
		cutilSafeCall(cudaFree(mem_));
		mem_ = NULL;
	}
}
