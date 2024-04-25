#pragma once

#include <sys/mman.h>
#include <PtraceRPCWrappers.h>

class RemoteBuffer {
public:

	RemoteBuffer(int pid, const void* buff, size_t size, int prot = PROT_READ | PROT_WRITE);

	operator bool();

	MmapAllocHandle mBuffer;
};