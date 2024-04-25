#include <RemoteBuffer.h>
#include <Ptrace.h>

RemoteBuffer::RemoteBuffer(int pid, const void* buff, size_t size, int prot)
	: mBuffer(PtraceCallMMap(pid, size, prot))
{
	if (!mBuffer)
		return;

	PtraceWriteProcessMemory(pid, mBuffer.mEntry, buff, size);
}

RemoteBuffer::operator bool()
{
	return mBuffer;
}
