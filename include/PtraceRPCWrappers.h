#pragma once

#include <cstdint>

struct MmapAllocHandle {
    MmapAllocHandle(int procId, uint64_t entry, size_t size);
    ~MmapAllocHandle();

    MmapAllocHandle(const MmapAllocHandle&) = delete;
    MmapAllocHandle(MmapAllocHandle&&) noexcept = default;
    MmapAllocHandle& operator=(const MmapAllocHandle&) = delete;
    MmapAllocHandle& operator=(MmapAllocHandle&&) noexcept = default;

    operator bool();

	uintptr_t mEntry;
    size_t mSize;

private:
    int mProcessId;
};

MmapAllocHandle PtraceCallMMap(int procId, size_t size, int prot);
void* PtraceCallNativeBridgeDlopen(int procId, const char* libPath, int mode);
void* PtraceThreadRemoteIgniteWait(int procId, uintptr_t entry, uintptr_t arg);
void PtraceCallMUnmap(int procId, uintptr_t entry, size_t size);
void PtraceThreadJoin(int procId, int tid);

