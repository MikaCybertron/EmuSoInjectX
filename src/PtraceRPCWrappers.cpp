#include "PtraceRPCWrappers.h"
#include "Ptrace.h"
#include <sys/mman.h>
#include <vector>
#include <sys/wait.h>
#include <thread>
#include <RemoteString.h>
#include <LinuxProcess.h>
#include <Errors.h>

#define NATIVEBRIDGE_LOADLIB_SYMNAME "_ZN7android23NativeBridgeLoadLibraryEPKci"

MmapAllocHandle PtraceCallMMap(int procId, size_t size, int prot)
{
    auto entry = PtraceCallModuleSymbol(procId, "libc.so", "mmap", false, {
        0x0,
        size,
        (unsigned int)prot,
        MAP_PRIVATE | MAP_ANONYMOUS,
        (unsigned int)-1,
        0
    });

    return MmapAllocHandle(procId, entry, size);
}

void* PtraceCallNativeBridgeDlopen(int procId, const char* libPath, int mode)
{
    RemoteString rs(procId, libPath);

    if (!rs)
        return nullptr;

    return (void*)PtraceCallModuleSymbol(procId, "libnativebridge.so", NATIVEBRIDGE_LOADLIB_SYMNAME, false, {
        rs.mString.mBuffer.mEntry,
        (unsigned int)mode
        });
}

void* PtraceThreadRemoteIgniteWait(int procId, uintptr_t entry, uintptr_t arg)
{
    auto remoteData = PtraceCallMMap(procId, sizeof(pthread_t) + sizeof(void*), PROT_READ | PROT_WRITE);

    if (PtraceCallModuleSymbol(procId, "libc.so", "pthread_create", false, {
        remoteData.mEntry,
        0,
        entry,
        arg
        }))
        return nullptr;

    PtraceCallModuleSymbol(procId, "libc.so", "pthread_join", false, {
        PtraceReadProcessMemoryWrapper<unsigned long>(procId, remoteData.mEntry),
        remoteData.mEntry + sizeof(pthread_t)
        });

    return PtraceReadProcessMemoryWrapper<void*>(procId, remoteData.mEntry + sizeof(pthread_t));
}

void PtraceCallMUnmap(int procId, uintptr_t entry, size_t size)
{
    PtraceCallModuleSymbol(procId, "libc.so", "munmap",  false, {
        entry,
        size
    });
}

void PtraceThreadJoin(int procId, int tid)
{
    int status;

    while (wait4(procId, &status, __WCLONE, NULL) != tid)
        std::this_thread::yield();
}

MmapAllocHandle::MmapAllocHandle(int procId, uint64_t entry, size_t size)
    : mProcessId(procId)
    , mEntry(entry)
    , mSize(size)
{}

MmapAllocHandle::~MmapAllocHandle()
{
    if (!*this)
        return;

    PtraceCallMUnmap(mProcessId, mEntry, mSize);
}

MmapAllocHandle::operator bool()
{
    return mEntry != -1ull;
}