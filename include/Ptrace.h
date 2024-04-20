#pragma once

#include <functional>

#include <sys/user.h>

bool PtraceStopCallbackResume(int procId, std::function<void()> callback);

bool SetContext(int procId, user_regs_struct& ctx);
bool GetContext(int procId, user_regs_struct& ctx);

bool PtraceReadProcessMemory(int pid, uintptr_t addr, void* data, size_t len);
bool PtraceWriteProcessMemory(int pid, uintptr_t addr, const void* data, size_t len);

bool PtracePushSnapshot(int procId, uintptr_t atAddr, size_t len);
bool PtracePopSnapshot(int procId, uintptr_t atAddr);

bool PushContext(int procId);
bool PopContext(int procId);

bool PtraceContinue(int procId);

/*This function spect a context of ptrace alredy attached and the process alredy stopped*/
uintptr_t PtraceCall(int procId, uintptr_t entry, const std::vector<size_t>& params);
uintptr_t PtraceCallModuleSymbol(int procId, const char* module, const char* symbol, bool nb, const std::vector<size_t>& params);

/* Wrappers */
template<typename T>
T PtraceReadProcessMemoryWrapper(int procId, uintptr_t addr)
{
    T obj;

    PtraceReadProcessMemory(procId, addr, (void*)&obj, sizeof(T));

    return obj;
}

template<typename T>
bool PtraceWriteProcessMemoryWrapper(int procId, uintptr_t addr, const T& obj)
{
    return PtraceWriteProcessMemory(procId, addr, (const void*)&obj, sizeof(T));
}