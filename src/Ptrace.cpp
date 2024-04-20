#include "Ptrace.h"
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <elf.h>
#include <vector>
#include <unordered_map>
#include <stack>
#include "LinuxProcess.h"
#include "Errors.h"
#include <unistd.h>

template<typename T, typename K>
long Ptrace(long request, unsigned long pid, T addr, K data)
{
    long result = 0;

    if ((result = ptrace(request, pid, (void*)addr, (void*)data)) < 0)
    {
        SetLastError(ERR_ACCESS_DENIED);
        return result;
    }

    return result;
}

static uint64_t ms() {
    struct timespec spec;
    clock_gettime(CLOCK_MONOTONIC, &spec);
    return (spec.tv_sec * 1000) + (spec.tv_nsec / 1.0e6);
}

bool PtraceStopCallbackResume(int procId, std::function<void()> callback)
{
    if (Ptrace(PTRACE_ATTACH, procId, NULL, NULL) < 0) 
        return false;

    printf("[+] Process Attached\n");

    int status;

    waitpid(procId, &status, 0);

    callback();

    if (Ptrace(PTRACE_DETACH, procId, NULL, NULL) < 0)
        return false;

    printf("[+] Process Detached\n");

    return true;
}

bool GetContext(int procId, user_regs_struct& ctx)
{
    // ctx = {0};

    if(Ptrace(PTRACE_GETREGS, procId, NULL, &ctx) < 0)
                return false;

    return true;
}

bool SetContext(int procId, user_regs_struct& ctx)
{
    if(Ptrace(PTRACE_SETREGS, procId, NULL, &ctx) < 0)
            return false;

    return true;
}

bool PtraceContinue(int procId)
{
    if(Ptrace(PTRACE_CONT, procId, NULL, NULL) < 0)
        return false;

    return true;
}

#ifdef __i386__

void PrintRegisters(user_regs_struct* regs) {
    printf("EIP: 0x%lx ESP: 0x%lx EBP: 0x%lx EAX: 0x%lx EBX: 0x%lx ECX: 0x%lx EDX: 0x%lx ESI: 0x%lx EDI: 0x%lx\n",
        regs->eip, regs->esp, regs->ebp, regs->eax, regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi);
}

void PtraceCallSetup(int procId, user_regs_struct& ctx, size_t callEntryAddr, const std::vector<size_t>& params, size_t retAddr) {
    ctx.eip = callEntryAddr;
    ctx.esp -= (params.size()) * sizeof(size_t);
    PtraceWriteProcessMemory(procId, ctx.esp, params.data(), params.size() * sizeof(size_t));
    ctx.esp -= sizeof(size_t);
    PtraceWriteProcessMemoryWrapper(procId, ctx.esp, retAddr);
}

uint64_t ContextProgramCounter(user_regs_struct& ctx)
{
    return ctx.eip;
}

uint64_t ContextProgramReturn(user_regs_struct& ctx)
{
    return ctx.eax;
}
#endif

#ifdef __x86_64__

void PrintRegisters(user_regs_struct* regs) {
    printf("RIP: 0x%llx RSP: 0x%llx RBP: 0x%llx RAX: 0x%llx RBX: 0x%llx RCX: 0x%llx RDX: 0x%llx RSI: 0x%llx RDI: 0x%llx\n",
        regs->rip, regs->rsp, regs->rbp, regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi, regs->rdi);
}

void PtraceCallSetup(int procId, user_regs_struct& ctx, size_t callEntryAddr, const std::vector<size_t>& params, size_t retAddr) {
    ctx.rip = callEntryAddr;

    switch (params.size())
    {
    default:
    case 6:
        ctx.r9 = params[5];
    case 5:
        ctx.r8 = params[4];
    case 4:
        ctx.rcx = params[3];
    case 3:
        ctx.rdx = params[2];
    case 2:
        ctx.rsi = params[1];
    case 1:
        ctx.rdi = params[0];
    case 0:
        break;
    }

    if (params.size() > 6)
    {
        ctx.rsp -= (params.size() - 6) * sizeof(size_t);
        PtraceWriteProcessMemory(procId, ctx.rsp, params.data() + 6, (params.size() - 6) * sizeof(size_t));
    }

    ctx.rsp -= sizeof(size_t);
    PtraceWriteProcessMemoryWrapper(procId, ctx.rsp, retAddr);
}

uint64_t ContextProgramCounter(user_regs_struct& ctx)
{
    return ctx.rip;
}

uint64_t ContextProgramReturn(user_regs_struct& ctx)
{
    return ctx.rax;
}
#endif

void PrintRegisters(user_regs_struct& regs)
{
    PrintRegisters(&regs);
}

#if !defined(__i386__) && !defined(__x86_64__)
#error Unsupported Arch
#endif

bool ProcessWaitSignal(int procId, int signalType)
{
    int status = 0;

    while(waitpid(procId, &status, WUNTRACED) == procId)
    {
        if (WIFEXITED(status)) 
            return false;

        // At this point process hasnt Exited

        // printf("At this point process hasnt Exited\n");

        if(WIFSTOPPED(status) == false)
        {
            if(PtraceContinue(procId)) return false;
            continue;
        }

        // At this point process was not stopped
        // printf("At this point process was not stopped\n");


        if(WSTOPSIG(status) != signalType)
        {
            if(PtraceContinue(procId)) return false;
            continue;
        }

        // SignalType Fired detected
        // printf("%d signal Fired detected\n", signalType);

        break;
    }

    return true;
}

uintptr_t PtraceCall(int procId, uintptr_t entry, const std::vector<size_t>& params)
{
    PushContext(procId);

    user_regs_struct ctx { 0 };

    if(GetContext(procId, ctx) == false)
        return -1;

    PrintRegisters(ctx);

    PtraceCallSetup(procId, ctx, entry, params, 0x0);

    PrintRegisters(ctx);

    SetContext(procId, ctx);

    //// Now lets just run and wait
    if(PtraceContinue(procId) == false)
        return -2;

    // do {
        if(ProcessWaitSignal(procId, SIGSEGV) == false)
            return -3;

        if(GetContext(procId, ctx) == false)
            return -4;
        
        if(ContextProgramCounter(ctx) != 0)
            PtraceContinue(procId);
        
    // } while(ContextProgramCounter(ctx) != 0);

    // Null-Call Found as expected

    PrintRegisters(ctx);

    if(PopContext(procId) == false)
        return -5;

    return ContextProgramReturn(ctx);
}

uintptr_t PtraceCallModuleSymbol(int procId, const char* module, const char* symbol, bool nb, const std::vector<size_t>& params)
{
    uintptr_t symbolEntry = FindModuleSymbol(procId, module, symbol, nb);

    if(symbolEntry == INVALID_SYMBOL_ADDR)
    {
        SetLastError(ERR_SYMBOL_NOT_FOUND);
        return 0;
    }

    printf("[+] %s %s Found: %p\n", module, symbol, (void*)symbolEntry);

    return PtraceCall(procId, symbolEntry, params);
}

bool PtraceReadProcessMemory(int pid, uintptr_t addr, void* data, size_t len) {
    size_t i, j, remain;
    uint8_t* laddr;

    union u {
        uintptr_t val;
        uint8_t chars[sizeof(uintptr_t)];
    } d;

    j = len / sizeof(uintptr_t);
    remain = len % sizeof(uintptr_t);

    laddr = (uint8_t*)data;

    for (i = 0; i < j; i++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
        memcpy(laddr, d.chars, sizeof(uintptr_t));
        addr += sizeof(uintptr_t);
        laddr += sizeof(uintptr_t);
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
        memcpy(laddr, d.chars, remain);
    }

    return true;
}

bool PtraceWriteProcessMemory(int pid, uintptr_t addr, const void* data, size_t len) {
    size_t i, remain;
    uint8_t* laddr;

    union u {
        uintptr_t val;
        uint8_t chars[sizeof(uintptr_t)];
    } d;

    i = 0;
    laddr = (uint8_t*)data;

    // Write data in chunks of sizeof(uintptr_t)
    for (; i + sizeof(uintptr_t) <= len; i += sizeof(uintptr_t)) {
        memcpy(d.chars, laddr, sizeof(uintptr_t));
        ptrace(PTRACE_POKETEXT, pid, addr + i, d.val);
        laddr += sizeof(uintptr_t);
    }

    // Write any remaining bytes
    remain = len - i;
    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, addr + i, nullptr);
        for (size_t j = 0; j < remain; j++) {
            d.chars[j] = *laddr++;
        }
        ptrace(PTRACE_POKETEXT, pid, addr + i, d.val);
    }

    return true;
}


std::unordered_map<int, std::unordered_map<uintptr_t, std::stack<std::vector<unsigned char>>>> snapshots;

bool PtracePushSnapshot(int procId, uintptr_t atAddr, size_t len)
{
    auto& snapshotStack = snapshots[procId][atAddr];
    snapshotStack.push(std::vector<unsigned char>(len));

    if (!PtraceReadProcessMemory(procId, atAddr, snapshotStack.top().data(), len)) {
        snapshotStack.pop();
        if (snapshotStack.empty())
            snapshots[procId].erase(atAddr);
        return false;
    }

    return true;
}

bool PtracePopSnapshot(int procId, uintptr_t atAddr)
{
    auto pidIt = snapshots.find(procId);
    if (pidIt == snapshots.end())
        return false;

    auto addrIt = pidIt->second.find(atAddr);
    if (addrIt == pidIt->second.end())
        return false;

    auto& snapshotStack = addrIt->second;
    if (snapshotStack.empty())
        return false;

    if (!PtraceWriteProcessMemory(procId, atAddr, snapshotStack.top().data(), snapshotStack.top().size())) {
        return false;
    }

    snapshotStack.pop();
    if (snapshotStack.empty())
        pidIt->second.erase(addrIt);

    return true;
}

std::unordered_map<int, std::stack< user_regs_struct >> contexts;

bool PushContext(int procId) {
    user_regs_struct ctx;
    if (!GetContext(procId, ctx))
        return false;

    contexts[procId].push(ctx);

    return true;
}

bool PopContext(int procId) {
    auto stackIt = contexts.find(procId);
    if (stackIt == contexts.end())
        return false;

    std::stack<user_regs_struct>& stack = stackIt->second;

    if (stack.empty())
        return false;

    if (!SetContext(procId, stack.top()))
        return false;

    stack.pop();

    if (stack.empty())
        contexts.erase(stackIt);

    return true;
}
