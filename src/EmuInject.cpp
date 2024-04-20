#include <EmuInject.h>
#include <PtraceRPCWrappers.h>
#include <Ptrace.h>
#include <Helper.h>
#include <Errors.h>
#include <LinuxProcess.h>
#include <RemoteString.h>
#include <dlfcn.h>
#include <unistd.h>

bool EmuInject::Inject(const char* pProcName, const char* pLibPath)
{
    if(FileExists(pLibPath) == false)
    {
        SetLastError(ERR_INJECTION_FILE_NOT_FOUND);
        return false;
    }

    std::string pLibAbsolutePath = "";

    if(ToAbsolutePath(pLibPath, pLibAbsolutePath) == false)
    {
        SetLastError(ERR_INJECTION_FILE_NOT_FOUND);
        return false;
    }

    printf("[+] Library: %s\n", pLibAbsolutePath.c_str());

    int procId = FindProcessId(pProcName);

    if(procId == INVALID_PROCESS_ID)
    {
        SetLastError(ERR_PROCESS_NOT_FOUND);
        return false;
    }

    printf("[+] Process Id: %d\n", procId);


    bool bSucessdedInjection = false;
    
    bool result = PtraceStopCallbackResume(procId, [&]{

        RemoteString rs(procId, pLibAbsolutePath.c_str());
        void* addr = nullptr;

        // printf("%p\n", 
        
        // (void*)PtraceCallModuleSymbol(procId, "/system/bin/linker64", "__dl_dlopen", false, {
        //     rs.mEntry,
        //     RTLD_NOW,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0
        // })
        
        // );

        bSucessdedInjection = (addr = PtraceCallNativeBridgeDlopen(procId, rs.mEntry, RTLD_NOW)) != nullptr;

        printf("PtraceCallNativeBridgeDlopen() => %p\n", addr);

        if(bSucessdedInjection == false && IsLastErrorSet() == false)
            SetLastError(ERR_INJECTION_FAILED);
    });

    if(result == false)
        return false;

    if(bSucessdedInjection == false)
        return false;

    return true;
}