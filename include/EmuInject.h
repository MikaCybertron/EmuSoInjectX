#pragma once

class EmuInject 
{
    public:
    static bool Inject(const char* pProcName, const char* pLibPath);
};