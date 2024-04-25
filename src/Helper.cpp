#include "Helper.h"
#include <fstream>
#include <unistd.h>
#include <iostream>
#include <iomanip>

bool FileExists(const char* pFileName)
{
    std::ifstream file(pFileName);

    return file.good();
}

bool ToAbsolutePath(const char* path, std::string& outPath)
{
    char absolutePath[PATH_MAX];

    const char* resolvedPath = realpath(path, absolutePath);

    printf("Full Path %s\n", resolvedPath);

    outPath = resolvedPath == nullptr ? "" : std::string(resolvedPath);

    return resolvedPath != nullptr;
}

bool OpenCallbackClose(const char* pFileName, const char* mode, std::function<void(FILE*)> callback)
{
    FILE* f = fopen(pFileName, mode);

    if(f == nullptr)
        return false;    

    callback(f);

    fclose(f);

    return true;
}

void HexDump(const void* buffer, std::size_t size) {
    const unsigned char* p = static_cast<const unsigned char*>(buffer);
    for (std::size_t i = 0; i < size; i += 16) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << i << " | ";
        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < size)
                std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned>(p[i + j]) << " ";
            else
                std::cout << "   ";
        }
        std::cout << " | ";
        for (std::size_t j = 0; j < 16 && i + j < size; ++j) {
            unsigned char c = p[i + j];
            std::cout << (c >= 32 && c < 127 ? c : '.');
        }
        std::cout << std::endl;
    }
}