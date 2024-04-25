#include <RemoteString.h>
#include <string.h>

RemoteString::RemoteString(int procId, const char* str)
    : mString(procId, str, strlen(str))
{}

RemoteString::operator bool()
{
    return mString;
}
