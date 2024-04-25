#pragma once

#include <cstdint>
#include <RemoteBuffer.h>

struct RemoteString {

    RemoteString(int procId, const char* str);

    operator bool();

    RemoteBuffer mString;
};