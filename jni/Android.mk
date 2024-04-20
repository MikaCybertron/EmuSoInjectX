LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_LDLIBS := -llog
LOCAL_CPPFLAGS += -fexceptions -std=c++17

LOCAL_MODULE := emuinj

LOCAL_SRC_FILES := \
main.cpp \
EmuInject.cpp \
LinuxProcess.cpp \
Errors.cpp \
Helper.cpp \
Ptrace.cpp \
RemoteString.cpp \
PtraceRPCWrappers.cpp

include $(BUILD_EXECUTABLE)